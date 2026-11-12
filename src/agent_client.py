"""
API client shared by the Python agents.

Handles what every agent needs and none should reimplement:
  - identity: a stable, API-safe agent ID
  - credentials: enroll once with TRON_AGENT_TOKEN, keep the per-agent key in a 0600 file
    in the agent state directory, rotate it when the server asks
  - offline spool: events that cannot be delivered are sealed to disk and replayed in
    order when the API is reachable again, so a network outage does not lose detections
  - transport policy: plain http is only accepted for loopback unless explicitly allowed
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests

from src import platform_support
from src.crypto import DataCipher, _decode_key, generate_key

log = logging.getLogger("tron.agent")

# Agents started from a checkout pick up TRON_AGENT_TOKEN / TRON_UPDATE_PUBKEY from the
# project's .env; real environment variables win.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(os.getenv("TRON_ENV_FILE") or Path(__file__).resolve().parent.parent / ".env"), override=False)
except ImportError:
    pass

SPOOL_MAX_ENTRIES = 5000
SPOOL_MAX_BYTES = 20 * 1024 * 1024
_ID_UNSAFE = re.compile(r"[^A-Za-z0-9._:@-]+")


class TransportRefused(RuntimeError):
    """The configured API URL does not meet the transport policy."""


def safe_agent_id(*parts: str) -> str:
    """Join parts into an ID the API accepts (DOMAIN\\user, spaces etc. are normalised)."""
    raw = "-".join(_ID_UNSAFE.sub("-", str(p)).strip("-") for p in parts if p)
    return (raw or "agent")[:128]


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


class AgentClient:
    def __init__(self, api_url: str, agent_id: str, agent_type: str, hostname: Optional[str] = None,
                 state_dir: Optional[Path] = None, session: Optional[requests.Session] = None):
        self.api_url = api_url.rstrip("/")
        self.agent_id = safe_agent_id(agent_id)
        self.agent_type = agent_type
        self.hostname = hostname or platform_support.hostname()
        self.state_dir = Path(state_dir) if state_dir else platform_support.state_dir()
        self.session = session or requests.Session()
        self._lock = threading.Lock()
        self._key: Optional[str] = None
        self._enroll_failed_logged = False
        self._check_transport()
        self._load_key()

    # ---------------------------------------------------------------- transport policy

    def _check_transport(self) -> None:
        parsed = urlparse(self.api_url)
        if parsed.scheme == "https":
            return
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "http" or (not loopback and os.getenv("TRON_ALLOW_INSECURE_API", "") != "1"):
            raise TransportRefused(
                f"refusing to send detections to {self.api_url}: use https, or set "
                "TRON_ALLOW_INSECURE_API=1 to accept plain http on a trusted network")
        if not loopback:
            log.warning("API URL %s is plain http: detections and the agent key travel unencrypted", self.api_url)

    # ---------------------------------------------------------------- credentials

    @property
    def _key_path(self) -> Path:
        return self.state_dir / f"{self.agent_id}.key.json"

    def _load_key(self) -> None:
        env_key = os.getenv("TRON_AGENT_KEY", "").strip()
        if env_key:
            self._key = env_key
            return
        try:
            data = json.loads(self._key_path.read_text(encoding="utf-8"))
            if data.get("api_url") == self.api_url and data.get("agent_key"):
                self._key = data["agent_key"]
        except (OSError, ValueError):
            pass

    def _store_key(self, key: str) -> None:
        self._key = key
        _write_private(self._key_path, json.dumps({"api_url": self.api_url, "agent_id": self.agent_id,
                                                   "agent_key": key}))

    @property
    def enrolled(self) -> bool:
        return bool(self._key)

    def headers(self) -> dict:
        if self._key:
            return {"X-Tron-Agent-Id": self.agent_id, "X-Tron-Agent-Key": self._key}
        token = os.getenv("TRON_AGENT_TOKEN", "").strip()
        headers = {"X-Tron-Agent-Id": self.agent_id}
        if token:
            headers["X-Tron-Agent-Token"] = token
        return headers

    def ensure_enrolled(self) -> bool:
        """Obtain a per-agent key if we have an enrollment token and no key yet."""
        if self._key:
            return True
        token = os.getenv("TRON_AGENT_TOKEN", "").strip()
        if not token:
            return False
        with self._lock:
            if self._key:
                return True
            try:
                res = self.session.post(
                    f"{self.api_url}/api/fleet/enroll", timeout=10,
                    headers={"X-Tron-Agent-Token": token},
                    json={"agent_id": self.agent_id, "agent_type": self.agent_type, "hostname": self.hostname})
            except requests.RequestException:
                return False
            if res.status_code == 201:
                self._store_key(res.json()["agent_key"])
                log.info("enrolled as %s", self.agent_id)
                return True
            if not self._enroll_failed_logged:
                self._enroll_failed_logged = True
                reason = "already enrolled elsewhere; revoke the key in the console to re-enroll" \
                    if res.status_code == 409 else f"HTTP {res.status_code}"
                log.warning("enrollment of %s failed: %s", self.agent_id, reason)
            return False

    def rotate_key(self) -> bool:
        if not self._key:
            return False
        try:
            res = self.session.post(f"{self.api_url}/api/fleet/agents/{self.agent_id}/key/rotate",
                                    headers=self.headers(), timeout=10)
        except requests.RequestException:
            return False
        if res.status_code != 200:
            log.warning("key rotation failed: HTTP %s", res.status_code)
            return False
        self._store_key(res.json()["agent_key"])
        log.info("agent key rotated")
        return True

    def handle_command(self, command: Optional[dict]) -> bool:
        """Handle transport-level commands. Returns True when the command was consumed."""
        if isinstance(command, dict) and command.get("type") == "rotate_key":
            self.rotate_key()
            return True
        return False

    # ---------------------------------------------------------------- requests

    def get(self, path: str, params: Optional[dict] = None, timeout: float = 5) -> Optional[requests.Response]:
        self.ensure_enrolled()
        try:
            return self.session.get(f"{self.api_url}{path}", params=params, headers=self.headers(), timeout=timeout)
        except requests.RequestException:
            return None

    def post(self, path: str, json_body: Optional[dict] = None, timeout: float = 5,
             spool: bool = False) -> Optional[requests.Response]:
        """POST to the API. With spool=True an undeliverable body is kept for replay."""
        self.ensure_enrolled()
        try:
            res = self.session.post(f"{self.api_url}{path}", json=json_body, headers=self.headers(), timeout=timeout)
        except requests.RequestException:
            if spool:
                self._spool_append(path, json_body)
            return None
        if res.status_code >= 500 or res.status_code == 429:
            if spool:
                self._spool_append(path, json_body)
        elif spool and res.ok:
            self.flush_spool()
        return res

    # ---------------------------------------------------------------- offline spool

    @property
    def _spool_path(self) -> Path:
        return self.state_dir / f"{self.agent_id}.spool"

    def _spool_cipher(self) -> DataCipher:
        key_path = self.state_dir / "spool.key"
        try:
            return DataCipher(_decode_key(key_path.read_text(encoding="ascii")))
        except (OSError, RuntimeError):
            encoded = generate_key()
            _write_private(key_path, encoded)
            return DataCipher(_decode_key(encoded))

    def _spool_append(self, path: str, body: Optional[dict]) -> None:
        try:
            with self._lock:
                spool = self._spool_path
                if spool.exists() and spool.stat().st_size > SPOOL_MAX_BYTES:
                    log.warning("offline spool is full; dropping event")
                    return
                line = self._spool_cipher().seal_text(json.dumps({"path": path, "body": body}))
                spool.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(spool, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="ascii") as fh:
                    fh.write(line + "\n")
        except OSError as exc:
            log.warning("could not spool event: %s", exc)

    def spool_size(self) -> int:
        try:
            with open(self._spool_path, encoding="ascii") as fh:
                return sum(1 for _ in fh)
        except OSError:
            return 0

    def flush_spool(self) -> int:
        """Replay spooled events in order. Stops at the first transient failure."""
        with self._lock:
            spool = self._spool_path
            try:
                lines = spool.read_text(encoding="ascii").splitlines()
            except OSError:
                return 0
            if not lines:
                return 0
            cipher = self._spool_cipher()
            sent = 0
            remaining = []
            for i, line in enumerate(lines[-SPOOL_MAX_ENTRIES:]):
                try:
                    entry = json.loads(cipher.open_text(line))
                except (ValueError, RuntimeError):
                    continue  # unreadable entry (key changed / truncated write): discard
                try:
                    res = self.session.post(f"{self.api_url}{entry['path']}", json=entry.get("body"),
                                            headers=self.headers(), timeout=5)
                except requests.RequestException:
                    remaining = lines[-SPOOL_MAX_ENTRIES:][i:]
                    break
                if res.status_code >= 500 or res.status_code == 429:
                    remaining = lines[-SPOOL_MAX_ENTRIES:][i:]
                    break
                sent += 1  # delivered, or rejected permanently (4xx): either way it leaves the spool
            if remaining:
                _write_private(spool, "\n".join(remaining) + "\n")
            else:
                try:
                    spool.unlink()
                except OSError:
                    pass
            if sent:
                log.info("replayed %s spooled event(s)", sent)
            return sent
