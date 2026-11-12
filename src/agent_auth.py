"""
Per-agent credentials for the ingest API.

Lifecycle
    enroll   An agent presents the shared enrollment token (TRON_AGENT_TOKEN) once and
             receives its own key. Enrolling an agent ID that already holds an active key
             is refused, so the enrollment token alone cannot take over an existing agent.
    use      Every ingest request carries X-Tron-Agent-Id and X-Tron-Agent-Key. The server
             stores only SHA-256(key); keys are 256 bits of CSPRNG output, so a fast hash
             is sufficient and keeps per-request verification cheap.
    rotate   The agent (or an operator-queued command) asks for a new key. The previous key
             stays valid for a short grace window in case the response is lost.
    revoke   An operator revokes the key; the agent must be re-enrolled.

Modes (TRON_AGENT_AUTH)
    open      No agent authentication. Only when TRON_AGENT_TOKEN is unset.
    token     Shared enrollment token or a per-agent key is accepted on ingest (default
              when TRON_AGENT_TOKEN is set; lets a fleet migrate to keys gradually).
    strict    Only per-agent keys are accepted on ingest. The enrollment token is valid
              for /api/fleet/enroll and nothing else.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

KEY_PREFIX = "tron_ak_"
AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
ROTATION_GRACE_SECONDS = 600


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    method: str          # "key" | "token" | "open"


def enrollment_token() -> str:
    return os.getenv("TRON_AGENT_TOKEN", "").strip()


def auth_mode() -> str:
    mode = os.getenv("TRON_AGENT_AUTH", "").strip().lower()
    if mode in {"open", "token", "strict"}:
        if mode == "open" and enrollment_token():
            return "token"
        if mode != "open" and not enrollment_token():
            # token/strict without an enrollment secret would lock every agent out; strict
            # still works for agents whose keys were issued from the console.
            return "strict" if mode == "strict" else "open"
        return mode
    return "token" if enrollment_token() else "open"


def valid_agent_id(agent_id: str) -> bool:
    return bool(AGENT_ID_RE.match(agent_id or ""))


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def key_prefix(key: str) -> str:
    """Non-secret identifier shown in the console (first characters after the scheme)."""
    return key[: len(KEY_PREFIX) + 6]


def token_matches(supplied: str) -> bool:
    expected = enrollment_token()
    return bool(expected) and bool(supplied) and hmac.compare_digest(supplied.encode(), expected.encode())


def verify_key(credential: Optional[dict], supplied_key: str) -> bool:
    """Constant-time check of a supplied key against the stored credential row."""
    if not credential or not supplied_key or credential.get("revoked_at"):
        return False
    digest = hash_key(supplied_key)
    if hmac.compare_digest(digest, str(credential.get("key_hash") or "")):
        return True
    prev = str(credential.get("prev_key_hash") or "")
    until = str(credential.get("prev_valid_until") or "")
    if prev and until and hmac.compare_digest(digest, prev):
        try:
            return datetime.now(timezone.utc) < datetime.fromisoformat(until)
        except ValueError:
            return False
    return False


def authenticate(database, headers, remote_ip: Optional[str] = None) -> Optional[AgentIdentity]:
    """Authenticate an ingest request. Returns None when the caller must be rejected."""
    mode = auth_mode()
    agent_id = (headers.get("X-Tron-Agent-Id") or "").strip()
    agent_key = (headers.get("X-Tron-Agent-Key") or "").strip()

    if agent_id and agent_key and database is not None and valid_agent_id(agent_id):
        credential = database.get_agent_credential(agent_id)
        if verify_key(credential, agent_key):
            try:
                database.touch_agent_credential(agent_id, remote_ip)
            except Exception:
                pass
            return AgentIdentity(agent_id=agent_id, method="key")
        # A key was presented and is wrong: never fall through to a weaker method.
        return None

    if mode == "strict":
        return None
    if mode == "token":
        if token_matches((headers.get("X-Tron-Agent-Token") or "").strip()):
            return AgentIdentity(agent_id=agent_id if valid_agent_id(agent_id) else "", method="token")
        return None
    return AgentIdentity(agent_id=agent_id if valid_agent_id(agent_id) else "", method="open")
