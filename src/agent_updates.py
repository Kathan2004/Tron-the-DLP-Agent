"""
Signed agent upgrades.

The console can queue an upgrade for an agent; the agent receives it on its next
fleet check-in. Upgrades used to carry a free-form shell command, which made the
API server (or anyone able to spoof it over plain HTTP) a remote shell on every
endpoint. Now an upgrade is only an HTTPS URL plus the installer's SHA-256 and an
Ed25519 signature over the installer bytes. Agents verify both against a public
key pinned locally in TRON_UPDATE_PUBKEY before executing anything, so a
compromised or impersonated server cannot run code on endpoints.

Generate a key pair and sign installers with scripts/sign_agent_update.py.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_INSTALLER_BYTES = 200 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class UpgradeRejected(ValueError):
    """The upgrade command failed validation and must not be executed."""


@dataclass(frozen=True)
class UpgradeCommand:
    download_url: str
    sha256: str
    signature: bytes
    target_version: str


def validate_upgrade_request(data: dict) -> UpgradeCommand:
    """Validate an upgrade request (server side and agent side use the same rules)."""
    if data.get("install_command"):
        raise UpgradeRejected("install_command is no longer supported; publish a signed installer instead")
    url = str(data.get("download_url") or "").strip()
    if urlparse(url).scheme != "https" or not urlparse(url).hostname:
        raise UpgradeRejected("download_url must be an https:// URL")
    digest = str(data.get("sha256") or "").strip().lower()
    if not _SHA256_RE.match(digest):
        raise UpgradeRejected("sha256 must be 64 lowercase hex characters")
    try:
        signature = base64.b64decode(str(data.get("signature") or ""), validate=True)
    except ValueError as exc:
        raise UpgradeRejected("signature must be base64") from exc
    if len(signature) != 64:
        raise UpgradeRejected("signature must be a 64-byte Ed25519 signature")
    version = str(data.get("target_version") or "latest").strip()[:64] or "latest"
    return UpgradeCommand(url, digest, signature, version)


def load_pinned_public_key(value: Optional[str] = None) -> Optional[Ed25519PublicKey]:
    raw = (value if value is not None else os.getenv("TRON_UPDATE_PUBKEY", "")).strip()
    if not raw:
        return None
    try:
        key_bytes = base64.b64decode(raw, validate=True)
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    except ValueError as exc:
        raise UpgradeRejected("TRON_UPDATE_PUBKEY is not a base64 Ed25519 public key") from exc


def verify_installer(payload: bytes, command: UpgradeCommand, public_key: Ed25519PublicKey) -> None:
    if hashlib.sha256(payload).hexdigest() != command.sha256:
        raise UpgradeRejected("installer SHA-256 does not match")
    try:
        public_key.verify(command.signature, payload)
    except InvalidSignature as exc:
        raise UpgradeRejected("installer signature is invalid") from exc


def _download(url: str) -> bytes:
    with requests.get(url, stream=True, timeout=30) as resp:
        resp.raise_for_status()
        chunks, total = [], 0
        for chunk in resp.iter_content(64 * 1024):
            total += len(chunk)
            if total > MAX_INSTALLER_BYTES:
                raise UpgradeRejected("installer exceeds size limit")
            chunks.append(chunk)
    return b"".join(chunks)


def apply_upgrade(raw_command: dict, public_key: Optional[Ed25519PublicKey] = None) -> str:
    """Download, verify and launch a signed installer. Returns a status string."""
    command = validate_upgrade_request(raw_command)
    key = public_key or load_pinned_public_key()
    if key is None:
        raise UpgradeRejected("TRON_UPDATE_PUBKEY is not set; remote upgrades are disabled on this agent")
    if os.name != "posix":
        raise UpgradeRejected("remote upgrades are only supported on POSIX agents")

    payload = _download(command.download_url)
    verify_installer(payload, command, key)

    fd, path = tempfile.mkstemp(prefix="tron-upgrade-", suffix=".sh")
    with os.fdopen(fd, "wb") as fh:
        fh.write(payload)
    os.chmod(path, 0o700)
    # Fixed argv, no shell: the installer path is the only thing executed.
    subprocess.Popen(["/bin/sh", path], stdout=sys.stdout, stderr=sys.stderr, start_new_session=True)
    return f"launched verified installer for {command.target_version}"


def agent_headers() -> dict:
    """Headers every agent sends to the API (enrollment token from TRON_AGENT_TOKEN)."""
    token = os.getenv("TRON_AGENT_TOKEN", "").strip()
    return {"X-Tron-Agent-Token": token} if token else {}
