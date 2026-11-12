"""
Encryption at rest for sensitive columns and captured artifacts.

AES-256-GCM with a 256-bit data key. The key comes from TRON_DATA_KEY (base64, 32 bytes)
or, when that is unset, from <data dir>/.data.key which is created with mode 0600 on first
use. Keeping the key outside the data directory (env var from a secret manager) is what
protects database copies and backups; the auto-generated key file only protects against
the database file leaking on its own.

Wire formats
    text field : "enc:v1:" + base64url(nonce[12] || ciphertext || tag[16])
    file       : b"TRONENC1" + nonce[12] + ciphertext || tag[16]

Both readers pass legacy plaintext through unchanged, so enabling encryption on an
existing deployment needs no migration step: old rows stay readable, new rows are sealed.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("tron.crypto")

TEXT_PREFIX = "enc:v1:"
FILE_MAGIC = b"TRONENC1"
_NONCE_LEN = 12
_KEY_FILE_NAME = ".data.key"


class DataKeyError(RuntimeError):
    """The data key is missing, malformed, or does not match the stored ciphertext."""


def generate_key() -> str:
    """Return a new base64 data key suitable for TRON_DATA_KEY."""
    return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode("ascii")


def _decode_key(raw: str) -> bytes:
    value = raw.strip()
    try:
        key = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise DataKeyError("data key is not valid base64") from exc
    if len(key) != 32:
        raise DataKeyError("data key must decode to exactly 32 bytes")
    return key


class DataCipher:
    """Seals and opens text fields and files. Disabled instances are transparent."""

    def __init__(self, key: bytes | None):
        self._aead = AESGCM(key) if key else None

    @property
    def enabled(self) -> bool:
        return self._aead is not None

    # ---- text fields -------------------------------------------------

    def seal_text(self, value: str | None, aad: bytes = b"") -> str | None:
        if value is None or self._aead is None or value == "":
            return value
        if value.startswith(TEXT_PREFIX):
            return value
        nonce = os.urandom(_NONCE_LEN)
        blob = nonce + self._aead.encrypt(nonce, value.encode("utf-8"), aad or None)
        return TEXT_PREFIX + base64.urlsafe_b64encode(blob).decode("ascii")

    def open_text(self, value: str | None, aad: bytes = b"") -> str | None:
        if not isinstance(value, str) or not value.startswith(TEXT_PREFIX):
            return value
        if self._aead is None:
            raise DataKeyError("encrypted value found but no data key is configured")
        try:
            blob = base64.urlsafe_b64decode(value[len(TEXT_PREFIX):])
            return self._aead.decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], aad or None).decode("utf-8")
        except (InvalidTag, ValueError) as exc:
            raise DataKeyError("could not decrypt value: wrong data key or corrupted data") from exc

    # ---- files -------------------------------------------------------

    def seal_bytes(self, data: bytes, aad: bytes = b"") -> bytes:
        if self._aead is None:
            return data
        nonce = os.urandom(_NONCE_LEN)
        return FILE_MAGIC + nonce + self._aead.encrypt(nonce, data, aad or None)

    def open_bytes(self, data: bytes, aad: bytes = b"") -> bytes:
        if not data.startswith(FILE_MAGIC):
            return data
        if self._aead is None:
            raise DataKeyError("encrypted artifact found but no data key is configured")
        body = data[len(FILE_MAGIC):]
        try:
            return self._aead.decrypt(body[:_NONCE_LEN], body[_NONCE_LEN:], aad or None)
        except InvalidTag as exc:
            raise DataKeyError("could not decrypt artifact: wrong data key or corrupted file") from exc


_lock = threading.Lock()
_ciphers: dict[str, DataCipher] = {}


def _load_or_create_key_file(data_dir: Path) -> bytes:
    path = data_dir / _KEY_FILE_NAME
    if path.exists():
        return _decode_key(path.read_text(encoding="ascii"))
    data_dir.mkdir(parents=True, exist_ok=True)
    encoded = generate_key()
    # O_EXCL: never overwrite a key another process created in the meantime.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _decode_key(path.read_text(encoding="ascii"))
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(encoded)
    log.warning(
        "TRON_DATA_KEY is not set: generated %s. Back this file up separately from the "
        "database; without it encrypted findings and artifacts cannot be read.", path)
    return _decode_key(encoded)


def get_cipher(data_dir: str | os.PathLike | None = None) -> DataCipher:
    """Process-wide cipher for a data directory.

    TRON_ENCRYPT_AT_REST=0 disables encryption (values are stored and returned as-is);
    already encrypted rows then fail loudly instead of being served as ciphertext.
    """
    directory = Path(data_dir) if data_dir else Path(__file__).resolve().parent.parent / "data"
    cache_key = str(directory.resolve())
    with _lock:
        cipher = _ciphers.get(cache_key)
        if cipher is not None:
            return cipher
        if os.getenv("TRON_ENCRYPT_AT_REST", "1").strip().lower() in {"0", "false", "no", "off"}:
            cipher = DataCipher(None)
        else:
            env_key = os.getenv("TRON_DATA_KEY", "").strip()
            key = _decode_key(env_key) if env_key else _load_or_create_key_file(directory)
            cipher = DataCipher(key)
        _ciphers[cache_key] = cipher
        return cipher


def reset_cipher_cache() -> None:
    """Forget cached ciphers (tests, key rotation tooling)."""
    with _lock:
        _ciphers.clear()
