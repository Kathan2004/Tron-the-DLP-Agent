#!/usr/bin/env python3
"""
Sign agent installers for remote upgrade.

    # once: create a key pair; keep the private key offline
    python scripts/sign_agent_update.py keygen --out tron-update.key
    #   -> prints TRON_UPDATE_PUBKEY=<base64>   (set this on every agent)

    # per release: sign the installer you will host over HTTPS
    python scripts/sign_agent_update.py sign --key tron-update.key install.sh
    #   -> prints the sha256 and signature to POST to /api/fleet/agents/<id>/upgrade
"""
import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def keygen(out: Path) -> None:
    if out.exists():
        sys.exit(f"{out} already exists; refusing to overwrite")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"private key written to {out} (mode 600, keep it offline)")
    print(f"TRON_UPDATE_PUBKEY={base64.b64encode(pub).decode()}")


def sign(key_path: Path, installer: Path, url: str, version: str) -> None:
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("key is not an Ed25519 private key")
    payload = installer.read_bytes()
    body = {
        "download_url": url or "https://<host>/" + installer.name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(key.sign(payload)).decode(),
        "target_version": version,
    }
    print(json.dumps(body, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("sign")
    s.add_argument("--key", type=Path, required=True)
    s.add_argument("--url", default="")
    s.add_argument("--version", default="latest")
    s.add_argument("installer", type=Path)
    args = parser.parse_args()
    if args.cmd == "keygen":
        keygen(args.out)
    else:
        sign(args.key, args.installer, args.url, args.version)


if __name__ == "__main__":
    main()
