"""API: event ingest with policies, deep scan, and auth on server-side scan endpoints."""

import base64
import json

import pytest

from tests import fixtures as F


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from src import api
    from src.ai_analyzer import FalsePositiveClassifier, VertexAIAnalyzer
    from src.database import Database
    from src.event_processor import EscalationEngine, EventProcessor
    from src.incident_store import IncidentStore
    from src.rules_engine import RulesEngine
    from src.telegram_bot import DLPTelegramBot

    db = Database(str(tmp_path / "test.db"))
    store = IncidentStore(db=db)
    rules = RulesEngine()
    rules.db = db
    processor = EventProcessor(rules, store)
    bot = DLPTelegramBot(store)
    analyzer = VertexAIAnalyzer()
    api.init_components(store, rules, processor, EscalationEngine(), analyzer,
                        FalsePositiveClassifier(analyzer), bot, db)
    api.app.config["TESTING"] = True
    with api.app.test_client() as c:
        yield c


def post(client, path, body, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post(path, data=json.dumps(body), content_type="application/json", headers=headers)


def login(client):
    r = post(client, "/api/auth/login", {"email": "admin@tron.local", "password": "Test-Admin-Pass-123!"})
    assert r.status_code == 200, r.json
    return r.json["token"]


def test_health(client):
    assert client.get("/api/health").status_code == 200


def test_event_ingest_matches_default_detector_policies(client):
    r = post(client, "/api/events", {"agent_type": "endpoint", "source_host": "h", "user": "u",
                                     "channel": "clipboard", "payload": "ssn 536-22-1234"})
    assert r.status_code == 200 and r.json["event_id"]


def test_event_ingest_ignores_lookalikes(client):
    r = post(client, "/api/events", {"agent_type": "endpoint", "source_host": "h", "user": "u",
                                     "channel": "clipboard", "payload": "order 1234567812345678 ref 123412341234"})
    assert r.status_code == 200 and r.json["event_id"] is None


@pytest.mark.parametrize("path", ["/api/scan/file", "/api/scan/clipboard"])
def test_server_side_scans_require_auth(client, path):
    assert post(client, path, {"path": "/etc"}).status_code == 401


def test_scan_file_with_auth(client, tmp_path):
    (tmp_path / "leak.txt").write_text("ssn 536-22-1234")
    r = post(client, "/api/scan/file", {"path": str(tmp_path / "leak.txt")}, token=login(client))
    assert r.status_code == 200 and r.json["files_scanned"] == 1


def test_browser_deep_scan(client):
    payload = {"file_name": "report.txt", "file_content_base64": base64.b64encode(F.text_pdf([F.SECRET_LINE])).decode()}
    r = post(client, "/api/scan/browser-file", payload)
    assert r.status_code == 200
    assert r.json["file_type"] == "pdf" and r.json["type_mismatch"] is True
    assert {f["pattern_name"] for f in r.json["findings"]} >= {"US_SSN", "CREDIT_CARD"}


def test_browser_deep_scan_encrypted(client):
    payload = {"file_name": "x.pdf", "file_content_base64": base64.b64encode(F.encrypted_pdf(["x"])).decode()}
    r = post(client, "/api/scan/browser-file", payload)
    assert r.json["encrypted"] is True and r.json["inspected"] is False


def test_policy_with_detector_reference(client):
    token = login(client)
    r = post(client, "/api/policies", {"name": "GH_TOKENS", "rule_type": "regex", "detector": "GITHUB_TOKEN",
                                       "severity": "CRITICAL"}, token=token)
    assert r.status_code == 201, r.json
    r = post(client, "/api/policies", {"name": "BAD", "rule_type": "regex", "detector": "NOPE"}, token=token)
    assert r.status_code == 400


def test_request_size_cap(client):
    from src import api
    big = b"x" * (api.app.config["MAX_CONTENT_LENGTH"] + 1)
    r = client.post("/api/scan/text", data=big, content_type="application/json")
    assert r.status_code == 413


def test_agent_token_enforced_on_ingestion_when_configured(client, monkeypatch):
    from src import api
    monkeypatch.setattr(api, "AGENT_TOKEN", "enroll-123")
    event = {"agent_type": "endpoint", "source_host": "h", "user": "u", "channel": "clipboard", "payload": "x"}
    assert post(client, "/api/events", event).status_code == 401
    assert post(client, "/api/fleet/checkin", {"agent_id": "a"}).status_code == 401
    r = client.post("/api/events", data=json.dumps(event), content_type="application/json",
                    headers={"X-Tron-Agent-Token": "enroll-123"})
    assert r.status_code == 200
    # Health and login stay reachable without the enrollment token.
    assert client.get("/api/health").status_code == 200


def test_upgrade_rejects_shell_commands(client):
    token = login(client)
    r = post(client, "/api/fleet/agents/a1/upgrade", {"install_command": "curl x | sh"}, token)
    assert r.status_code == 400
    r = post(client, "/api/fleet/agents/a1/upgrade", {"download_url": "http://x/i.sh"}, token)
    assert r.status_code == 400


def test_upgrade_queues_signed_manifest(client):
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    token = login(client)
    payload = b"#!/bin/sh\necho ok\n"
    body = {
        "download_url": "https://updates.example.com/install.sh",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(Ed25519PrivateKey.generate().sign(payload)).decode(),
        "target_version": "1.2",
    }
    r = post(client, "/api/fleet/agents/a1/upgrade", body, token)
    assert r.status_code == 200
    assert "install_command" not in r.json["command"]
    assert r.json["command"]["requested_by"] == "admin@tron.local"
