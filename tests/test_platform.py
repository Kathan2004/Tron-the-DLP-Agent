"""Platform features: agent keys, encryption at rest, document matching, SIEM forwarding,
retention, audit chain, metrics and HTTP hardening."""

import io
import json
import sqlite3

import pytest

from src import agent_auth, crypto, retention, siem
from src.detection import idm

ENROLL = {"X-Tron-Agent-Token": "enroll-123"}
EVENT = {"agent_type": "endpoint", "source_host": "h1", "user": "alice", "channel": "clipboard",
         "payload": "ssn 536-22-1234"}


def enroll(client, agent_id="agent-01"):
    r = client.post("/api/fleet/enroll", json={"agent_id": agent_id, "agent_type": "endpoint",
                                               "hostname": "h1"}, headers=ENROLL)
    assert r.status_code == 201, r.json
    return {"X-Tron-Agent-Id": agent_id, "X-Tron-Agent-Key": r.json["agent_key"]}


# ----------------------------------------------------------------- agent credentials

def test_enrollment_issues_key_once_and_refuses_takeover(client, monkeypatch):
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    assert client.post("/api/fleet/enroll", json={"agent_id": "agent-01"}).status_code == 401
    creds = enroll(client)
    assert creds["X-Tron-Agent-Key"].startswith(agent_auth.KEY_PREFIX)
    # The enrollment token alone cannot replace an enrolled agent's key.
    r = client.post("/api/fleet/enroll", json={"agent_id": "agent-01"}, headers=ENROLL)
    assert r.status_code == 409
    # Only the hash is stored.
    stored = client.db.get_agent_credential("agent-01")
    assert creds["X-Tron-Agent-Key"] not in json.dumps(stored)
    assert stored["key_hash"] == agent_auth.hash_key(creds["X-Tron-Agent-Key"])


def test_enrollment_disabled_without_token(client):
    assert client.post("/api/fleet/enroll", json={"agent_id": "agent-01"}).status_code == 403


def test_strict_mode_requires_per_agent_key(client, monkeypatch):
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    creds = enroll(client)
    monkeypatch.setenv("TRON_AGENT_AUTH", "strict")
    assert client.post("/api/events", json=EVENT, headers=ENROLL).status_code == 401
    assert client.post("/api/events", json=EVENT).status_code == 401
    assert client.post("/api/events", json=EVENT, headers=creds).status_code == 200
    bad = {**creds, "X-Tron-Agent-Key": agent_auth.generate_key()}
    assert client.post("/api/events", json=EVENT, headers=bad).status_code == 401


def test_wrong_key_does_not_fall_back_to_shared_token(client, monkeypatch):
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    creds = enroll(client)
    headers = {**ENROLL, "X-Tron-Agent-Id": creds["X-Tron-Agent-Id"], "X-Tron-Agent-Key": "tron_ak_wrong"}
    assert client.post("/api/events", json=EVENT, headers=headers).status_code == 401


def test_key_binds_agent_identity_on_checkin(client, monkeypatch):
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    creds = enroll(client)
    r = client.post("/api/fleet/checkin", json={"agent_id": "someone-else", "hostname": "h1"}, headers=creds)
    assert r.status_code == 200 and r.json["auth"] == "key"
    assert client.db.get_fleet_agent("agent-01") is not None
    assert client.db.get_fleet_agent("someone-else") is None
    # ... and cannot write another agent's operational log.
    r = client.post("/api/fleet/agents/other-agent/operational", json={"message": "x"}, headers=creds)
    assert r.status_code == 403


def test_key_rotation_with_grace_and_revocation(client, monkeypatch, auth):
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    monkeypatch.setenv("TRON_AGENT_AUTH", "strict")
    old = enroll(client)
    r = client.post("/api/fleet/agents/agent-01/key/rotate", headers=old)
    assert r.status_code == 200
    new = {**old, "X-Tron-Agent-Key": r.json["agent_key"]}
    assert new["X-Tron-Agent-Key"] != old["X-Tron-Agent-Key"]
    assert client.post("/api/events", json=EVENT, headers=new).status_code == 200
    # Old key still works during the grace window ...
    assert client.post("/api/events", json=EVENT, headers=old).status_code == 200
    # ... and stops once the window has passed.
    with client.db._cursor() as cur:
        cur.execute("UPDATE agent_credentials SET prev_valid_until = '2000-01-01T00:00:00+00:00'")
    assert client.post("/api/events", json=EVENT, headers=old).status_code == 401

    assert client.delete("/api/fleet/agents/agent-01/key", headers=auth).status_code == 200
    assert client.post("/api/events", json=EVENT, headers=new).status_code == 401
    # After revocation the agent can enroll again.
    assert client.post("/api/fleet/enroll", json={"agent_id": "agent-01"}, headers=ENROLL).status_code == 201


def test_rotation_requires_the_agents_own_key(client, monkeypatch):
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    a = enroll(client, "agent-01")
    enroll(client, "agent-02")
    assert client.post("/api/fleet/agents/agent-02/key/rotate", headers=a).status_code == 401
    assert client.post("/api/fleet/agents/agent-01/key/rotate", headers=ENROLL).status_code == 401


def test_credential_inventory_never_exposes_key_material(client, monkeypatch, auth):
    monkeypatch.setenv("TRON_AGENT_TOKEN", "enroll-123")
    creds = enroll(client)
    r = client.get("/api/fleet/credentials", headers=auth)
    assert r.status_code == 200 and r.json["credentials"][0]["agent_id"] == "agent-01"
    body = r.get_data(as_text=True)
    assert creds["X-Tron-Agent-Key"] not in body and "key_hash" not in body


# ----------------------------------------------------------------- fleet persistence

def test_fleet_state_and_commands_survive_restart(client, auth, tmp_path):
    client.post("/api/fleet/checkin", json={"agent_id": "agent-01", "hostname": "h1", "agent_type": "endpoint"})
    r = client.post("/api/fleet/agents/agent-01/policy", json={"managed_settings": {"mode": "block"}}, headers=auth)
    assert r.status_code == 200
    import base64
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    payload = b"#!/bin/sh\n"
    client.post("/api/fleet/agents/agent-01/upgrade", headers=auth, json={
        "download_url": "https://updates.example.com/i.sh", "sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(Ed25519PrivateKey.generate().sign(payload)).decode(), "target_version": "9"})

    # A second Database object on the same file stands in for a restarted process.
    from src.database import Database
    reopened = Database(client.db.db_path)
    assert reopened.get_fleet_agent("agent-01")["hostname"] == "h1"
    # A check-in must not wipe console-managed settings, and it delivers the queued command.
    r = client.post("/api/fleet/checkin", json={"agent_id": "agent-01", "hostname": "h1",
                                                "meta": {"managed_settings": {"mode": "off"}}})
    assert reopened.get_fleet_agent("agent-01")["managed_settings"]
    assert "managed_settings" not in reopened.get_fleet_agent("agent-01")["meta"]
    command = r.json["command"]
    assert command["type"] == "upgrade" and command["target_version"] == "9"
    assert reopened.pop_fleet_command("agent-01") is None  # delivered exactly once


# ----------------------------------------------------------------- encryption at rest

def test_sensitive_columns_are_encrypted_on_disk(client):
    assert client.post("/api/events", json=EVENT).json["event_id"]
    client.db.add_scan_result("file", "/tmp/x", [{"matched_text": "536-22-1234"}], "high")
    raw = sqlite3.connect(client.db.db_path)
    sample = raw.execute("SELECT payload_sample FROM events").fetchone()[0]
    findings = raw.execute("SELECT findings FROM scan_results").fetchone()[0]
    assert sample.startswith(crypto.TEXT_PREFIX) and "536-22-1234" not in sample
    assert findings.startswith(crypto.TEXT_PREFIX) and "536-22-1234" not in findings
    # ... and transparently readable through the API layer.
    assert "536-22-1234" in client.db.get_all_events()[0]["payload_sample"]
    assert "536-22-1234" in client.db.get_scan_results()[0]["findings"]


def test_legacy_plaintext_rows_stay_readable(client):
    with client.db._cursor() as cur:
        cur.execute("""INSERT INTO events (event_id, timestamp, agent_type, source_host, user, channel,
                       payload_hash, payload_sample, matched_rules, severity, geo)
                       VALUES ('EVT-OLD', '2020-01-01T00:00:00', 'endpoint', 'h', 'u', 'c', 'x', 'plain sample', '[]', 'low', '{}')""")
    assert client.db.get_event("EVT-OLD")["payload_sample"] == "plain sample"


def test_artifacts_are_encrypted_and_never_rendered_as_html(client, auth):
    html = b"<script>alert(document.domain)</script>"
    r = client.post("/api/browser/artifact/raw", data={
        "file": (io.BytesIO(html), "evil.html"), "user": "../../etc", "file_type": "text/html"})
    assert r.status_code == 200
    art = client.db.get_upload_artifact(r.json["artifact_id"])
    on_disk = open(art["content_path"], "rb").read()
    assert on_disk.startswith(crypto.FILE_MAGIC) and b"alert" not in on_disk
    from pathlib import Path
    store = (Path(client.db.db_path).parent / "artifacts" / "by_user").resolve()
    assert store in Path(art["content_path"]).resolve().parents  # "../../etc" stayed inside the store

    view = client.get(f"/api/fleet/artifacts/{r.json['artifact_id']}/view", headers=auth)
    assert view.data == html
    assert view.headers["Content-Disposition"].startswith("attachment")
    assert view.mimetype == "application/octet-stream"
    assert "sandbox" in view.headers["Content-Security-Policy"]


def test_wrong_data_key_fails_closed():
    a = crypto.DataCipher(crypto._decode_key(crypto.generate_key()))
    b = crypto.DataCipher(crypto._decode_key(crypto.generate_key()))
    sealed = a.seal_text("secret")
    with pytest.raises(crypto.DataKeyError):
        b.open_text(sealed)
    with pytest.raises(crypto.DataKeyError):
        crypto.DataCipher(None).open_text(sealed)
    with pytest.raises(crypto.DataKeyError):
        b.open_bytes(a.seal_bytes(b"x", aad=b"ART-1"), aad=b"ART-1")
    with pytest.raises(crypto.DataKeyError):  # moved to another artifact ID
        a.open_bytes(a.seal_bytes(b"x", aad=b"ART-1"), aad=b"ART-2")


# ----------------------------------------------------------------- IDM

DOC = ("Project Falcon acquisition memorandum. The board has approved an offer of four hundred "
       "and twelve million for the target company subject to regulatory clearance in three "
       "jurisdictions. Integration planning begins in the second quarter and the retention pool "
       "for key engineering staff is set at eighteen million vesting over thirty six months. "
       "Disclosure before the announcement date would breach the exclusivity agreement and "
       "expose the company to termination fees and regulatory penalties in every jurisdiction.")
UNRELATED = ("Quarterly facilities update. The cafeteria menu changes on Monday and the parking "
             "garage on level two will be closed for resurfacing during the last week of the "
             "month. Please use the visitor lot and display your badge on the dashboard. "
             "Bicycle storage has moved next to the loading dock behind the east entrance.")


def test_idm_detects_full_copy_reformatted_copy_and_excerpt(client, auth):
    r = client.post("/api/idm/documents", json={"name": "Falcon memo", "text": DOC, "sensitivity": "CRITICAL"}, headers=auth)
    assert r.status_code == 201, r.json
    index = client.application.view_functions and __import__("src.api", fromlist=["idm_index"]).idm_index

    assert index.match(DOC)[0].containment == 1.0
    reformatted = DOC.upper().replace(". ", ".\n\n   ").replace(",", " ,")
    assert index.match(reformatted)[0].containment > 0.9
    words = DOC.split()
    excerpt = "fyi see below >> " + " ".join(words[20:60]) + " << thanks"
    hit = index.match(excerpt)
    assert hit and hit[0].name == "Falcon memo"
    assert index.match(UNRELATED) == []

    # Wired into the scan pipeline as a finding.
    r = client.post("/api/scan/text", json={"text": excerpt})
    assert "IDM_MATCH" in {f["pattern_name"] for f in r.json["findings"]}


def test_idm_stores_fingerprints_not_content(client, auth):
    client.post("/api/idm/documents", json={"name": "Falcon memo", "text": DOC}, headers=auth)
    dump = "\n".join(sqlite3.connect(client.db.db_path).iterdump())
    assert "exclusivity agreement" not in dump and "Falcon memo" in dump


def test_idm_rejects_short_documents_and_dedupes(client, auth):
    r = client.post("/api/idm/documents", json={"name": "tiny", "text": "too short to index"}, headers=auth)
    assert r.status_code == 400 and r.json["error"] == "document_too_short"
    first = client.post("/api/idm/documents", json={"name": "a", "text": DOC}, headers=auth)
    again = client.post("/api/idm/documents", json={"name": "b", "text": DOC}, headers=auth)
    assert first.status_code == 201 and again.status_code == 200 and again.json["status"] == "exists"


def test_idm_file_upload_and_deactivation(client, auth):
    r = client.post("/api/idm/documents", headers=auth, data={
        "file": (io.BytesIO(DOC.encode()), "falcon.txt"), "sensitivity": "HIGH"})
    assert r.status_code == 201 and r.json["document"]["name"] == "falcon.txt"
    doc_id = r.json["document"]["doc_id"]
    assert client.post("/api/idm/match", json={"text": DOC}, headers=auth).json["matches"]
    client.patch(f"/api/idm/documents/{doc_id}", json={"is_active": False}, headers=auth)
    assert client.post("/api/idm/match", json={"text": DOC}, headers=auth).json["matches"] == []
    assert client.delete(f"/api/idm/documents/{doc_id}", headers=auth).status_code == 200


def test_winnowing_guarantee():
    key = b"k" * 32
    words = [f"w{i}" for i in range(400)]
    doc = idm.fingerprint(" ".join(words), key)
    span = idm.SHINGLE_WORDS + idm.WINDOW - 1
    for start in range(0, 380, 7):
        passage = ["x1", "x2"] + words[start:start + span] + ["y1", "y2"]
        assert doc & idm.fingerprint(" ".join(passage), key), start


# ----------------------------------------------------------------- SIEM forwarding

def test_cef_escaping_and_no_content_leak():
    line = siem.to_cef({"kind": "incident", "action": "created", "id": "INC-1", "user": "a=b|c\\d",
                        "host": "h", "severity": "critical", "detectors": ["US_SSN"], "risk": 90})
    assert line.startswith("CEF:0|Tron|DLP|")
    assert "|10|" in line and "suser=a\\=b|c\\\\d" in line and "cs1=US_SSN" in line


def test_siem_config_validation():
    ok = siem.validate_config({"enabled": True, "destinations": [
        {"id": "splunk", "type": "webhook", "url": "https://collector.example.com/hec", "format": "splunk_hec",
         "auth_header": "Splunk abc"}]}, resolve=False)
    assert ok["destinations"][0]["auth_header"] == "Splunk abc"
    assert "auth_header" not in siem.redact_config(ok)["destinations"][0]
    for bad in (
        {"destinations": [{"id": "x", "type": "webhook", "url": "http://collector.example.com"}]},
        {"destinations": [{"id": "x", "type": "webhook", "url": "https://user:pw@collector.example.com"}]},
        {"destinations": [{"id": "x", "type": "syslog", "host": "", "port": 514}]},
        {"destinations": [{"id": "x", "type": "ftp"}]},
    ):
        with pytest.raises(siem.ConfigError):
            siem.validate_config(bad, resolve=False)
    with pytest.raises(siem.ConfigError):  # cloud metadata range
        siem.validate_config({"destinations": [{"id": "x", "type": "webhook", "url": "https://169.254.169.254/"}]})


def test_siem_outbox_delivers_retries_and_omits_payloads(client, auth):
    from src import api
    sent, fail = [], {"on": True}

    def sender(dest, records):
        if fail["on"]:
            raise ConnectionError("collector down")
        sent.extend(records)

    forwarder = api.siem_forwarder
    forwarder._sender = sender
    forwarder.save_config(siem.validate_config({"enabled": True, "destinations": [
        {"id": "d1", "type": "webhook", "url": "https://collector.example.com/in"}]}, resolve=False))

    assert client.post("/api/events", json=EVENT).json["event_id"]
    assert client.db.siem_outbox_stats()["pending"] >= 1
    assert forwarder.drain_once() == 0                      # collector down: nothing lost
    stats = client.db.siem_outbox_stats()
    assert stats["pending"] >= 1 and "collector down" in stats["last_error"]

    fail["on"] = False
    with client.db._cursor() as cur:                        # skip the backoff delay
        cur.execute("UPDATE siem_outbox SET next_attempt_at = '2000-01-01T00:00:00+00:00'")
    assert forwarder.drain_once() >= 1
    assert client.db.siem_outbox_stats()["pending"] == 0
    event = next(r for r in sent if r["kind"] == "event")
    assert event["detectors"] and event["user"] == "alice"
    assert "536-22-1234" not in json.dumps(sent)            # matched values never leave

    # Queue is encrypted at rest too.
    client.post("/api/events", json=EVENT)
    raw = sqlite3.connect(client.db.db_path).execute("SELECT payload FROM siem_outbox").fetchone()[0]
    assert raw.startswith(crypto.TEXT_PREFIX)


def test_siem_api_requires_settings_permission_and_hides_secrets(client, auth):
    assert client.get("/api/siem/config").status_code == 401
    r = client.put("/api/siem/config", headers=auth, json={"config": {"enabled": True, "destinations": [
        {"id": "d1", "type": "syslog", "host": "127.0.0.1", "port": 6514, "protocol": "tcp"},
        {"id": "d2", "type": "webhook", "url": "https://127.0.0.1/in", "secret": "s3cret"}]}})
    assert r.status_code == 200, r.json
    body = client.get("/api/siem/config", headers=auth).get_data(as_text=True)
    assert "s3cret" not in body and '"has_secret":true' in body.replace(" ", "")
    # Re-saving without the secret keeps the stored one.
    client.put("/api/siem/config", headers=auth, json={"config": {"enabled": True, "destinations": [
        {"id": "d2", "type": "webhook", "url": "https://127.0.0.1/in"}]}})
    from src import api
    assert api.siem_forwarder.config(max_age=0)["destinations"][0]["secret"] == "s3cret"


def test_syslog_tcp_delivery_end_to_end():
    import socket
    import threading
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    received = []

    def accept():
        conn, _ = server.accept()
        conn.settimeout(2)
        chunks = b""
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                chunks += data
        except OSError:
            pass
        received.append(chunks)
        conn.close()

    t = threading.Thread(target=accept)
    t.start()
    dest = siem.validate_config({"destinations": [{"id": "s", "type": "syslog", "host": "127.0.0.1",
                                                   "port": server.getsockname()[1], "protocol": "tcp"}]})["destinations"][0]
    siem.deliver(dest, [{"kind": "incident", "action": "created", "id": "INC-9", "severity": "high",
                         "timestamp": "2026-01-01T00:00:00+00:00"}], hostname="tron-test")
    t.join(5)
    server.close()
    frame = received[0].decode()
    length, _, message = frame.partition(" ")
    assert int(length) == len(message.encode())
    assert message.startswith("<163>1 2026-01-01T00:00:00+00:00 tron-test tron-dlp - incident - CEF:0|Tron|DLP|")


# ----------------------------------------------------------------- retention

def test_retention_defaults_delete_nothing_and_policy_prunes(client, auth, tmp_path):
    client.post("/api/events", json=EVENT)
    art = client.post("/api/browser/artifact/raw", data={"file": (io.BytesIO(b"data"), "a.txt"), "user": "u"}).json["artifact_id"]
    path = client.db.get_upload_artifact(art)["content_path"]
    with client.db._cursor() as cur:
        cur.execute("UPDATE events SET timestamp = '2020-01-01T00:00:00', created_at = '2020-01-01 00:00:00'")
        cur.execute("UPDATE upload_artifacts SET created_at = '2020-01-01 00:00:00'")
    client.post("/api/events", json={**EVENT, "payload": "ssn 536-22-9999 fresh"})

    assert client.post("/api/settings/retention/run", headers=auth).json["deleted"].get("events", 0) == 0
    assert len(client.db.get_all_events()) == 2

    r = client.put("/api/settings/retention", headers=auth, json={"retention_days": {"events": 30, "artifacts": 30}})
    assert r.status_code == 200
    deleted = client.post("/api/settings/retention/run", headers=auth).json["deleted"]
    assert deleted["events"] == 1 and deleted["artifacts"] == 1 and deleted["artifact_files"] == 1
    assert len(client.db.get_all_events()) == 1
    import os
    assert not os.path.exists(path)


def test_retention_never_deletes_outside_artifact_store(client, tmp_path):
    outside = tmp_path / "important.txt"
    outside.write_text("keep me")
    client.db.add_upload_artifact("ART-X", "a", "", "h", "u", "h", "f", "text/plain", 1, "block", "high", [],
                                  str(outside), "0" * 64)
    with client.db._cursor() as cur:
        cur.execute("UPDATE upload_artifacts SET created_at = '2020-01-01 00:00:00'")
    client.db.set_platform_setting(retention.SETTING_KEY, {"artifacts": 1})
    counts = retention.run_once(client.db, tmp_path / "artifacts")
    assert counts["artifacts"] == 1 and counts["artifact_files"] == 0 and outside.exists()


def test_retention_validation(client, auth):
    for bad in ({"events": -1}, {"events": "30"}, {"events": 99999}, {"events": True}):
        assert client.put("/api/settings/retention", headers=auth, json={"retention_days": bad}).status_code == 400


# ----------------------------------------------------------------- audit chain

def test_audit_chain_detects_tampering(client, auth):
    client.post("/api/policies", headers=auth, json={"name": "P1", "rule_type": "regex", "detector": "GITHUB_TOKEN"})
    result = client.get("/api/audit/verify", headers=auth).json
    assert result["ok"] and result["checked"] > 0
    with client.db._cursor() as cur:
        cur.execute("UPDATE audit_log SET actor = 'nobody' WHERE id = (SELECT MIN(id) + 1 FROM audit_log)")
    result = client.get("/api/audit/verify", headers=auth).json
    assert result["ok"] is False and result["first_bad_id"]


def test_audit_chain_detects_deleted_row(client, auth):
    for i in range(3):
        client.post("/api/policies", headers=auth, json={"name": f"P{i}", "rule_type": "regex", "detector": "GITHUB_TOKEN"})
    with client.db._cursor() as cur:
        cur.execute("DELETE FROM audit_log WHERE id = (SELECT MIN(id) + 2 FROM audit_log)")
    assert client.get("/api/audit/verify", headers=auth).json["ok"] is False


# ----------------------------------------------------------------- HTTP hardening

def test_event_stream_requires_ticket(client, auth):
    assert client.get("/api/stream").status_code == 401
    assert client.get("/api/stream?ticket=forged").status_code == 401
    assert client.post("/api/stream/ticket").status_code == 401
    ticket = client.post("/api/stream/ticket", headers=auth).json["ticket"]
    r = client.get(f"/api/stream?ticket={ticket}", buffered=False)
    assert r.status_code == 200 and r.mimetype == "text/event-stream"
    assert b"connected" in next(r.response)
    r.close()
    # A ticket dies with its session.
    client.post("/api/auth/logout", headers=auth)
    assert client.get(f"/api/stream?ticket={ticket}").status_code == 401


def test_login_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("TRON_RATE_LOGIN_PER_MIN", "3")
    codes = [client.post("/api/auth/login", json={"email": "x@y.z", "password": "nope"}).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
    assert client.post("/api/auth/login", json={"email": "x@y.z", "password": "nope"}).headers["Retry-After"]


def test_security_headers_and_opaque_errors(client, auth):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Request-ID"]
    assert "version" not in r.json
    assert client.get("/api/debug/incidents-status", headers=auth).status_code == 404
    r = client.post("/api/events", data="{not json", content_type="application/json")
    assert r.status_code == 400


def test_metrics_disabled_by_default_and_token_gated(client, monkeypatch):
    assert client.get("/api/metrics").status_code == 404
    monkeypatch.setenv("TRON_METRICS_TOKEN", "scrape-me")
    assert client.get("/api/metrics").status_code == 401
    r = client.get("/api/metrics", headers={"Authorization": "Bearer scrape-me"})
    assert r.status_code == 200 and "tron_fleet_agents" in r.get_data(as_text=True)


def test_new_endpoints_enforce_rbac(client, auth):
    r = client.post("/api/admin/users", headers=auth, json={
        "email": "readonly@tron.local", "display_name": "V", "role": "VIEWER", "password": "Look-Only-12345!"})
    assert r.status_code in (200, 201), r.json
    login = client.post("/api/auth/login", json={"email": "readonly@tron.local", "password": "Look-Only-12345!"})
    viewer = {"Authorization": f"Bearer {login.json['token']}"}
    if login.json.get("user", {}).get("must_change_password"):
        client.post("/api/auth/change-password", headers=viewer,
                    json={"old_password": "Look-Only-12345!", "new_password": "Look-Only-67890!"})
    for method, path in (("get", "/api/siem/config"), ("get", "/api/settings/retention"),
                         ("get", "/api/settings/data-protection"), ("post", "/api/idm/documents"),
                         ("delete", "/api/fleet/agents/a1/key"), ("post", "/api/scan/file"),
                         ("get", "/api/fleet/credentials")):
        r = getattr(client, method)(path, headers=viewer, json={})
        assert r.status_code == 403 or (path == "/api/fleet/credentials" and r.status_code == 200), (path, r.status_code)
    assert client.get("/api/idm/documents", headers=viewer).status_code == 200
