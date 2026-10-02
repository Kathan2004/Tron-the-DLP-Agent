"""Console-editable detector library: validation, overrides, custom detectors, API, extension parity."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from src.database import Database
from src.detection.config import DetectorConfigStore, check_pattern, validate_custom, validate_override
from src.detection.generators import DETECTOR_GENERATORS, GENERATORS, generate, luhn_number
from src.detection.validators import VALIDATOR_INFO, VALIDATORS

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("pattern,ok", [
    (r"EMP-\d{6}", True),
    (r"(?P<id>\d+)", False),      # Python-only named group
    (r"(?i)secret", False),       # inline flag
    (r"\d+\Z", False),            # Python-only anchor
    (r"a*", False),               # matches empty string
    (r"(\d+", False),             # invalid
])
def test_pattern_safety(pattern, ok):
    assert (check_pattern(pattern) is None) == ok


def test_override_validation_and_defaults_dropped():
    clean, errors = validate_override("US_SSN", {"severity": "critical", "confidence": 0.5})
    assert not errors and clean == {"confidence": 0.5}          # severity equals default -> dropped
    _, errors = validate_override("US_SSN", {"severity": "extreme"})
    assert errors
    _, errors = validate_override("PASSPORT", {"keywords": []})  # require_keyword without keywords
    assert errors


def test_custom_validation():
    clean, errors = validate_custom({"name": "emp id", "pattern": r"\d+"})
    assert errors                                                  # bad name
    _, errors = validate_custom({"name": "US_SSN", "pattern": r"\d+"})
    assert errors                                                  # built-in name
    clean, errors = validate_custom({"name": "EMP_ID", "pattern": r"EMP-(\d{6})", "group": 1,
                                     "validator": "luhn_any", "keywords": "employee, staff"})
    assert not errors and clean["keywords"] == ["employee", "staff"] and clean["group"] == 1


def test_store_applies_overrides_and_custom(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.set_detector_override("EMAIL_ADDRESS", {"enabled": False})
    db.set_detector_override("US_SSN", {"severity": "medium"})
    clean, _ = validate_custom({"name": "EMP_ID", "pattern": r"EMP-(\d{6})", "group": 1, "validator": "luhn_any",
                                "severity": "high"})
    db.upsert_custom_detector(clean)
    eng = DetectorConfigStore(db).engine()
    v = luhn_number(6)
    hits = {m.detector: m for m in eng.scan(f"EMP-{v} ssn 536-22-1234 mail a@b.co EMP-123456").matches}
    assert set(hits) == {"EMP_ID", "US_SSN"} and hits["US_SSN"].severity == "medium" and hits["EMP_ID"].value == v


def test_generators_produce_valid_values():
    for kind in GENERATORS:
        assert all(VALIDATORS[kind](v) for v in generate(kind, 50)), kind
    assert set(VALIDATOR_INFO) == set(VALIDATORS)


def test_generated_values_are_detected():
    from src.detection import get_engine
    kw = {"US_BANK_ROUTING": "routing ", "CA_SIN": "sin ", "UK_NHS_NUMBER": "nhs ", "AU_TFN": "tfn ", "IMEI": "imei "}
    for det in DETECTOR_GENERATORS:
        for v in generate(det, 25):
            assert det in {m.detector for m in get_engine().scan(kw.get(det, "value ") + v).matches}, (det, v)


# ------------------------------------------------------------------ API
@pytest.fixture()
def client(tmp_path):
    from tests.test_api import client as _client  # noqa: F401  (reuse fixture logic)
    from src import api
    from src.ai_analyzer import FalsePositiveClassifier, VertexAIAnalyzer
    from src.event_processor import EscalationEngine, EventProcessor
    from src.incident_store import IncidentStore
    from src.rules_engine import RulesEngine
    from src.telegram_bot import DLPTelegramBot
    db = Database(str(tmp_path / "api.db"))
    store = IncidentStore(db=db)
    rules = RulesEngine()
    rules.db = db
    analyzer = VertexAIAnalyzer()
    api.init_components(store, rules, EventProcessor(rules, store), EscalationEngine(), analyzer,
                        FalsePositiveClassifier(analyzer), DLPTelegramBot(store), db)
    api.app.config["TESTING"] = True
    with api.app.test_client() as c:
        r = c.post("/api/auth/login", json={"email": "admin@tron.local", "password": "Test-Admin-Pass-123!"})
        c.environ_base["HTTP_AUTHORIZATION"] = "Bearer " + r.json["token"]
        yield c


def test_detector_crud_and_reset(client):
    r = client.get("/api/detectors")
    assert r.status_code == 200 and len(r.json["detectors"]) >= 53 and r.json["validators"]
    r = client.patch("/api/detectors/EMAIL_ADDRESS", json={"enabled": False})
    assert r.status_code == 200
    assert client.post("/api/scan/text", json={"text": "mail a@b.co"}).json["finding_count"] == 0
    assert client.patch("/api/detectors/US_SSN", json={"pattern": "(?P<x>1)"}).status_code == 400
    assert client.delete("/api/detectors/EMAIL_ADDRESS").json["status"] == "reset"
    assert client.post("/api/scan/text", json={"text": "mail a@b.co"}).json["finding_count"] == 1


def test_custom_detector_end_to_end(client):
    body = {"name": "LOYALTY_CARD", "pattern": r"\bLC\d{10}\b", "validator": "luhn_any",
            "keywords": ["loyalty"], "severity": "high", "category": "Financial"}
    assert client.post("/api/detectors", json=body).status_code == 201
    assert client.post("/api/detectors", json=body).status_code == 409
    good = "LC" + luhn_number(10)
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    r = client.post("/api/detectors/test", json={"text": f"card {good} and {bad}", "detector": "LOYALTY_CARD"})
    reasons = {c["value"]: (c["accepted"], c["reason"]) for c in r.json["candidates"]}
    assert reasons[good][0] is True and reasons[bad] == (False, "failed luhn_any check")
    names = {f["pattern_name"] for f in client.post("/api/scan/text", json={"text": good}).json["findings"]}
    assert "LOYALTY_CARD" in names
    # policy referencing the custom detector drives event ingest
    assert client.post("/api/policies", json={"name": "LOYALTY", "rule_type": "regex", "detector": "LOYALTY_CARD",
                                              "severity": "HIGH"}).status_code == 201
    r = client.post("/api/events", json={"agent_type": "endpoint", "source_host": "h", "user": "u",
                                         "channel": "clipboard", "payload": good})
    assert r.json["event_id"]
    assert client.delete("/api/detectors/LOYALTY_CARD").status_code == 409   # in use
    sync = client.get("/api/policies/sync").json["detector_config"]
    assert any(c["name"] == "LOYALTY_CARD" for c in sync["custom"])


def test_draft_trace_check_and_generate(client):
    r = client.post("/api/detectors/test", json={"text": "id 79927398713 and 79927398710",
                                                  "definition": {"pattern": r"\d{11}", "validator": "luhn_any"}})
    assert [c["accepted"] for c in r.json["candidates"]] == [True, False]
    r = client.post("/api/detectors/check", json={"value": "4111 1111 1111 1111"})
    assert {"luhn", "payment_card", "luhn_any"} <= set(r.json["passed"])
    r = client.post("/api/detectors/generate", json={"kind": "payment_card", "count": 3, "options": {"brand": "amex"}})
    assert len(r.json["values"]) == 3 and all(v.startswith("3") for v in r.json["values"])
    assert client.post("/api/detectors/generate", json={"kind": "nope"}).status_code == 400
    r = client.post("/api/detectors/test", json={"text": "ssn 536-22-1234"})
    assert r.json["mode"] == "library" and r.json["findings"][0]["detector"] == "US_SSN"


def test_redaction_ignores_disabled_detectors(client):
    from src.file_scanner import redact_for_llm
    client.patch("/api/detectors/US_SSN", json={"enabled": False})
    assert "536-22-1234" not in redact_for_llm("ssn 536-22-1234")


# ------------------------------------------------------------------ extension parity
@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_extension_applies_detector_config():
    clean, _ = validate_custom({"name": "EMP_ID", "pattern": r"EMP-(\d{6})", "group": 1, "validator": "luhn_any"})
    config = {"version": "1", "overrides": {"EMAIL_ADDRESS": {"enabled": False}, "US_SSN": {"severity": "medium"}},
              "custom": [clean, {"name": "FUTURE", "pattern": "X+", "validator": "not_a_real_validator"}]}
    v = luhn_number(6)
    texts = [f"EMP-{v} mail a@b.co ssn 536-22-1234", "EMP-123456 FUTURE XXXX"]
    out = subprocess.run(["node", str(ROOT / "tests" / "js_scan.js"), "", json.dumps(config)],
                         input="\n".join(json.dumps(t) for t in texts), capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == [["EMP_ID", "US_SSN"], []]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_every_validator_matches_javascript():
    samples = []
    for kind in GENERATORS:
        for v in generate(kind, 10):
            samples.append(v)
            samples.append(v[:-1] + ("0" if v[-1] != "0" else "1"))
    samples += ["", "x", "changeme", "aK8sd9F2kLq0Zx7Vb3Nm", "https://u:Secr3t@h", "https://u:pass@h",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "helperFunctionName", "a.b.c.dEfGhIjKlMnOp"]
    script = """
const fs=require('fs'),vm=require('vm'),path=require('path');
const ext=path.join(process.argv[1]);
const c={console:{log(){},warn(){},error(){}},atob,TextDecoder,Uint8Array};c.globalThis=c;vm.createContext(c);
for(const f of ['detectors.js','scanner.js']) vm.runInContext(fs.readFileSync(path.join(ext,f),'utf8'),c);
const samples=JSON.parse(fs.readFileSync(0,'utf8'));
const out={};for(const k of Object.keys(c.TRON_VALIDATORS||{})){}
vm.runInContext('globalThis.__V=TRON_VALIDATORS',c);
for(const k of Object.keys(c.__V)) out[k]=samples.map(s=>!!c.__V[k](s));
process.stdout.write(JSON.stringify(out));
"""
    out = json.loads(subprocess.run(["node", "-e", script, str(ROOT / "browser-extension")], input=json.dumps(samples),
                                    capture_output=True, text=True, check=True).stdout)
    assert set(out) == set(VALIDATORS), set(out) ^ set(VALIDATORS)
    for name, fn in VALIDATORS.items():
        py = [bool(fn(s)) for s in samples]
        diffs = [s for s, a, b in zip(samples, py, out[name]) if a != b]
        assert not diffs, (name, diffs[:5])


def test_lab_generation_offline_builtin_and_detector(client):
    r = client.post("/api/lab/generate_rule", json={"prompt": "alert when someone shares aadhaar numbers"})
    assert r.status_code == 200 and r.json["kind"] == "builtin" and r.json["rule_data"] == {"detector": "IN_AADHAAR"}
    r = client.post("/api/lab/generate_rule", json={"prompt": "block employee IDs like EMP-482913 with a luhn check digit"})
    d = r.json["detector_definition"]
    assert r.json["kind"] == "detector" and d["validator"] == "luhn_any" and d["pattern"] == r"\bEMP-\d{6}\b"
    assert r.json["action"] == "block" and r.json["source"] == "offline"
    r = client.post("/api/lab/generate_rule", json={"prompt": "block uploads larger than 25 MB"})
    assert r.json["kind"] == "file_size" and r.json["rule_data"] == {"max_size_mb": 25}


def test_pattern_from_example():
    from src.detection.rule_builder import pattern_from_example
    assert pattern_from_example("EMP-482913") == r"\bEMP-\d{6}\b"
    assert pattern_from_example("INV/2026/0042") == r"\bINV/\d{4}/\d{4}\b"
