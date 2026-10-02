"""Detection engine: validators, corpus quality, evasion, redaction, extension parity."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from src.detection import DETECTORS, DetectionEngine, get_engine
from src.detection import validators as V
from tests.detection_corpus import AWS_KEY, CASES, GITHUB_PAT

ROOT = Path(__file__).resolve().parent.parent


def detect(text):
    return {m.detector for m in get_engine().scan(text).matches}


# ------------------------------------------------------------------ validators
@pytest.mark.parametrize("fn,good,bad", [
    (V.payment_card, ["4111 1111 1111 1111", "5555555555554444", "378282246310005", "6011111111111117"],
     ["1234567812345678", "4111111111111112", "0000000000000000"]),
    (V.aadhaar, ["2341 2341 2346"], ["234123412341", "123412341234", "000000000000"]),
    (V.iban, ["GB82 WEST 1234 5698 7654 32", "DE89370400440532013000"], ["GB82WEST12345698765431", "XX00123"]),
    (V.us_ssn, ["536-22-1234", "123-45-6789"], ["666-12-3456", "900-12-3456", "536-00-1234", "536-22-0000", "078-05-1120"]),
    (V.aba_routing, ["021000021", "011000015"], ["021000022", "000000000"]),
    (V.ca_sin, ["046 454 286"], ["046 454 287"]),
    (V.gstin, ["27AAPFU0939F1ZV"], ["27AAPFU0939F1ZX"]),
    (V.jwt, ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"], ["eyJub3BlIjoxfQ.eyJzdWIiOiIxIn0.sig"]),
    (V.high_entropy_secret, ["aK8sd9F2kLq0Zx7Vb3Nm"], ["your-api-key-here", "aaaaaaaaaaaaaaaaaaaa", "changeme"]),
])
def test_validators(fn, good, bad):
    assert all(fn(v) for v in good), [v for v in good if not fn(v)]
    assert not any(fn(v) for v in bad), [v for v in bad if fn(v)]


def test_every_detector_compiles_and_has_metadata():
    engine = DetectionEngine()
    assert len(engine.detector_names) == len(DETECTORS)
    for d in DETECTORS:
        assert d["severity"] in {"critical", "high", "medium", "low"}
        assert 0 < d["confidence"] <= 1
        assert d.get("description") and d.get("category")
        if d.get("require_keyword"):
            assert d.get("keywords"), d["name"]


# ------------------------------------------------------------------ corpus quality
def test_corpus_precision_and_recall():
    tp = fp = fn = 0
    for text, expected in CASES:
        got = detect(text)
        tp += len(got & expected)
        fp += len(got - expected)
        fn += len(expected - got)
    precision, recall = tp / (tp + fp), tp / (tp + fn)
    assert precision >= 0.97, f"precision {precision:.3f}"
    assert recall >= 0.97, f"recall {recall:.3f}"


@pytest.mark.parametrize("text", [
    "Order #4201736893376915 shipped",        # 16 digits failing Luhn
    "Reference 234123412341 processed",       # 12 digits failing Verhoeff
    "Please update the deck before Monday",
    "hello world version=1.2.3 debug=true",
    "api_key = your-api-key-here",
    "postgres://localhost:5432/dev",
    "meeting using a single sin cos table",   # 'sin' keyword must be a whole word
])
def test_hard_negatives(text):
    assert detect(text) == set()


def test_overlap_keeps_strongest_single_finding():
    hits = get_engine().scan("card 4111 1111 1111 1111").matches
    assert [m.detector for m in hits] == ["CREDIT_CARD"]


def test_specific_detector_beats_generic_secret():
    assert detect("export GITHUB_TOKEN=" + GITHUB_PAT) == {"GITHUB_TOKEN"}


def test_keyword_required_and_boost():
    assert "US_BANK_ROUTING" not in detect("value 021000021")
    m = get_engine().scan("routing number 021000021").matches
    assert m and m[0].detector == "US_BANK_ROUTING" and m[0].keyword == "routing"
    plain = get_engine().scan("x 536-22-1234").matches[0].confidence
    boosted = get_engine().scan("ssn 536-22-1234").matches[0].confidence
    assert boosted > plain


# ------------------------------------------------------------------ evasion
def test_zero_width_and_fullwidth_evasion():
    assert "CREDIT_CARD" in detect("4111​1111​1111​1111")
    assert "US_SSN" in detect("ssn ５３６-２２-１２３４")


def test_base64_encoded_content():
    import base64
    blob = base64.b64encode(b"payroll export ssn=536-22-1234 for review").decode()
    hits = [m for m in get_engine().scan(f"data: {blob}").matches if m.detector == "US_SSN"]
    assert hits and hits[0].encoding == "base64" and hits[0].value == "536-22-1234"


# ------------------------------------------------------------------ redaction
def test_redaction_masks_values_and_ignores_keyword_requirements():
    from src.file_scanner import redact_for_llm
    out = redact_for_llm(f"ssn 536-22-1234 card 4111 1111 1111 1111 key {AWS_KEY} acct no 000123456789")
    for raw in ("536-22-1234", "4111 1111 1111 1111", AWS_KEY, "000123456789"):
        assert raw not in out
    assert "[REDACTED:US_SSN]" in out and "[REDACTED:CREDIT_CARD]" in out


def test_llm_prompt_only_contains_redacted_values(monkeypatch):
    from src import ai_analyzer
    sent = {}

    class Resp:
        status_code = 200

        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": '{"verdict": "NEEDS_REVIEW"}'}]}}]}

    def fake_post(url, json=None, headers=None, timeout=None):
        sent["body"], sent["url"], sent["headers"] = json, url, headers
        return Resp()

    monkeypatch.setattr(ai_analyzer.requests, "post", fake_post)
    a = ai_analyzer.VertexAIAnalyzer()
    a.api_key = "test-key"
    a.analyze_incident("INC-1", "jane@corp.com", "host", "upload", "SSN 536-22-1234", 3, "card 4111111111111111", "x")
    prompt = sent["body"]["contents"][0]["parts"][0]["text"]
    assert "536-22-1234" not in prompt and "4111111111111111" not in prompt and "jane@corp.com" not in prompt
    assert "key=" not in sent["url"] and sent["headers"]["x-goog-api-key"] == "test-key"


# ------------------------------------------------------------------ custom policies
def test_custom_rules_compile_and_bad_rules_are_reported():
    e = DetectionEngine()
    failed = e.set_custom_rules([{"name": "PROJECT", "pattern": r"project[ _-]?falcon"},
                                 {"name": "BROKEN", "pattern": "([unclosed"}])
    assert failed == ["BROKEN"]
    assert any(m.detector == "PROJECT" for m in e.scan("Project Falcon roadmap").matches)


# ------------------------------------------------------------------ extension parity
def test_generated_extension_detectors_up_to_date():
    r = subprocess.run(["python", str(ROOT / "scripts" / "build_extension_detectors.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_extension_scanner_matches_server_engine():
    inp = "\n".join(json.dumps(t) for t, _ in CASES)
    out = subprocess.run(["node", str(ROOT / "tests" / "js_scan.js")], input=inp,
                         capture_output=True, text=True, check=True).stdout
    js = json.loads(out)
    diffs = [(t[:60], sorted(detect(t)), j) for (t, _), j in zip(CASES, js) if sorted(detect(t)) != j]
    assert not diffs, diffs[:5]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_extension_policy_detector_reference_and_builtin_restore():
    policies = [{"name": "CREDIT_CARD", "rule_type": "regex", "severity": "CRITICAL", "action": "block",
                 "rule_data": {"detector": "CREDIT_CARD", "pattern": r"\d{16}"}}]
    texts = ["card 4111 1111 1111 1111", "order 1234567812345678"]
    out = subprocess.run(["node", str(ROOT / "tests" / "js_scan.js"), json.dumps(policies)],
                         input="\n".join(json.dumps(t) for t in texts), capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == [["CREDIT_CARD"], []]


# ------------------------------------------------------------------ exact data match
def test_edm_matches_records_not_lookalikes(tmp_path, monkeypatch):
    import csv
    monkeypatch.setenv("TRON_EDM_KEY", "unit-test-key")
    from src.detection.edm import EDMIndex
    from src.file_scanner import FileContentScanner
    path = tmp_path / "customers.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name", "email", "ssn", "card"])
        w.writerow(["Jane A Doe", "jane.doe@acme.com", "536-22-1234", "4111111111111111"])
        w.writerow(["Raj Kumar", "raj@acme.in", "219-09-9998", ""])
    EDMIndex.build(str(path), ["name", "email", "ssn", "card"]).save(str(tmp_path / "c.edm"))
    idx = EDMIndex.load(str(tmp_path / "c.edm"))
    assert b"536-22-1234" not in (tmp_path / "c.edm").read_bytes()          # hashes only
    assert [m.columns for m in idx.scan("jane a doe, ssn 536 22 1234")] == [["name", "ssn"]]
    assert [m.row for m in idx.scan("card 4111-1111-1111-1111 for JANE A DOE.")] == [0]
    assert idx.scan("ssn 536-22-1234 only") == []                           # one field is not a record
    assert idx.scan("someone else 536-22-1235 jane a doer") == []
    s = FileContentScanner(edm=[idx])
    assert "EDM_MATCH" in {f.pattern_name for f in s.scan_text("RAJ@ACME.IN asked about 219-09-9998")}
