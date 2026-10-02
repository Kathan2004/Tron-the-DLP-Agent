"""Rules engine: policy loading from rule_data (regression), detector references, seed migration."""

import json
import sqlite3

from src.database import LEGACY_DEFAULT_POLICY_RULE_DATA, Database
from src.rules_engine import RulesEngine


def engine_for(db):
    r = RulesEngine()
    r.db = db
    return r


def test_policies_load_from_rule_data(tmp_path):
    # Regression: policies used to be read from a non-existent "regex_pattern" column, so
    # every policy was silently ignored and /api/events never detected anything.
    db = Database(str(tmp_path / "t.db"))
    db.add_policy("PROJECT_X", "regex", {"pattern": r"project[ _-]?falcon"}, severity="HIGH")
    rules = engine_for(db).get_all_rules()
    assert "PROJECT_X" in rules and "SSN_PATTERN" in rules


def test_detector_policies_validate(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    r = engine_for(db)
    hits = {d.rule_name for d in r.detect_patterns("ssn 536-22-1234 card 4111 1111 1111 1111")}
    assert hits == {"SSN_PATTERN", "CREDIT_CARD"}
    assert r.detect_patterns("order 1234567812345678 ref 123412341234 x 999-99-9999") == []


def test_custom_policy_named_like_builtin_does_not_collide(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.add_policy("US_SSN", "regex", {"pattern": r"employee id \d{5}"}, severity="LOW")
    names = [d.rule_name for d in engine_for(db).detect_patterns("employee id 12345")]
    assert names == ["US_SSN"]


def test_untouched_legacy_seed_policies_are_upgraded(tmp_path):
    path = str(tmp_path / "t.db")
    Database(path)
    con = sqlite3.connect(path)
    for pid, rd in LEGACY_DEFAULT_POLICY_RULE_DATA.items():
        con.execute("UPDATE policies SET rule_data=? WHERE policy_id=?", (json.dumps(rd), pid))
    con.execute("UPDATE policies SET rule_data=? WHERE policy_id='POL-DEFAULT-3'", (json.dumps({"pattern": "MINE"}),))
    con.commit()
    con.close()
    rows = {p["policy_id"]: p["rule_data"] for p in Database(path).get_policies()}
    assert rows["POL-DEFAULT-1"]["detector"] == "US_SSN"
    assert rows["POL-DEFAULT-3"] == {"pattern": "MINE"}   # edited by the user: left alone


def test_policy_cache_invalidation(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    r = engine_for(db)
    assert r.detect_patterns("codename bluebird") == []
    db.add_policy("CODENAME", "regex", {"pattern": "bluebird"})
    r.invalidate()
    assert [d.rule_name for d in r.detect_patterns("codename bluebird")] == ["CODENAME"]
