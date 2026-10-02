"""
Console-editable detector library.

The built-in library (library.py) is the default. Admins can, per built-in detector, change
enabled / severity / confidence / keywords / require_keyword / pattern / validator, and reset
to default; and create custom detectors (regex + optional validator + keyword context).

Everything is validated here so a bad edit cannot break scanning on the server or in the
browser extension (patterns must compile in Python and use only syntax shared with JavaScript).
"""

from __future__ import annotations

import copy
import re
import threading
import time
from typing import Dict, List, Optional, Tuple

from src.detection.engine import DetectionEngine
from src.detection.library import DETECTORS
from src.detection.validators import VALIDATORS

BUILTIN_BY_NAME = {d["name"]: d for d in DETECTORS}
SEVERITIES = ("critical", "high", "medium", "low")
CATEGORIES = ("PII", "Financial", "Credentials", "Health", "Classification", "Source Code", "Custom")
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,48}$")
OVERRIDABLE = ("enabled", "severity", "confidence", "keywords", "require_keyword", "pattern", "validator", "ignore_case")
CONFIG_TTL = 5.0

# Python-only regex syntax that JavaScript rejects or interprets differently.
_JS_INCOMPATIBLE = [
    (re.compile(r"\(\?P[<=>]"), "named groups (?P<...>) are Python-only; use plain groups"),
    (re.compile(r"\(\?[aiLmsux]+[):]"), "inline flags like (?i) are not supported; use the ignore_case option"),
    (re.compile(r"\(\?#"), "inline comments (?#...) are not supported"),
    (re.compile(r"\\[AZz]"), "\\A / \\Z anchors are Python-only; use ^ and $"),
    (re.compile(r"\(\?>"), "atomic groups are not supported"),
    (re.compile(r"[*+?}][+]"), "possessive quantifiers are not supported"),
]


def check_pattern(pattern: str, group: int = 0) -> Optional[str]:
    """Return an error message, or None if the pattern is safe for both engines."""
    if not isinstance(pattern, str) or not pattern.strip():
        return "pattern is required"
    if len(pattern) > 2000:
        return "pattern is longer than 2000 characters"
    for rx, msg in _JS_INCOMPATIBLE:
        if rx.search(pattern):
            return msg
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return f"invalid regular expression: {e}"
    if group < 0 or group > compiled.groups:
        return f"capture group {group} does not exist (pattern has {compiled.groups})"
    if compiled.match(""):
        return "pattern matches the empty string"
    return None


def _clean_keywords(value) -> Tuple[Optional[List[str]], Optional[str]]:
    if value is None:
        return [], None
    if isinstance(value, str):
        value = [v for v in re.split(r"[,\n]", value)]
    if not isinstance(value, list):
        return None, "keywords must be a list or comma-separated string"
    out = []
    for k in value:
        k = str(k).strip().lower()
        if not k:
            continue
        if len(k) > 40:
            return None, f"keyword too long: {k[:20]}..."
        if k not in out:
            out.append(k)
    if len(out) > 40:
        return None, "at most 40 keywords"
    return out, None


def validate_override(name: str, settings: dict) -> Tuple[dict, List[str]]:
    """Validate an override for a built-in detector. Returns (clean settings, errors)."""
    base = BUILTIN_BY_NAME.get(name)
    if base is None:
        return {}, [f"unknown built-in detector {name}"]
    errors, clean = [], {}
    for key, value in (settings or {}).items():
        if key not in OVERRIDABLE:
            errors.append(f"field {key} cannot be overridden")
            continue
        if key in ("enabled", "require_keyword", "ignore_case"):
            clean[key] = bool(value)
        elif key == "severity":
            if str(value).lower() not in SEVERITIES:
                errors.append("severity must be one of " + ", ".join(SEVERITIES))
            else:
                clean[key] = str(value).lower()
        elif key == "confidence":
            try:
                c = float(value)
                if not 0.05 <= c <= 0.99:
                    raise ValueError
                clean[key] = round(c, 2)
            except (TypeError, ValueError):
                errors.append("confidence must be between 0.05 and 0.99")
        elif key == "keywords":
            kws, err = _clean_keywords(value)
            if err:
                errors.append(err)
            else:
                clean[key] = kws
        elif key == "pattern":
            err = check_pattern(value, int(base.get("group", 0)))
            if err:
                errors.append(err)
            else:
                clean[key] = value
        elif key == "validator":
            if value in (None, "", "none"):
                clean[key] = None
            elif value not in VALIDATORS:
                errors.append(f"unknown validator {value}")
            else:
                clean[key] = value
    merged = {**base, **clean}
    if merged.get("require_keyword") and not merged.get("keywords"):
        errors.append("require_keyword needs at least one keyword")
    # Drop values equal to the default so "reset" semantics stay simple.
    clean = {k: v for k, v in clean.items() if base.get(k, None if k != "enabled" else True) != v}
    return clean, errors


def validate_custom(definition: dict, existing: bool = False) -> Tuple[dict, List[str]]:
    """Validate a custom detector definition. Returns (clean definition, errors)."""
    d = definition or {}
    errors: List[str] = []
    name = str(d.get("name") or "").strip().upper()
    if not NAME_RE.match(name):
        errors.append("name must be 3-49 chars: uppercase letters, digits, underscore; start with a letter")
    elif name in BUILTIN_BY_NAME:
        errors.append(f"{name} is a built-in detector; edit it instead of creating a new one")
    try:
        group = int(d.get("group") or 0)
    except (TypeError, ValueError):
        group = -1
    err = check_pattern(d.get("pattern"), group)
    if err:
        errors.append(err)
    validator = d.get("validator") or None
    if validator in ("none", ""):
        validator = None
    if validator and validator not in VALIDATORS:
        errors.append(f"unknown validator {validator}")
    keywords, kerr = _clean_keywords(d.get("keywords"))
    if kerr:
        errors.append(kerr)
    require_keyword = bool(d.get("require_keyword"))
    if require_keyword and not keywords:
        errors.append("require_keyword needs at least one keyword")
    severity = str(d.get("severity") or "medium").lower()
    if severity not in SEVERITIES:
        errors.append("severity must be one of " + ", ".join(SEVERITIES))
    try:
        confidence = round(float(d.get("confidence", 0.8)), 2)
        if not 0.05 <= confidence <= 0.99:
            raise ValueError
    except (TypeError, ValueError):
        errors.append("confidence must be between 0.05 and 0.99")
        confidence = 0.8
    category = str(d.get("category") or "Custom")
    if category not in CATEGORIES:
        category = "Custom"
    prefilter, perr = _clean_keywords(d.get("prefilter")) if d.get("prefilter") else ([], None)
    if perr:
        errors.append("prefilter: " + perr)
    clean = {
        "name": name,
        "pattern": d.get("pattern"),
        "ignore_case": bool(d.get("ignore_case")),
        "group": max(group, 0),
        "validator": validator,
        "keywords": keywords or [],
        "require_keyword": require_keyword,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "description": str(d.get("description") or name)[:300],
        "enabled": bool(d.get("enabled", True)),
    }
    if prefilter:
        # Prefilter literals are case-sensitive unless ignore_case (matched against lowercased text).
        clean["prefilter"] = prefilter if clean["ignore_case"] else [str(p).strip() for p in d.get("prefilter") if str(p).strip()]
    return clean, errors


def merge(overrides: Dict[str, dict], customs: List[dict]) -> List[dict]:
    """Full detector list (enabled and disabled) with UI metadata."""
    out = []
    for d in DETECTORS:
        o = (overrides.get(d["name"]) or {}).get("settings", {})
        merged = {**copy.deepcopy(d), **o}
        merged.setdefault("enabled", True)
        merged["source"] = "builtin"
        merged["overridden"] = sorted(o.keys())
        merged["defaults"] = {k: d.get(k) for k in OVERRIDABLE if k != "enabled"}
        out.append(merged)
    for c in customs:
        merged = {**c, "source": "custom", "overridden": []}
        merged.setdefault("enabled", True)
        out.append(merged)
    return out


_META_KEYS = ("source", "overridden", "defaults", "enabled", "created_at", "updated_at", "updated_by")


def engine_format(d: dict) -> dict:
    """Strip UI/storage metadata, leaving the engine definition."""
    return {k: v for k, v in d.items() if k not in _META_KEYS}


def effective(overrides: Dict[str, dict], customs: List[dict]) -> List[dict]:
    """Enabled detectors, in engine format."""
    return [engine_format(d) for d in merge(overrides, customs) if d.get("enabled", True)]


class DetectorConfigStore:
    """Loads overrides + custom detectors from the database (TTL cached) and builds engines."""

    def __init__(self, db=None, ttl: float = CONFIG_TTL):
        self.db = db
        self.ttl = ttl
        self._lock = threading.Lock()
        self._loaded_at = 0.0
        self._overrides: Dict[str, dict] = {}
        self._customs: List[dict] = []
        self.version: tuple = ()
        self._engine: Optional[DetectionEngine] = None
        self._engine_version: tuple = ("unset",)

    def invalidate(self) -> None:
        self._loaded_at = 0.0

    def refresh(self) -> tuple:
        if time.monotonic() - self._loaded_at < self.ttl and self.version:
            return self.version
        with self._lock:
            if time.monotonic() - self._loaded_at < self.ttl and self.version:
                return self.version
            overrides, customs = {}, []
            if self.db is not None:
                try:
                    overrides = self.db.get_detector_overrides()
                    customs = self.db.list_custom_detectors()
                except Exception as e:
                    print(f"⚠️ Detector config not loaded: {e}")
            # Drop stored entries that no longer validate (e.g. a validator was removed).
            customs = [c for c in customs if not validate_custom(c)[1]]
            self._overrides, self._customs = overrides, customs
            self.version = (
                tuple(sorted((k, repr(sorted(v["settings"].items()))) for k, v in overrides.items())),
                tuple(sorted((c["name"], c.get("updated_at") or "", repr(sorted((k, repr(v)) for k, v in c.items()))) for c in customs)),
            )
            self._loaded_at = time.monotonic()
            return self.version

    def detectors(self) -> List[dict]:
        self.refresh()
        return merge(self._overrides, self._customs)

    def effective_detectors(self) -> List[dict]:
        self.refresh()
        return effective(self._overrides, self._customs)

    def detector_names(self) -> set:
        return {d["name"] for d in self.effective_detectors()}

    def engine(self) -> DetectionEngine:
        version = self.refresh()
        if self._engine is None or self._engine_version != version:
            with self._lock:
                if self._engine is None or self._engine_version != version:
                    self._engine = DetectionEngine(self.effective_detectors())
                    self._engine_version = version
        return self._engine

    def redaction_detectors(self) -> List[dict]:
        """All built-ins (unmodified, even if disabled) + enabled custom detectors.

        Redaction before external LLM calls must never get weaker because someone disabled
        or loosened a detector for alerting purposes.
        """
        self.refresh()
        customs = [engine_format(c) for c in self._customs
                   if c.get("enabled", True) and c["name"] not in BUILTIN_BY_NAME]
        return list(DETECTORS) + customs

    def snapshot(self) -> dict:
        """Config for the browser extension (policy sync)."""
        self.refresh()
        return {
            "version": str(abs(hash(self.version))),
            "overrides": {k: v["settings"] for k, v in self._overrides.items()},
            "custom": [engine_format(c) for c in self._customs if c.get("enabled", True)],
        }
