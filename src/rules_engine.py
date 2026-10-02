"""
Rules engine for agent events (/api/events).

Events are matched against the active console policies. A regex policy is either
  * a reference to a built-in validated detector:  rule_data = {"detector": "US_SSN", ...}
  * a custom regular expression:                    rule_data = {"pattern": "..."}
Built-in references get checksums, keyword proximity and evasion handling for free; custom
regexes behave as before. Policies are loaded from the database at most every POLICY_TTL
seconds and compiled once per change (previously every event re-read and recompiled them).
"""

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from src.detection import DetectionEngine, LEGACY_ALIASES, get_engine

POLICY_TTL = 5.0
_POLICY_PREFIX = "policy:"   # custom regex rules are namespaced inside the engine


class RuleType(Enum):
    REGEX = "regex"
    DETECTOR = "detector"
    THRESHOLD = "threshold"
    FINGERPRINT = "fingerprint"
    ML = "ml"


@dataclass
class DetectionResult:
    rule_name: str
    severity: str
    matched_pattern: str
    confidence: float


def policy_detector_name(rule_data: dict, detector_store=None) -> Optional[str]:
    """Detector (built-in or custom) referenced by a policy, or None."""
    name = str((rule_data or {}).get("detector") or "").strip().upper()
    if not name:
        return None
    name = LEGACY_ALIASES.get(name, name)
    if detector_store is not None:
        return name if name in {d["name"] for d in detector_store.detectors()} else None
    return name if get_engine().detector(name) else None


class RulesEngine:
    """DLP policy matching for agent events."""

    def __init__(self):
        self.db: Optional[Any] = None
        self.detector_store = None   # DetectorConfigStore (console overrides + custom detectors)
        self.rules: Dict = {}
        self._lock = threading.Lock()
        self._loaded_at = 0.0
        self._signature: Optional[Tuple] = None
        self._compiled: Optional[DetectionEngine] = None
        self._detector_policies: Dict[str, List[str]] = {}
        self._include: set = set()

    # ------------------------------------------------------------------ policy loading
    def invalidate(self) -> None:
        self._loaded_at = 0.0

    def _active_policies(self) -> List[dict]:
        if not self.db:
            return []
        try:
            return [p for p in self.db.get_policies(active_only=True)
                    if str(p.get("rule_type") or "regex").lower() == "regex"]
        except Exception as e:
            print(f"Error loading dynamic policies: {e}")
            return []

    def _refresh(self) -> None:
        now = time.monotonic()
        if self._compiled is not None and now - self._loaded_at < POLICY_TTL:
            return
        with self._lock:
            if self._compiled is not None and time.monotonic() - self._loaded_at < POLICY_TTL:
                return
            policies = self._active_policies()
            store_version = self.detector_store.refresh() if self.detector_store is not None else None
            signature = (store_version,) + tuple(sorted(
                (str(p.get("policy_id")), str(p.get("name")), str(p.get("rule_data")), str(p.get("severity")),
                 str(p.get("threshold_count")), str(p.get("threshold_window_mins")), str(p.get("updated_at")))
                for p in policies))
            if signature != self._signature:
                rules, custom, detector_policies = {}, [], {}
                for p in policies:
                    name = str(p.get("name") or "").strip()
                    rule_data = p.get("rule_data") if isinstance(p.get("rule_data"), dict) else {}
                    if not name:
                        continue
                    severity = str(p.get("severity") or "medium").lower()
                    detector = policy_detector_name(rule_data, self.detector_store)
                    pattern = rule_data.get("pattern") or p.get("regex_pattern") or ""
                    if not detector and not pattern:
                        continue
                    rules[name] = {
                        "type": RuleType.DETECTOR if detector else RuleType.REGEX,
                        "detector": detector,
                        "pattern": pattern,
                        "severity": severity,
                        "confidence": 0.85,
                        "threshold": int(p.get("threshold_count") or 1),
                        "window": int(p.get("threshold_window_mins") or 60),
                    }
                    if detector:
                        detector_policies.setdefault(detector, []).append(name)
                    else:
                        custom.append({"name": _POLICY_PREFIX + name, "pattern": pattern, "severity": severity})
                engine = DetectionEngine(self.detector_store.effective_detectors()) if self.detector_store is not None else DetectionEngine()
                failed = engine.set_custom_rules(custom)
                for name in failed:
                    print(f"Invalid regex in rule {name[len(_POLICY_PREFIX):]}")
                    rules.pop(name[len(_POLICY_PREFIX):], None)
                self.rules = rules
                self._compiled = engine
                self._detector_policies = detector_policies
                self._include = set(detector_policies) | {c["name"] for c in custom if c["name"] not in failed}
                self._signature = signature
            self._loaded_at = time.monotonic()

    def get_all_rules(self) -> Dict:
        """Active policies keyed by name (type, severity, confidence, threshold, window)."""
        self._refresh()
        return dict(self.rules)

    def regex_policies(self) -> Tuple[Optional[Tuple], List[dict]]:
        """(version, custom regex rules) for attaching to a FileContentScanner."""
        self._refresh()
        custom = [{"name": n, "pattern": r["pattern"], "severity": r["severity"]}
                  for n, r in self.rules.items() if r["type"] == RuleType.REGEX]
        return self._signature, custom

    # ------------------------------------------------------------------ matching
    def detect_patterns(self, payload: str) -> List[DetectionResult]:
        self._refresh()
        if not payload or not self._include or self._compiled is None:
            return []
        results = []
        for m in self._compiled.scan(payload, include=self._include, with_context=False).matches:
            if m.detector.startswith(_POLICY_PREFIX):
                policy_names = [m.detector[len(_POLICY_PREFIX):]]
            else:
                policy_names = self._detector_policies.get(m.detector, [])
            for name in policy_names:
                rule = self.rules[name]
                results.append(DetectionResult(
                    rule_name=name,
                    severity=rule["severity"],
                    matched_pattern=m.value[:50],
                    confidence=max(rule["confidence"], m.confidence) if m.validated else rule["confidence"],
                ))
        return results

    def calculate_pii_count(self, payload: str) -> int:
        """Count identity-number findings (bulk detection) using the built-in detectors."""
        pii = {"US_SSN", "EMAIL_ADDRESS", "IN_PAN", "IN_AADHAAR", "CREDIT_CARD", "IBAN"}
        return sum(1 for m in get_engine().scan(payload, include=pii, with_context=False).matches)

    def evaluate_severity(self, detections: List[DetectionResult]) -> Tuple[str, float]:
        """Overall severity and risk score from detections."""
        if not detections:
            return "low", 0.0
        severity_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25}
        max_score = max(severity_scores.get(d.severity, 0) for d in detections)
        avg_confidence = sum(d.confidence for d in detections) / len(detections)
        risk_score = max_score * avg_confidence
        if risk_score >= 80:
            severity = "critical"
        elif risk_score >= 60:
            severity = "high"
        elif risk_score >= 40:
            severity = "medium"
        else:
            severity = "low"
        return severity, risk_score
