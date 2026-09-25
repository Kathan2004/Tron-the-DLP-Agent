import re
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

class RuleType(Enum):
    REGEX = "regex"
    THRESHOLD = "threshold"
    FINGERPRINT = "fingerprint"
    ML = "ml"

@dataclass
class DetectionResult:
    rule_name: str
    severity: str
    matched_pattern: str
    confidence: float

class RulesEngine:
    """DLP pattern detection and rules engine"""
    
    def __init__(self):
        self.db: Optional[Any] = None
        self.rules = self._init_rules()
    
    def _init_rules(self) -> Dict:
        """Initialize empty rules (all rules now dynamically loaded from DB)"""
        return {}
    
    def get_all_rules(self) -> Dict:
        """Fetch all dynamic policies from the database"""
        combined_rules = {}
        
        if hasattr(self, 'db') and self.db:
            try:
                db_policies = self.db.get_policies(active_only=True)
                for p in db_policies:
                    rule_name = p["name"]
                    combined_rules[rule_name] = {
                        "type": RuleType.REGEX,
                        "pattern": p["regex_pattern"],
                        "severity": p["severity"].lower() if p["severity"] else "medium",
                        "confidence": 0.85,
                        "threshold": p["threshold_count"],
                        "window": p["threshold_window_mins"]
                    }
            except Exception as e:
                print(f"Error loading dynamic policies: {e}")
                
        return combined_rules

    def detect_patterns(self, payload: str) -> List[DetectionResult]:
        """Scan payload for all matching patterns"""
        results = []
        active_rules = self.get_all_rules()
        
        for rule_name, rule_config in active_rules.items():
            if rule_config["type"] == RuleType.REGEX:
                try:
                    matches = re.finditer(
                        rule_config["pattern"],
                        payload,
                        re.IGNORECASE | re.MULTILINE
                    )
                    
                    for match in matches:
                        results.append(DetectionResult(
                            rule_name=rule_name,
                            severity=rule_config["severity"],
                            matched_pattern=match.group(0)[:50],  # First 50 chars
                            confidence=rule_config["confidence"]
                        ))
                except Exception as e:
                    print(f"Invalid regex in rule {rule_name}: {e}")
        
        return results
    
    def calculate_pii_count(self, payload: str) -> int:
        """Count total PII matches (for bulk detection)"""
        pii_patterns = ["SSN_PATTERN", "EMAIL", "PAN_INDIA", "AADHAAR"]
        total = 0
        
        for pattern_name in pii_patterns:
            rule = self.rules.get(pattern_name)
            if rule and rule["type"] == RuleType.REGEX:
                matches = len(re.findall(rule["pattern"], payload, re.IGNORECASE))
                total += matches
        
        return total
    
    def evaluate_severity(self, detections: List[DetectionResult]) -> Tuple[str, float]:
        """Determine overall severity and risk score based on detections"""
        if not detections:
            return "low", 0.0
        
        severity_scores = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25
        }
        
        # Calculate weighted average
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
