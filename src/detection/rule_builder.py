"""
Offline rule suggestions for the Lab (used when no LLM is configured, and to sanity-check LLM output).

  "alert on aadhaar numbers"                       -> policy referencing IN_AADHAAR
  "employee ids like EMP-482913 with luhn check"   -> custom detector \\bEMP-\\d{6}\\b + luhn_any
  "block 'Project Falcon'"                          -> regex policy
"""

from __future__ import annotations

import re
from typing import Optional

from src.detection.config import validate_custom

# phrase -> built-in detector
BUILTIN_HINTS = [
    (r"credit ?cards?|debit ?cards?|card numbers?|payment cards?|\bpan\b(?! card)", "CREDIT_CARD"),
    (r"aadhaa?r", "IN_AADHAAR"), (r"\bpan card|permanent account", "IN_PAN"), (r"\biban", "IBAN"),
    (r"\bssn|social security", "US_SSN"), (r"routing number|\baba\b", "US_BANK_ROUTING"),
    (r"\bnhs\b", "UK_NHS_NUMBER"), (r"\bcpf\b", "BR_CPF"), (r"\bdni\b|\bnie\b", "ES_DNI"),
    (r"\btfn\b|tax file number", "AU_TFN"), (r"\bimei\b", "IMEI"), (r"passports?", "PASSPORT"),
    (r"gstin|\bgst\b", "IN_GSTIN"), (r"upi", "IN_UPI_ID"), (r"private keys?", "PRIVATE_KEY"),
    (r"aws (?:access )?keys?", "AWS_ACCESS_KEY"), (r"github tokens?", "GITHUB_TOKEN"),
    (r"slack tokens?", "SLACK_TOKEN"), (r"jwt|json web tokens?", "JWT_TOKEN"),
    (r"connection strings?|database passwords?", "CONNECTION_STRING"), (r"e-?mail addresses?", "EMAIL_ADDRESS"),
    (r"medical record|\bmrn\b", "MEDICAL_RECORD_NUMBER"), (r"confidential|classification label", "CLASSIFICATION_LABEL"),
]

# phrase -> validator for custom formats
VALIDATOR_HINTS = [
    (r"luhn|mod[- ]?10", "luhn_any"), (r"verhoeff", "verhoeff"), (r"mod[- ]?97|iso ?7064", "iso7064_mod97"),
    (r"mod[- ]?11[- ]?2", "iso7064_mod11_2"), (r"entropy|random secret|api key|token", "high_entropy_secret"),
]

_META = re.compile(r"([.^$*+?{}\[\]\\|()])")


def _escape(text: str) -> str:
    return _META.sub(r"\\\1", text)


_EXAMPLE = re.compile(r"(?:like|e\.g\.?|such as|format|example|eg)\s*[:\"']?\s*([A-Za-z0-9][A-Za-z0-9._/-]{3,40})", re.I)
_QUOTED = re.compile(r"'([^']+)'|\"([^\"]+)\"")


def pattern_from_example(example: str) -> str:
    """EMP-482913 -> \\bEMP-\\d{6}\\b ; AB12-XY -> \\b[A-Z]{2}\\d{2}-[A-Z]{2}\\b (letters kept when they look like a prefix)."""
    parts = re.findall(r"[A-Za-z]+|\d+|[^A-Za-z\d]", example)
    out = []
    for i, p in enumerate(parts):
        if p.isdigit():
            out.append(r"\d{%d}" % len(p))
        elif p.isalpha():
            # Leading alphabetic block is usually a fixed prefix (EMP, INV, ACC); others vary.
            out.append(_escape(p.upper()) if i == 0 and len(p) <= 6 else "[A-Z]{%d}" % len(p))
        else:
            out.append(_escape(p))
    return r"\b" + "".join(out) + r"\b"


def suggest_from_prompt(prompt: str) -> dict:
    """Best-effort rule from a natural language prompt, without an LLM."""
    text = prompt.strip()
    low = text.lower()
    severity = "HIGH" if re.search(r"block|critical|never|prevent", low) else "MEDIUM"
    action = "block" if "block" in low or "prevent" in low else ("warn" if "warn" in low else "monitor")

    validator = next((v for rx, v in VALIDATOR_HINTS if re.search(rx, low)), None)
    example = _EXAMPLE.search(text)
    if example and (validator or re.search(r"\d", example.group(1))):
        ex = example.group(1).rstrip(".,;")
        name = re.sub(r"[^A-Z0-9]+", "_", (re.match(r"[A-Za-z]+", ex) or re.match(r".", "CUSTOM")).group(0).upper())[:20]
        definition = {
            "name": f"{name}_ID" if not name.endswith("_ID") else name,
            "pattern": pattern_from_example(ex),
            "validator": validator if validator in ("luhn_any", "verhoeff", "iso7064_mod97", "iso7064_mod11_2") else None,
            "keywords": [], "require_keyword": False, "severity": severity.lower(), "confidence": 0.85,
            "category": "Custom", "description": text[:200],
        }
        clean, errors = validate_custom(definition)
        if not errors:
            return {"name": clean["name"], "description": text[:200], "rule_type": "detector",
                    "detector_definition": clean, "severity": severity, "action": action, "source": "offline"}

    for rx, det in BUILTIN_HINTS:
        if re.search(rx, low):
            return {"name": det, "description": text[:200], "rule_type": "builtin", "rule_data": {"detector": det},
                    "severity": severity, "action": action, "source": "offline"}
    return {}
