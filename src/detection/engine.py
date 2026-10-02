"""
Detection engine: runs the detector library (plus console policies) over text.

Pipeline per scan:
  1. normalize   NFKC + strip zero-width/soft-hyphen chars (defeats "4111​1111..." and
                 full-width digit evasion); only when the text is not pure ASCII
  2. prefilter   skip a detector unless one of its literal anchors occurs in the text
  3. match       one finditer over the whole text per detector (no per-line loops)
  4. validate    checksum / structure validators drop look-alikes
  5. context     keyword proximity: boosts confidence, or is required for ambiguous formats
  6. resolve     overlapping candidates -> keep the strongest (validated > severity > confidence)
  7. decode      base64 blobs are decoded and scanned too (encoded exfiltration)
"""

from __future__ import annotations

import base64
import binascii
import re
import threading
import unicodedata
from bisect import bisect_right, insort
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from src.detection.library import DETECTORS, KEYWORD_BOOST, KEYWORD_WINDOW, LEGACY_ALIASES
from src.detection.validators import VALIDATORS

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

# Characters attackers insert to break pattern matching; they render as nothing.
_INVISIBLE = re.compile("[­᠎​-‏‪-‮⁠-⁤﻿]")
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-](?<![A-Za-z0-9+/=_-].)[A-Za-z0-9+/_-]{39,}={0,2}(?![A-Za-z0-9+/=_-])")
_DIGITS = set("0123456789")

MAX_SCAN_CHARS = 20_000_000       # text beyond this is not scanned (flagged as truncated)
MAX_CANDIDATES_PER_DETECTOR = 20_000
MAX_B64_BLOBS = 64
MAX_B64_DECODED_BYTES = 2_000_000


@dataclass
class Match:
    detector: str
    value: str
    start: int
    end: int
    severity: str
    confidence: float
    category: str
    description: str
    validated: bool = False
    generic: bool = False
    keyword: Optional[str] = None
    encoding: Optional[str] = None
    line: int = 0
    context: str = ""


@dataclass
class ScanOutcome:
    matches: List[Match]
    counts: Dict[str, int] = field(default_factory=dict)
    truncated: bool = False
    normalized: bool = False


@dataclass
class _Compiled:
    name: str
    regex: "re.Pattern"
    group: int
    validator: Optional[callable]
    keyword_re: Optional["re.Pattern"]
    keywords: tuple
    require_keyword: bool
    prefilter: Optional[List[str]]
    prefilter_digits: bool
    prefilter_lower: bool
    severity: str
    confidence: float
    category: str
    description: str
    generic: bool = False
    source: str = "builtin"
    action: Optional[str] = None


def normalize_text(text: str) -> str:
    if text.isascii():
        return text
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))


def _compile_detector(d: dict, source: str = "builtin") -> _Compiled:
    flags = re.MULTILINE | (re.IGNORECASE if d.get("ignore_case") else 0)
    keywords = [k.lower() for k in d.get("keywords") or []]
    keyword_re = None
    if keywords:
        alt = "|".join(re.escape(k) for k in sorted(keywords, key=len, reverse=True))
        # Left word boundary is checked in _find_keyword: a pattern that starts with a plain
        # alternation lets the regex engine skip ahead on the first characters (much faster).
        keyword_re = re.compile(r"(?:" + alt + r")(?![a-z0-9])")
    prefilter = d.get("prefilter")
    prefilter_digits = bool(prefilter) and set(prefilter) <= _DIGITS and len(prefilter) >= 8
    validator = VALIDATORS.get(d["validator"]) if d.get("validator") else None
    if d.get("validator") and validator is None:
        raise ValueError(f"unknown validator {d['validator']!r} for {d['name']}")
    return _Compiled(
        name=d["name"],
        regex=re.compile(d["pattern"], flags),
        group=int(d.get("group", 0)),
        validator=validator,
        keyword_re=keyword_re,
        keywords=tuple(keywords),
        require_keyword=bool(d.get("require_keyword")),
        prefilter=None if not prefilter or prefilter_digits else
        ([p.lower() for p in prefilter] if d.get("ignore_case") else list(prefilter)),
        prefilter_digits=prefilter_digits,
        prefilter_lower=bool(d.get("ignore_case")),
        severity=str(d.get("severity", "medium")).lower(),
        confidence=float(d.get("confidence", 0.8)),
        category=d.get("category", "Custom"),
        description=d.get("description", d["name"]),
        generic=bool(d.get("generic")),
        source=source,
        action=d.get("action"),
    )


class DetectionEngine:
    """Compiled detector set. Thread-safe for concurrent scans (no mutable scan state)."""

    def __init__(self, detectors: Iterable[dict] = DETECTORS, custom_rules: Iterable[dict] = ()):
        self._builtin = [_compile_detector(d) for d in detectors]
        self._by_name = {c.name: c for c in self._builtin}
        self._custom: List[_Compiled] = []
        self.set_custom_rules(custom_rules)

    # ---------------------------------------------------------------- policies
    def set_custom_rules(self, rules: Iterable[dict]) -> List[str]:
        """Compile console regex policies. Returns names of rules that failed to compile."""
        compiled, errors = [], []
        for r in rules or ():
            try:
                pattern = str(r.get("pattern") or "")
                if not pattern or len(pattern) > 2000:
                    raise ValueError("empty or oversized pattern")
                if pattern.startswith("(?i)"):
                    pattern, ignore_case = pattern[4:], True
                else:
                    ignore_case = bool(r.get("ignore_case", True))
                compiled.append(_compile_detector({
                    "name": r["name"], "pattern": pattern, "ignore_case": ignore_case,
                    "severity": r.get("severity", "medium"), "confidence": r.get("confidence", 0.85),
                    "category": "SIEM Policy", "description": r.get("description") or r["name"],
                    "action": r.get("action"),
                }, source="policy"))
            except Exception:
                errors.append(str(r.get("name")))
        self._custom = compiled
        return errors

    def detector(self, name: str) -> Optional[_Compiled]:
        return self._by_name.get(LEGACY_ALIASES.get(name, name))

    @property
    def detector_names(self) -> List[str]:
        return [c.name for c in self._builtin]

    # ---------------------------------------------------------------- scanning
    def scan(self, text: str, *, include: Optional[set] = None, decode: bool = True,
             ignore_keyword_requirement: bool = False, with_context: bool = True) -> ScanOutcome:
        if not text:
            return ScanOutcome(matches=[])
        truncated = len(text) > MAX_SCAN_CHARS
        if truncated:
            text = text[:MAX_SCAN_CHARS]
        norm = normalize_text(text)
        normalized = norm is not text

        candidates = self._candidates(norm, include, ignore_keyword_requirement)
        if decode:
            candidates.extend(self._decoded_candidates(norm, include, ignore_keyword_requirement))
        matches = _resolve_overlaps(candidates)

        counts: Dict[str, int] = {}
        for m in matches:
            counts[m.detector] = counts.get(m.detector, 0) + 1
        if with_context and matches:
            _annotate_lines(norm, matches)
        return ScanOutcome(matches=matches, counts=counts, truncated=truncated, normalized=normalized)

    def _candidates(self, text: str, include: Optional[set], ignore_kw: bool,
                    encoding: Optional[str] = None, offset_base: int = 0) -> List[Match]:
        lower = None
        has_digit = any(ch in text for ch in "0123456789") if len(text) < 4096 else bool(re.search(r"\d", text))
        out: List[Match] = []
        for det in (*self._builtin, *self._custom):
            if include is not None and det.name not in include:
                continue
            if det.prefilter_digits and not has_digit:
                continue
            if det.prefilter:
                if det.prefilter_lower:
                    if lower is None:
                        lower = text.lower()
                    hay = lower
                else:
                    hay = text
                if not any(p in hay for p in det.prefilter):
                    continue
            if det.require_keyword and not ignore_kw:
                # Cheap whole-text keyword check first: no keyword anywhere -> no match possible.
                if lower is None:
                    lower = text.lower()
                if not any(k in lower for k in det.keywords) or not _find_keyword(det.keyword_re, lower, 0, len(lower)):
                    continue
            n = 0
            for m in det.regex.finditer(text):
                try:
                    value = m.group(det.group)
                    start, end = m.span(det.group)
                except IndexError:
                    value, (start, end) = m.group(0), m.span(0)
                if not value or not value.strip():
                    continue
                validated = False
                if det.validator is not None:
                    if not det.validator(value):
                        continue
                    validated = True
                keyword = None
                if det.keyword_re is not None:
                    if lower is None:
                        lower = text.lower()
                    keyword = _find_keyword(det.keyword_re, lower, max(0, m.start() - KEYWORD_WINDOW),
                                            m.end() + KEYWORD_WINDOW)
                if det.require_keyword and not keyword and not ignore_kw:
                    continue
                conf = det.confidence + (KEYWORD_BOOST if keyword else 0.0)
                out.append(Match(
                    detector=det.name, value=value, start=start + offset_base, end=end + offset_base,
                    severity=det.severity, confidence=round(min(conf, 0.99), 2),
                    category=det.category, description=det.description,
                    validated=validated, generic=det.generic, keyword=keyword, encoding=encoding,
                ))
                n += 1
                if n >= MAX_CANDIDATES_PER_DETECTOR:
                    break
        return out

    def _decoded_candidates(self, text: str, include: Optional[set], ignore_kw: bool) -> List[Match]:
        out: List[Match] = []
        budget = MAX_B64_DECODED_BYTES
        for i, m in enumerate(_B64_RUN.finditer(text)):
            if i >= MAX_B64_BLOBS or budget <= 0:
                break
            blob = m.group(0)
            if blob.startswith("eyJ") and blob.count(".") >= 2:
                continue  # JWTs are handled directly
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), altchars=b"-_" if ("-" in blob or "_" in blob) else None)
            except (binascii.Error, ValueError):
                continue
            budget -= len(raw)
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded)
            if not decoded or printable / len(decoded) < 0.95:
                continue
            for c in self._candidates(decoded, include, ignore_kw, encoding="base64"):
                # Report the decoded value, but position it on the encoded blob in the original text.
                c.start, c.end = m.start(), m.end()
                out.append(c)
        return out

    # ---------------------------------------------------------------- redaction
    def redact(self, text: str) -> str:
        """Replace every sensitive value with [REDACTED:<DETECTOR>].

        Aggressive by design (used before text leaves the host): keyword requirements are
        ignored so ambiguous identifiers are masked even without context.
        """
        if not text:
            return text
        norm = normalize_text(str(text))
        matches = _resolve_overlaps(self._candidates(norm, None, ignore_kw=True))
        if not matches:
            return norm
        parts, last = [], 0
        for m in sorted(matches, key=lambda x: x.start):
            if m.start < last:
                continue
            parts.append(norm[last:m.start])
            parts.append(f"[REDACTED:{m.detector}]")
            last = m.end
        parts.append(norm[last:])
        return "".join(parts)


def _find_keyword(keyword_re, lower: str, lo: int, hi: int) -> Optional[str]:
    for km in keyword_re.finditer(lower, lo, hi):
        s = km.start()
        if s == 0 or not lower[s - 1].isalnum():
            return km.group(0)
    return None


def _priority(m: Match):
    return (not m.generic, m.validated, SEVERITY_RANK.get(m.severity, 0), m.confidence, m.end - m.start)


def _resolve_overlaps(candidates: List[Match]) -> List[Match]:
    """Greedy interval selection: strongest candidate wins any overlapping span."""
    if len(candidates) < 2:
        return list(candidates)
    accepted: List[Match] = []
    starts: List[int] = []
    ends_by_start: Dict[int, int] = {}
    for c in sorted(candidates, key=_priority, reverse=True):
        if c.encoding or c.category == "SIEM Policy":
            # Decoded findings share the blob span, and policy findings carry enforcement
            # metadata: keep them all (deduped below).
            accepted.append(c)
            continue
        i = bisect_right(starts, c.start)
        if i > 0 and ends_by_start[starts[i - 1]] > c.start:
            continue
        if i < len(starts) and starts[i] < c.end:
            continue
        if c.start in ends_by_start:
            continue
        insort(starts, c.start)
        ends_by_start[c.start] = c.end
        accepted.append(c)
    seen, out = set(), []
    for m in sorted(accepted, key=lambda x: (x.start, x.end)):
        key = (m.detector, m.value, m.start)
        if key in seen:
            continue
        seen.add(key)
        out.append(m)
    return out


def _annotate_lines(text: str, matches: List[Match]) -> None:
    newlines = [m.start() for m in re.finditer("\n", text)]
    for m in matches:
        m.line = bisect_right(newlines, m.start) + 1
        a = max(0, m.start - 30)
        b = min(len(text), m.end + 30)
        m.context = text[a:b].replace("\n", " ")[:120]


_default_engine: Optional[DetectionEngine] = None
_default_lock = threading.Lock()


def get_engine() -> DetectionEngine:
    """Process-wide engine with the built-in library (compiled once)."""
    global _default_engine
    if _default_engine is None:
        with _default_lock:
            if _default_engine is None:
                _default_engine = DetectionEngine()
    return _default_engine
