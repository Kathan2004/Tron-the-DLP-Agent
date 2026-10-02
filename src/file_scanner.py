"""
File Content Scanner — TRON THE DLP AGENT

Thin layer over:
  src/extraction.py        true-type detection, text extraction, OCR, archives, encryption
  src/detection/           detector library, validators, keyword proximity, redaction

Public API is unchanged for the agents and API (ScanFinding, ScanResult, FileContentScanner,
quick_scan, redact_for_llm).
"""

import hashlib
import os
import subprocess
import sys
import threading
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.detection import DETECTORS, SEVERITY_RANK, DetectionEngine, Match, get_engine
from src.detection.edm import EDMIndex, load_indexes
from src.detection.validators import luhn as _luhn
from src.extraction import MAX_INPUT_BYTES, Extraction, extract


@dataclass
class ScanFinding:
    """A single sensitive data finding."""
    pattern_name: str
    matched_text: str
    line_number: int
    severity: str
    confidence: float
    context: str
    description: str = ""
    category: str = ""
    validated: bool = False
    source: str = "builtin"          # builtin detector or SIEM policy
    encoding: Optional[str] = None   # e.g. "base64" when found inside encoded content

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    """Result of scanning a single file."""
    file_path: str
    file_hash: str
    file_size: int
    file_type: str
    scan_time: str
    findings: List[ScanFinding]
    severity: str
    encrypted: bool = False
    truncated: bool = False
    ocr_used: bool = False
    type_mismatch: bool = False
    bulk: bool = False
    counts: Dict[str, int] = field(default_factory=dict)
    scan_ms: float = 0.0

    def to_dict(self):
        return {
            **{k: v for k, v in asdict(self).items() if k != 'findings'},
            'findings': [f.to_dict() for f in self.findings],
            'finding_count': len(self.findings),
        }


# Kept for backward compatibility (name -> {pattern, severity, confidence, description}).
SENSITIVE_PATTERNS = {
    d["name"]: {k: d[k] for k in ("pattern", "severity", "confidence", "description")} for d in DETECTORS
}

# Extensions treated as text by the directory walker and file watcher
SCANNABLE_TEXT_EXTENSIONS = {
    '.txt', '.csv', '.tsv', '.json', '.yaml', '.yml', '.xml',
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
    '.c', '.cpp', '.h', '.rs', '.swift', '.kt',
    '.html', '.htm', '.css', '.scss', '.less',
    '.md', '.rst', '.log', '.conf', '.cfg', '.ini', '.toml',
    '.env', '.env.local', '.env.production',
    '.sh', '.bash', '.zsh', '.bat', '.ps1',
    '.sql', '.pgsql', '.mysql',
    '.dockerfile', '.tf', '.hcl',
    '.properties', '.gradle', '.pom',
}
SCANNABLE_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp', '.bmp', '.tif', '.tiff', '.gif'}
SCANNABLE_DOCUMENT_EXTENSIONS = {
    '.pdf', '.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm', '.odt', '.ods', '.odp',
    '.rtf', '.eml', '.doc', '.xls', '.ppt', '.msg', '.zip', '.gz', '.tgz', '.tar',
}
SCANNABLE_EXTENSIONS = SCANNABLE_TEXT_EXTENSIONS | SCANNABLE_IMAGE_EXTENSIONS | SCANNABLE_DOCUMENT_EXTENSIONS

SKIP_DIRS = {
    '.git', '__pycache__', 'node_modules', '.venv', 'venv',
    '.idea', '.vscode', '.DS_Store', 'dist', 'build',
    '.next', '.nuxt', 'coverage', '.tox',
}

MAX_FILE_SIZE = MAX_INPUT_BYTES

# Identity/financial/health findings counted toward "bulk" exposure.
BULK_CATEGORIES = {"PII", "Financial", "Health"}
BULK_THRESHOLD = int(os.getenv("TRON_BULK_THRESHOLD", "10"))
RESULT_CACHE_SIZE = 512

_edm_cache: Optional[List[EDMIndex]] = None
_edm_lock = threading.Lock()


def edm_indexes() -> List[EDMIndex]:
    """Exact Data Match indexes from TRON_EDM_DIR (loaded once per process)."""
    global _edm_cache
    if _edm_cache is None:
        with _edm_lock:
            if _edm_cache is None:
                _edm_cache = load_indexes()
                if _edm_cache:
                    print(f"  ✅ EDM: {', '.join(i.name for i in _edm_cache)}")
    return _edm_cache


def _edm_findings(text: str, indexes: List[EDMIndex]) -> List["ScanFinding"]:
    out = []
    for idx in indexes:
        for m in idx.scan(text):
            out.append(ScanFinding(
                pattern_name="EDM_MATCH", matched_text=text[m.start:m.end][:200],
                line_number=text.count("\n", 0, m.start) + 1, severity="critical", confidence=0.99,
                context=f"record {m.row} of '{m.index}' matched on {', '.join(m.columns)}",
                description=f"Exact data match: {m.index} ({', '.join(m.columns)})",
                category="PII", validated=True,
            ))
    return out


def _to_finding(m: Match, source: str = "builtin") -> ScanFinding:
    return ScanFinding(
        pattern_name=m.detector, matched_text=m.value, line_number=m.line,
        severity=m.severity, confidence=m.confidence, context=m.context,
        description=m.description, category=m.category, validated=m.validated,
        source="policy" if m.category == "SIEM Policy" else source, encoding=m.encoding,
    )


class FileContentScanner:
    """Scans text and files for sensitive data."""

    def __init__(self, engine: Optional[DetectionEngine] = None, ocr: bool = True,
                 edm: Optional[List[EDMIndex]] = None):
        # Default: shared engine with the built-in library. A private engine is created
        # on demand when SIEM policies are attached (set_policies).
        self.engine = engine or get_engine()
        self.ocr = ocr
        self.edm = edm if edm is not None else edm_indexes()
        self._policy_version = None
        self._cache: "OrderedDict[Tuple[str, object], ScanResult]" = OrderedDict()
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------ policies
    def set_policies(self, regex_rules: List[dict], version=None) -> None:
        """Attach console regex policies (name, pattern, severity, ...). Cheap if unchanged."""
        if version is not None and version == self._policy_version:
            return
        if self.engine is get_engine():
            self.engine = DetectionEngine()
        self.engine.set_custom_rules(regex_rules)
        self._policy_version = version if version is not None else object()
        with self._cache_lock:
            self._cache.clear()

    # ------------------------------------------------------------------ text
    def scan_text(self, text: str, source: str = "unknown") -> List[ScanFinding]:
        if not text:
            return []
        findings = [_to_finding(m) for m in self.engine.scan(text).matches]
        if self.edm:
            findings.extend(_edm_findings(text, self.edm))
        return findings

    # ------------------------------------------------------------------ files
    def scan_file(self, file_path: str) -> Optional[ScanResult]:
        path = Path(file_path)
        if not path.is_file():
            return None
        size = path.stat().st_size
        if size == 0:
            return None
        with open(path, 'rb') as f:
            data = f.read(MAX_FILE_SIZE + 1)
        result, _ = self.scan_bytes(data, path.name, file_path=str(path), file_size=size)
        return result

    def scan_bytes(self, data: bytes, name: str = "upload.bin", file_path: Optional[str] = None,
                   file_size: Optional[int] = None) -> Tuple[ScanResult, Optional[Extraction]]:
        """Scan in-memory content. Returns (result, extraction); extraction is None on cache hit."""
        started = datetime.now()
        file_hash = hashlib.sha256(data).hexdigest()
        key = (file_hash, self._policy_version)
        with self._cache_lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
        if cached is not None:
            hit = ScanResult(**{**cached.__dict__, "file_path": file_path or name,
                                "scan_time": started.isoformat(), "scan_ms": 0.0})
            return hit, None

        ext = extract(data=data, name=name, ocr=self.ocr)
        outcome = self.engine.scan(ext.text) if ext.text else None
        findings = [_to_finding(m) for m in outcome.matches] if outcome else []
        counts = dict(outcome.counts) if outcome else {}
        if self.edm and ext.text:
            edm_hits = _edm_findings(ext.text, self.edm)
            findings.extend(edm_hits)
            if edm_hits:
                counts["EDM_MATCH"] = len(edm_hits)

        if ext.encrypted:
            findings.append(ScanFinding(
                pattern_name="ENCRYPTED_CONTENT", matched_text=f"<encrypted {ext.file_type}>",
                line_number=0, severity="high", confidence=1.0,
                context="password-protected content cannot be inspected",
                description="Encrypted / password-protected file", category="Policy Violation",
                validated=True,
            ))

        severity = "none"
        if findings:
            severity = max(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0)).severity
        sensitive = sum(1 for f in findings if f.category in BULK_CATEGORIES)
        bulk = sensitive >= BULK_THRESHOLD
        if bulk:
            severity = "critical"

        result = ScanResult(
            file_path=file_path or name, file_hash=file_hash,
            file_size=file_size if file_size is not None else len(data),
            file_type=ext.file_type, scan_time=started.isoformat(), findings=findings,
            severity=severity, encrypted=ext.encrypted, truncated=ext.truncated or bool(outcome and outcome.truncated),
            ocr_used=ext.ocr_used, type_mismatch=ext.type_mismatch, bulk=bulk, counts=counts,
            scan_ms=round((datetime.now() - started).total_seconds() * 1000, 1),
        )
        with self._cache_lock:
            self._cache[key] = result
            if len(self._cache) > RESULT_CACHE_SIZE:
                self._cache.popitem(last=False)
        return result, ext

    def scan_directory(self, directory: str, recursive: bool = True,
                       extensions: set = None) -> List[ScanResult]:
        results = []
        scan_extensions = extensions or SCANNABLE_EXTENSIONS
        root = Path(directory)
        if not root.exists():
            return results
        iterator = root.rglob("*") if recursive else root.glob("*")
        for path in iterator:
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue
            if not path.is_file() or path.suffix.lower() not in scan_extensions:
                continue
            try:
                result = self.scan_file(str(path))
                if result and result.findings:
                    results.append(result)
            except Exception as e:
                print(f"⚠️  Error scanning {path}: {e}")
        return results

    def scan_clipboard(self) -> List[ScanFinding]:
        try:
            if sys.platform == "darwin":
                cmd = ["pbpaste"]
            elif sys.platform == "linux":
                cmd = ["xclip", "-selection", "clipboard", "-o"]
            else:
                return []
            content = subprocess.run(cmd, capture_output=True, text=True, timeout=2).stdout
            if content and len(content) > 3:
                return self.scan_text(content, "clipboard")
        except Exception:
            pass
        return []

    # ------------------------------------------------------------------ compatibility helpers
    def _read_file(self, path: Path, ext: str = "") -> Optional[str]:
        """Extract text from a file (kept for callers of the old private API)."""
        try:
            return extract(str(path), ocr=self.ocr).text or None
        except Exception:
            return None

    def _hash_file(self, path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def _is_valid_luhn(digits: str) -> bool:
        return _luhn(digits)

    def _redact(self, text: str, pattern_name: str) -> str:
        """Matched values are stored as-is for analyst review (see README: Security notes)."""
        return text


def redact_for_llm(text: str) -> str:
    """Mask every sensitive value before text is sent to an external LLM.

    Uses the full detector library with keyword requirements ignored (over-redaction is the
    safe failure mode), e.g. "ssn 536-22-1234" -> "ssn [REDACTED:US_SSN]".
    """
    if not text:
        return text
    return get_engine().redact(str(text))


def quick_scan(path: str) -> List[Dict]:
    """Scan a file or directory and return results as dicts."""
    scanner = FileContentScanner()
    p = Path(path)
    if p.is_file():
        result = scanner.scan_file(path)
        return [result.to_dict()] if result and result.findings else []
    return [r.to_dict() for r in scanner.scan_directory(path)]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m src.file_scanner <path>")
        sys.exit(1)
    target = sys.argv[1]
    print(f"\nScanning: {target}\n")
    results = quick_scan(target)
    if not results:
        print("No sensitive data found.")
    for r in results:
        print(f"\nALERT {r['file_path']}  [{r['file_type']}, {r['scan_ms']} ms]")
        print(f"   Severity: {r['severity'].upper()}  Findings: {r['finding_count']}"
              + ("  (BULK)" if r['bulk'] else "") + ("  (ENCRYPTED)" if r['encrypted'] else ""))
        for f in r['findings'][:20]:
            print(f"     - [{f['severity']}] {f['pattern_name']}: {f['matched_text']} (line {f['line_number']})")
