#!/usr/bin/env python3
"""
Real File Content Scanner — TRON THE DLP AGENT
Scans file CONTENTS (not just names) for sensitive data patterns.
Supports: text files, CSVs, PDFs, DOCX, XLSX, JSON, YAML, etc.
"""

import os
import re
import sys
import csv
import json
import hashlib
import mimetypes
import io
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class ScanFinding:
    """A single sensitive data finding in a file."""
    pattern_name: str
    matched_text: str  # Redacted version
    line_number: int
    severity: str
    confidence: float
    context: str  # Surrounding text (redacted)

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
    severity: str  # Highest severity found

    def to_dict(self):
        return {
            **{k: v for k, v in asdict(self).items() if k != 'findings'},
            'findings': [f.to_dict() for f in self.findings],
            'finding_count': len(self.findings)
        }


# Sensitive data patterns with their detection rules
SENSITIVE_PATTERNS = {
    # PII - Identity Numbers
    "SSN": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "severity": "critical",
        "confidence": 0.95,
        "description": "US Social Security Number"
    },
    "AADHAAR": {
        "pattern": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "severity": "critical",
        "confidence": 0.88,
        "description": "Indian Aadhaar Number"
    },
    "PAN_INDIA": {
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "severity": "high",
        "confidence": 0.92,
        "description": "Indian PAN Card Number"
    },
    "PASSPORT": {
        "pattern": r"\b[A-Z]{1}[0-9]{7}\b",
        "severity": "high",
        "confidence": 0.70,
        "description": "Passport Number"
    },

    # Financial
    "CREDIT_CARD": {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": "critical",
        "confidence": 0.90,
        "description": "Credit Card Number (Visa/MC/Amex/Discover)"
    },
    "CREDIT_CARD_FORMATTED": {
        "pattern": r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b",
        "severity": "critical",
        "confidence": 0.92,
        "description": "Formatted Credit Card Number"
    },
    "IBAN": {
        "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
        "severity": "high",
        "confidence": 0.85,
        "description": "IBAN Number"
    },
    "BANK_ACCOUNT": {
        "pattern": r"(?:account|acct|a/c)[\s#:.-]*\d{8,18}",
        "severity": "high",
        "confidence": 0.75,
        "description": "Bank Account Number"
    },

    # Credentials & Secrets
    "AWS_ACCESS_KEY": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "confidence": 0.99,
        "description": "AWS Access Key ID"
    },
    "AWS_SECRET_KEY": {
        "pattern": r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "critical",
        "confidence": 0.95,
        "description": "AWS Secret Access Key"
    },
    "GENERIC_API_KEY": {
        "pattern": r"(?:api[_-]?key|apikey|api_secret|access_token)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?",
        "severity": "critical",
        "confidence": 0.80,
        "description": "API Key / Secret"
    },
    "PRIVATE_KEY": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "confidence": 0.99,
        "description": "Private Key File"
    },
    "PASSWORD_INLINE": {
        "pattern": r"(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
        "severity": "critical",
        "confidence": 0.85,
        "description": "Hardcoded Password"
    },
    "CONNECTION_STRING": {
        "pattern": r"(?:mongodb|mysql|postgres|redis|amqp):\/\/[^\s'\"]+",
        "severity": "critical",
        "confidence": 0.90,
        "description": "Database Connection String"
    },
    "JWT_TOKEN": {
        "pattern": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "severity": "high",
        "confidence": 0.95,
        "description": "JWT Token"
    },
    "GCP_SERVICE_ACCOUNT": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "severity": "critical",
        "confidence": 0.99,
        "description": "GCP Service Account Key"
    },

    # PII - Contact Information
    "EMAIL_ADDRESS": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "severity": "low",
        "confidence": 0.98,
        "description": "Email Address"
    },
    "PHONE_NUMBER": {
        "pattern": r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
        "severity": "medium",
        "confidence": 0.65,
        "description": "Phone Number"
    },
    "PHONE_INDIA": {
        "pattern": r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b",
        "severity": "medium",
        "confidence": 0.70,
        "description": "Indian Phone Number"
    },

    # Source Code & Intellectual Property
    "SQL_QUERY": {
        "pattern": r"\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM|DROP TABLE|ALTER TABLE)\b.{5,}",
        "severity": "medium",
        "confidence": 0.60,
        "description": "SQL Statement"
    },
    "ENV_VARIABLE": {
        "pattern": r"(?:export\s+)?[A-Z_]{2,}=(?:['\"]?[^\s'\"]+['\"]?)",
        "severity": "medium",
        "confidence": 0.55,
        "description": "Environment Variable Assignment"
    },
}

# File types we can scan
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

SCANNABLE_IMAGE_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.webp', '.bmp', '.tif', '.tiff'
}

DOCLING_EXTENSIONS = {
    '.pdf', '.docx', '.pptx', '.xlsx',
    '.png', '.jpg', '.jpeg', '.webp', '.bmp', '.tif', '.tiff'
}

# Skip these directories
SKIP_DIRS = {
    '.git', '__pycache__', 'node_modules', '.venv', 'venv',
    '.idea', '.vscode', '.DS_Store', 'dist', 'build',
    '.next', '.nuxt', 'coverage', '.tox',
}

# Max file size to scan (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024


class FileContentScanner:
    """Scans file contents for sensitive data patterns."""

    def __init__(self, patterns: dict = None):
        self.patterns = patterns or SENSITIVE_PATTERNS
        self._compiled_patterns = {}
        self._docling_converter = None
        self._init_docling()
        self._compile_patterns()

    def _init_docling(self):
        """Initialize optional Docling converter for richer document extraction."""
        try:
            from docling.document_converter import DocumentConverter
            self._docling_converter = DocumentConverter()
        except Exception:
            self._docling_converter = None

    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        for name, config in self.patterns.items():
            try:
                self._compiled_patterns[name] = re.compile(
                    config["pattern"],
                    re.IGNORECASE | re.MULTILINE
                )
            except re.error as e:
                print(f"⚠️  Invalid regex for {name}: {e}")

    def scan_text(self, text: str, source: str = "unknown") -> List[ScanFinding]:
        """Scan text content for sensitive patterns."""
        findings = []
        lines = text.split('\n')

        for name, compiled_re in self._compiled_patterns.items():
            config = self.patterns[name]

            for line_num, line in enumerate(lines, 1):
                for match in compiled_re.finditer(line):
                    matched = match.group(0)

                    # Redact the match for storage
                    redacted = self._redact(matched, name)

                    # Get context (surrounding text, redacted)
                    start = max(0, match.start() - 20)
                    end = min(len(line), match.end() + 20)
                    context = line[start:end]
                    context = self._redact_in_context(context, matched)

                    findings.append(ScanFinding(
                        pattern_name=name,
                        matched_text=redacted,
                        line_number=line_num,
                        severity=config["severity"],
                        confidence=config["confidence"],
                        context=context[:100]
                    ))

        # Extra pass: generic Luhn-valid credit card detection.
        card_like = re.compile(r"\b(?:\d[ -]?){13,19}\b")
        for line_num, line in enumerate(lines, 1):
            for match in card_like.finditer(line):
                raw = match.group(0)
                digits = re.sub(r"\D", "", raw)
                if not self._is_valid_luhn(digits):
                    continue

                redacted = self._redact(raw, "CREDIT_CARD")
                start = max(0, match.start() - 20)
                end = min(len(line), match.end() + 20)
                context = line[start:end]
                context = self._redact_in_context(context, raw)

                findings.append(ScanFinding(
                    pattern_name="CREDIT_CARD_LUHN",
                    matched_text=redacted,
                    line_number=line_num,
                    severity="critical",
                    confidence=0.96,
                    context=context[:100]
                ))

        return findings

    @staticmethod
    def _is_valid_luhn(digits: str) -> bool:
        if not digits or not digits.isdigit():
            return False
        if len(digits) < 13 or len(digits) > 19:
            return False

        total = 0
        double = False
        for ch in reversed(digits):
            n = int(ch)
            if double:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
            double = not double
        return (total % 10) == 0

    def scan_file(self, file_path: str) -> Optional[ScanResult]:
        """Scan a single file for sensitive data."""
        path = Path(file_path)

        if not path.exists() or not path.is_file():
            return None

        # Check file size
        file_size = path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            return None

        if file_size == 0:
            return None

        # Determine file type
        ext = path.suffix.lower()
        file_type = mimetypes.guess_type(str(path))[0] or "unknown"

        # Calculate file hash
        file_hash = self._hash_file(path)

        # Read and scan content
        content = self._read_file(path, ext)
        if content is None:
            return None

        findings = self.scan_text(content, str(path))

        # Determine overall severity
        severity = "none"
        if findings:
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            severity = max(findings, key=lambda f: severity_order.get(f.severity, 0)).severity

        return ScanResult(
            file_path=str(path),
            file_hash=file_hash,
            file_size=file_size,
            file_type=file_type or ext,
            scan_time=datetime.now().isoformat(),
            findings=findings,
            severity=severity
        )

    def scan_directory(self, directory: str, recursive: bool = True,
                       extensions: set = None) -> List[ScanResult]:
        """Scan all scannable files in a directory."""
        results = []
        scan_extensions = extensions or SCANNABLE_TEXT_EXTENSIONS
        root = Path(directory)

        if not root.exists():
            return results

        iterator = root.rglob("*") if recursive else root.glob("*")

        for path in iterator:
            # Skip directories in skip list
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue

            if not path.is_file():
                continue

            if path.suffix.lower() not in scan_extensions:
                continue

            try:
                result = self.scan_file(str(path))
                if result and result.findings:
                    results.append(result)
            except Exception as e:
                print(f"⚠️  Error scanning {path}: {e}")

        return results

    def scan_clipboard(self) -> List[ScanFinding]:
        """Scan current clipboard contents."""
        try:
            import subprocess
            if sys.platform == "darwin":
                result = subprocess.run(
                    ["pbpaste"], capture_output=True, text=True, timeout=2
                )
                content = result.stdout
            elif sys.platform == "linux":
                result = subprocess.run(
                    ["xclip", "-selection", "clipboard", "-o"],
                    capture_output=True, text=True, timeout=2
                )
                content = result.stdout
            else:
                return []

            if content and len(content) > 3:
                return self.scan_text(content, "clipboard")
        except Exception:
            pass
        return []

    def _read_file(self, path: Path, ext: str) -> Optional[str]:
        """Read file content, handling different file types."""
        try:
            # Plain text files
            if ext in SCANNABLE_TEXT_EXTENSIONS or ext == '':
                encodings = ['utf-8', 'latin-1', 'ascii', 'cp1252']
                for encoding in encodings:
                    try:
                        return path.read_text(encoding=encoding)
                    except (UnicodeDecodeError, UnicodeError):
                        continue
                return None

            # CSV files (already covered above, but explicit)
            if ext in {'.csv', '.tsv'}:
                return path.read_text(encoding='utf-8', errors='replace')

            # Image files: combine OCR engines to maximize recall.
            if ext in SCANNABLE_IMAGE_EXTENSIONS:
                ocr_text = self._read_image_ocr(path)
                docling_text = self._read_with_docling(path)
                return self._merge_extractions(ocr_text, docling_text)

            # Docling first-pass for supported binary formats
            if ext in DOCLING_EXTENSIONS:
                docling_text = self._read_with_docling(path)
                if docling_text and docling_text.strip():
                    return docling_text

            # PDF files
            if ext == '.pdf':
                return self._read_pdf(path)

            # DOCX files
            if ext == '.docx':
                return self._read_docx(path)

            # XLSX files
            if ext == '.xlsx':
                return self._read_xlsx(path)

            # Image files (OCR)
            if ext in SCANNABLE_IMAGE_EXTENSIONS:
                return self._read_image_ocr(path)

        except Exception as e:
            print(f"⚠️  Cannot read {path}: {e}")
        return None

    def _read_with_docling(self, path: Path) -> Optional[str]:
        """Extract text using Docling when available."""
        if not self._docling_converter:
            return None

        try:
            result = self._docling_converter.convert(str(path))
            document = getattr(result, 'document', result)

            candidates = []
            for method_name in ('export_to_markdown', 'export_to_text', 'to_markdown', 'to_text'):
                method = getattr(document, method_name, None)
                if callable(method):
                    try:
                        value = method()
                        if isinstance(value, str) and value.strip():
                            candidates.append(value)
                    except Exception:
                        continue

            for attr_name in ('text', 'content', 'markdown'):
                value = getattr(document, attr_name, None)
                if isinstance(value, str) and value.strip():
                    candidates.append(value)

            if candidates:
                return max(candidates, key=len)
        except Exception:
            return None

        return None

    def _merge_extractions(self, primary: Optional[str], secondary: Optional[str]) -> Optional[str]:
        """Merge extraction outputs; prefer higher-information combined text.

        Keeps unique lines in stable order to reduce duplicate noise.
        """
        p = (primary or '').strip()
        s = (secondary or '').strip()

        if not p and not s:
            return None
        if not p:
            return s
        if not s:
            return p

        merged_lines = []
        seen = set()
        for text in (p, s):
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                key = line.lower()
                if key in seen:
                    continue
                seen.add(key)
                merged_lines.append(line)

        if merged_lines:
            return '\n'.join(merged_lines)

        # Fallback in pathological cases where line splitting removes too much.
        return p if len(p) >= len(s) else s

    def _read_image_ocr(self, path: Path) -> Optional[str]:
        """Extract text from image files using OCR.

        Requires: Pillow + pytesseract and Tesseract binary installed on host.
        """
        try:
            from PIL import Image
            import pytesseract

            with Image.open(path) as img:
                # Improve OCR quality by trying multiple deterministic variants/configs.
                base = img.convert('RGB') if img.mode not in ('L', 'RGB') else img
                gray = base.convert('L')

                # Upscale to help OCR on low-res uploads.
                w, h = gray.size
                up = gray.resize((max(1, w * 2), max(1, h * 2)))

                # Binary threshold often helps with logos/signatures.
                bw = up.point(lambda x: 255 if x > 165 else 0, mode='1').convert('L')

                variants = [base, gray, up, bw]
                configs = [
                    '--oem 3 --psm 6',
                    '--oem 3 --psm 7',
                    '--oem 3 --psm 11',
                ]

                chunks = []
                seen = set()
                for v in variants:
                    for cfg in configs:
                        txt = pytesseract.image_to_string(v, config=cfg)
                        norm = (txt or '').strip()
                        if not norm:
                            continue
                        key = norm.lower()
                        if key in seen:
                            continue
                        seen.add(key)
                        chunks.append(norm)

                if chunks:
                    return "\n".join(chunks)
        except Exception:
            return None

        return None

    def _read_pdf(self, path: Path) -> Optional[str]:
        """Extract text from PDF."""
        extracted = ""
        try:
            import PyPDF2
            with open(path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                text_parts = []
                for page in reader.pages[:50]:  # Limit pages
                    text = page.extract_text()
                    if text:
                        text_parts.append(text)
                extracted = '\n'.join(text_parts)
        except ImportError:
            extracted = ""
        except Exception:
            extracted = ""

        # OCR fallback for scanned-image PDFs (no selectable text layer)
        if extracted and extracted.strip():
            return extracted

        ocr_text = self._ocr_pdf(path, max_pages=5)
        if ocr_text and ocr_text.strip():
            return ocr_text

        return None

    def _ocr_pdf(self, path: Path, max_pages: int = 5) -> Optional[str]:
        """OCR fallback for scanned PDFs using pdf2image + pytesseract.

        Note: Requires poppler and tesseract installed on host.
        """
        try:
            from pdf2image import convert_from_path
            import pytesseract

            images = convert_from_path(str(path), first_page=1, last_page=max_pages, dpi=220)
            text_parts = []
            for img in images:
                txt = pytesseract.image_to_string(img)
                if txt and txt.strip():
                    text_parts.append(txt)

            if text_parts:
                return "\n".join(text_parts)
        except Exception:
            return None

        return None

    def _read_docx(self, path: Path) -> Optional[str]:
        """Extract text from DOCX."""
        try:
            import zipfile
            import xml.etree.ElementTree as ET

            with zipfile.ZipFile(path) as zf:
                with zf.open('word/document.xml') as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
                    paragraphs = root.findall('.//w:p', ns)
                    text_parts = []
                    for para in paragraphs:
                        texts = para.findall('.//w:t', ns)
                        text_parts.append(''.join(t.text or '' for t in texts))
                    return '\n'.join(text_parts)
        except Exception:
            pass
        return None

    def _read_xlsx(self, path: Path) -> Optional[str]:
        """Extract text from XLSX."""
        try:
            import zipfile
            import xml.etree.ElementTree as ET

            with zipfile.ZipFile(path) as zf:
                # Read shared strings
                if 'xl/sharedStrings.xml' in zf.namelist():
                    with zf.open('xl/sharedStrings.xml') as f:
                        tree = ET.parse(f)
                        root = tree.getroot()
                        ns = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                        strings = root.findall('.//s:t', ns)
                        return '\n'.join(s.text or '' for s in strings)
        except Exception:
            pass
        return None

    def _hash_file(self, path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _redact(self, text: str, pattern_name: str) -> str:
        """Return exact matched text (no masking)."""
        return text

    def _redact_in_context(self, context: str, matched: str) -> str:
        """Return original context (no masking)."""
        return context


_LLM_REDACTION_PATTERNS: Optional[List] = None
_CARD_LIKE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def redact_for_llm(text: str) -> str:
    """Mask every sensitive-pattern match (and Luhn-valid card number) in text.

    Applied to anything sent to an external LLM so raw values never leave the host.
    Matches are replaced with a typed placeholder, e.g. "[REDACTED:SSN]".
    """
    global _LLM_REDACTION_PATTERNS
    if not text:
        return text
    if _LLM_REDACTION_PATTERNS is None:
        compiled = []
        for name, config in SENSITIVE_PATTERNS.items():
            try:
                compiled.append((name, re.compile(config["pattern"], re.IGNORECASE | re.MULTILINE)))
            except re.error:
                continue
        _LLM_REDACTION_PATTERNS = compiled

    def _mask_card(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if FileContentScanner._is_valid_luhn(digits):
            raw = match.group(0)
            return "[REDACTED:CREDIT_CARD]" + raw[len(raw.rstrip(" -")):]
        return match.group(0)

    # Cards first so shorter numeric patterns cannot leave partial digits behind.
    out = _CARD_LIKE_RE.sub(_mask_card, str(text))
    for name, compiled_re in _LLM_REDACTION_PATTERNS:
        out = compiled_re.sub(f"[REDACTED:{name}]", out)
    return out


# Convenience function
def quick_scan(path: str) -> List[Dict]:
    """Quick scan a file or directory and return results as dicts."""
    scanner = FileContentScanner()
    target = Path(path)

    if target.is_file():
        result = scanner.scan_file(str(target))
        return [result.to_dict()] if result and result.findings else []
    elif target.is_dir():
        results = scanner.scan_directory(str(target))
        return [r.to_dict() for r in results]
    return []


if __name__ == "__main__":
    # CLI usage
    if len(sys.argv) < 2:
        print("Usage: python file_scanner.py <path>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"\nScanning: {target}\n")

    results = quick_scan(target)

    if not results:
        print("✅ No sensitive data found.")
    else:
        for r in results:
            print(f"\nALERT {r['file_path']}")
            print(f"   Hash: {r['file_hash'][:16]}...")
            print(f"   Size: {r['file_size']} bytes | Type: {r['file_type']}")
            print(f"   Severity: {r['severity'].upper()}")
            print(f"   Findings: {r['finding_count']}")
            for f in r['findings'][:5]:
                print(f"     - [{f['severity']}] {f['pattern_name']}: {f['matched_text']} (line {f['line_number']})")
