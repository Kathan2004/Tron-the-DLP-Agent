"""Content extraction and file scanning (formats, OCR, archives, encryption, caching)."""

import pytest

from src.extraction import extract, ocr_available, sniff_type
from src.file_scanner import FileContentScanner
from tests import fixtures as F

SECRET = F.SECRET_LINE
needs_ocr = pytest.mark.skipif(not ocr_available(), reason="tesseract not installed")


def found(text):
    from src.detection import get_engine
    return {m.detector for m in get_engine().scan(text).matches}


@pytest.mark.parametrize("name,builder", [
    ("a.pdf", lambda: F.text_pdf([SECRET])),
    ("a.docx", lambda: F.docx(["intro"], header_line=SECRET)),
    ("a.pptx", lambda: F.pptx(["Q3"], notes_line=SECRET)),
    ("a.zip", lambda: F.zip_of({"x/notes.txt": SECRET})),
    ("nested.zip", lambda: F.zip_of({"inner.zip": F.zip_of({"deep.docx": F.docx([SECRET])})})),
    ("mail.eml", lambda: F.eml_with_attachment("see attached", "a.docx", F.docx([SECRET]))),
])
def test_formats_extract_sensitive_text(name, builder):
    x = extract(data=builder(), name=name)
    assert {"US_SSN", "CREDIT_CARD"} <= found(x.text), (x.file_type, x.text[:200], x.errors)


def test_docx_comments_are_scanned():
    x = extract(data=F.docx(["intro"], comment_line="aadhaar 2341 2341 2346"), name="c.docx")
    assert "IN_AADHAAR" in found(x.text)


def test_xlsx_numeric_cells_are_rendered_in_full():
    x = extract(data=F.xlsx([["name", "card"], ["bob", 4111111111111111]]), name="s.xlsx")
    assert "4111111111111111" in x.text and "CREDIT_CARD" in found(x.text)


def test_encrypted_pdf_is_flagged():
    x = extract(data=F.encrypted_pdf([SECRET]), name="locked.pdf")
    assert x.encrypted and x.file_type == "pdf"


def test_true_type_detection_beats_extension():
    x = extract(data=F.text_pdf([SECRET]), name="innocent.txt")
    assert x.file_type == "pdf" and x.type_mismatch
    assert "US_SSN" in found(x.text)


def test_sniff_types():
    assert sniff_type(b"%PDF-1.7 ...") == "pdf"
    assert sniff_type(b"\x89PNG\r\n\x1a\n....") == "png"
    assert sniff_type("From: a@b.c\nTo: d@e.f\nSubject: hi\n\nbody".encode()) == "eml"
    assert sniff_type("plain text".encode("utf-16")) == "text"


def test_zip_bomb_ratio_is_refused():
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb.txt", b"0" * (20 * 1024 * 1024))
    x = extract(data=buf.getvalue(), name="bomb.zip")
    assert x.truncated and any("zip bomb" in e for e in x.errors)


@needs_ocr
def test_ocr_image():
    x = extract(data=F.text_image([SECRET]), name="shot.png")
    assert x.ocr_used and {"US_SSN", "CREDIT_CARD"} <= found(x.text)


@needs_ocr
def test_ocr_scanned_pdf_without_text_layer():
    x = extract(data=F.scanned_pdf([SECRET]), name="scan.pdf")
    assert x.ocr_used and "US_SSN" in found(x.text)


def test_scanner_bulk_escalation_and_cache():
    s = FileContentScanner(ocr=False)
    data = F.xlsx([["ssn"]] + [["536-22-1234"]] * 12)
    r, ext = s.scan_bytes(data, "people.xlsx")
    assert r.bulk and r.severity == "critical" and r.counts["US_SSN"] == 12 and ext is not None
    r2, ext2 = s.scan_bytes(data, "copy.xlsx")
    assert ext2 is None and r2.file_path == "copy.xlsx" and r2.counts == r.counts


def test_scanner_reports_encrypted_content_as_finding():
    r, _ = FileContentScanner(ocr=False).scan_bytes(F.encrypted_pdf(["x"]), "locked.pdf")
    assert [f.pattern_name for f in r.findings] == ["ENCRYPTED_CONTENT"] and r.severity == "high"


def test_scanner_applies_policies_and_invalidates_cache():
    s = FileContentScanner(ocr=False)
    data = F.docx(["Project Falcon launch plan"])
    r, _ = s.scan_bytes(data, "plan.docx")
    assert not r.findings
    s.set_policies([{"name": "PROJECT_FALCON", "pattern": r"project falcon", "severity": "high"}], version=1)
    r, _ = s.scan_bytes(data, "plan.docx")
    assert [f.pattern_name for f in r.findings] == ["PROJECT_FALCON"] and r.findings[0].source == "policy"
