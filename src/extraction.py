"""
Content extraction for DLP scanning (replaces Docling).

Design goals: low latency, small install, safe on hostile input.
  * True file type from magic bytes, not the extension (a PDF renamed to .txt is still parsed
    as PDF; a mismatch is reported).
  * PDF via pypdfium2 (PDFium, BSD/Apache): fast text layer extraction; pages with no text
    layer are rendered and OCR'd (no poppler needed). Falls back to pypdf.
  * Office Open XML / OpenDocument parsed with the stdlib: body, headers, footers, footnotes,
    comments, speaker notes, and numeric spreadsheet cells.
  * Archives (zip, tar, gzip) and email (.eml, attachments included) are expanded recursively
    with zip-bomb limits.
  * Encrypted content (password-protected zip/PDF/Office) is detected and reported, so policy
    can treat "cannot inspect" explicitly instead of passing it as clean.
  * Image OCR: one Tesseract pass, a second only when the first yields almost nothing.
"""

from __future__ import annotations

import email
import email.policy
import gzip
import html
import io
import os
import re
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import List, Optional

MAX_INPUT_BYTES = 50 * 1024 * 1024        # larger inputs: first 50 MB only (reported as truncated)
MAX_TEXT_CHARS = 20_000_000
MAX_ARCHIVE_DEPTH = 3
MAX_ARCHIVE_MEMBERS = 500
MAX_ARCHIVE_TOTAL_BYTES = 200 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_PDF_PAGES = 500
MAX_OCR_PAGES = 10
OCR_TIMEOUT_SECONDS = 30
OCR_WORKERS = max(1, min(4, os.cpu_count() or 1))

# Tesseract's internal OpenMP threading roughly doubles latency on page-sized images;
# one thread per process, with pages OCR'd in parallel, is faster.
os.environ.setdefault("OMP_THREAD_LIMIT", "1")

IMAGE_TYPES = {"png", "jpeg", "gif", "bmp", "tiff", "webp"}


@dataclass
class Extraction:
    text: str = ""
    file_type: str = "unknown"
    encrypted: bool = False
    truncated: bool = False
    ocr_used: bool = False
    type_mismatch: bool = False
    members: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def inspected(self) -> bool:
        return bool(self.text.strip()) and not self.encrypted


# --------------------------------------------------------------------------- type sniffing
_EXT_FAMILY = {
    ".pdf": "pdf", ".docx": "docx", ".docm": "docx", ".xlsx": "xlsx", ".xlsm": "xlsx",
    ".pptx": "pptx", ".pptm": "pptx", ".odt": "odt", ".ods": "ods", ".odp": "odp",
    ".zip": "zip", ".jar": "zip", ".gz": "gzip", ".tgz": "gzip", ".tar": "tar",
    ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".bmp": "bmp",
    ".tif": "tiff", ".tiff": "tiff", ".webp": "webp", ".rtf": "rtf", ".eml": "eml",
    ".doc": "ole", ".xls": "ole", ".ppt": "ole", ".msg": "ole",
    **{e: "text" for e in (".txt", ".csv", ".tsv", ".json", ".xml", ".log", ".md", ".yaml", ".yml",
                           ".ini", ".cfg", ".conf", ".env", ".sql", ".html", ".htm")},
}


def sniff_type(head: bytes, name: str = "") -> str:
    if head.startswith(b"%PDF-") or b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"  # refined to docx/xlsx/pptx/odt/... after opening
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head.startswith(b"BM") and len(head) > 14:
        return "bmp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if head.lstrip().startswith(b"{\\rtf"):
        return "rtf"
    if _looks_like_email(head):
        return "eml"
    if _looks_like_text(head):
        return "text"
    return "binary"


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return True
    if head.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in head:
        # UTF-16 without BOM: every other byte is NUL
        return head[1::2].count(0) > len(head) * 0.4 or head[0::2].count(0) > len(head) * 0.4
    ctrl = sum(b < 9 or 13 < b < 32 for b in head)
    return ctrl / len(head) < 0.05


def _looks_like_email(head: bytes) -> bool:
    top = head[:2048].lower()
    hits = sum(h in top for h in (b"\nfrom:", b"\nto:", b"\nsubject:", b"\nmime-version:", b"\nreceived:", b"\ndate:"))
    return (top.startswith((b"from:", b"received:", b"return-path:", b"mime-version:", b"delivered-to:", b"date:")) and hits >= 1) or hits >= 3


# --------------------------------------------------------------------------- entry point
def extract(path: Optional[str] = None, data: Optional[bytes] = None, name: str = "",
            ocr: bool = True, _depth: int = 0) -> Extraction:
    if data is None:
        p = Path(path)
        name = name or p.name
        with open(p, "rb") as f:
            data = f.read(MAX_INPUT_BYTES + 1)
    out = Extraction()
    if len(data) > MAX_INPUT_BYTES:
        data = data[:MAX_INPUT_BYTES]
        out.truncated = True

    kind = sniff_type(data[:4096], name)
    ext = Path(name).suffix.lower()
    try:
        if kind == "zip":
            kind = _extract_zip_family(data, name, out, ocr, _depth)
        elif kind == "pdf":
            _extract_pdf(data, out, ocr)
        elif kind == "ole":
            _extract_ole(data, out)
        elif kind in IMAGE_TYPES:
            if ocr:
                out.text = ocr_image_bytes(data)
                out.ocr_used = True
        elif kind == "gzip":
            _extract_gzip(data, name, out, ocr, _depth)
        elif kind == "tar":
            _extract_tar(data, out, ocr, _depth)
        elif kind == "rtf":
            out.text = rtf_to_text(decode_text(data))
        elif kind == "eml":
            _extract_email(data, out, ocr, _depth)
        elif kind == "text":
            out.text = decode_text(data)
        else:
            out.text = binary_strings(data)
    except Exception as e:  # never let one bad file kill the scan
        out.errors.append(f"{kind}: {type(e).__name__}: {e}")

    out.file_type = kind
    expected = _EXT_FAMILY.get(ext)
    if expected and expected != kind and not (expected == "zip" and kind in ("docx", "xlsx", "pptx", "odt", "ods", "odp")):
        out.type_mismatch = True
    if len(out.text) > MAX_TEXT_CHARS:
        out.text = out.text[:MAX_TEXT_CHARS]
        out.truncated = True
    return out


# --------------------------------------------------------------------------- text helpers
def decode_text(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:4096]:
        head = data[:4096]
        enc = "utf-16-le" if head[1::2].count(0) > head[0::2].count(0) else "utf-16-be"
        return data.decode(enc, errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{6,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def binary_strings(data: bytes, limit: int = 5 * 1024 * 1024) -> str:
    """`strings`-style extraction for unknown binaries (ASCII + UTF-16LE runs)."""
    chunk = data[:limit]
    parts = [m.group(0).decode("ascii", "replace") for m in _ASCII_RUN.finditer(chunk)]
    parts += [m.group(0).decode("utf-16-le", "replace") for m in _UTF16_RUN.finditer(chunk)]
    return "\n".join(parts)


_TAG = re.compile(r"<[^>]+>")


def xml_to_text(xml: str, para_tags=("w:p", "a:p", "text:p", "text:h", "row"), cell_tags=("w:tab", "c", "table:table-cell")) -> str:
    for t in para_tags:
        xml = xml.replace(f"</{t}>", "\n")
    for t in cell_tags:
        xml = xml.replace(f"</{t}>", "\t").replace(f"<{t}/>", "\t")
    xml = xml.replace("<w:br/>", "\n").replace("<a:br/>", "\n").replace("<text:line-break/>", "\n")
    return html.unescape(_TAG.sub("", xml))


def html_to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", markup)
    markup = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>", "\n", markup)
    return html.unescape(_TAG.sub(" ", markup))


def rtf_to_text(rtf: str) -> str:
    rtf = re.sub(r"\\'([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]).decode("cp1252", "replace"), rtf)
    rtf = re.sub(r"\\u(-?\d+)\??", lambda m: chr(int(m.group(1)) % 65536), rtf)
    rtf = re.sub(r"\\(?:par|line)\b ?", "\n", rtf)
    rtf = re.sub(r"\\tab\b ?", "\t", rtf)
    rtf = re.sub(r"\{\\\*[^{}]*\}", "", rtf)
    rtf = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", rtf)
    return rtf.replace("{", "").replace("}", "").replace("\\\\", "\\")


# --------------------------------------------------------------------------- zip family
def _extract_zip_family(data: bytes, name: str, out: Extraction, ocr: bool, depth: int) -> str:
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = zf.namelist()
    if any(i.flag_bits & 0x1 for i in zf.infolist()):
        out.encrypted = True
    if "word/document.xml" in names:
        out.text = _ooxml_parts(zf, names, r"word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$")
        _ooxml_embedded(zf, names, "word/embeddings/", out, ocr, depth)
        return "docx"
    if "xl/workbook.xml" in names:
        out.text = _xlsx_text(zf, names)
        _ooxml_embedded(zf, names, "xl/embeddings/", out, ocr, depth)
        return "xlsx"
    if "ppt/presentation.xml" in names:
        out.text = _ooxml_parts(zf, names, r"ppt/(slides/slide\d+|notesSlides/notesSlide\d+|comments/comment\d+)\.xml$")
        _ooxml_embedded(zf, names, "ppt/embeddings/", out, ocr, depth)
        return "pptx"
    if "mimetype" in names:
        mt = zf.read("mimetype")[:100].decode("ascii", "ignore")
        if "opendocument" in mt and "content.xml" in names:
            out.text = xml_to_text(zf.read("content.xml").decode("utf-8", "replace"))
            return {"text": "odt", "spreadsheet": "ods", "presentation": "odp"}.get(mt.rsplit(".", 1)[-1], "odt")
    _expand_archive_members(
        ((i.filename, i.file_size, i.compress_size, lambda i=i: zf.read(i)) for i in zf.infolist()
         if not i.is_dir() and not i.flag_bits & 0x1),
        out, ocr, depth)
    return "zip"


def _ooxml_parts(zf: zipfile.ZipFile, names: List[str], pattern: str) -> str:
    rx = re.compile(pattern)
    return "\n".join(xml_to_text(zf.read(n).decode("utf-8", "replace")) for n in sorted(names) if rx.match(n))


def _ooxml_embedded(zf, names, prefix, out, ocr, depth):
    members = [i for i in zf.infolist() if i.filename.startswith(prefix) or i.filename.startswith(prefix.split("/")[0] + "/media/")]
    if members:
        _expand_archive_members(((i.filename, i.file_size, i.compress_size, lambda i=i: zf.read(i)) for i in members),
                                out, ocr and len(members) <= 20, depth)


_CELL = re.compile(r'<c\b([^>]*?)(?:/>|>(.*?)</c>)', re.S)
_V = re.compile(r"<v>(.*?)</v>", re.S)
_T_ATTR = re.compile(r'\bt="(\w+)"')


def _xlsx_text(zf: zipfile.ZipFile, names: List[str]) -> str:
    shared: List[str] = []
    if "xl/sharedStrings.xml" in names:
        sst = zf.read("xl/sharedStrings.xml").decode("utf-8", "replace")
        shared = [html.unescape(_TAG.sub("", si)) for si in re.findall(r"<si>(.*?)</si>", sst, re.S)]
    rows_out: List[str] = []
    for n in sorted(x for x in names if re.match(r"xl/worksheets/sheet\d+\.xml$", x)):
        xml = zf.read(n).decode("utf-8", "replace")
        for row in re.findall(r"<row\b[^>]*>(.*?)</row>", xml, re.S):
            cells = []
            for attrs, inner in _CELL.findall(row):
                inner = inner or ""
                t = _T_ATTR.search(attrs)
                t = t.group(1) if t else "n"
                if t == "inlineStr":
                    cells.append(html.unescape(_TAG.sub("", inner)))
                    continue
                v = _V.search(inner)
                if not v:
                    continue
                val = html.unescape(v.group(1))
                if t == "s":
                    idx = int(val) if val.isdigit() else -1
                    cells.append(shared[idx] if 0 <= idx < len(shared) else "")
                elif t == "n":
                    cells.append(_excel_number(val))
                else:
                    cells.append(val)
            if cells:
                rows_out.append("\t".join(cells))
    if not rows_out and shared:
        return "\n".join(shared)
    return "\n".join(rows_out)


def _excel_number(val: str) -> str:
    """Excel stores 4111111111111111 as 4.111111111111111E+15; render integers in full."""
    try:
        d = Decimal(val)
    except InvalidOperation:
        return val
    if d == d.to_integral_value() and abs(d) < Decimal("1e20"):
        return str(int(d))
    return val


# --------------------------------------------------------------------------- archives
def _expand_archive_members(members, out: Extraction, ocr: bool, depth: int) -> None:
    if depth >= MAX_ARCHIVE_DEPTH:
        out.errors.append("archive depth limit reached")
        return
    total = 0
    texts = [out.text] if out.text else []
    for count, (mname, size, csize, read) in enumerate(members):
        if count >= MAX_ARCHIVE_MEMBERS:
            out.errors.append("archive member limit reached")
            out.truncated = True
            break
        if csize and size / max(csize, 1) > MAX_COMPRESSION_RATIO and size > 1024 * 1024:
            out.errors.append(f"{mname}: compression ratio too high (possible zip bomb)")
            out.truncated = True
            continue
        total += size
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            out.errors.append("archive size limit reached")
            out.truncated = True
            break
        sub = extract(data=read(), name=mname, ocr=ocr, _depth=depth + 1)
        out.members.append(mname)
        out.members.extend(f"{mname}/{m}" for m in sub.members)
        out.encrypted |= sub.encrypted
        out.ocr_used |= sub.ocr_used
        out.truncated |= sub.truncated
        out.errors.extend(f"{mname}: {e}" for e in sub.errors)
        if sub.text.strip():
            texts.append(f"\n----- {mname} -----\n{sub.text}")
    out.text = "\n".join(texts)


def _extract_gzip(data: bytes, name: str, out: Extraction, ocr: bool, depth: int) -> None:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
        raw = g.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        out.truncated = True
        raw = raw[:MAX_INPUT_BYTES]
    inner_name = name[:-3] if name.lower().endswith(".gz") else (name[:-4] + ".tar" if name.lower().endswith(".tgz") else name)
    _expand_archive_members([(inner_name, len(raw), len(data), lambda: raw)], out, ocr, depth)


def _extract_tar(data: bytes, out: Extraction, ocr: bool, depth: int) -> None:
    tf = tarfile.open(fileobj=io.BytesIO(data))
    members = [m for m in tf.getmembers() if m.isfile()]
    _expand_archive_members(((m.name, m.size, m.size, lambda m=m: tf.extractfile(m).read()) for m in members),
                            out, ocr, depth)


# --------------------------------------------------------------------------- email
def _extract_email(data: bytes, out: Extraction, ocr: bool, depth: int) -> None:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    texts = [f"{h}: {msg.get(h, '')}" for h in ("From", "To", "Cc", "Subject") if msg.get(h)]
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        ctype = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            attachments.append((filename or "attachment.bin", len(payload), len(payload), lambda p=payload: p))
        elif ctype == "text/plain":
            texts.append(decode_text(payload))
        elif ctype == "text/html":
            texts.append(html_to_text(decode_text(payload)))
    out.text = "\n".join(texts)
    if attachments:
        _expand_archive_members(attachments, out, ocr, depth)


# --------------------------------------------------------------------------- OLE (legacy Office)
def _extract_ole(data: bytes, out: Extraction) -> None:
    # Encrypted OOXML files are OLE containers holding EncryptionInfo/EncryptedPackage streams.
    if "EncryptionInfo".encode("utf-16-le") in data[:1_000_000] or "EncryptedPackage".encode("utf-16-le") in data[:1_000_000]:
        out.encrypted = True
        return
    out.text = binary_strings(data)


# --------------------------------------------------------------------------- PDF
def _extract_pdf(data: bytes, out: Extraction, ocr: bool) -> None:
    try:
        import pypdfium2 as pdfium
    except ImportError:
        _extract_pdf_pypdf(data, out)
        return
    try:
        doc = pdfium.PdfDocument(data)
    except pdfium.PdfiumError as e:
        if "password" in str(e).lower() or b"/Encrypt" in data[-4096:] or b"/Encrypt" in data[:4096]:
            out.encrypted = True
            return
        raise
    parts: List[str] = []
    to_ocr = []  # (page index, rendered image)
    try:
        n = len(doc)
        if n > MAX_PDF_PAGES:
            out.truncated = True
        for i in range(min(n, MAX_PDF_PAGES)):
            page = doc[i]
            textpage = page.get_textpage()
            text = textpage.get_text_bounded() or ""
            textpage.close()
            if ocr and len(text.strip()) < 20:
                if len(to_ocr) < MAX_OCR_PAGES:
                    # Scanned page (no text layer): render at ~200 dpi for OCR.
                    to_ocr.append((i, page.render(scale=200 / 72).to_pil()))
                else:
                    out.truncated = True
            page.close()
            parts.append(text)
    finally:
        doc.close()
    if to_ocr:
        out.ocr_used = True
        with ThreadPoolExecutor(max_workers=OCR_WORKERS) as pool:
            for (i, _), text in zip(to_ocr, pool.map(lambda item: ocr_image(item[1]), to_ocr)):
                parts[i] = (parts[i] + "\n" + text).strip()
    out.text = "\n".join(parts)


def _extract_pdf_pypdf(data: bytes, out: Extraction) -> None:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        try:
            if not reader.decrypt(""):
                out.encrypted = True
                return
        except Exception:
            out.encrypted = True
            return
    out.text = "\n".join((p.extract_text() or "") for p in reader.pages[:MAX_PDF_PAGES])


# --------------------------------------------------------------------------- OCR
def ocr_available() -> bool:
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def ocr_image_bytes(data: bytes) -> str:
    try:
        from PIL import Image
    except ImportError:
        return ""
    with Image.open(io.BytesIO(data)) as img:
        img.load()
        return ocr_image(img)


def ocr_image(img) -> str:
    """Single Tesseract pass on a normalized grayscale image; one retry only if it found nothing."""
    try:
        import pytesseract
        from PIL import ImageOps
    except ImportError:
        return ""
    gray = ImageOps.exif_transpose(img).convert("L")
    w, h = gray.size
    longest = max(w, h)
    if longest < 1200:
        f = 1200 / max(longest, 1)
        gray = gray.resize((max(1, int(w * f)), max(1, int(h * f))))
    elif longest > 4000:
        f = 4000 / longest
        gray = gray.resize((int(w * f), int(h * f)))
    try:
        text = pytesseract.image_to_string(gray, config="--oem 1 --psm 3", timeout=OCR_TIMEOUT_SECONDS)
        if len(text.strip()) < 16:
            bw = ImageOps.autocontrast(gray).point(lambda x: 255 if x > 150 else 0)
            text2 = pytesseract.image_to_string(bw, config="--oem 1 --psm 11", timeout=OCR_TIMEOUT_SECONDS)
            if len(text2.strip()) > len(text.strip()):
                text = text2
    except Exception:
        return ""
    return text
