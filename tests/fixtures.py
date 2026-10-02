"""Builders for synthetic test documents (no binary fixtures committed)."""

import io
import zipfile
from email.message import EmailMessage

SECRET_LINE = "Employee SSN 536-22-1234 card 4111 1111 1111 1111"


def _pdf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def text_pdf(lines, pages: int = 1) -> bytes:
    """Minimal valid PDF with a real text layer (Helvetica), one or more pages."""
    objs = []
    page_ids = []
    font_id = 3
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(None)  # pages placeholder
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for _ in range(pages):
        stream = "BT /F1 12 Tf 72 720 Td 14 TL " + " ".join(f"({_pdf_escape(l)}) '" for l in lines) + " ET"
        content = f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream".encode()
        objs.append(content)
        content_id = len(objs)
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {content_id} 0 R "
                    f"/Resources << /Font << /F1 {font_id} 0 R >> >> >>".encode())
        page_ids.append(len(objs))
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(f'{i} 0 R' for i in page_ids)}] /Count {len(page_ids)} >>".encode()
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + o + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def text_image(lines, size=(1400, 300), fmt="PNG") -> bytes:
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 40)
    except OSError:
        try:
            font = ImageFont.load_default(size=40)
        except TypeError:
            font = ImageFont.load_default()
    y = 30
    for line in lines:
        draw.text((30, y), line, fill="black", font=font)
        y += 60
    buf = io.BytesIO()
    img.save(buf, fmt)
    return buf.getvalue()


def scanned_pdf(lines) -> bytes:
    """Image-only PDF (no text layer), like a scanned page."""
    from PIL import Image
    img = Image.open(io.BytesIO(text_image(lines, size=(1700, 400))))
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "PDF", resolution=200)
    return buf.getvalue()


def encrypted_pdf(lines) -> bytes:
    from pypdf import PdfReader, PdfWriter
    w = PdfWriter()
    for p in PdfReader(io.BytesIO(text_pdf(lines))).pages:
        w.add_page(p)
    w.encrypt(user_password="s3cret", owner_password="owner")
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def docx(body_lines, header_line=None, comment_line=None) -> bytes:
    paras = "".join(f"<w:p><w:r><w:t>{l}</w:t></w:r></w:p>" for l in body_lines)
    files = {
        "[Content_Types].xml": "<Types/>",
        "word/document.xml": f"<w:document {W_NS}><w:body>{paras}</w:body></w:document>",
    }
    if header_line:
        files["word/header1.xml"] = f"<w:hdr {W_NS}><w:p><w:r><w:t>{header_line}</w:t></w:r></w:p></w:hdr>"
    if comment_line:
        files["word/comments.xml"] = f"<w:comments {W_NS}><w:comment><w:p><w:r><w:t>{comment_line}</w:t></w:r></w:p></w:comment></w:comments>"
    return _zip(files)


def xlsx(rows) -> bytes:
    """rows: list of lists; str -> shared string, int/float -> numeric cell (as Excel stores it)."""
    shared, sheet_rows = [], []
    for r, row in enumerate(rows, 1):
        cells = []
        for c, v in enumerate(row):
            ref = f"{chr(65 + c)}{r}"
            if isinstance(v, str):
                shared.append(v)
                cells.append(f'<c r="{ref}" t="s"><v>{len(shared) - 1}</v></c>')
            else:
                cells.append(f'<c r="{ref}"><v>{repr(float(v)).upper() if v > 1e15 else v}</v></c>')
        sheet_rows.append(f'<row r="{r}">{"".join(cells)}</row>')
    return _zip({
        "[Content_Types].xml": "<Types/>",
        "xl/workbook.xml": "<workbook/>",
        "xl/sharedStrings.xml": "<sst>" + "".join(f"<si><t>{s}</t></si>" for s in shared) + "</sst>",
        "xl/worksheets/sheet1.xml": f"<worksheet><sheetData>{''.join(sheet_rows)}</sheetData></worksheet>",
    })


def pptx(slide_lines, notes_line=None) -> bytes:
    files = {
        "[Content_Types].xml": "<Types/>",
        "ppt/presentation.xml": "<p:presentation/>",
        "ppt/slides/slide1.xml": "<p:sld>" + "".join(f"<a:p><a:r><a:t>{l}</a:t></a:r></a:p>" for l in slide_lines) + "</p:sld>",
    }
    if notes_line:
        files["ppt/notesSlides/notesSlide1.xml"] = f"<p:notes><a:p><a:r><a:t>{notes_line}</a:t></a:r></a:p></p:notes>"
    return _zip(files)


def zip_of(files: dict) -> bytes:
    return _zip(files)


def eml_with_attachment(body: str, attachment_name: str, attachment: bytes) -> bytes:
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.org"
    msg["Subject"] = "quarterly numbers"
    msg.set_content(body)
    msg.add_attachment(attachment, maintype="application", subtype="octet-stream", filename=attachment_name)
    return msg.as_bytes()
