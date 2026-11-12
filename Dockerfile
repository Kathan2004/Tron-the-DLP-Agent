# Tron DLP API
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5001

WORKDIR /app

# tesseract: OCR of images and scanned PDFs (PDF pages are rendered by pypdfium2).
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

# Application code only (see .dockerignore: no secrets, data, console or docs).
COPY config/ config/
COPY src/ src/
COPY main.py wsgi.py gunicorn.conf.py ./

RUN useradd --create-home --uid 10001 tron \
    && mkdir -p /app/data \
    && chown -R tron:tron /app/data
USER tron
VOLUME ["/app/data"]

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5001/api/health', timeout=4).status == 200 else 1)"]

CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
