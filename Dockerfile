FROM python:3.11-slim

WORKDIR /app

# System dependencies: curl for the healthcheck, tesseract for OCR of images and
# scanned PDFs (PDF pages are rendered by pypdfium2, so poppler is not needed).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (secrets and runtime data are excluded via .dockerignore)
COPY . .

RUN mkdir -p config data

EXPOSE 5001

ENV FLASK_APP=main.py
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
