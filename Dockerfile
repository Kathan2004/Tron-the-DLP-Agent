FROM python:3.11-slim

WORKDIR /app

# System dependencies: gcc for wheels, curl for the healthcheck,
# tesseract + poppler for OCR of images and scanned PDFs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    tesseract-ocr \
    poppler-utils \
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
