# SIH Secure DMS — Self-hosted OCR (Option 3)

This package replaces the old Tesseract-based OCR with PaddleOCR PP-OCRv5.
PP-OCRv5 is self-hosted: uploaded documents are processed by the FastAPI
server rather than sent to an OCR SaaS API. PaddleOCR documents PP-OCRv5 as
supporting challenging handwriting as well as general OCR.

## Files
- invite_backend.py — SIH backend with the self-hosted OCR endpoints.
- ocr_engine.py — PaddleOCR wrapper for images and PDF pages.
- warmup_ocr.py — downloads/warms the model during deployment build.
- requirements_sih_ocr_option3.txt — dependencies.
- RENDER_OCR_SETUP.txt — Render commands and environment variables.

## Local
```bash
pip install -r requirements_sih_ocr_option3.txt
python warmup_ocr.py
python -m uvicorn invite_backend:app --reload --port 8000
```

The first warmup downloads the OCR model into `.paddlex`.

## Render
Build command:
```bash
pip install -r requirements_sih_ocr_option3.txt && python warmup_ocr.py
```

Start command:
```bash
uvicorn invite_backend:app --host 0.0.0.0 --port $PORT
```

Use one worker because each worker loads an OCR model into memory.

Environment:
```text
OCR_VERSION=PP-OCRv5
OCR_LANG=en
OCR_DEVICE=cpu
OCR_CPU_THREADS=4
```

## Endpoints
- GET `/ocr/health`
- POST `/ocr/extract`
- POST `/documents/ocr/{version_id}`

All OCR routes retain the existing elevated Files/OTP requirement.
The original document bytes are never changed by OCR.

## Important
OCR output is a derived result. Do not treat OCR text as a replacement for
the original FIR/evidence/document. Keep the original immutable file,
hash, signature and version history.
