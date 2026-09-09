"""
Run during deployment build to download/cache the self-hosted OCR model.

Render Build Command example:
    pip install -r requirements_sih_ocr_option3.txt
    python warmup_ocr.py

The model cache is kept under .paddlex in the application directory so
the build artifact contains the downloaded model cache.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.environ.setdefault("PADDLE_PDX_CACHE_HOME", str(ROOT / ".paddlex"))
os.environ.setdefault("OCR_VERSION", "PP-OCRv5")
os.environ.setdefault("OCR_LANG", "en")
os.environ.setdefault("OCR_DEVICE", "cpu")
os.environ.setdefault("OCR_CPU_THREADS", "4")

from ocr_engine import warmup

print(warmup())
print("OCR cache:", os.environ["PADDLE_PDX_CACHE_HOME"])
