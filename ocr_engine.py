"""
SIH Secure DMS - self-hosted OCR engine.

Uses PaddleOCR PP-OCRv5 locally. PP-OCRv5 supports printed text and
challenging handwriting scenarios. No OCR SaaS/API is used.

Models are downloaded to PADDLE_PDX_CACHE_HOME on first build/startup.
For deployment, run warmup_ocr.py during the Render build so the model
is present in the deployed environment.
"""
from __future__ import annotations

import io
import os
import threading
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageOps, ImageFilter

# Set this BEFORE importing paddleocr/paddlex.
os.environ.setdefault(
    "PADDLE_PDX_CACHE_HOME",
    str(Path(__file__).resolve().parent / ".paddlex")
)

_OCR = None
_LOCK = threading.Lock()


def _engine():
    global _OCR
    if _OCR is not None:
        return _OCR

    with _LOCK:
        if _OCR is not None:
            return _OCR

        try:
            from paddleocr import PaddleOCR
        except Exception as exc:
            raise RuntimeError(
                "Self-hosted OCR dependencies are missing. "
                "Install paddlepaddle and paddleocr."
            ) from exc

        # PP-OCRv5 is explicitly designed for multi-scenario recognition,
        # including difficult handwriting, while retaining general OCR.
        _OCR = PaddleOCR(
            ocr_version=os.getenv("OCR_VERSION", "PP-OCRv5"),
            lang=os.getenv("OCR_LANG", "en"),
            use_doc_orientation_classify=False,
            use_doc_unwarping=False,
            use_textline_orientation=False,
            device=os.getenv("OCR_DEVICE", "cpu"),
            enable_mkldnn=True,
            cpu_threads=int(os.getenv("OCR_CPU_THREADS", "4")),
        )
        return _OCR


def _image(data: bytes) -> np.ndarray:
    im = Image.open(io.BytesIO(data)).convert("RGB")
    # Non-destructive preprocessing. The source file remains immutable.
    im = ImageOps.exif_transpose(im)
    im = ImageOps.autocontrast(im)
    im = im.filter(ImageFilter.SHARPEN)
    return np.asarray(im)


def _result_to_dict(result: Any) -> dict:
    """
    PaddleOCR 3.x Result objects expose a JSON-like mapping. This parser
    tolerates both the current mapping representation and object wrappers.
    """
    if isinstance(result, dict):
        return result

    for attr in ("json", "to_json"):
        try:
            value = getattr(result, attr)
            value = value() if callable(value) else value
            if isinstance(value, str):
                return __import__("json").loads(value)
            if isinstance(value, dict):
                return value
        except Exception:
            pass

    try:
        return dict(result)
    except Exception:
        return {}


def _extract_lines(results: Any) -> tuple[list[dict], float | None]:
    lines: list[dict] = []
    scores: list[float] = []

    for result in results:
        obj = _result_to_dict(result)

        # PaddleOCR 3.x normally exposes these arrays in res:
        # rec_texts, rec_scores, rec_boxes / rec_polys.
        texts = obj.get("rec_texts") or []
        rec_scores = obj.get("rec_scores") or []
        boxes = obj.get("rec_boxes") or obj.get("rec_polys") or []

        if texts:
            for i, text in enumerate(texts):
                text = str(text).strip()
                if not text:
                    continue

                score = None
                if i < len(rec_scores):
                    try:
                        score = float(rec_scores[i])
                        scores.append(score)
                    except Exception:
                        score = None

                box = boxes[i].tolist() if i < len(boxes) and hasattr(boxes[i], "tolist") else (
                    boxes[i] if i < len(boxes) else None
                )

                lines.append({
                    "text": text,
                    "confidence": round(score, 4) if score is not None else None,
                    "box": box,
                })

    # If a future PaddleOCR release wraps the result differently, preserve
    # raw output instead of silently claiming that no text was found.
    return lines, (sum(scores) / len(scores) if scores else None)


def _predict_image(image: np.ndarray) -> dict:
    ocr = _engine()
    results = ocr.predict(image)
    lines, confidence = _extract_lines(results)

    # PaddleOCR detects text regions, so this works for ordinary printed
    # pages as well as handwriting supported by PP-OCRv5.
    text = "\n".join(x["text"] for x in lines).strip()

    return {
        "text": text,
        "lines": lines,
        "confidence": round(confidence, 4) if confidence is not None else None,
        "engine": "PaddleOCR PP-OCRv5 (self-hosted)",
        "handwriting_supported": True,
    }


def image_bytes_to_ocr(data: bytes) -> dict:
    return _predict_image(_image(data))


def pdf_bytes_to_ocr(data: bytes) -> dict:
    try:
        import fitz  # PyMuPDF
    except Exception as exc:
        raise RuntimeError("PyMuPDF is required for PDF OCR.") from exc

    doc = fitz.open(stream=data, filetype="pdf")
    pages = []
    all_lines = []
    confidences = []

    for page_no, page in enumerate(doc, start=1):
        # Digital PDFs already contain searchable text. Avoid running the
        # expensive OCR model on those pages.
        native = page.get_text("text").strip()
        if native:
            pages.append(f"--- Page {page_no} ---\n{native}")
            continue

        # Only scanned/image pages reach PaddleOCR. 1.5x is a good CPU
        # compromise; the original PDF bytes are never modified.
        pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), alpha=False)
        result = _predict_image(_image(pix.tobytes("png")))
        page_text = result["text"]

        if page_text:
            pages.append(f"--- Page {page_no} ---\n{page_text}")

        for line in result["lines"]:
            line = dict(line)
            line["page"] = page_no
            all_lines.append(line)

        if result["confidence"] is not None:
            confidences.append(result["confidence"])

    doc.close()

    return {
        "text": "\n\n".join(pages).strip(),
        "lines": all_lines,
        "confidence": round(sum(confidences) / len(confidences), 4)
        if confidences else None,
        "pages": len(pages),
        "engine": "PaddleOCR PP-OCRv5 (self-hosted)",
        "handwriting_supported": True,
    }


def run_ocr(data: bytes, filename: str) -> dict:
    ext = Path(filename or "").suffix.lower()

    if ext == ".txt":
        text = data.decode("utf-8", errors="replace").strip()
        return {
            "text": text, "lines": [], "confidence": 1.0,
            "engine": "Native UTF-8 text extraction",
            "handwriting_supported": False,
        }

    if ext == ".docx":
        try:
            from docx import Document
            import io as _io
            doc = Document(_io.BytesIO(data))
            text = "\n".join(p.text for p in doc.paragraphs if p.text.strip()).strip()
            return {
                "text": text, "lines": [], "confidence": 1.0 if text else None,
                "engine": "Native DOCX text extraction",
                "handwriting_supported": False,
            }
        except Exception as exc:
            raise RuntimeError(f"DOCX text extraction failed: {exc}") from exc

    if ext == ".pptx":
        try:
            from pptx import Presentation
            import io as _io
            prs = Presentation(_io.BytesIO(data))
            chunks = []
            for slide_no, slide in enumerate(prs.slides, start=1):
                texts = []
                for shape in slide.shapes:
                    if hasattr(shape, "text") and shape.text.strip():
                        texts.append(shape.text.strip())
                if texts:
                    chunks.append(f"--- Slide {slide_no} ---\n" + "\n".join(texts))
            text = "\n\n".join(chunks).strip()
            return {
                "text": text, "lines": [], "confidence": 1.0 if text else None,
                "engine": "Native PPTX text extraction",
                "handwriting_supported": False,
            }
        except Exception as exc:
            raise RuntimeError(f"PPTX text extraction failed: {exc}") from exc

    if ext == ".pdf":
        return pdf_bytes_to_ocr(data)

    if ext in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}:
        return image_bytes_to_ocr(data)

    raise ValueError(
        "Text extraction supports PDF, PNG, JPG, JPEG, WEBP, BMP, TIF, TIFF, TXT, DOCX and PPTX files."
    )


def warmup() -> str:
    """Download/load the model during deployment build."""
    _engine()
    return "PaddleOCR PP-OCRv5 model is ready."
