# SIH Case AI Tracking Fix

This package fixes the Case AI experience:

- Case AI shows a persistent ENABLED / DISABLED state.
- Enabling/disabling refreshes the UI immediately after OTP verification.
- AI extraction runs once per immutable document version; opening Case AI or a document does not re-run extraction.
- Each AI job records queue/start/completion timestamps, processing stage, progress percentage and an estimated duration.
- Files page polls processing status every 2 seconds.
- Document viewer shows live AI progress and elapsed time while extraction is running.
- Ollama failure is visible before Gemini fallback begins.
- Failed jobs show the actual error instead of staying on "still processing" forever.
- PDF original preview uses a controlled canvas viewer without the browser PDF download/print toolbar.
- Integrity remains automatic; no manual verification button is exposed.

## Supabase
Run `SIH_Case_AI_Ollama_Gemini_Migration.sql` in the Supabase SQL editor. It is safe to re-run and adds the AI telemetry columns with `IF NOT EXISTS`.

## Render
Deploy `invite_backend.py`, `ai_engine.py`, requirements, render.yaml and .python-version as usual.

Required AI environment variables remain:
- OLLAMA_API_KEY
- OLLAMA_URL=https://ollama.com
- OLLAMA_MODEL=gemma3:12b
- GEMINI_API_KEY
- GEMINI_MODEL=gemini-2.5-flash
- AI_REQUEST_TIMEOUT=90
- AI_PDF_DPI=120
- AI_CHUNK_SIZE=3500
- AI_TOP_K=10

## Frontend
Replace the deployed `case-detail.html` with the included version. It keeps the Files, Upload, Members, external participant and Case AI tabs.
