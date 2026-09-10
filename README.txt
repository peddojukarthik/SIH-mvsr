SIH Secure DMS - Automatic OCR + Automatic Integrity Upgrade

WHAT CHANGED
1. OCR starts automatically after every internal upload and FIR creation.
2. OCR runs as a FastAPI background task, so the upload request does not wait 165+ seconds.
3. OCR output is stored in document_ocr as a derived OCR Version 1 artifact.
4. The original document_versions Version 1 remains immutable and unchanged.
5. Files page automatically verifies the current document bytes, signature and version chain.
6. Users no longer need a Verify Integrity button.
7. If integrity is INVALID/WARNING/UNKNOWN, the UI shows a security warning and blocks original-file viewing.
8. Original-file viewing is server-side and returns the bytes only after integrity verification.
9. Frontend API URL is dynamic: localhost uses 127.0.0.1:8000; Netlify uses the Render backend.
10. File name, storage UUID, raw file type and SHA-256 are no longer shown in the Files UI.
11. OCR text and confidence are shown automatically when processing completes.

DATABASE
Run SIH_Auto_OCR_Integrity_Migration.sql once in Supabase SQL Editor.
It creates public.document_ocr.

DEPLOY
Replace the matching files in the GitHub repository, commit, push, and let Render/Netlify redeploy.
Render must use Python 3.12.9, not Python 3.14.x.

IMPORTANT
The background task is intentionally used to avoid gateway timeout. OCR may take time, especially for large handwritten PDFs. The UI displays PROCESSING and polls for completion.
