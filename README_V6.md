# SIH Secure DMS V6 — upload, preview and AI fixes

## Fixed
- Upload tab now opens the upload form immediately; email OTP is requested only when the actual Upload & Sign action is performed.
- Restored missing upload functions in case-detail.html.
- Removed the broken/obsolete viewerFrame reference.
- Original PDF/image preview now uses a controlled PDF.js/canvas viewer and a protected backend preview endpoint; no native browser PDF download/print toolbar is exposed.
- PDF.js worker is configured explicitly.
- Gemini fallback updated to stable `gemini-3.8-flash`.
- Ollama default updated to current cloud `gemma4:cloud`.
- Gemini request no longer sends deprecated temperature configuration.
- Existing FIR file_type constraint is migrated to allow `pdf`.
- Existing enabled cases are updated to the current Ollama model.
- Case AI continues to reuse saved extraction per immutable version.

## Render environment
Set/update:
`FRONTEND_URL=https://allaince.netlify.app`
`BASE_URL=https://alliance-cqnf.onrender.com`
`OLLAMA_MODEL=gemma4:cloud`
`GEMINI_MODEL=gemini-3.8-flash`
`AI_CHAT_TIMEOUT=45`

Run the included SQL migration before testing.
