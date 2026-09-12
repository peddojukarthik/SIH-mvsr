# SIH Secure DMS V7

V7 keeps the working Case AI (Ollama Cloud primary + Gemini fallback) and external participant portal, and fixes three reliability/UI issues:

- FIR creation now uses a client idempotency key. If the browser loses the POST response after the backend created the FIR, the frontend automatically checks `/case/create/recover` and opens the already-created case instead of reporting a false failure or creating a duplicate.
- `case-detail.html` no longer references the missing `#title` element, so Upload Photos / Files opens correctly.
- Case AI retry checks the authoritative AI status if the retry response is lost, avoiding a false `Failed to fetch` message when the job was already queued.
- Migration adds `cases.client_request_id` and a unique index. It also fixes the `documents.file_type` migration order so existing FIR rows are updated only after the old check constraint is replaced.
- Render config now includes `AI_CHAT_TIMEOUT=45`.

## Deploy
1. Replace the backend/frontend files with this package.
2. Run `SIH_Case_AI_Ollama_Gemini_Migration.sql` once in Supabase.
3. Deploy the backend to Render and the HTML files to Netlify.
4. Keep production AI settings:
   - `OLLAMA_MODEL=gemma4:cloud`
   - `GEMINI_MODEL=gemini-3.8-flash`
   - `AI_CHAT_TIMEOUT=45`
5. Hard-refresh the Netlify site (Ctrl+Shift+R).
