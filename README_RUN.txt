
SIH CORRECTED v10

IMPORTANT:
Replace the old files with:
  invite_backend.py
  homepage.html
  case-detail.html
  file-fir.html
  activate.html

Run notifications_migration.sql in Supabase.

The new backend is unified: run ONLY invite_backend.py for these routes.
Do not run the old document_backend.py at the same time on port 8000.

1. Activate your Python environment.

2. Install:
   python -m pip install -r requirements.txt

3. Check .env contains:
   SUPABASE_URL=...
   SUPABASE_SERVICE_ROLE_KEY=...
   GMAIL_ADDRESS=...
   GMAIL_APP_PASSWORD=...
   DOCUMENT_BUCKET=documents
   BASE_URL=http://localhost:8000

4. Start:
   python -m uvicorn invite_backend:app --reload --port 8000

5. In another terminal, from the folder containing the HTML files:
   python -m http.server 5500

6. Open:
   http://localhost:5500/login.html

FIR:
Form -> official PDF -> SHA-256 -> ECDSA-P256 signature -> document row ->
document_versions row -> Storage path:
case_id/document_id/version_id/fir_FIR-....pdf

The bytes that are hashed are the actual PDF bytes stored in Storage.
Therefore Verify Integrity downloads that same object and recomputes SHA-256.

"[object Object]" was caused by the old frontend printing data.detail
without handling structured error responses. The new FIR page converts both
string and structured FastAPI errors to readable text.

CASE SEARCH:
Homepage search calls /case/search. It returns only:
case_id, fir_id, status, created_at.
It does NOT return file contents, storage_path, hashes, signatures or URLs.

FILES:
Case Details -> Files -> email OTP -> only that case's documents and only
document types allowed by the viewer's case_membership.

UPLOAD:
Case Details -> Upload -> email OTP -> server checks case membership,
permission and allowed_document_types -> hashes/signs -> stores.

MEMBERS:
Case Details -> Members -> email OTP -> view members. Granting also requires
the existing authenticator TOTP elevation.

APP INVITE:
Homepage -> Invite Employee -> employee search -> email OTP -> /invite.
The /invite endpoint additionally requires completed authenticator 2FA.
The employee receives an activation email, creates a password, then logs in.

KEYS:
A user signing key is generated/reused at login. Private material remains
encrypted locally through document_crypto.py; the public key is stored in
user_keys.

NOTIFICATIONS:
Run notifications_migration.sql first. The backend creates notifications
for case grants, FIR creation and uploads. The SQL trigger notifies a
requester when an access request changes from pending to granted/denied.

NOTE:
This is still a local prototype. BASE_URL=http://localhost:8000 means an
email activation link works only when the recipient can reach your local
machine. For deployment, BASE_URL must be your HTTPS application URL.


V11 fixes: explicit DOM references (fixes Loading and location/window conflicts), readable FastAPI validation errors, email OTP elevates session for 15 minutes so invitation/case member grant can proceed, and case-detail uses explicit DOM references.
