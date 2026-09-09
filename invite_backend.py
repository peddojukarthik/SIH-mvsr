"""
SIH Secure DMS - unified backend v10

Run:
    python -m uvicorn invite_backend:app --reload --port 8000

This version keeps the existing session/TOTP/key/document model, but fixes:
- FIR form -> official PDF FIR -> SHA-256 -> ECDSA-P256 signature -> Supabase Storage
- useful error messages instead of "[object Object]"
- case search returns metadata only; it never exposes files
- case files are filtered by case_id + document permissions
- email OTP for Files / Upload / Members
- TOTP step-up remains required for app/case invitations
- notifications for case invitations and access-request decisions
- no separate invite page is required
"""

import os, secrets, hashlib, smtplib, mimetypes, uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

import bcrypt
import pyotp
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from supabase import create_client
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from fir_pdf import generate_fir_pdf
from document_crypto import calculate_file_hash, generate_user_key_pair
from document_crypto import encrypt_private_key, sign_file_hash

from document_crypto import (
    calculate_file_hash,
    generate_user_key_pair,
    #save_private_key,
    sign_file_hash,
    verify_signature,
)

load_dotenv()

app = FastAPI(title="SIH Secure DMS")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

supabase = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SERVICE_ROLE_KEY"],
)

GMAIL_ADDRESS = os.environ["GMAIL_ADDRESS"]
GMAIL_APP_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]

# Email links must point to a real HTTP page.
# For local development this is the backend's activate-page.
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")

SESSION_LIFETIME_HOURS = 8
ELEVATION_LIFETIME_MINUTES = 15
EMAIL_OTP_MINUTES = 5
DOCUMENT_BUCKET = os.getenv("DOCUMENT_BUCKET", "documents")
MAX_FILE_SIZE = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".pdf", ".png", ".jpg", ".jpeg", ".doc", ".docx",
    ".ppt", ".pptx", ".txt"
}
ALLOWED_DOCUMENT_TYPES = {
    "fir", "evidence", "forensic_report", "postmortem_report",
    "witness_statement", "charge_sheet", "court_order", "judgment",
}

# Prototype-only short-lived OTP state.
# OTP itself is hashed and never returned to the browser.
EMAIL_OTP_STATE = {}


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat()


def error_text(exc):
    """Convert Supabase/Python exceptions into readable text."""
    parts = []
    for attr in ("message", "details", "hint", "code"):
        value = getattr(exc, attr, None)
        if value:
            parts.append(f"{attr}: {value}")
    if parts:
        return " | ".join(parts)
    return str(exc)


def parse_dt(value):
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def get_current_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Not logged in.")

    raw_token = authorization.removeprefix("Bearer ").strip()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    try:
        sr = (
            supabase.table("sessions")
            .select("session_id,user_id,expires_at,elevated_until")
            .eq("token_hash", token_hash)
            .limit(1).execute()
        )
    except Exception as exc:
        raise HTTPException(500, f"Session lookup failed: {error_text(exc)}")

    if not sr.data:
        raise HTTPException(401, "Invalid session. Please log in again.")

    session = sr.data[0]
    if now() > parse_dt(session["expires_at"]):
        raise HTTPException(401, "Session expired. Please log in again.")

    try:
        ur = (
            supabase.table("users")
            .select(
                "user_id,employee_id,account_status,totp_secret,"
                "employee_registry!fk_users_employee("
                "full_name,department_id,departments(type,name))"
            )
            .eq("user_id", session["user_id"])
            .limit(1).execute()
        )
    except Exception as exc:
        raise HTTPException(500, f"User lookup failed: {error_text(exc)}")

    if not ur.data:
        raise HTTPException(401, "User not found.")

    user = ur.data[0]
    registry = user.get("employee_registry") or {}
    dept = registry.get("departments") or {}

    try:
        admin = (
            supabase.table("department_admins")
            .select("can_invite_employees,can_delegate")
            .eq("user_id", user["user_id"])
            .eq("department_id", registry.get("department_id"))
            .limit(1).execute()
        )
    except Exception:
        admin = type("R", (), {"data": []})()

    elevated = bool(
        session.get("elevated_until")
        and now() < parse_dt(session["elevated_until"])
    )

    return {
        "user_id": user["user_id"],
        "session_id": session["session_id"],
        "employee_id": user["employee_id"],
        "account_status": user["account_status"],
        "full_name": registry.get("full_name", "User"),
        "department_id": registry.get("department_id"),
        "department_type": dept.get("type"),
        "department_name": dept.get("name"),
        "is_admin": bool(admin.data),
        "can_invite_employees": bool(
            admin.data and admin.data[0].get("can_invite_employees")
        ),
        "can_delegate": bool(admin.data and admin.data[0].get("can_delegate")),
        "has_2fa": bool(user.get("totp_secret")),
        "is_elevated": elevated,
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/me")
def me(authorization: str | None = Header(default=None)):
    return get_current_user(authorization)


def ensure_user_key(user_id, supabase):
    # Find the current active key
    result = (
        supabase.table("user_keys")
        .select("*")
        .eq("user_id", user_id)
        .eq("key_status", "active")
        .limit(1)
        .execute()
    )

    active_key = result.data[0] if result.data else None

    # Existing active key is usable
    if active_key and active_key.get("encrypted_private_key"):
        return active_key

    # Active key exists but private key is missing.
    # Rotate it instead of throwing an error.
    if active_key:
        supabase.table("user_keys").update({
            "key_status": "rotated"
        }).eq(
            "key_id", active_key["key_id"]
        ).execute()

    # Generate a completely new signing key
    private_key_pem, public_key_pem = generate_user_key_pair()

    encrypted_private_key = encrypt_private_key(
        private_key_pem
    )

    new_key = (
        supabase.table("user_keys")
        .insert({
            "user_id": user_id,
            "public_key": public_key_pem,
            "encrypted_private_key": encrypted_private_key,
            "algorithm": "RSA-PSS-SHA256",
            "key_status": "active",
            "kms_key_reference": f"supabase-encrypted-private:{user_id}"
        })
        .execute()
    )

    if not new_key.data:
        raise RuntimeError("Failed to create new signing key")

    return new_key.data[0]


@app.post("/login")
def login(req: dict):
    employee_id = str(req.get("employee_id", "")).strip()
    password = str(req.get("password", ""))
    if not employee_id or not password:
        raise HTTPException(400, "Employee ID and password are required.")

    try:
        result = (
            supabase.table("users")
            .select(
                "user_id,password_hash,account_status,totp_secret,"
                "employee_registry!fk_users_employee("
                "full_name,department_id,departments(type,name))"
            )
            .eq("employee_id", employee_id).limit(1).execute()
        )
    except Exception as exc:
        raise HTTPException(500, f"Login lookup failed: {error_text(exc)}")

    if not result.data:
        raise HTTPException(401, "Invalid employee ID or password.")

    user = result.data[0]
    stored = user.get("password_hash")
    if not stored or not bcrypt.checkpw(password.encode(), stored.encode()):
        raise HTTPException(401, "Invalid employee ID or password.")

    if user["account_status"] not in ("activated", "profile_pending", "active"):
        raise HTTPException(
            403, f"Account not usable yet (status: {user['account_status']})."
        )

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    try:
        supabase.table("sessions").insert({
            "user_id": user["user_id"],
            "token_hash": token_hash,
            "expires_at": iso(now() + timedelta(hours=SESSION_LIFETIME_HOURS)),
        }).execute()
        # Every user gets a signing key on first login.
        ensure_user_key(user["user_id"], supabase)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Could not create session/key: {error_text(exc)}")

    registry = user["employee_registry"]
    dept = registry["departments"]

    try:
        admin = (
            supabase.table("department_admins")
            .select("admin_id,can_invite_employees,can_delegate")
            .eq("user_id", user["user_id"])
            .eq("department_id", registry["department_id"])
            .limit(1).execute()
        )
    except Exception:
        admin = type("R", (), {"data": []})()

    return {
        "token": raw_token,
        "expires_in_hours": SESSION_LIFETIME_HOURS,
        "account_status": user["account_status"],
        "full_name": registry["full_name"],
        "department_type": dept["type"],
        "department_name": dept["name"],
        "is_admin": bool(admin.data),
        "has_2fa": bool(user.get("totp_secret")),
    }


class Verify2FARequest(BaseModel):
    code: str


@app.post("/setup-2fa")
def setup_2fa(authorization: str | None = Header(default=None)):
    u = get_current_user(authorization)
    if u["has_2fa"]:
        raise HTTPException(400, "2FA is already set up.")

    secret = pyotp.random_base32()
    try:
        supabase.table("users").update({"totp_secret": secret}).eq(
            "user_id", u["user_id"]
        ).execute()
    except Exception as exc:
        raise HTTPException(500, f"Could not save 2FA: {error_text(exc)}")

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=u["full_name"], issuer_name="Secure DMS"
    )
    return {"secret": secret, "otpauth_url": uri}


@app.post("/verify-2fa")
def verify_2fa(req: Verify2FARequest, authorization: str | None = Header(default=None)):
    u = get_current_user(authorization)
    try:
        r = supabase.table("users").select("totp_secret").eq(
            "user_id", u["user_id"]
        ).limit(1).execute()
    except Exception as exc:
        raise HTTPException(500, f"2FA lookup failed: {error_text(exc)}")

    secret = r.data[0].get("totp_secret") if r.data else None
    if not secret:
        raise HTTPException(400, "2FA is not set up. Call /setup-2fa first.")

    if not pyotp.TOTP(secret).verify(req.code.strip(), valid_window=1):
        raise HTTPException(401, "Invalid or expired authenticator code.")

    until = now() + timedelta(minutes=ELEVATION_LIFETIME_MINUTES)
    supabase.table("sessions").update(
        {"elevated_until": iso(until)}
    ).eq("session_id", u["session_id"]).execute()

    return {"verified": True, "elevated_for_minutes": ELEVATION_LIFETIME_MINUTES}


# --------------------------- EMAIL OTP ---------------------------

class EmailOTPRequest(BaseModel):
    purpose: str
    case_id: str | None = None


class EmailOTPVerifyRequest(BaseModel):
    purpose: str
    case_id: str | None = None
    code: str


def send_otp_email(to_email, name, code):
    msg = MIMEText(
        f"Hello {name},\n\n"
        f"Your Secure DMS verification code is: {code}\n"
        f"It expires in {EMAIL_OTP_MINUTES} minutes.\n\n"
        "If you did not request this code, ignore this email."
    )
    msg["Subject"] = "Secure DMS verification code"
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_ADDRESS, [to_email], msg.as_string())


@app.post("/security/request-otp")
def request_email_otp(
    req: EmailOTPRequest,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)

    purposes = {"VIEW_FILES", "UPLOAD_FILE", "MANAGE_MEMBERS", "APP_INVITE"}
    if req.purpose not in purposes:
        raise HTTPException(400, "Invalid OTP purpose.")

    try:
        r = (
            supabase.table("employee_registry")
            .select("full_name,official_email")
            .eq("employee_id", u["employee_id"]).limit(1).execute()
        )
    except Exception as exc:
        raise HTTPException(500, f"Email lookup failed: {error_text(exc)}")

    if not r.data or not r.data[0].get("official_email"):
        raise HTTPException(400, "Your official email is not configured.")

    code = f"{secrets.randbelow(1_000_000):06d}"
    state_key = (u["session_id"], req.purpose, req.case_id or "")
    EMAIL_OTP_STATE[state_key] = {
        "hash": hashlib.sha256(code.encode()).hexdigest(),
        "expires_at": now() + timedelta(minutes=EMAIL_OTP_MINUTES),
        "attempts": 0,
    }

    try:
        send_otp_email(
            r.data[0]["official_email"],
            r.data[0]["full_name"],
            code,
        )
    except Exception as exc:
        EMAIL_OTP_STATE.pop(state_key, None)
        raise HTTPException(502, f"Could not send OTP email: {error_text(exc)}")

    return {
        "message": "A 6-digit verification code was sent to your official email.",
        "expires_in_seconds": EMAIL_OTP_MINUTES * 60,
    }


@app.post("/security/verify-otp")
def verify_email_otp(
    req: EmailOTPVerifyRequest,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    if not req.code.isdigit() or len(req.code) != 6:
        raise HTTPException(400, "OTP must be exactly 6 digits.")

    key = (u["session_id"], req.purpose, req.case_id or "")
    state = EMAIL_OTP_STATE.get(key)
    if not state:
        raise HTTPException(401, "No active OTP. Request a new code.")

    if state["attempts"] >= 5:
        EMAIL_OTP_STATE.pop(key, None)
        raise HTTPException(401, "Too many attempts. Request a new code.")

    if now() > state["expires_at"]:
        EMAIL_OTP_STATE.pop(key, None)
        raise HTTPException(401, "OTP expired. Request a new code.")

    state["attempts"] += 1
    supplied = hashlib.sha256(req.code.encode()).hexdigest()
    if not secrets.compare_digest(supplied, state["hash"]):
        raise HTTPException(401, "Invalid verification code.")

    EMAIL_OTP_STATE.pop(key, None)

    # Email OTP is the requested second factor for protected actions.
    # Elevate the current login session for a short period so /invite and
    # /case/invite accept the same verified factor.
    try:
        supabase.table("sessions").update({
            "elevated_until": iso(now() + timedelta(minutes=15))
        }).eq("session_id", u["session_id"]).execute()
    except Exception as exc:
        raise HTTPException(500, f"OTP verified, but security elevation failed: {error_text(exc)}")

    return {"verified": True, "elevated_for_seconds": 900}


# --------------------------- NOTIFICATIONS ---------------------------

@app.get("/notifications")
def notifications(authorization: str | None = Header(default=None)):
    u = get_current_user(authorization)
    try:
        r = (
            supabase.table("notifications").select("*")
            .eq("user_id", u["user_id"])
            .order("created_at", desc=True).limit(100).execute()
        )
        return r.data or []
    except Exception as exc:
        # The rest of the application should still work if migration has
        # not been run yet.
        raise HTTPException(500, f"Notifications table is unavailable: {error_text(exc)}")


@app.get("/notifications/unread-count")
def unread_count(authorization: str | None = Header(default=None)):
    u = get_current_user(authorization)
    try:
        r = (
            supabase.table("notifications")
            .select("notification_id", count="exact")
            .eq("user_id", u["user_id"]).is_("read_at", "null").execute()
        )
        return {"count": r.count or 0}
    except Exception as exc:
        raise HTTPException(500, f"Notifications table is unavailable: {error_text(exc)}")


@app.post("/notifications/read")
def mark_read(authorization: str | None = Header(default=None)):
    u = get_current_user(authorization)
    supabase.table("notifications").update(
        {"read_at": iso(now())}
    ).eq("user_id", u["user_id"]).is_("read_at", "null").execute()
    return {"success": True}


def notify(user_id, title, message, ntype="info", case_id=None, request_id=None):
    try:
        supabase.table("notifications").insert({
            "user_id": user_id,
            "type": ntype,
            "title": title,
            "message": message,
            "case_id": case_id,
            "request_id": request_id,
        }).execute()
    except Exception:
        # Notification failure must not undo a valid case grant/upload.
        pass


# --------------------------- APP INVITES ---------------------------

@app.get("/employees/search")
def search_employees(q: str, authorization: str | None = Header(default=None)):
    u = get_current_user(authorization)
    q = q.strip()
    if len(q) < 2:
        return []

    try:
        r = (
            supabase.table("employee_registry")
            .select("employee_id,full_name,official_email,rank,department_id,departments(name)")
            .eq("department_id", u["department_id"])
            .or_(f"full_name.ilike.%{q}%,employee_id.ilike.%{q}%")
            .limit(30).execute()
        )
        if not r.data:
            return []

        ids = [x["employee_id"] for x in r.data]
        existing = (
            supabase.table("users").select("employee_id")
            .in_("employee_id", ids).execute()
        )
        existing_ids = {x["employee_id"] for x in existing.data}
        return [x for x in r.data if x["employee_id"] not in existing_ids]
    except Exception as exc:
        raise HTTPException(500, f"Employee search failed: {error_text(exc)}")


class InviteRequest(BaseModel):
    employee_id: str


@app.post("/invite")
def invite(req: InviteRequest, authorization: str | None = Header(default=None)):
    u = get_current_user(authorization)
    if not u["is_admin"] or not u["can_invite_employees"]:
        raise HTTPException(403, "You don't have permission to invite employees.")
    if not u["is_elevated"]:
        raise HTTPException(403, "Complete authenticator 2FA before inviting.")

    try:
        r = (
            supabase.table("employee_registry")
            .select("employee_id,full_name,official_email,department_id")
            .eq("employee_id", req.employee_id).limit(1).execute()
        )
        if not r.data:
            raise HTTPException(404, "Employee not found in the registry.")
        employee = r.data[0]

        if employee["department_id"] != u["department_id"]:
            raise HTTPException(403, "You can invite only employees from your department.")

        existing = supabase.table("users").select("user_id").eq(
            "employee_id", req.employee_id
        ).limit(1).execute()
        if existing.data:
            raise HTTPException(400, "This employee already has an app account.")

        created = supabase.table("users").insert({
            "employee_id": req.employee_id,
            "account_status": "credentials_issued",
            "invited_by": u["user_id"],
        }).execute()
        if not created.data:
            raise RuntimeError("users insert returned no row")

        uid = created.data[0]["user_id"]
        raw = secrets.token_urlsafe(32)

        supabase.table("activation_tokens").insert({
            "user_id": uid,
            "token_hash": hashlib.sha256(raw.encode()).hexdigest(),
            "expires_at": iso(now() + timedelta(hours=72)),
            "status": "pending",
        }).execute()

        link = f"{BASE_URL}/activate-page?token={raw}"
        send_email(employee["official_email"], employee["full_name"], link)

        notify(
            uid,
            "You were invited",
            f"You were invited to Secure DMS by {u['full_name']}. Open the activation link sent to your email.",
            "app_invitation",
        )

        return {"message": f"Invitation sent to {employee['full_name']}."}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Invitation failed: {error_text(exc)}")


def send_email(to_email: str, full_name: str, activation_link: str):
    body = (
        f"Hi {full_name},\n\n"
        "You have been invited to Secure DMS.\n\n"
        "Activate your account using this link (valid 72 hours):\n"
        f"{activation_link}\n\n"
        "After activation, log in and complete your profile."
    )
    msg = MIMEText(body)
    msg["Subject"] = "Activate your Secure DMS account"
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = to_email
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_ADDRESS, [to_email], msg.as_string())


# --------------------------- ACTIVATION / PROFILE ---------------------------

@app.get("/activate-page", response_class=HTMLResponse)
def activate_page():
    path = Path("activate.html")
    if not path.exists():
        raise HTTPException(500, "activate.html is missing.")
    return path.read_text(encoding="utf-8")


@app.post("/activate")
def activate(req: dict):
    raw = str(req.get("token", ""))
    password = str(req.get("password", ""))
    if not raw:
        raise HTTPException(400, "Activation token is missing.")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")

    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    try:
        r = (
            supabase.table("activation_tokens")
            .select("user_id,expires_at,status")
            .eq("token_hash", token_hash).limit(1).execute()
        )
        if not r.data:
            raise HTTPException(400, "Invalid activation link.")
        row = r.data[0]
        if row["status"] != "pending":
            raise HTTPException(400, "This activation link has already been used.")
        if now() > parse_dt(row["expires_at"]):
            supabase.table("activation_tokens").update({"status": "expired"}).eq(
                "token_hash", token_hash
            ).execute()
            raise HTTPException(400, "This activation link has expired.")

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        supabase.table("users").update({
            "password_hash": password_hash,
            "account_status": "activated",
        }).eq("user_id", row["user_id"]).execute()

        supabase.table("activation_tokens").update({
            "status": "used"
        }).eq("token_hash", token_hash).execute()

        return {"message": "Account activated.", "account_status": "activated"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Activation failed: {error_text(exc)}")


class ProfileRequest(BaseModel):
    dob: str
    personal_address: str
    personal_phone: str
    emergency_contact_name: str
    emergency_contact_phone: str


@app.post("/profile/complete")
def complete_profile(
    req: ProfileRequest,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    try:
        supabase.table("user_profile").upsert({
            "user_id": u["user_id"],
            "dob": req.dob,
            "personal_address": req.personal_address,
            "personal_phone": req.personal_phone,
            "emergency_contact_name": req.emergency_contact_name,
            "emergency_contact_phone": req.emergency_contact_phone,
            "completed_at": iso(now()),
        }).execute()
        supabase.table("users").update(
            {"account_status": "active"}
        ).eq("user_id", u["user_id"]).execute()
        return {"message": "Profile completed.", "account_status": "active"}
    except Exception as exc:
        raise HTTPException(500, f"Profile update failed: {error_text(exc)}")


# --------------------------- CASES ---------------------------

def generate_fir_number():
    return f"FIR-{now().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"


class CreateCaseRequest(BaseModel):
    complainant_name: str
    incident_type: str
    incident_date: str
    location: str
    description: str


def make_fir_pdf(fir_id, u, req, filed_at):
    """
    Creates a real official-looking PDF letter from the submitted form.
    The PDF bytes are exactly what gets hashed and signed.
    """
    from io import BytesIO
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, rightMargin=50, leftMargin=50,
        topMargin=45, bottomMargin=45
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "FIRTitle", parent=styles["Title"], alignment=TA_CENTER,
        fontSize=17, leading=22, spaceAfter=18
    )
    normal = ParagraphStyle(
        "FIRNormal", parent=styles["BodyText"], fontSize=10.5,
        leading=16, spaceAfter=7
    )

    def p(text, style=normal):
        safe = (
            str(text).replace("&", "&amp;")
            .replace("<", "&lt;").replace(">", "&gt;")
        )
        return Paragraph(safe, style)

    story = [
        p("FIRST INFORMATION REPORT", title),
        p(f"<b>FIR Number:</b> {fir_id}"),
        p(f"<b>Date and Time Filed:</b> {filed_at}"),
        p(f"<b>Filed By:</b> {u['full_name']}"),
        p(f"<b>Employee ID:</b> {u['employee_id']}"),
        p(f"<b>Department:</b> {u['department_name']}"),
        Spacer(1, 8),
    ]

    data = [
        ["Particular", "Details"],
        ["Complainant Name", req.complainant_name],
        ["Incident Type", req.incident_type],
        ["Incident Date", req.incident_date],
        ["Location", req.location],
    ]
    table = Table(data, colWidths=[150, 330])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e5e7eb")),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.6, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 9.5),
        ("LEFTPADDING", (0,0), (-1,-1), 7),
        ("RIGHTPADDING", (0,0), (-1,-1), 7),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
    ]))
    story += [table, Spacer(1, 14), p("<b>Description</b>"), p(req.description)]
    story += [
        Spacer(1, 25),
        p("Digital filing record"),
        p(
            "This FIR was generated by Secure DMS from the submitted form. "
            "The final PDF bytes are SHA-256 hashed and digitally signed "
            "with the filing user's ECDSA-P256 private key."
        ),
        Spacer(1, 30),
        p(f"<b>Digital Signatory:</b> {u['full_name']} ({u['employee_id']})"),
        p(f"<b>Signed/Filed At:</b> {filed_at}"),
    ]
    doc.build(story)
    return buf.getvalue()


@app.post("/case/create")
def create_case(
    req: CreateCaseRequest,
    authorization: str | None = Header(default=None),
):
    current_user = get_current_user(authorization)

    if current_user["department_type"] != "police":
        raise HTTPException(
            status_code=403,
            detail="Only police department members can file an FIR.",
        )

    # Generate the FIR reference.
    fir_id = generate_fir_number(
        current_user["department_type"]
    )

    filed_at = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------
    # Create the case first.
    # ------------------------------------------------------------

    case_result = (
        supabase.table("cases")
        .insert({
            "fir_id": fir_id,
            "status": "open",
            "created_by": current_user["user_id"],
        })
        .execute()
    )

    if not case_result.data:
        raise HTTPException(
            status_code=500,
            detail="Could not create the case."
        )

    case_id = case_result.data[0]["case_id"]

    # ------------------------------------------------------------
    # Give the FIR creator full case-management permission.
    # ------------------------------------------------------------

    membership_result = (
        supabase.table("case_membership")
        .insert({
            "user_id": current_user["user_id"],
            "case_id": case_id,
            "permission_level": "grant",
            "granted_by": current_user["user_id"],
            "allowed_document_types": [
                "fir",
                "evidence",
                "witness_statement",
                "charge_sheet",
            ],
        })
        .execute()
    )

    if not membership_result.data:
        # Do not leave an ownerless case.
        try:
            supabase.table("cases").delete().eq(
                "case_id", case_id
            ).execute()
        except Exception:
            pass

        raise HTTPException(
            status_code=500,
            detail="Could not create case membership."
        )

    # ------------------------------------------------------------
    # Create the ACTUAL official FIR PDF.
    # ------------------------------------------------------------

    pdf_bytes = generate_fir_pdf(
        fir_number=fir_id,
        filed_at=filed_at,
        filed_by=current_user["full_name"],
        employee_id=current_user.get("employee_id", ""),
        department=current_user["department_name"],
        complainant_name=req.complainant_name,
        incident_type=req.incident_type,
        incident_date=req.incident_date,
        location=req.location,
        description=req.description,
    )

    # ------------------------------------------------------------
    # Hash the EXACT PDF bytes that will be stored.
    # ------------------------------------------------------------

    file_hash = calculate_file_hash(pdf_bytes)

    # ------------------------------------------------------------
    # Make sure this user has a persistent signing key.
    # ------------------------------------------------------------

    ensure_user_key(current_user["user_id"], supabase)

    # sign_file_hash now retrieves/decrypts the private key
    # from Supabase instead of reading ./private_keys.
    signature = sign_file_hash(
        current_user["user_id"],
        file_hash,
        supabase,
    )

    document_result = (
        supabase.table("documents")
        .insert({
            "case_id": case_id,
            "document_type": "fir",
            "file_type": "text",
            "uploader_id": current_user["user_id"],
        })
        .execute()
    )

    if not document_result.data:
        raise HTTPException(
            status_code=500,
            detail="Could not create FIR document record."
        )

    document_id = document_result.data[0]["document_id"]

    version_id = str(uuid.uuid4())

    storage_path = (
        f"{case_id}/"
        f"{document_id}/"
        f"{version_id}/"
        f"FIR_{fir_id}.pdf"
    )

    # ------------------------------------------------------------
    # Storage is private.
    # The path contains the case UUID, so files are grouped by case.
    # ------------------------------------------------------------

    try:
        supabase.storage.from_(DOCUMENT_BUCKET).upload(
            storage_path,
            pdf_bytes,
            {
                "content-type": "application/pdf",
                "upsert": False,
            },
        )
    except Exception as exc:
        try:
            supabase.table("documents").delete().eq(
                "document_id", document_id
            ).execute()
        except Exception:
            pass

        raise HTTPException(
            status_code=500,
            detail=f"FIR PDF storage failed: {exc}",
        )

    # ------------------------------------------------------------
    # Append the signed version.
    # ------------------------------------------------------------

    version_result = (
        supabase.table("document_versions")
        .insert({
            "version_id": version_id,
            "document_id": document_id,
            "storage_path": storage_path,
            "file_hash": file_hash,
            "previous_version_hash": None,
            "signature": signature,
            "co_signature": None,
            "uploader_id": current_user["user_id"],
            "timestamp": filed_at,
        })
        .execute()
    )

    if not version_result.data:
        try:
            supabase.storage.from_(DOCUMENT_BUCKET).remove(
                [storage_path]
            )
        except Exception:
            pass

        try:
            supabase.table("documents").delete().eq(
                "document_id", document_id
            ).execute()
        except Exception:
            pass

        raise HTTPException(
            status_code=500,
            detail="Could not create FIR document version."
        )

    # ------------------------------------------------------------
    # Point documents.current_version_id to the signed version.
    # ------------------------------------------------------------

    update_result = (
        supabase.table("documents")
        .update({
            "current_version_id": version_id
        })
        .eq("document_id", document_id)
        .execute()
    )

    if not update_result.data:
        raise HTTPException(
            status_code=500,
            detail="Could not set current FIR document version."
        )

    return {
        "message": "FIR filed successfully.",
        "case_id": case_id,
        "fir_id": fir_id,
        "document_id": document_id,
        "version_id": version_id,
        "filename": f"FIR_{fir_id}.pdf",
        "file_hash": file_hash,
        "hash_algorithm": "SHA-256",
        "signature": signature,
        "signature_algorithm": "RSA-PSS-SHA256",
        "storage_path": storage_path,
    }



@app.get("/case/my")
def my_cases(authorization: str | None = Header(default=None)):
    u = get_current_user(authorization)
    try:
        r = (
            supabase.table("case_membership")
            .select(
                "case_id,permission_level,allowed_document_types,"
                "cases(fir_id,status,created_at)"
            )
            .eq("user_id", u["user_id"]).execute()
        )
        return r.data or []
    except Exception as exc:
        raise HTTPException(500, f"Could not load cases: {error_text(exc)}")


@app.get("/case/search")
def search_cases(
    q: str,
    authorization: str | None = Header(default=None),
):
    """
    SEARCHABLE BUT NOT ACCESSIBLE:
    Returns only case metadata. It does NOT return documents, storage paths,
    hashes, signatures, members or file URLs.
    """
    get_current_user(authorization)
    q = q.strip()
    if len(q) < 2:
        return []

    try:
        r = (
            supabase.table("cases")
            .select("case_id,fir_id,status,created_at,created_by")
            .or_(f"fir_id.ilike.%{q}%,case_id.ilike.%{q}%")
            .limit(30).execute()
        )
        return [
            {
                "case_id": x["case_id"],
                "fir_id": x["fir_id"],
                "status": x["status"],
                "created_at": x.get("created_at"),
            }
            for x in (r.data or [])
        ]
    except Exception as exc:
        raise HTTPException(500, f"Case search failed: {error_text(exc)}")


def membership(user_id, case_id):
    r = (
        supabase.table("case_membership")
        .select("membership_id,permission_level,allowed_document_types,expires_at")
        .eq("case_id", case_id).eq("user_id", user_id).limit(1).execute()
    )
    if not r.data:
        raise HTTPException(403, "You are not a member of this case.")
    row = r.data[0]
    if row.get("expires_at") and now() > parse_dt(row["expires_at"]):
        raise HTTPException(403, "Your access to this case has expired.")
    return row


@app.get("/case/documents")
def case_documents(
    case_id: str,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    m = membership(u["user_id"], case_id)
    allowed = set(m.get("allowed_document_types") or [])

    try:
        r = (
            supabase.table("documents")
            .select(
                "document_id,case_id,document_type,file_type,uploader_id,"
                "current_version_id,"
                "document_versions!fk_documents_current_version("
                "version_id,storage_path,file_hash,signature,timestamp)"
            )
            .eq("case_id", case_id).execute()
        )

        visible = []
        for d in r.data or []:
            if d["document_type"] not in allowed:
                continue
            versions = d.get("document_versions") or []
            v = versions[0] if isinstance(versions, list) and versions else (
                versions if isinstance(versions, dict) else {}
            )
            visible.append({
                "document_id": d["document_id"],
                "case_id": d["case_id"],
                "document_type": d["document_type"],
                "file_type": d["file_type"],
                "uploader_id": d["uploader_id"],
                "current_version_id": d["current_version_id"],
                "filename": Path(v.get("storage_path", "")).name or "Unnamed file",
                "version": {
                    "version_id": v.get("version_id"),
                    "file_hash": v.get("file_hash"),
                    "signature": v.get("signature"),
                    "timestamp": v.get("timestamp"),
                },
            })

        return {
            "my_permission_level": m["permission_level"],
            "my_allowed_document_types": sorted(allowed),
            "documents": visible,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Could not load case files: {error_text(exc)}")


@app.get("/documents/file/{version_id}")
def document_file(
    version_id: str,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    try:
        vr = (
            supabase.table("document_versions")
            .select("version_id,document_id,storage_path")
            .eq("version_id", version_id).limit(1).execute()
        )
        if not vr.data:
            raise HTTPException(404, "Document version not found.")

        v = vr.data[0]
        dr = (
            supabase.table("documents")
            .select("document_id,case_id,document_type")
            .eq("document_id", v["document_id"]).limit(1).execute()
        )
        if not dr.data:
            raise HTTPException(404, "Document not found.")

        d = dr.data[0]
        m = membership(u["user_id"], d["case_id"])
        if d["document_type"] not in set(m.get("allowed_document_types") or []):
            raise HTTPException(403, "You are not authorized to view this document.")

        signed = supabase.storage.from_(DOCUMENT_BUCKET).create_signed_url(
            v["storage_path"], 120
        )
        url = (
            signed.get("signedURL")
            or signed.get("signedUrl")
            or signed.get("signed_url")
        )
        if not url:
            raise RuntimeError(f"Supabase did not return a signed URL: {signed}")
        return {"url": url, "expires_in": 120}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Could not create secure file URL: {error_text(exc)}")


@app.get("/documents/verify/{version_id}")
def verify_document(
    version_id: str,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    try:
        vr = (
            supabase.table("document_versions")
            .select(
                "version_id,document_id,storage_path,file_hash,signature,uploader_id"
            )
            .eq("version_id", version_id).limit(1).execute()
        )
        if not vr.data:
            raise HTTPException(404, "Document version not found.")
        v = vr.data[0]

        dr = (
            supabase.table("documents")
            .select("document_id,case_id,document_type")
            .eq("document_id", v["document_id"]).limit(1).execute()
        )
        if not dr.data:
            raise HTTPException(404, "Document not found.")

        d = dr.data[0]
        m = membership(u["user_id"], d["case_id"])
        if d["document_type"] not in set(m.get("allowed_document_types") or []):
            raise HTTPException(403, "You are not authorized to verify this document.")

        stored = supabase.storage.from_(DOCUMENT_BUCKET).download(
            v["storage_path"]
        )
        actual_hash = hashlib.sha256(stored).hexdigest()
        hash_valid = secrets.compare_digest(actual_hash, v["file_hash"])

        kr = (
            supabase.table("user_keys").select("public_key")
            .eq("user_id", v["uploader_id"]).eq("key_status", "active")
            .limit(1).execute()
        )
        if not kr.data:
            raise HTTPException(404, "Uploader public key not found.")

        signature_valid = verify_signature(
            kr.data[0]["public_key"], v["file_hash"], v["signature"]
        )

        return {
            "valid": bool(hash_valid and signature_valid),
            "hash_valid": hash_valid,
            "signature_valid": signature_valid,
            "stored_hash": v["file_hash"],
            "actual_hash": actual_hash,
            "algorithm": "SHA-256 + ECDSA-P256",
            "version_id": version_id,
            "uploader_id": v["uploader_id"],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Verification failed: {error_text(exc)}")


def check_upload_permission(user_id, case_id, document_type):
    m = membership(user_id, case_id)
    if m["permission_level"] not in {"upload", "sign", "grant"}:
        raise HTTPException(403, "You don't have upload permission for this case.")
    if document_type not in set(m.get("allowed_document_types") or []):
        raise HTTPException(
            403,
            f"You are not authorized to upload '{document_type}'."
        )
    return m


@app.post("/documents/upload")
async def upload_document(
    case_id: str = Form(...),
    document_type: str = Form(...),
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    document_type = document_type.strip().lower()

    if document_type not in ALLOWED_DOCUMENT_TYPES:
        raise HTTPException(400, "Invalid document type.")

    check_upload_permission(u["user_id"], case_id, document_type)

    if not file.filename:
        raise HTTPException(400, "Filename missing.")

    name = os.path.basename(file.filename)
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            400,
            "Unsupported file type. Allowed: PDF, PNG, JPG, DOC, DOCX, PPT, PPTX, TXT."
        )

    data = await file.read()
    if not data:
        raise HTTPException(400, "The selected file is empty.")
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(413, "File is larger than 50 MB.")

    try:
        ft = "image" if ext in {".jpg", ".jpeg", ".png"} else "text"
        h = calculate_file_hash(data)
        ensure_user_key(u["user_id"], supabase)
        sig = sign_file_hash(u["user_id"], h)

        dr = supabase.table("documents").insert({
            "case_id": case_id,
            "document_type": document_type,
            "file_type": ft,
            "uploader_id": u["user_id"],
        }).execute()
        if not dr.data:
            raise RuntimeError("Document insert returned no row.")
        did = dr.data[0]["document_id"]

        vid = str(uuid.uuid4())
        safe = name.replace("/", "_").replace("\\", "_")
        path = f"{case_id}/{did}/{vid}/{safe}"
        ctype = file.content_type or mimetypes.guess_type(name)[0] or "application/octet-stream"

        supabase.storage.from_(DOCUMENT_BUCKET).upload(
            path, data, {"content-type": ctype, "upsert": False}
        )

        vr = supabase.table("document_versions").insert({
            "version_id": vid,
            "document_id": did,
            "storage_path": path,
            "file_hash": h,
            "previous_version_hash": None,
            "signature": sig,
            "co_signature": None,
            "uploader_id": u["user_id"],
            "timestamp": iso(now()),
        }).execute()
        if not vr.data:
            raise RuntimeError("document_versions insert returned no row.")

        supabase.table("documents").update({
            "current_version_id": vid
        }).eq("document_id", did).execute()

        notify(
            u["user_id"],
            "File uploaded",
            f"{name} was uploaded to the case and digitally signed.",
            "document_uploaded",
            case_id=case_id,
        )

        return {
            "success": True,
            "message": "File uploaded and digitally signed.",
            "document_id": did,
            "version_id": vid,
            "file_hash": h,
            "signature": sig,
            "storage_path": path,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"File registration failed: {error_text(exc)}")


# --------------------------- CASE MEMBERS ---------------------------

@app.get("/case/members")
def case_members(
    case_id: str,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    mine = membership(u["user_id"], case_id)
    try:
        r = (
            supabase.table("case_membership")
            .select(
                "user_id,permission_level,allowed_document_types,granted_by,"
                "delegated_by,users!case_membership_user_id_fkey(employee_id,"
                "employee_registry!fk_users_employee(full_name,departments(name)))"
            )
            .eq("case_id", case_id).execute()
        )
        return {"my_access": mine, "members": r.data or []}
    except Exception as exc:
        raise HTTPException(500, f"Could not load members: {error_text(exc)}")


@app.get("/case/search-members")
def search_case_members(
    case_id: str,
    q: str,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    mine = membership(u["user_id"], case_id)
    if mine["permission_level"] != "grant":
        raise HTTPException(403, "You don't have grant permission on this case.")

    q = q.strip()
    if len(q) < 2:
        return []

    try:
        r = (
            supabase.table("employee_registry")
            .select("employee_id,full_name,official_email,rank,department_id")
            .eq("department_id", u["department_id"])
            .or_(f"full_name.ilike.%{q}%,employee_id.ilike.%{q}%")
            .limit(20).execute()
        )
        return r.data or []
    except Exception as exc:
        raise HTTPException(500, f"Member search failed: {error_text(exc)}")


@app.get("/case/invite-options")
def case_invite_options(
    case_id: str,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    mine = membership(u["user_id"], case_id)
    if mine["permission_level"] != "grant":
        raise HTTPException(403, "You don't have grant permission on this case.")
    return {"allowed_document_types": sorted(mine.get("allowed_document_types") or [])}


class CaseInviteRequest(BaseModel):
    case_id: str
    employee_id: str
    permission_level: str
    allowed_document_types: list[str]


@app.post("/case/invite")
def case_invite(
    req: CaseInviteRequest,
    authorization: str | None = Header(default=None),
):
    u = get_current_user(authorization)
    if not u["is_elevated"]:
        raise HTTPException(403, "Complete authenticator 2FA before granting case access.")

    if req.permission_level not in {"read", "upload", "sign", "grant"}:
        raise HTTPException(400, "Invalid permission level.")

    inviter = membership(u["user_id"], req.case_id)
    if inviter["permission_level"] != "grant":
        raise HTTPException(403, "You don't have grant permission on this case.")

    requested = set(req.allowed_document_types)
    available = set(inviter.get("allowed_document_types") or [])
    if not requested or not requested.issubset(available):
        raise HTTPException(
            403,
            f"You can grant only document types you have: {sorted(available)}"
        )

    try:
        target = (
            supabase.table("users").select("user_id")
            .eq("employee_id", req.employee_id).limit(1).execute()
        )
        if not target.data:
            raise HTTPException(
                404,
                "That employee does not have an app account yet. Invite them from the homepage first."
            )
        target_uid = target.data[0]["user_id"]

        existing = (
            supabase.table("case_membership").select("membership_id")
            .eq("case_id", req.case_id).eq("user_id", target_uid)
            .limit(1).execute()
        )
        if existing.data:
            raise HTTPException(400, "This person already has access to this case.")

        supabase.table("case_membership").insert({
            "user_id": target_uid,
            "case_id": req.case_id,
            "permission_level": req.permission_level,
            "granted_by": u["user_id"],
            "delegated_by": u["user_id"],
            "allowed_document_types": sorted(requested),
        }).execute()

        # Immediate notification; the SQL trigger is also supplied as a
        # fallback/audit layer, so duplicate notifications may be avoided by
        # using either one, not both. Here we use application notification.
        notify(
            target_uid,
            "Case access granted",
            f"{u['full_name']} granted you {req.permission_level} access to case {req.case_id}. "
            f"Documents: {', '.join(sorted(requested))}.",
            "case_access_granted",
            case_id=req.case_id,
        )

        return {"success": True, "message": f"{req.employee_id} added to the case."}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Case invitation failed: {error_text(exc)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
