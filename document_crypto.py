"""NEMESIS document signing and key-at-rest encryption."""
import os
import base64
import hashlib
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()

def _master_key() -> bytes:
    value = os.getenv("KEY_ENCRYPTION_KEY")
    if not value:
        raise RuntimeError("KEY_ENCRYPTION_KEY is missing from .env / server environment.")
    try:
        key = base64.urlsafe_b64decode(value.encode())
    except Exception as exc:
        raise RuntimeError("KEY_ENCRYPTION_KEY is not valid base64.") from exc
    if len(key) != 32:
        raise RuntimeError("KEY_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).")
    return key

def calculate_file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def generate_user_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem

def encrypt_private_key(private_key_pem: bytes) -> str:
    aes = AESGCM(_master_key())
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, private_key_pem, None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

def decrypt_private_key(encrypted_value: str) -> bytes:
    raw = base64.urlsafe_b64decode(encrypted_value.encode("ascii"))
    if len(raw) < 13:
        raise ValueError("Encrypted private key is invalid.")
    return AESGCM(_master_key()).decrypt(raw[:12], raw[12:], None)

def sign_file_hash(user_id: str, file_hash: str, supabase=None) -> dict:
    if supabase is None:
        raise RuntimeError("sign_file_hash requires the Supabase client.")
    result = (
        supabase.table("user_keys")
        .select("key_id,encrypted_private_key,key_status,algorithm")
        .eq("user_id", user_id)
        .eq("key_status", "active")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    if not result.data:
        raise RuntimeError("No active signing key exists for this user.")
    row = result.data[0]
    if not row.get("encrypted_private_key"):
        raise RuntimeError("The user's private key is not stored in user_keys.encrypted_private_key.")
    private_pem = decrypt_private_key(row["encrypted_private_key"])
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    signature = private_key.sign(
        file_hash.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "signature": base64.b64encode(signature).decode("ascii"),
        "key_id": row["key_id"],
        "algorithm": row.get("algorithm") or "RSA-PSS-SHA256",
    }

def verify_signature(public_key_pem: str, file_hash: str, signature_b64: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        public_key.verify(
            base64.b64decode(signature_b64),
            file_hash.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
