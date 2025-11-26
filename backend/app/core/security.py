import base64
import hashlib
from cryptography.fernet import Fernet
from app.core.config import settings

def _get_fernet_key() -> bytes:
    """Derive a Fernet-compatible key from the JWT_SECRET_KEY."""
    # SHA256 gives 32 bytes
    key_bytes = hashlib.sha256(settings.JWT_SECRET_KEY.encode()).digest()
    # Base64 encode to make it URL-safe for Fernet
    return base64.urlsafe_b64encode(key_bytes)

def encrypt_value(value: str) -> str:
    """Encrypt a string value."""
    if not value:
        return ""
    f = Fernet(_get_fernet_key())
    return f.encrypt(value.encode()).decode()

def decrypt_value(encrypted_value: str) -> str:
    """Decrypt a string value."""
    if not encrypted_value:
        return ""
    f = Fernet(_get_fernet_key())
    return f.decrypt(encrypted_value.encode()).decode()
