import os
import base64
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# =========================================================
# PASSWORD SECURITY
# =========================================================

password_hasher = PasswordHasher()


def hash_password(password):
    """
    Hash a user password using Argon2.
    Passwords should NOT be encrypted because
    authentication does not require recovering
    the original password.
    """

    return password_hasher.hash(password)


def verify_password(password_hash, password):
    """
    Verify a plaintext password against
    the stored Argon2 hash.
    """

    try:
        return password_hasher.verify(
            password_hash,
            password
        )

    except VerifyMismatchError:
        return False

    except Exception:
        return False


# =========================================================
# AES-256-GCM ENCRYPTION
# =========================================================

def get_encryption_key():
    """
    Read a 32-byte AES-256 key from environment.
    The key must be Base64 encoded.
    """

    key_b64 = os.getenv("AES_256_KEY_B64")

    if not key_b64:
        raise RuntimeError(
            "AES_256_KEY_B64 is not configured."
        )

    try:
        key = base64.b64decode(
            key_b64,
            validate=True
        )

    except Exception as error:
        raise RuntimeError(
            "AES_256_KEY_B64 is not valid Base64."
        ) from error

    if len(key) != 32:
        raise RuntimeError(
            "AES-256 requires exactly 32 bytes."
        )

    return key


def encrypt_sensitive_data(plaintext):
    """
    Encrypt sensitive information using AES-256-GCM.

    A new random nonce is generated for every encryption.
    """

    if plaintext is None:
        return None

    key = get_encryption_key()

    aesgcm = AESGCM(key)

    # 96-bit nonce recommended for AES-GCM
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None
    )

    # Store nonce + ciphertext together
    encrypted_data = nonce + ciphertext

    return base64.b64encode(
        encrypted_data
    ).decode("utf-8")


def decrypt_sensitive_data(encrypted_value):
    """
    Decrypt AES-256-GCM encrypted data.
    """

    if encrypted_value is None:
        return None

    key = get_encryption_key()

    encrypted_data = base64.b64decode(
        encrypted_value,
        validate=True
    )

    nonce = encrypted_data[:12]

    ciphertext = encrypted_data[12:]

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


# =========================================================
# CAPABILITY CODE
# =========================================================

def generate_capability_code():
    """
    Generate a cryptographically secure
    random capability code.
    """

    return secrets.token_urlsafe(32)


def hash_capability_code(capability_code):
    """
    Hash the capability code before storing it.
    """

    return hashlib.sha256(
        capability_code.encode("utf-8")
    ).hexdigest()
