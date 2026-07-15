"""AES-256-GCM encryption helpers for sensitive prompt storage.

Key material: ``PROMPTSHIELD_ENCRYPTION_KEY`` as 64 hex characters (32 bytes).
If the key is missing or invalid, encryption is skipped (returns None).
"""

from __future__ import annotations

import hashlib
import os
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_SIZE: Final[int] = 12


def load_encryption_key() -> bytes | None:
    """Load AES-256 key from environment, or None if unavailable."""
    raw = os.environ.get("PROMPTSHIELD_ENCRYPTION_KEY", "").strip()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(key) != 32:
        return None
    return key


def encrypt_prompt(plaintext: str, key: bytes | None = None) -> bytes | None:
    """Encrypt UTF-8 plaintext with AES-256-GCM.

    Returns:
        ``nonce || ciphertext||tag`` bytes, or ``None`` if no key.
    """
    material = key if key is not None else load_encryption_key()
    if material is None:
        return None
    aesgcm = AESGCM(material)
    nonce = os.urandom(_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct


def decrypt_prompt(ciphertext: bytes, key: bytes | None = None) -> str:
    """Decrypt payload produced by :func:`encrypt_prompt`.

    Raises:
        ValueError: If key is missing or decryption fails.
    """
    material = key if key is not None else load_encryption_key()
    if material is None:
        raise ValueError("Encryption key not configured")
    if len(ciphertext) <= _NONCE_SIZE:
        raise ValueError("Ciphertext too short")
    nonce = ciphertext[:_NONCE_SIZE]
    body = ciphertext[_NONCE_SIZE:]
    aesgcm = AESGCM(material)
    plain = aesgcm.decrypt(nonce, body, None)
    return plain.decode("utf-8")


def hash_api_key(api_key: str | None) -> str | None:
    """Return SHA-256 hex digest of an API key (never store plaintext)."""
    if not api_key:
        return None
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def hash_prompt(prompt: str) -> str:
    """SHA-256 of the raw prompt for correlation without storing plaintext."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()
