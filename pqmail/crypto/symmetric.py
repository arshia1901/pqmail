"""
AES-256-GCM symmetric encryption for PQMail.

This module provides authenticated encryption using AES-256 in Galois/Counter Mode.
The encryption key is derived from hybrid ML-KEM + X25519 shared secrets via HKDF.

Security: GCM provides both confidentiality and authentication. Nonces must never
be reused with the same key. Each message gets a fresh random nonce.
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.

    Args:
        key: 32-byte encryption key (from HKDF)
        plaintext: Message to encrypt
        associated_data: Optional authenticated but not encrypted data

    Returns:
        Tuple of (nonce, ciphertext) both as bytes

    The nonce is randomly generated and should be prepended to ciphertext for transmission.
    The ciphertext includes the authentication tag.

    Raises:
        ValueError: If key is not 32 bytes
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AES-256-GCM key must be exactly 32 bytes")

    if not isinstance(plaintext, bytes):
        raise ValueError("plaintext must be bytes")

    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("associated_data must be bytes or None")

    try:
        cipher = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce (12 bytes)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    except Exception as e:
        raise RuntimeError(f"AES-256-GCM encryption failed: {e}")


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes = None,
) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    Args:
        key: 32-byte decryption key (same as encryption)
        nonce: 12-byte nonce (from encryption)
        ciphertext: Encrypted data (includes authentication tag)
        associated_data: Optional authenticated data (must match encryption)

    Returns:
        Plaintext as bytes

    Raises:
        ValueError: If key/nonce are invalid or authentication fails
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AES-256-GCM key must be exactly 32 bytes")

    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("Nonce must be exactly 12 bytes")

    if not isinstance(ciphertext, bytes):
        raise ValueError("ciphertext must be bytes")

    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("associated_data must be bytes or None")

    try:
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except Exception as e:
        raise RuntimeError(f"AES-256-GCM decryption failed (auth tag mismatch?): {e}")


# Constants
AES256_KEY_SIZE = 32
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16  # bytes
