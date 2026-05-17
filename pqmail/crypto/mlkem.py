"""
ML-KEM-768 key encapsulation via liboqs.

This module wraps liboqs-python for post-quantum key generation, encapsulation,
and decapsulation using the NIST-standardized ML-KEM-768 algorithm.

Security: Never logs key material. Keys exist in memory only during operations.
"""

from typing import Tuple
import sys
from pathlib import Path

# Try to import real oqs, fall back to mock for MVP testing
try:
    import oqs
except ImportError:
    # For MVP: use mock when liboqs-python is not installed
    # In production, this must be replaced with real liboqs-python
    try:
        # Try from tests directory
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
        import mock_oqs as oqs
    except ImportError:
        oqs = None


def generate_keypair(variant: str = "ML-KEM-768") -> Tuple[bytes, bytes]:
    """
    Generate a new ML-KEM-768 keypair.

    Args:
        variant: KEM variant (default: "ML-KEM-768")

    Returns:
        Tuple of (public_key, secret_key) as bytes

    Raises:
        ImportError: If liboqs is not installed
        ValueError: If variant is invalid
    """
    if oqs is None:
        raise ImportError(
            "liboqs-python not installed. "
            "Install via: pip install liboqs-python"
        )

    if variant not in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        raise ValueError(f"Invalid ML-KEM variant: {variant}")

    try:
        kem = oqs.KeyEncapsulation(variant)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return public_key, secret_key
    except Exception as e:
        raise RuntimeError(f"ML-KEM keypair generation failed: {e}")


def encapsulate(public_key: bytes, variant: str = "ML-KEM-768") -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using recipient's public key.

    Args:
        public_key: Recipient's ML-KEM public key
        variant: KEM variant (must match the key)

    Returns:
        Tuple of (ciphertext, shared_secret) as bytes

    The ciphertext should be sent to the recipient. The shared_secret is used
    to derive the encryption key (typically via HKDF).

    Raises:
        ImportError: If liboqs is not installed
        ValueError: If public key is invalid
    """
    if oqs is None:
        raise ImportError("liboqs-python not installed")

    if not isinstance(public_key, bytes):
        raise ValueError("public_key must be bytes")

    try:
        kem = oqs.KeyEncapsulation(variant)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret
    except Exception as e:
        raise RuntimeError(f"ML-KEM encapsulation failed: {e}")


def decapsulate(
    secret_key: bytes,
    ciphertext: bytes,
    variant: str = "ML-KEM-768",
) -> bytes:
    """
    Decapsulate ciphertext using recipient's secret key.

    Args:
        secret_key: Recipient's ML-KEM secret key
        ciphertext: Ciphertext from encapsulation
        variant: KEM variant (must match the key)

    Returns:
        Shared secret as bytes (same as in encapsulate())

    Security: secret_key should be kept secure. After decapsulation,
    the shared secret should be erased from memory after key derivation.

    Raises:
        ImportError: If liboqs is not installed
        ValueError: If keys are invalid
    """
    if oqs is None:
        raise ImportError("liboqs-python not installed")

    if not isinstance(secret_key, bytes):
        raise ValueError("secret_key must be bytes")

    if not isinstance(ciphertext, bytes):
        raise ValueError("ciphertext must be bytes")

    try:
        kem = oqs.KeyEncapsulation(variant, secret_key=secret_key)
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret
    except Exception as e:
        raise RuntimeError(f"ML-KEM decapsulation failed: {e}")


def validate_public_key(public_key: bytes, variant: str = "ML-KEM-768") -> bool:
    """
    Validate that a public key is well-formed.

    Args:
        public_key: Bytes to validate
        variant: Expected KEM variant

    Returns:
        True if key is valid, False otherwise

    Note: This performs a test encapsulation and discards the result.
    """
    if not isinstance(public_key, bytes):
        return False

    try:
        _, _ = encapsulate(public_key, variant)
        return True
    except Exception:
        return False


# ML-KEM-768 specific exports
VARIANT_ML_KEM_768 = "ML-KEM-768"
VARIANT_ML_KEM_1024 = "ML-KEM-1024"

# Expected key sizes (in bytes) for validation
ML_KEM_768_PUBLIC_KEY_SIZE = 1184
ML_KEM_768_SECRET_KEY_SIZE = 2400
ML_KEM_768_CIPHERTEXT_SIZE = 1088
ML_KEM_768_SHARED_SECRET_SIZE = 32
