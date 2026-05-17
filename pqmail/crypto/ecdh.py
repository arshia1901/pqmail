"""
X25519 Elliptic Curve Diffie-Hellman for hybrid KEM.

This module provides X25519 key exchange for the classical component of the
hybrid ML-KEM-768 + X25519 composite KEM.

Security: X25519 is vulnerable to quantum attacks, but when combined with
ML-KEM-768 via hybrid composition, the overall scheme is quantum-resistant
as long as at least one component remains unbroken.
"""

from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Generate a new X25519 keypair.

    Returns:
        Tuple of (private_key, public_key) as cryptography objects

    Security: Private key should not be serialized. Keep only in memory.
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def get_public_key_bytes(public_key: X25519PublicKey) -> bytes:
    """
    Serialize X25519 public key to raw bytes.

    Args:
        public_key: X25519PublicKey object

    Returns:
        32 bytes of public key material
    """
    return public_key.public_bytes_raw()


def public_key_from_bytes(data: bytes) -> X25519PublicKey:
    """
    Deserialize X25519 public key from raw bytes.

    Args:
        data: 32 bytes of public key material

    Returns:
        X25519PublicKey object

    Raises:
        ValueError: If data is not exactly 32 bytes
    """
    if not isinstance(data, bytes) or len(data) != 32:
        raise ValueError("X25519 public key must be exactly 32 bytes")

    return X25519PublicKey.from_public_bytes(data)


def exchange(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> bytes:
    """
    Perform X25519 key exchange (ECDH).

    Args:
        private_key: Our X25519 private key
        peer_public_key: Peer's X25519 public key

    Returns:
        32 bytes of shared secret

    Security: The shared secret should be used as input to HKDF for key
    derivation, not used directly as an encryption key.
    """
    return private_key.exchange(peer_public_key)


def exchange_with_bytes(
    private_key: X25519PrivateKey,
    peer_public_key_bytes: bytes,
) -> bytes:
    """
    Perform X25519 key exchange with public key as raw bytes.

    Args:
        private_key: Our X25519 private key
        peer_public_key_bytes: Peer's public key as 32 bytes

    Returns:
        32 bytes of shared secret

    Raises:
        ValueError: If peer_public_key_bytes is not 32 bytes
    """
    peer_public_key = public_key_from_bytes(peer_public_key_bytes)
    return exchange(private_key, peer_public_key)


# Constants
X25519_PUBLIC_KEY_SIZE = 32
X25519_SHARED_SECRET_SIZE = 32
