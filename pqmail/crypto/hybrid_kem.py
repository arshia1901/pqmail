"""
Hybrid ML-KEM-768 + X25519 KEM for PQMail.

This module performs the composite key encapsulation and symmetric encryption
for upgrading classical OpenPGP emails to quantum-resistant hybrid encryption.

The hybrid construction ensures that breaking only one component (either ML-KEM-768
or X25519) is insufficient to compromise the message. Both shared secrets are
combined via HKDF before deriving the symmetric key.

Security: Based on draft-ietf-openpgp-pqc specification.
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from pqmail.crypto import mlkem, ecdh, symmetric
from pqmail.parser.mime_parser import ParsedEmail


# Hybrid KEM info string for HKDF
HYBRID_KEM_INFO = b"PQMail-HybridKEM-ML-KEM-768+X25519-v1"

# Algorithm identifier in future OpenPGP packets
HYBRID_ALG_ID = 29  # Draft OID for ML-KEM composite


def derive_key(
    mlkem_shared_secret: bytes,
    x25519_shared_secret: bytes,
    info: bytes = HYBRID_KEM_INFO,
    length: int = 32,
) -> bytes:
    """
    Derive symmetric encryption key from hybrid shared secrets.

    Args:
        mlkem_shared_secret: Output from ML-KEM-768 decapsulation (32 bytes)
        x25519_shared_secret: Output from X25519 exchange (32 bytes)
        info: HKDF info string (default: PQMail-specific)
        length: Output key length (default: 32 for AES-256)

    Returns:
        Derived key as bytes

    The two shared secrets are concatenated and used as HKDF input material:
        key = HKDF-SHA256(mlkem_ss || x25519_ss, salt=None, info=..., length=32)
    """
    combined_secret = mlkem_shared_secret + x25519_shared_secret

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )

    return hkdf.derive(combined_secret)


def hybrid_encapsulate(
    mlkem_public_key: bytes,
    x25519_public_key_bytes: bytes,
) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Perform hybrid encapsulation with ML-KEM-768 and X25519.

    Args:
        mlkem_public_key: Recipient's ML-KEM-768 public key (1184 bytes)
        x25519_public_key_bytes: Recipient's X25519 public key (32 bytes)

    Returns:
        Tuple of (mlkem_ciphertext, ephemeral_x25519_public, nonce, derived_key)

    The derived_key is ready to use for AES-256-GCM encryption.

    Raises:
        ValueError: If keys are invalid
        RuntimeError: If encapsulation fails
    """
    # ML-KEM component: encapsulate to recipient's ML-KEM public key
    mlkem_ct, mlkem_ss = mlkem.encapsulate(mlkem_public_key, "ML-KEM-768")

    # X25519 component: generate ephemeral keypair and exchange
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public_bytes = ecdh.get_public_key_bytes(ephemeral_private.public_key())

    # Exchange with recipient's X25519 public key
    x25519_public_key = ecdh.public_key_from_bytes(x25519_public_key_bytes)
    x25519_ss = ecdh.exchange(ephemeral_private, x25519_public_key)

    # Derive symmetric key
    derived_key = derive_key(mlkem_ss, x25519_ss)

    return mlkem_ct, ephemeral_public_bytes, mlkem_ss, x25519_ss


def hybrid_encrypt(
    plaintext: bytes,
    mlkem_public_key: bytes,
    x25519_public_key_bytes: bytes,
    associated_data: bytes = None,
) -> bytes:
    """
    Encrypt plaintext with hybrid ML-KEM-768 + X25519.

    Args:
        plaintext: Message to encrypt
        mlkem_public_key: Recipient's ML-KEM-768 public key
        x25519_public_key_bytes: Recipient's X25519 public key
        associated_data: Optional authenticated-only data

    Returns:
        Encrypted package as bytes

    Package format:
        [mlkem_ct_len(4 bytes)][mlkem_ct][ephemeral_x25519_pub(32)][nonce(12)][ciphertext]

    The ciphertext includes the GCM authentication tag.
    """
    # Perform hybrid encapsulation
    mlkem_ct, eph_pub_bytes, mlkem_ss, x25519_ss = hybrid_encapsulate(
        mlkem_public_key,
        x25519_public_key_bytes,
    )

    # Derive symmetric key
    derived_key = derive_key(mlkem_ss, x25519_ss)

    # Encrypt message with AES-256-GCM
    nonce, ciphertext = symmetric.encrypt(derived_key, plaintext, associated_data)

    # Package: [mlkem_ct_length(4)][mlkem_ct][eph_x25519_pub(32)][nonce(12)][ciphertext]
    mlkem_len = len(mlkem_ct).to_bytes(4, byteorder="big")
    package = mlkem_len + mlkem_ct + eph_pub_bytes + nonce + ciphertext

    return package


def hybrid_decrypt(
    package: bytes,
    mlkem_secret_key: bytes,
    x25519_private_key,
    associated_data: bytes = None,
) -> bytes:
    """
    Decrypt hybrid KEM package back to plaintext.

    Args:
        package: Encrypted package (output from hybrid_encrypt)
        mlkem_secret_key: Recipient's ML-KEM-768 secret key (2400 bytes)
        x25519_private_key: Recipient's X25519 private key (cryptography object)
        associated_data: Optional authenticated data (must match encryption)

    Returns:
        Plaintext as bytes

    Raises:
        ValueError: If package format is invalid
        RuntimeError: If decapsulation or decryption fails
    """
    # Parse package
    if len(package) < 4 + 1088 + 32 + 12:
        raise ValueError("Package too short for valid hybrid KEM")

    offset = 0

    # Extract ML-KEM ciphertext
    mlkem_len = int.from_bytes(package[offset : offset + 4], byteorder="big")
    offset += 4

    if mlkem_len != 1088:  # ML-KEM-768 ciphertext is always 1088 bytes
        raise ValueError(f"Invalid ML-KEM ciphertext length: {mlkem_len}")

    mlkem_ct = package[offset : offset + mlkem_len]
    offset += mlkem_len

    # Extract ephemeral X25519 public key
    eph_pub_bytes = package[offset : offset + 32]
    offset += 32

    # Extract nonce
    nonce = package[offset : offset + 12]
    offset += 12

    # Remaining is ciphertext
    ciphertext = package[offset:]

    # ML-KEM decapsulation
    mlkem_ss = mlkem.decapsulate(mlkem_secret_key, mlkem_ct, "ML-KEM-768")

    # X25519 exchange
    eph_pub_key = ecdh.public_key_from_bytes(eph_pub_bytes)
    x25519_ss = ecdh.exchange(x25519_private_key, eph_pub_key)

    # Derive symmetric key
    derived_key = derive_key(mlkem_ss, x25519_ss)

    # Decrypt
    plaintext = symmetric.decrypt(derived_key, nonce, ciphertext, associated_data)

    return plaintext


async def re_encrypt_message(
    parsed: ParsedEmail,
    rcpt_tos: list,
) -> bytes:
    """
    Re-encrypt a message from classical (RSA/ECDH/UNENCRYPTED) to hybrid ML-KEM-768 + X25519.

    Phase 4 Implementation:
    1. Extract plaintext from parsed message
    2. Load recipient ML-KEM + X25519 public keys
    3. Call hybrid_encrypt(plaintext, mlkem_pub, x25519_pub)
    4. Wrap in multipart/encrypted PGP/MIME structure
    5. Return new message bytes

    Args:
        parsed: ParsedEmail from parser
        rcpt_tos: List of recipient email addresses

    Returns:
        Bytes of re-encrypted message (or original if not supported)

    Security:
        - If crypto fails, returns original bytes unchanged
        - Caller logs action but never content
    """
    from pqmail.keys.key_manager import KeyManager
    from email.message import EmailMessage
    import base64
    from datetime import datetime
    
    try:
        # Get first recipient's email
        rcpt_email = rcpt_tos[0] if rcpt_tos else None
        if not rcpt_email:
            return parsed.raw_bytes
        
        # Get recipient's ML-KEM + X25519 public keys
        key_manager = KeyManager()
        keys = key_manager.get_keys(rcpt_email)
        if not keys:
            # Recipient doesn't have keys stored; can't upgrade
            return parsed.raw_bytes
        
        # Extract plaintext body for encryption
        plaintext = parsed.body_text
        if not plaintext:
            return parsed.raw_bytes
        
        # Ensure plaintext is bytes
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        # Perform hybrid encryption: ML-KEM-768 + X25519
        encrypted_package = hybrid_encrypt(
            plaintext_bytes,
            keys.mlkem_public_key,
            keys.x25519_public_key,
        )
        
        # Create new EmailMessage with PGP/MIME multipart/encrypted structure
        msg = EmailMessage()
        
        # Copy safe headers from original
        msg['From'] = parsed.headers.get('from', 'unknown@example.com')
        msg['To'] = parsed.headers.get('to', rcpt_email)
        msg['Message-ID'] = parsed.headers.get('message_id', f"<upgraded-{os.urandom(8).hex()}@pqmail>")
        msg['Subject'] = f"[PQMail Hybrid Encrypted] {parsed.headers.get('subject', '(no subject)')}"
        msg['Date'] = datetime.now().isoformat()
        msg['X-PQMail-Upgraded'] = 'true'
        msg['X-PQMail-Algorithm'] = 'hybrid-ml-kem-768-x25519'
        
        # Create multipart/mixed structure (simplifying for the demo instead of strict PGP/MIME)
        msg['Content-Type'] = 'multipart/mixed'
        msg.preamble = "This message contains an ML-KEM-768 + X25519 hybrid encrypted attachment."
        
        # Attach the encrypted data
        encrypted_part = EmailMessage()
        encrypted_part['Content-Type'] = 'application/octet-stream; name="encrypted.asc"'
        encrypted_part['Content-Description'] = 'ML-KEM-768 + X25519 Encrypted Message'
        encrypted_part['Content-Disposition'] = 'attachment; filename="encrypted.asc"'
        encrypted_part['Content-Transfer-Encoding'] = 'base64'
        
        # Encode encrypted package in base64 for MIME transport
        encrypted_b64 = base64.b64encode(encrypted_package).decode('ascii')
        encrypted_part.set_payload(encrypted_b64)
        msg.attach(encrypted_part)
        
        # Convert to bytes
        return msg.as_bytes(unixfrom=False)
        
    except Exception as e:
        # On any error, return original message unchanged
        print(f"[Crypto] Re-encryption failed: {e}")
        return parsed.raw_bytes

