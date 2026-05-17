"""Comprehensive tests for PQMail cryptography module."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
ROOT_STR = str(ROOT)

if ROOT_STR not in sys.path:
    sys.path.insert(0, ROOT_STR)

import pytest

# Try to import liboqs, fall back to mock for MVP testing
try:
    import oqs
except ImportError:
    # For MVP: use mock liboqs when real one is not installed
    # In production Phase 4, this must be replaced with real liboqs-python
    sys.path.insert(0, str(Path(__file__).parent))
    import mock_oqs as oqs

from pqmail.crypto import mlkem, ecdh, symmetric, hybrid_kem


# ============================================================================
# ML-KEM Tests
# ============================================================================


class TestMLKEM:
    """Tests for ML-KEM-768 key encapsulation."""

    def test_generate_keypair(self):
        """Generate ML-KEM-768 keypair."""
        pub, sec = mlkem.generate_keypair("ML-KEM-768")

        assert isinstance(pub, bytes)
        assert isinstance(sec, bytes)
        assert len(pub) == mlkem.ML_KEM_768_PUBLIC_KEY_SIZE
        assert len(sec) == mlkem.ML_KEM_768_SECRET_KEY_SIZE

    def test_encapsulate_decapsulate_roundtrip(self):
        """ML-KEM encapsulate and decapsulate round-trip."""
        pub, sec = mlkem.generate_keypair()

        ct, ss1 = mlkem.encapsulate(pub)
        ss2 = mlkem.decapsulate(sec, ct)

        assert ss1 == ss2
        assert len(ss1) == mlkem.ML_KEM_768_SHARED_SECRET_SIZE

    def test_validate_public_key_valid(self):
        """Validate a correctly formatted public key."""
        pub, _ = mlkem.generate_keypair()

        is_valid = mlkem.validate_public_key(pub)

        assert is_valid is True

    def test_validate_public_key_invalid(self):
        """Reject an invalid public key."""
        is_valid = mlkem.validate_public_key(b"not a valid key")

        assert is_valid is False

    def test_encapsulate_with_invalid_key(self):
        """Encapsulation with invalid key raises error."""
        with pytest.raises(RuntimeError):
            mlkem.encapsulate(b"too short")

    def test_decapsulate_with_invalid_ciphertext(self):
        """Decapsulation with invalid ciphertext raises error."""
        _, sec = mlkem.generate_keypair()

        with pytest.raises(RuntimeError):
            mlkem.decapsulate(sec, b"invalid ciphertext")


# ============================================================================
# X25519 ECDH Tests
# ============================================================================


class TestX25519ECDH:
    """Tests for X25519 elliptic curve Diffie-Hellman."""

    def test_generate_keypair(self):
        """Generate X25519 keypair."""
        priv, pub = ecdh.generate_keypair()

        assert priv is not None
        assert pub is not None

    def test_public_key_serialization(self):
        """Serialize and deserialize X25519 public key."""
        _, pub = ecdh.generate_keypair()

        pub_bytes = ecdh.get_public_key_bytes(pub)
        assert len(pub_bytes) == ecdh.X25519_PUBLIC_KEY_SIZE

        pub_restored = ecdh.public_key_from_bytes(pub_bytes)
        pub_bytes_2 = ecdh.get_public_key_bytes(pub_restored)

        assert pub_bytes == pub_bytes_2

    def test_public_key_from_bytes_invalid(self):
        """Invalid public key bytes raise error."""
        with pytest.raises(ValueError):
            ecdh.public_key_from_bytes(b"too short")

        with pytest.raises(ValueError):
            ecdh.public_key_from_bytes(b"x" * 33)  # Too long

    def test_exchange_produces_same_secret(self):
        """Two-party X25519 exchange produces identical secrets."""
        alice_priv, alice_pub = ecdh.generate_keypair()
        bob_priv, bob_pub = ecdh.generate_keypair()

        # Alice derives secret from Bob's public key
        secret_at_alice = ecdh.exchange(alice_priv, bob_pub)

        # Bob derives secret from Alice's public key
        secret_at_bob = ecdh.exchange(bob_priv, alice_pub)

        # Secrets must match
        assert secret_at_alice == secret_at_bob
        assert len(secret_at_alice) == ecdh.X25519_SHARED_SECRET_SIZE

    def test_exchange_with_bytes(self):
        """Exchange using public key as bytes."""
        alice_priv, alice_pub = ecdh.generate_keypair()
        bob_priv, bob_pub = ecdh.generate_keypair()

        bob_pub_bytes = ecdh.get_public_key_bytes(bob_pub)

        secret1 = ecdh.exchange(alice_priv, bob_pub)
        secret2 = ecdh.exchange_with_bytes(alice_priv, bob_pub_bytes)

        assert secret1 == secret2


# ============================================================================
# Symmetric Encryption Tests
# ============================================================================


class TestSymmetric:
    """Tests for AES-256-GCM symmetric encryption."""

    @pytest.fixture
    def encryption_key(self):
        """32-byte encryption key."""
        return b"x" * 32

    @pytest.fixture
    def plaintext(self):
        """Sample plaintext."""
        return b"This is a confidential financial contract - do not share."

    def test_encrypt_decrypt_roundtrip(self, encryption_key, plaintext):
        """Encrypt and decrypt round-trip."""
        nonce, ciphertext = symmetric.encrypt(encryption_key, plaintext)

        recovered = symmetric.decrypt(encryption_key, nonce, ciphertext)

        assert recovered == plaintext
        assert len(nonce) == symmetric.GCM_NONCE_SIZE

    def test_decrypt_with_wrong_key_fails(self, plaintext):
        """Decryption with wrong key fails."""
        key1 = b"a" * 32
        key2 = b"b" * 32

        nonce, ciphertext = symmetric.encrypt(key1, plaintext)

        with pytest.raises(RuntimeError, match="auth tag mismatch"):
            symmetric.decrypt(key2, nonce, ciphertext)

    def test_decrypt_with_tampered_ciphertext_fails(self, encryption_key, plaintext):
        """Decryption with tampered ciphertext fails."""
        nonce, ciphertext = symmetric.encrypt(encryption_key, plaintext)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF

        with pytest.raises(RuntimeError, match="auth tag mismatch"):
            symmetric.decrypt(encryption_key, nonce, bytes(tampered))

    def test_encrypt_with_associated_data(self, encryption_key, plaintext):
        """Encrypt with authenticated but unencrypted data."""
        associated = b"metadata: sender=alice@example.com"

        nonce, ciphertext = symmetric.encrypt(
            encryption_key,
            plaintext,
            associated_data=associated,
        )

        # Decryption succeeds with same associated data
        recovered = symmetric.decrypt(
            encryption_key,
            nonce,
            ciphertext,
            associated_data=associated,
        )
        assert recovered == plaintext

        # Decryption fails with different associated data
        with pytest.raises(RuntimeError, match="auth tag mismatch"):
            symmetric.decrypt(
                encryption_key,
                nonce,
                ciphertext,
                associated_data=b"different metadata",
            )

    def test_invalid_key_length(self, plaintext):
        """Encryption with invalid key length fails."""
        with pytest.raises(ValueError, match="32 bytes"):
            symmetric.encrypt(b"short key", plaintext)

    def test_invalid_nonce_length(self, encryption_key):
        """Decryption with invalid nonce length fails."""
        with pytest.raises(ValueError, match="12 bytes"):
            symmetric.decrypt(encryption_key, b"short", b"ciphertext")


# ============================================================================
# Hybrid KEM Tests
# ============================================================================


class TestHybridKEM:
    """Tests for hybrid ML-KEM-768 + X25519 composite KEM."""

    @pytest.fixture
    def mlkem_keypair(self):
        """ML-KEM keypair for recipient."""
        return mlkem.generate_keypair("ML-KEM-768")

    @pytest.fixture
    def x25519_keypair(self):
        """X25519 keypair for recipient."""
        priv, pub = ecdh.generate_keypair()
        pub_bytes = ecdh.get_public_key_bytes(pub)
        return priv, pub_bytes

    @pytest.fixture
    def plaintext(self):
        """Sample message."""
        return b"Top secret merger details. Destroy after reading."

    def test_hybrid_encrypt_decrypt_roundtrip(
        self,
        mlkem_keypair,
        x25519_keypair,
        plaintext,
    ):
        """Hybrid encrypt and decrypt round-trip."""
        mlkem_pub, mlkem_sec = mlkem_keypair
        x25519_priv, x25519_pub = x25519_keypair

        # Encrypt
        package = hybrid_kem.hybrid_encrypt(plaintext, mlkem_pub, x25519_pub)

        # Decrypt
        recovered = hybrid_kem.hybrid_decrypt(package, mlkem_sec, x25519_priv)

        assert recovered == plaintext

    def test_package_format_valid(self, mlkem_keypair, x25519_keypair, plaintext):
        """Encrypted package has valid format."""
        mlkem_pub, _ = mlkem_keypair
        _, x25519_pub = x25519_keypair

        package = hybrid_kem.hybrid_encrypt(plaintext, mlkem_pub, x25519_pub)

        # Package must be: [4][1088][32][12][ciphertext]
        min_size = 4 + 1088 + 32 + 12
        assert len(package) >= min_size

        # Extract and verify lengths
        mlkem_len = int.from_bytes(package[:4], byteorder="big")
        assert mlkem_len == 1088

    def test_hybrid_decrypt_with_wrong_key_fails(
        self,
        mlkem_keypair,
        x25519_keypair,
        plaintext,
    ):
        """Decryption with wrong key fails."""
        mlkem_pub, _ = mlkem_keypair
        x25519_priv_1, x25519_pub_1 = x25519_keypair
        _, x25519_pub_2 = ecdh.generate_keypair()
        x25519_pub_2_bytes = ecdh.get_public_key_bytes(x25519_pub_2)

        # Encrypt for x25519_pub_1
        package = hybrid_kem.hybrid_encrypt(plaintext, mlkem_pub, x25519_pub_1)

        # Try to decrypt with different private key (won't work)
        x25519_priv_2, _ = ecdh.generate_keypair()
        with pytest.raises(RuntimeError, match="auth tag mismatch"):
            hybrid_kem.hybrid_decrypt(package, b"x" * 2400, x25519_priv_2)

    def test_hybrid_decrypt_with_invalid_package_fails(self, mlkem_keypair, x25519_keypair):
        """Decryption of malformed package fails."""
        mlkem_pub, mlkem_sec = mlkem_keypair
        x25519_priv, _ = x25519_keypair

        # Too short
        with pytest.raises(ValueError, match="too short"):
            hybrid_kem.hybrid_decrypt(b"short", mlkem_sec, x25519_priv)

    def test_multiple_encryptions_use_different_nonces(
        self,
        mlkem_keypair,
        x25519_keypair,
    ):
        """Multiple encryptions use different nonces."""
        mlkem_pub, _ = mlkem_keypair
        _, x25519_pub = x25519_keypair

        plaintext = b"Message"

        package1 = hybrid_kem.hybrid_encrypt(plaintext, mlkem_pub, x25519_pub)
        package2 = hybrid_kem.hybrid_encrypt(plaintext, mlkem_pub, x25519_pub)

        # Packages must be different (because nonces are random)
        assert package1 != package2

    def test_derive_key_deterministic(self):
        """Key derivation is deterministic."""
        mlkem_ss = b"x" * 32
        x25519_ss = b"y" * 32

        key1 = hybrid_kem.derive_key(mlkem_ss, x25519_ss)
        key2 = hybrid_kem.derive_key(mlkem_ss, x25519_ss)

        assert key1 == key2
        assert len(key1) == 32

    def test_derive_key_differs_with_different_secrets(self):
        """Different input secrets produce different keys."""
        mlkem_ss = b"x" * 32
        x25519_ss = b"y" * 32

        key1 = hybrid_kem.derive_key(mlkem_ss, x25519_ss)
        key2 = hybrid_kem.derive_key(mlkem_ss, b"z" * 32)

        assert key1 != key2


# ============================================================================
# Large Plaintext Test
# ============================================================================


class TestLargePlaintext:
    """Test crypto with large messages."""

    def test_hybrid_encrypt_large_message(self):
        """Encrypt a large message (1 MB)."""
        plaintext = b"x" * (1024 * 1024)  # 1 MB
        mlkem_pub, mlkem_sec = mlkem.generate_keypair()
        x25519_priv, x25519_pub = ecdh.generate_keypair()
        x25519_pub_bytes = ecdh.get_public_key_bytes(x25519_pub)

        # Encrypt
        package = hybrid_kem.hybrid_encrypt(plaintext, mlkem_pub, x25519_pub_bytes)

        # Decrypt
        recovered = hybrid_kem.hybrid_decrypt(package, mlkem_sec, x25519_priv)

        assert recovered == plaintext
        assert len(package) > len(plaintext)  # Overhead from KEM + nonce
