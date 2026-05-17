"""Tests for Key Manager."""

from pathlib import Path
import sys
import tempfile
import shutil

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from pqmail.keys.key_manager import KeyManager, RecipientKeys


@pytest.fixture
def temp_keys_dir():
    """Create temporary keys directory for testing."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir)


@pytest.fixture
def key_manager(temp_keys_dir):
    """Create key manager with temporary directory."""
    return KeyManager(keys_dir=temp_keys_dir)


@pytest.fixture
def sample_keys():
    """Sample key material for testing."""
    return {
        "mlkem_pub": b"x" * 1184,  # ML-KEM-768 public key
        "x25519_pub": b"y" * 32,   # X25519 public key
    }


def test_store_and_retrieve_keys(key_manager, sample_keys):
    """Test storing and retrieving keys."""
    email = "alice@example.com"
    
    key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    keys = key_manager.get_keys(email)
    assert keys is not None
    assert keys.email == "alice@example.com"
    assert keys.mlkem_public_key == sample_keys["mlkem_pub"]
    assert keys.x25519_public_key == sample_keys["x25519_pub"]


def test_email_normalization(key_manager, sample_keys):
    """Test that emails are normalized (lowercased, stripped)."""
    key_manager.store_keys("Alice@EXAMPLE.COM", sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    keys = key_manager.get_keys("  alice@example.com  ")
    assert keys is not None
    assert keys.email == "alice@example.com"


def test_invalid_mlkem_key_size(key_manager):
    """Test that invalid ML-KEM key size is rejected."""
    with pytest.raises(ValueError, match="ML-KEM public key must be 1184 bytes"):
        key_manager.store_keys("bob@example.com", b"too short", b"y" * 32)


def test_invalid_x25519_key_size(key_manager):
    """Test that invalid X25519 key size is rejected."""
    with pytest.raises(ValueError, match="X25519 public key must be 32 bytes"):
        key_manager.store_keys("bob@example.com", b"x" * 1184, b"too short")


def test_keys_not_found(key_manager):
    """Test retrieving non-existent keys."""
    keys = key_manager.get_keys("nonexistent@example.com")
    assert keys is None


def test_has_keys(key_manager, sample_keys):
    """Test has_keys method."""
    email = "charlie@example.com"
    
    assert not key_manager.has_keys(email)
    
    key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    assert key_manager.has_keys(email)


def test_delete_keys(key_manager, sample_keys):
    """Test deleting keys."""
    email = "diana@example.com"
    
    key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    assert key_manager.has_keys(email)
    
    deleted = key_manager.delete_keys(email)
    assert deleted is True
    assert not key_manager.has_keys(email)


def test_delete_nonexistent_keys(key_manager):
    """Test deleting keys that don't exist."""
    deleted = key_manager.delete_keys("nonexistent@example.com")
    assert deleted is False


def test_list_recipients(key_manager, sample_keys):
    """Test listing all recipients."""
    emails = ["alice@example.com", "bob@example.com", "charlie@example.com"]
    
    for email in emails:
        key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    recipients = key_manager.list_recipients()
    assert len(recipients) == 3
    assert "alice@example.com" in recipients
    assert "bob@example.com" in recipients
    assert "charlie@example.com" in recipients


def test_in_memory_cache(key_manager, sample_keys):
    """Test that keys are cached in memory."""
    email = "eva@example.com"
    
    key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    # First retrieval loads from disk to cache
    keys1 = key_manager.get_keys(email)
    
    # Second retrieval should come from cache
    keys2 = key_manager.get_keys(email)
    
    assert keys1 is keys2  # Same object


def test_export_mlkem_key(key_manager, sample_keys):
    """Test exporting ML-KEM public key."""
    email = "frank@example.com"
    key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    key = key_manager.export_public_key(email, "mlkem")
    assert key == sample_keys["mlkem_pub"]


def test_export_x25519_key(key_manager, sample_keys):
    """Test exporting X25519 public key."""
    email = "grace@example.com"
    key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    key = key_manager.export_public_key(email, "x25519")
    assert key == sample_keys["x25519_pub"]


def test_export_invalid_key_type(key_manager, sample_keys):
    """Test exporting with invalid key type."""
    email = "henry@example.com"
    key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    with pytest.raises(ValueError, match="Unknown key type"):
        key_manager.export_public_key(email, "invalid")


def test_export_nonexistent_key(key_manager):
    """Test exporting from non-existent recipient."""
    key = key_manager.export_public_key("nonexistent@example.com", "mlkem")
    assert key is None


def test_get_mlkem_x25519_pair(key_manager, sample_keys):
    """Test getting both keys as a tuple."""
    email = "iris@example.com"
    key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    pair = key_manager.get_mlkem_x25519_pair(email)
    assert pair is not None
    mlkem_pub, x25519_pub = pair
    assert mlkem_pub == sample_keys["mlkem_pub"]
    assert x25519_pub == sample_keys["x25519_pub"]


def test_get_mlkem_x25519_pair_nonexistent(key_manager):
    """Test getting pair for non-existent recipient."""
    pair = key_manager.get_mlkem_x25519_pair("nonexistent@example.com")
    assert pair is None


def test_clear_cache(key_manager, sample_keys):
    """Test clearing in-memory cache."""
    email = "jack@example.com"
    key_manager.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    # Load into cache
    keys1 = key_manager.get_keys(email)
    
    # Clear cache
    key_manager.clear_cache()
    
    # Next retrieval should reload from disk
    keys2 = key_manager.get_keys(email)
    
    assert keys1 is not keys2  # Different objects
    assert keys1.mlkem_public_key == keys2.mlkem_public_key  # But same content


def test_persistence_across_instances(temp_keys_dir, sample_keys):
    """Test that keys persist across KeyManager instances."""
    email = "kate@example.com"
    
    # First instance stores keys
    km1 = KeyManager(keys_dir=temp_keys_dir)
    km1.store_keys(email, sample_keys["mlkem_pub"], sample_keys["x25519_pub"])
    
    # Second instance reads same keys
    km2 = KeyManager(keys_dir=temp_keys_dir)
    keys = km2.get_keys(email)
    
    assert keys is not None
    assert keys.mlkem_public_key == sample_keys["mlkem_pub"]
    assert keys.x25519_public_key == sample_keys["x25519_pub"]
