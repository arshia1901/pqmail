"""
Key Manager for PQMail.

Manages ML-KEM and X25519 public keys for recipients, including:
- Loading/storing keys from disk
- Validating keys before use
- Looking up recipient keys by email address
- In-memory cache for performance
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class RecipientKeys:
    """Public keys for a recipient."""
    email: str
    mlkem_public_key: bytes  # 1184 bytes for ML-KEM-768
    x25519_public_key: bytes  # 32 bytes
    imported_at: str  # ISO timestamp


class KeyManager:
    """Manage recipient public keys."""
    
    def __init__(self, keys_dir: str = ".pqmail/keys"):
        """Initialize key manager with storage directory."""
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache for frequently accessed keys
        self._cache: Dict[str, RecipientKeys] = {}
    
    def store_keys(self, email: str, mlkem_pub: bytes, x25519_pub: bytes) -> None:
        """
        Store recipient's public keys.
        
        Args:
            email: Recipient email address
            mlkem_pub: ML-KEM-768 public key (1184 bytes)
            x25519_pub: X25519 public key (32 bytes)
        
        Raises:
            ValueError: If key sizes are invalid
        """
        if len(mlkem_pub) != 1184:
            raise ValueError(f"ML-KEM public key must be 1184 bytes, got {len(mlkem_pub)}")
        if len(x25519_pub) != 32:
            raise ValueError(f"X25519 public key must be 32 bytes, got {len(x25519_pub)}")
        
        # Normalize email
        email_normalized = email.lower().strip()
        
        # Store to disk as JSON (base64-encoded for binary data)
        import base64
        from datetime import datetime, timezone
        
        key_file = self.keys_dir / f"{email_normalized}.json"
        
        key_data = {
            "email": email_normalized,
            "mlkem_public_key": base64.b64encode(mlkem_pub).decode('ascii'),
            "x25519_public_key": base64.b64encode(x25519_pub).decode('ascii'),
            "imported_at": datetime.now(timezone.utc).isoformat(),
        }
        
        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)
        
        # Update cache
        self._cache[email_normalized] = RecipientKeys(
            email=email_normalized,
            mlkem_public_key=mlkem_pub,
            x25519_public_key=x25519_pub,
            imported_at=key_data["imported_at"],
        )
    
    def get_keys(self, email: str) -> Optional[RecipientKeys]:
        """
        Retrieve recipient's public keys.
        
        Args:
            email: Recipient email address
        
        Returns:
            RecipientKeys if found, None otherwise
        """
        email_normalized = email.lower().strip()
        
        # Check cache first
        if email_normalized in self._cache:
            return self._cache[email_normalized]
        
        # Try to load from disk
        key_file = self.keys_dir / f"{email_normalized}.json"
        if not key_file.exists():
            return None
        
        import base64
        try:
            with open(key_file, 'r') as f:
                key_data = json.load(f)
            
            keys = RecipientKeys(
                email=key_data["email"],
                mlkem_public_key=base64.b64decode(key_data["mlkem_public_key"]),
                x25519_public_key=base64.b64decode(key_data["x25519_public_key"]),
                imported_at=key_data["imported_at"],
            )
            
            # Cache it
            self._cache[email_normalized] = keys
            return keys
        except Exception as e:
            raise RuntimeError(f"Failed to load keys for {email}: {e}")
    
    def has_keys(self, email: str) -> bool:
        """Check if recipient has keys available."""
        return self.get_keys(email) is not None
    
    def delete_keys(self, email: str) -> bool:
        """
        Delete recipient's keys.
        
        Returns:
            True if deleted, False if not found
        """
        email_normalized = email.lower().strip()
        
        key_file = self.keys_dir / f"{email_normalized}.json"
        if key_file.exists():
            key_file.unlink()
            self._cache.pop(email_normalized, None)
            return True
        
        return False
    
    def list_recipients(self) -> list[str]:
        """List all recipients with stored keys."""
        recipients = []
        for key_file in self.keys_dir.glob("*.json"):
            recipients.append(key_file.stem)
        return sorted(recipients)
    
    def export_public_key(self, email: str, key_type: str = "mlkem") -> Optional[bytes]:
        """
        Export a specific public key for a recipient.
        
        Args:
            email: Recipient email
            key_type: "mlkem" or "x25519"
        
        Returns:
            Public key bytes or None if not found
        """
        keys = self.get_keys(email)
        if not keys:
            return None
        
        if key_type.lower() == "mlkem":
            return keys.mlkem_public_key
        elif key_type.lower() == "x25519":
            return keys.x25519_public_key
        else:
            raise ValueError(f"Unknown key type: {key_type}")
    
    def get_mlkem_x25519_pair(self, email: str) -> Optional[Tuple[bytes, bytes]]:
        """
        Get both keys as a tuple for encryption.
        
        Returns:
            (mlkem_pub, x25519_pub) or None if not found
        """
        keys = self.get_keys(email)
        if not keys:
            return None
        return (keys.mlkem_public_key, keys.x25519_public_key)
    
    def clear_cache(self) -> None:
        """Clear in-memory cache (reload from disk next access)."""
        self._cache.clear()
