#!/usr/bin/env python3
"""
Setup recipient keys for Option B testing.
Generates and stores ML-KEM-768 + X25519 keypairs for angeleo.angelei@gmail.com
"""

import asyncio
from pqmail.keys.key_manager import KeyManager
from pqmail.crypto import mlkem
from pqmail.crypto import ecdh


async def setup_recipient_keys(recipient_email):
    """Generate and store keys for recipient."""
    
    # recipient_email = "angeleo.angelei@gmail.com"
    
    print(f"🔑 Setting up keys for: {recipient_email}")
    print("=" * 80)
    
    # Initialize key manager
    key_manager = KeyManager()
    
    # Check if keys already exist
    if key_manager.has_keys(recipient_email):
        print(f"⚠️  Keys already exist for {recipient_email}")
        print("Deleting old keys...")
        key_manager.delete_keys(recipient_email)
    
    # Generate ML-KEM-768 keypair
    print("\n🔐 Generating ML-KEM-768 keypair...")
    mlkem_public_key, mlkem_secret_key = mlkem.generate_keypair()
    print(f"✅ ML-KEM public key size: {len(mlkem_public_key)} bytes")
    print(f"✅ ML-KEM secret key size: {len(mlkem_secret_key)} bytes")
    
    # Generate X25519 keypair
    print("\n🔐 Generating X25519 keypair...")
    x25519_private_key, x25519_public_key = ecdh.generate_keypair()
    x25519_public_bytes = ecdh.get_public_key_bytes(x25519_public_key)
    x25519_private_bytes = x25519_private_key.private_bytes_raw()
    print(f"✅ X25519 public key size: {len(x25519_public_bytes)} bytes")
    print(f"✅ X25519 private key size: {len(x25519_private_bytes)} bytes")
    
    # Store in KeyManager (public keys for encryption, private keys saved for decryption demo)
    print(f"\n💾 Storing keys for {recipient_email}...")
    key_manager.store_keys(
        email=recipient_email,
        mlkem_pub=mlkem_public_key,
        x25519_pub=x25519_public_bytes,
        mlkem_secret=mlkem_secret_key,
        x25519_private=x25519_private_bytes
    )
    print(f"✅ Public keys stored successfully")
    
    # Verify retrieval
    print(f"\n🔍 Verifying keys can be retrieved...")
    retrieved_keys = key_manager.get_keys(recipient_email)
    if retrieved_keys:
        print(f"✅ ML-KEM public key retrieved: {len(retrieved_keys.mlkem_public_key)} bytes")
        print(f"✅ X25519 public key retrieved: {len(retrieved_keys.x25519_public_key)} bytes")
        print(f"\n✨ Recipient is ready for UPGRADE action!")
    else:
        print(f"❌ Failed to retrieve keys for {recipient_email}")
        return False
    
    # List all recipients
    print(f"\n📋 All recipients with keys:")
    recipients = key_manager.list_recipients()
    for email in recipients:
        print(f"  - {email}")
    
    return True


if __name__ == "__main__":
    print("Enter recipient email: ")
    recipient_email = input()
    success = asyncio.run(setup_recipient_keys(recipient_email))
    exit(0 if success else 1)
