#!/usr/bin/env python3
"""
PQMail Decryption Tool

This tool simulates the recipient's computer. It loads their private keys
and decrypts an ML-KEM-768 + X25519 hybrid encrypted email attachment.
"""

import sys
import argparse
import base64
from pathlib import Path

from pqmail.keys.key_manager import KeyManager
from pqmail.crypto.hybrid_kem import hybrid_decrypt
from pqmail.crypto import ecdh


def main():
    parser = argparse.ArgumentParser(description="Decrypt a PQMail hybrid encrypted .asc file")
    parser.add_argument("file", help="Path to the encrypted.asc file")
    parser.add_argument("email", help="Recipient email address (must have private keys stored)")
    parser.add_argument("--out", "-o", help="Optional output file for decrypted content", default="decrypted.txt")
    
    args = parser.parse_args()
    
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"❌ Error: File not found: {file_path}")
        sys.exit(1)
        
    print(f"🔍 Loading private keys for: {args.email}")
    km = KeyManager()
    
    private_keys = km.get_private_keys(args.email)
    if not private_keys:
        print(f"❌ Error: Private keys not found for {args.email}")
        print("Make sure you run `python setup_recipient_keys.py` to generate and save private keys first!")
        sys.exit(1)
        
    mlkem_secret_key, x25519_private_bytes = private_keys
    
    print(f"✅ Loaded ML-KEM-768 Secret Key ({len(mlkem_secret_key)} bytes)")
    print(f"✅ Loaded X25519 Private Key ({len(x25519_private_bytes)} bytes)")
    
    # Load the encrypted file
    print(f"\n📂 Reading encrypted file: {file_path}")
    try:
        # Thunderbird automatically base64 decodes the attachment when saving!
        # So it might already be raw binary.
        with open(file_path, "rb") as f:
            raw_content = f.read()
        
        # Try to decode from base64 (if the user manually copied the text)
        try:
            # We must convert to string, remove newlines, and decode
            b64_str = raw_content.decode('ascii').replace('\n', '').replace('\r', '')
            encrypted_package = base64.b64decode(b64_str, validate=True)
            print(f"✅ Extracted and decoded base64 into {len(encrypted_package)} bytes of ciphertext")
        except Exception:
            # If it's not base64, assume it's already the raw binary package!
            encrypted_package = raw_content
            print(f"✅ Read {len(encrypted_package)} bytes of raw binary ciphertext")
            
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        sys.exit(1)
        
    # Reconstruct X25519 private key object
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    x25519_private_key_obj = X25519PrivateKey.from_private_bytes(x25519_private_bytes)

    print("\n🔐 Performing ML-KEM-768 Decapsulation & X25519 Decryption...")
    try:
        plaintext = hybrid_decrypt(
            package=encrypted_package,
            mlkem_secret_key=mlkem_secret_key,
            x25519_private_key=x25519_private_key_obj
        )
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        sys.exit(1)
        
    print("\n✨ DECRYPTION SUCCESSFUL! ✨")
    print("=" * 60)
    
    try:
        text_content = plaintext.decode('utf-8')
        print(text_content)
        
        # Also write to file
        out_path = Path(args.out)
        out_path.write_text(text_content, encoding='utf-8')
        print("=" * 60)
        print(f"📝 Decrypted content also saved to: {out_path.absolute()}")
        
    except UnicodeDecodeError:
        print("<Binary data decrypted successfully but cannot be printed as text>")
        out_path = Path(args.out)
        out_path.write_bytes(plaintext)
        print("=" * 60)
        print(f"📝 Decrypted binary data saved to: {out_path.absolute()}")


if __name__ == "__main__":
    main()
