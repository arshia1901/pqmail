# Run this once to generate your keys:
from pqmail.crypto.mlkem import generate_keypair as mlkem_gen
from pqmail.crypto.ecdh import generate_keypair as ecdh_gen, get_public_key_bytes
from pqmail.keys.key_manager import KeyManager

# Generate keypairs
mlkem_pub, mlkem_sec = mlkem_gen()
ecdh_sec, ecdh_pub = ecdh_gen()  # Returns tuple: (private_key, public_key)
x25519_pub = get_public_key_bytes(ecdh_pub)  # Pass the public key

# Store in key manager
km = KeyManager()
km.store_keys("angeleo.angelei@gmail.com", mlkem_pub, x25519_pub)
print("✅ Keys stored and ready for hybrid encryption!")