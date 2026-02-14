import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def load_key_from_env(key_b64=None):
    # If key was passed in (from main.py), decode it
    if key_b64:
        if isinstance(key_b64, str):
            key_b64 = key_b64.strip().encode()
        return base64.b64decode(key_b64)

    # Otherwise, try env var
    key_b64 = os.environ.get(KEY_ENV)
    if key_b64:
        return base64.b64decode(key_b64.strip().encode())

    # Otherwise, fallback to persisted key file
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()

    # Last resort: generate and persist a new 256-bit key
    key = AESGCM.generate_key(bit_length=256)
    with open(KEY_FILE, "wb") as f:
        f.write(key)

    print(f"[WARNING] No encryption key provided; generated and saved key to {KEY_FILE}")
    return key

def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = blob[:12]
    ciphertext = blob[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)
