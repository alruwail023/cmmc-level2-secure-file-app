import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ENV = "UPLOAD_ENC_KEY"
KEY_FILE = ".upload_enc_key"


def load_key_from_env(env_var_name=None):
    if env_var_name:
        key_b64 = os.environ.get(env_var_name)
    else:
        key_b64 = os.environ.get(KEY_ENV)

    if key_b64:
        return base64.b64decode(key_b64)

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()

    # Generate a strong 256-bit AES key
    key = AESGCM.generate_key(bit_length=256)
    with open(KEY_FILE, "wb") as f:
        f.write(key)

    print(f"[WARNING] No encryption key provided; generated and saved key to {KEY_FILE}")
    return key


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce (required for AES-GCM)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = blob[:12]
    ciphertext = blob[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

