import os
import base64
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# --------------- AES-256

def generate_aes_key() -> bytes:
    return os.urandom(32)

def encrypt_aes(plaintext: str, key: bytes) -> Tuple[str, str]:
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    padder = asym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    encrypted = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(encrypted).decode(), base64.b64encode(iv).decode()

def decrypt_aes(encrypted_b64: str, key: bytes, iv_b64: str) -> str:
    encrypted = base64.b64decode(encrypted_b64)
    iv = base64.b64decode(iv_b64)
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = asym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

# --------------------- RSA

def generate_rsa_keypair() -> Tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return public_pem, private_pem

def encrypt_with_rsa(data: bytes, public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_with_rsa(encrypted_b64: str, private_key_pem: str) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    encrypted = base64.b64decode(encrypted_b64)
    return private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

# ------------------ Digital Signature

def sign_note(title: str, content: str, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    payload = f"{title}\n{content}".encode()
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(title: str, content: str, signature_b64: str, public_key_pem: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        payload = f"{title}\n{content}".encode()
        public_key.verify(
            base64.b64decode(signature_b64),
            payload,
            padding.PSS(
                mgf=padding.MGF1(SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            SHA256()
        )
        return True
    except Exception:
        return False