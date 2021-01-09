import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_key(password):
    salt = b''  #  put your own salt here
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=123210, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt(encryption_key, to_encrypt):
    encrypted = Fernet(encryption_key).encrypt(to_encrypt.encode()).decode('utf-8')
    return encrypted


def decrypt(encryption_key, to_decrypt):
    decrypted = Fernet(encryption_key).decrypt(to_decrypt.encode()).decode('utf-8')
    return decrypted
