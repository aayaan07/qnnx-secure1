from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from client.config import HKDF_ALGORITHM, HKDF_KEY_LENGTH, HKDF_SALT, HKDF_INFO

def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derives an AES-256 session key from a shared secret using HKDF.
    Uses parameters defined in client/config.py.
    """
    hkdf = HKDF(
        algorithm=HKDF_ALGORITHM,
        length=HKDF_KEY_LENGTH,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)
