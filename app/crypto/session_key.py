"""
session_key.py — HKDF-based AES-256 session key derivation.

Takes a raw shared_secret (bytes) from the KEM decapsulation and stretches /
domain-separates it into a 32-byte AES-256 key.

Parameters (from settings):
    HKDF_SALT  — a fixed, application-specific salt (bytes).
                  Change this value (and update all connected clients) to rotate
                  the key derivation domain.
    HKDF_INFO  — binding label (bytes) that ties the derived key to this specific
                  use case ("qvpn-tunnel-key-v1"). Must match between gateway and client.

Why HKDF instead of using shared_secret directly?
    - KEM shared secrets may have non-uniform entropy; HKDF extracts and expands it.
    - The info parameter domain-separates tunnel keys from any other keys derived
      from the same KEM material in future use-cases.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings


def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derive a 32-byte AES-256 session key from a KEM shared secret using HKDF-SHA256.

    Args:
        shared_secret: Raw bytes from KEM decapsulation (typically 32 bytes for ML-KEM).

    Returns:
        32-byte AES-256 key suitable for use with AES-GCM.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=settings.HKDF_SALT,
        info=settings.HKDF_INFO,
    )
    return hkdf.derive(shared_secret)
