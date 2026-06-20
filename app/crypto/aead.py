"""
aead.py — AES-256-GCM authenticated encryption helpers for VPN tunnel payloads.

Wire format (encrypted_payload):
    [12-byte nonce][ciphertext + 16-byte GCM auth tag]

Security properties:
    - Each call to encrypt() generates a fresh os.urandom(12) nonce.
    - Callers MUST NOT pass the same nonce twice for the same key.
      This module enforces uniqueness by always generating nonces internally.
    - GCM authentication tag (16 bytes) is included in the ciphertext returned
      by cryptography.hazmat — decrypt() verifies it automatically and raises
      on any tampering.

Usage:
    from app.crypto.aead import encrypt_payload, decrypt_payload

    payload = encrypt_payload(aes_key, b"hello tunnel")
    plaintext = decrypt_payload(aes_key, payload)
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.exceptions import AEADError

NONCE_LEN = 12  # 96-bit GCM nonce — NIST recommended size


def encrypt_payload(aes_key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM using a fresh random nonce.

    Args:
        aes_key:   32-byte AES-256 key (must not be reused across sessions).
        plaintext: Arbitrary bytes to encrypt.

    Returns:
        encrypted_payload = nonce (12 bytes) + ciphertext+tag

    Raises:
        AEADError: If encryption fails.
    """
    if len(aes_key) != 32:
        raise AEADError(f"AES key must be 32 bytes, got {len(aes_key)}")
    try:
        nonce = os.urandom(NONCE_LEN)
        cipher = AESGCM(aes_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    except Exception as exc:
        raise AEADError(f"Encryption failed: {exc}") from exc


def decrypt_payload(aes_key: bytes, encrypted_payload: bytes) -> bytes:
    """
    Decrypt an encrypted_payload produced by encrypt_payload().

    Args:
        aes_key:           32-byte AES-256 key.
        encrypted_payload: nonce (12 bytes) + ciphertext+tag

    Returns:
        Plaintext bytes.

    Raises:
        AEADError: On authentication failure (tampered payload) or malformed input.
    """
    if len(aes_key) != 32:
        raise AEADError(f"AES key must be 32 bytes, got {len(aes_key)}")
    if len(encrypted_payload) < NONCE_LEN + 16:  # 16 = GCM tag min size
        raise AEADError(f"Encrypted payload too short: {len(encrypted_payload)} bytes")
    try:
        nonce = encrypted_payload[:NONCE_LEN]
        ciphertext = encrypted_payload[NONCE_LEN:]
        cipher = AESGCM(aes_key)
        return cipher.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise AEADError("Authentication tag verification failed — payload may be tampered") from exc
    except Exception as exc:
        raise AEADError(f"Decryption failed: {exc}") from exc


def make_aesgcm(aes_key: bytes) -> AESGCM:
    """
    Return a reusable AESGCM cipher object for a given key.

    Useful in the socket server where encrypt/decrypt is called in a tight loop
    and you want to avoid reconstructing the cipher object on every packet.
    """
    if len(aes_key) != 32:
        raise AEADError(f"AES key must be 32 bytes, got {len(aes_key)}")
    return AESGCM(aes_key)
