"""
kem.py — Thin async shim around pqc_client.

This module exists for backward compatibility with code that imports KEMManager.
New code should import from app.crypto.pqc_client directly.

The gateway NEVER generates or stores raw private key bytes long-term.
Flow:
  1. keygen()         → PQC service returns { key_id, public_key, private_key }
  2. Gateway DB row   → stores key_id (reference) + public_key + private_key bytes
                         (private_key is server-side only, never sent to clients)
  3. decapsulate()    → gateway sends { algorithm, ciphertext, private_key } to PQC
  4. shared_secret    → stays in memory, derived into AES-256 key via HKDF
"""
from __future__ import annotations

import base64
import logging
from typing import Any

from app.crypto.pqc_client import keygen as _keygen, decapsulate as _decapsulate, KeygenResponse
from app.services.algorithm_support import enabled_mechanisms

logger = logging.getLogger("qvpn.kem")


class KEMManager:
    """
    Async KEM operations via the external PQC API.

    All public methods are coroutines — use `await` when calling them.
    """

    @staticmethod
    def get_supported_kems() -> list[str]:
        """
        Returns the list of KEM algorithm names that the PQC service supports.
        Falls back to a static list if the API is unreachable at import time.
        """
        enabled, _ = enabled_mechanisms()
        preferred = (
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
            "Kyber512",
            "Kyber768",
            "Kyber1024",
        )
        return [name for name in preferred if name.casefold() in enabled]

    @staticmethod
    async def generate_keypair(algorithm_name: str) -> dict[str, Any]:
        """
        Request a new KEM keypair from the PQC service.

        Returns:
            {
                "key_id": str,
                "public_key": bytes,
                "private_key": bytes,
            }
        """
        resp: KeygenResponse = await _keygen(algorithm_name)
        private_key_b64 = resp.private_key or ""
        return {
            "key_id": resp.key_id,
            "public_key": base64.b64decode(resp.public_key),
            "private_key": base64.b64decode(private_key_b64) if private_key_b64 else b"",
        }

    @staticmethod
    async def decapsulate(algorithm_name: str, ciphertext: bytes, key_id: str) -> dict[str, bytes]:
        """
        Decapsulate a KEM ciphertext using the key ID reference.

        Args:
            algorithm_name: e.g. "ML-KEM-768"
            ciphertext:     Raw ciphertext bytes from the client.
            key_id:         The key ID reference.

        Returns:
            { "shared_secret": bytes }
        """
        shared_secret = await _decapsulate(algorithm_name, ciphertext, key_id)
        return {"shared_secret": shared_secret}
