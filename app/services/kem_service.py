"""
kem_service.py — Async KEM service functions.

Thin service layer over KEMManager/pqc_client. New code should call
pqc_client or handshake_service directly.
"""
from app.crypto.kem import KEMManager


SUPPORTED_KEMS = {name.casefold(): name for name in KEMManager.get_supported_kems()}


def _resolve_algorithm(algorithm: str) -> str:
    normalized_algorithm = algorithm.strip().casefold()
    return SUPPORTED_KEMS.get(normalized_algorithm, algorithm.strip())


async def generate_kem_keypair(algorithm: str) -> dict:
    """Async: generate a KEM keypair via the PQC API."""
    algorithm = _resolve_algorithm(algorithm)
    keys = await KEMManager.generate_keypair(algorithm)
    return {
        "algorithm": algorithm,
        "key_id": keys["key_id"],
        "public_key": keys["public_key"],
        "private_key": keys["private_key"],
    }


async def encapsulate_secret(algorithm: str, public_key: bytes) -> dict:
    """Async: encapsulate a shared secret using a public key via the PQC API."""
    from app.crypto.pqc_client import keygen as _keygen
    # Encapsulation is done client-side; the gateway does not call this in production.
    # This exists for testing and administrative tooling only.
    raise NotImplementedError(
        "Encapsulation is the VPN client's responsibility. "
        "The gateway only decapsulates."
    )


async def decapsulate_secret(algorithm: str, ciphertext: bytes, key_id: str) -> dict:
    """Async: decapsulate a KEM ciphertext via the PQC API."""
    algorithm = _resolve_algorithm(algorithm)
    decap = await KEMManager.decapsulate(algorithm, ciphertext, key_id)
    return {
        "algorithm": algorithm,
        "shared_secret": decap["shared_secret"],
    }
