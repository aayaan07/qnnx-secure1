from app.crypto.kem import KEMManager


SUPPORTED_KEMS = {name.casefold(): name for name in KEMManager.get_supported_kems()}


def _resolve_algorithm(algorithm: str) -> str:
    normalized_algorithm = algorithm.strip().casefold()
    return SUPPORTED_KEMS.get(normalized_algorithm, algorithm.strip())


def generate_kem_keypair(algorithm: str) -> dict:
    algorithm = _resolve_algorithm(algorithm)
    keys = KEMManager.generate_keypair(algorithm)
    return {
        "algorithm": algorithm,
        "public_key": keys["public_key"],
        "private_key": keys["private_key"],
    }


def encapsulate_secret(algorithm: str, public_key: bytes) -> dict:
    algorithm = _resolve_algorithm(algorithm)
    encap = KEMManager.encapsulate(algorithm, public_key)
    return {
        "algorithm": algorithm,
        "ciphertext": encap["ciphertext"],
        "shared_secret": encap["shared_secret"],
    }


def decapsulate_secret(algorithm: str, ciphertext: bytes, private_key: bytes) -> dict:
    algorithm = _resolve_algorithm(algorithm)
    decap = KEMManager.decapsulate(algorithm, ciphertext, private_key)
    return {
        "algorithm": algorithm,
        "shared_secret": decap["shared_secret"],
    }
