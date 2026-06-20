from functools import lru_cache
import requests
from app.core.config import settings

@lru_cache(maxsize=1)
def enabled_mechanisms() -> tuple[frozenset[str], frozenset[str]]:
    try:
        api_url = f"{settings.PQC_API_URL.rstrip('/')}/algorithms"
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        kems = []
        signatures = []
        for algo in data.get("algorithms", []):
            name = algo.get("name", "").casefold()
            algo_type = algo.get("type", "").lower()
            if "kem" in algo_type:
                kems.append(name)
            elif "signature" in algo_type or "sig" in algo_type:
                signatures.append(name)
                
        return frozenset(kems), frozenset(signatures)
    except Exception as e:
        # Fallback to standard algorithms if API is down during import or initialization
        fallback_kems = frozenset([
            "ml-kem-512", "ml-kem-768", "ml-kem-1024",
            "kyber512", "kyber768", "kyber1024"
        ])
        fallback_sigs = frozenset([
            "ml-dsa-65", "ml-dsa-87", "falcon-512", "falcon-1024"
        ])
        import logging
        logging.getLogger("qvpn.algo").warning(
            f"Failed to fetch supported algorithms from PQC API, using fallback list: {e}"
        )
        return fallback_kems, fallback_sigs


def algorithm_family(algorithm_type: str | None) -> str | None:
    normalized = (algorithm_type or "").strip().casefold()
    if normalized in {"kem", "key encapsulation"}:
        return "kem"
    if normalized in {"sig", "signature", "dsa"}:
        return "signature"
    return None


def is_algorithm_executable(name: str, algorithm_type: str | None) -> bool:
    kems, signatures = enabled_mechanisms()
    family = algorithm_family(algorithm_type)
    normalized_name = name.strip().casefold()
    if family == "kem":
        return normalized_name in kems
    if family == "signature":
        return normalized_name in signatures
    return normalized_name in kems or normalized_name in signatures
