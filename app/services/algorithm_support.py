from functools import lru_cache


@lru_cache(maxsize=1)
def enabled_mechanisms() -> tuple[frozenset[str], frozenset[str]]:
    import oqs

    kems = frozenset(name.casefold() for name in oqs.get_enabled_kem_mechanisms())
    signatures = frozenset(name.casefold() for name in oqs.get_enabled_sig_mechanisms())
    return kems, signatures


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
