import hashlib
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.core.exceptions import InvalidApiKey, ApiKeyExpired, ApiKeyRevoked
from app.models.api_key import ApiKey
from app.repositories.api_key_repo import ApiKeyRepository

_api_key_repo = ApiKeyRepository()


def hash_secret(secret: str) -> str:
    """Helper to SHA-256 hash the secret portion of the API key."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_api_key(db: Session, raw_key: str) -> ApiKey:
    """
    Verify a raw API key.

    Format of raw key: qvpn_live_<token>
    where token starts with 12 characters of public key_id prefix,
    followed by the secret portion.

    E.g. key_id = qvpn_live_<token[:12]>
         secret = token[12:]
    """
    if not raw_key.startswith("qvpn_live_"):
        raise InvalidApiKey("Invalid API key prefix")

    token = raw_key[len("qvpn_live_"):]
    if len(token) < 16:  # sanity check to ensure minimum entropy
        raise InvalidApiKey("Invalid API key length")

    # Split into key_id prefix and secret portion
    key_id = "qvpn_live_" + token[:12]
    secret = token[12:]

    # Retrieve the API key record
    api_key = _api_key_repo.get_by_key_id(db, key_id)
    if not api_key:
        raise InvalidApiKey("API key not found")

    # Verify hash match
    expected_hash = hash_secret(secret)
    if api_key.hashed_key != expected_hash:
        raise InvalidApiKey("API key verification failed")

    # Check revoked
    if api_key.revoked_at is not None:
        raise ApiKeyRevoked("API key has been revoked")

    # Check expired
    if api_key.expires_at is not None:
        expires_at_utc = api_key.expires_at
        if expires_at_utc.tzinfo is None:
            expires_at_utc = expires_at_utc.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) > expires_at_utc:
            raise ApiKeyExpired("API key has expired")

    # Update last used timestamp
    _api_key_repo.update_last_used(db, key_id)

    return api_key
