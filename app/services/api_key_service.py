import hashlib
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.orm import Session

from app.core.exceptions import InvalidApiKey, ApiKeyExpired, ApiKeyRevoked
from app.models.api_key import ApiKey
from app.repositories.api_key_repo import ApiKeyRepository

_api_key_repo = ApiKeyRepository()

# Background executor for fire-and-forget last_used_at updates
_update_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="apikey-update")

# ---------------------------------------------------------------------------
# In-process API key cache (TTL = 60 seconds)
#
# Stores plain dataclass fields — never ORM objects — so there is no
# SQLAlchemy session lifetime concern and no _sa_instance_state needed.
#
# verify_api_key() returns a _CachedKey on both cache-hit and cache-miss paths.
# auth.py reads .api_key_id (the UUID string) from it directly.
#
# Invalidation:
#   - TTL expiry (60 s) — covers key rotation / revocation within one minute
#   - Explicit eviction via invalidate_api_key_cache(raw_key)
# ---------------------------------------------------------------------------

_CACHE_TTL = 60.0  # seconds


@dataclass
class _CachedKey:
    key_id: str
    api_key_id: str           # UUID as str — stored in request.state.api_key_id
    hashed_key: str
    revoked_at: Optional[datetime]
    expires_at: Optional[datetime]
    name: str
    scopes: list
    cached_at: float          # monotonic timestamp


# raw_key → _CachedKey
_cache: dict[str, _CachedKey] = {}
_cache_lock = threading.Lock()


def _cache_get(raw_key: str) -> Optional[_CachedKey]:
    with _cache_lock:
        entry = _cache.get(raw_key)
        if entry is None:
            return None
        if time.monotonic() - entry.cached_at > _CACHE_TTL:
            del _cache[raw_key]
            return None
        return entry


def _cache_set(raw_key: str, api_key: ApiKey) -> None:
    entry = _CachedKey(
        key_id=api_key.key_id,
        api_key_id=str(api_key.id),
        hashed_key=api_key.hashed_key,
        revoked_at=api_key.revoked_at,
        expires_at=api_key.expires_at,
        name=api_key.name,
        scopes=list(api_key.scopes or []),
        cached_at=time.monotonic(),
    )
    with _cache_lock:
        _cache[raw_key] = entry


def invalidate_api_key_cache(raw_key: str) -> None:
    """Immediately evict a key from the cache (call after revoking a key)."""
    with _cache_lock:
        _cache.pop(raw_key, None)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_api_key(db: Session, raw_key: str) -> _CachedKey:
    """
    Verify a raw API key and return a _CachedKey dataclass.

    On cache hit: zero DB calls, returns cached entry immediately.
    On cache miss: queries DB, populates cache, returns entry.
    last_used_at is always updated fire-and-forget in a background thread.

    Raises InvalidApiKey / ApiKeyRevoked / ApiKeyExpired on failure.
    """
    if not raw_key.startswith("qvpn_live_"):
        raise InvalidApiKey("Invalid API key prefix")

    token = raw_key[len("qvpn_live_"):]
    if len(token) < 16:
        raise InvalidApiKey("Invalid API key length")

    key_id = "qvpn_live_" + token[:12]
    secret = token[12:]
    expected_hash = hash_secret(secret)

    # ── Cache hit — zero DB round trips ──────────────────────────────────────
    cached = _cache_get(raw_key)
    if cached is not None:
        if cached.hashed_key != expected_hash:
            raise InvalidApiKey("API key verification failed")
        if cached.revoked_at is not None:
            raise ApiKeyRevoked("API key has been revoked")
        if cached.expires_at is not None:
            exp = cached.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                raise ApiKeyExpired("API key has expired")
        _update_executor.submit(_update_last_used_background, key_id)
        return cached

    # ── Cache miss — query DB ─────────────────────────────────────────────────
    api_key = _api_key_repo.get_by_key_id(db, key_id)
    if not api_key:
        raise InvalidApiKey("API key not found")

    if api_key.hashed_key != expected_hash:
        raise InvalidApiKey("API key verification failed")

    if api_key.revoked_at is not None:
        raise ApiKeyRevoked("API key has been revoked")

    if api_key.expires_at is not None:
        expires_at_utc = api_key.expires_at
        if expires_at_utc.tzinfo is None:
            expires_at_utc = expires_at_utc.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at_utc:
            raise ApiKeyExpired("API key has expired")

    # Populate cache while the ORM object is still session-attached
    _cache_set(raw_key, api_key)
    _update_executor.submit(_update_last_used_background, key_id)

    return _cache_get(raw_key)  # return the just-stored dataclass, not the ORM object


def _update_last_used_background(key_id: str) -> None:
    """Write last_used_at in a background thread — never blocks a request."""
    try:
        from app.core.database import SessionLocal
        db = SessionLocal()
        try:
            _api_key_repo.update_last_used(db, key_id)
        finally:
            db.close()
    except Exception:
        pass
