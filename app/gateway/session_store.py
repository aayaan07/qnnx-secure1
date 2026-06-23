"""
session_store.py — In-memory TTL cache for AES-256 session keys.

AES session keys MUST NOT be persisted to any database or file.
This module provides a thread-safe, TTL-aware store keyed by session_id (str).

Design:
    - Uses cachetools.TTLCache internally; the TTL is SESSION_TTL_SECONDS.
    - Thread-safe via threading.Lock (asyncio tasks + to_thread bridges may
      access this from multiple threads).
    - Keys are automatically evicted after TTL elapses since last insertion.
    - Explicit evict() is called when a session closes so memory is freed
      immediately rather than waiting for the TTL.

Usage:
    from app.gateway.session_store import session_store

    # Store an AES key (bytes)
    session_store.put(session_id, aes_key)

    # Retrieve (returns None if missing/expired)
    aes_key = session_store.get(session_id)

    # Explicitly remove on disconnect
    session_store.evict(session_id)

    # Snapshot all live session IDs (for reconciliation — no keys exposed)
    ids = session_store.active_session_ids()
"""
from __future__ import annotations

import logging
import threading

from cachetools import TTLCache

from app.core.config import settings

logger = logging.getLogger("qvpn.session_store")


class SessionKeyStore:
    """
    Thread-safe TTL cache for AES-256 session keys.

    Maximum capacity is set to 10_000 sessions — adjust if the gateway
    is expected to handle more concurrent tunnels.
    """

    MAX_SESSIONS = 10_000

    def __init__(self, ttl_seconds: int | None = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else settings.SESSION_TTL_SECONDS
        self._cache: TTLCache = TTLCache(maxsize=self.MAX_SESSIONS, ttl=ttl)
        self._lock = threading.Lock()

    def put(self, session_id: str, aes_key: bytes) -> None:
        """
        Store an AES-256 key for session_id.

        Overwrites any existing key for the same session_id (safe for re-handshake).
        """
        if len(aes_key) != 32:
            raise ValueError(f"AES key must be 32 bytes, got {len(aes_key)}")
        with self._lock:
            self._cache[session_id] = aes_key
        logger.debug("[SESSION_STORE] Stored AES key for session=%s", session_id)

    def get(self, session_id: str) -> bytes | None:
        """
        Retrieve the AES key for session_id.

        Returns None if the key is missing or has expired.
        """
        with self._lock:
            return self._cache.get(session_id)

    def evict(self, session_id: str) -> None:
        """
        Explicitly remove an AES key from the store.

        Call this when a session closes or times out — don't wait for the TTL.
        """
        with self._lock:
            self._cache.pop(session_id, None)
        logger.debug("[SESSION_STORE] Evicted AES key for session=%s", session_id)

    def size(self) -> int:
        """Return the current number of active keys in the store."""
        with self._lock:
            return len(self._cache)

    def active_session_ids(self) -> list[str]:
        """
        Return a point-in-time snapshot of all session IDs currently held in the store.

        Keys are NOT exposed — this is safe to pass to background tasks or logging.
        The list is a copy; mutations to it do not affect the store.
        Used by the reconciliation task to cross-check live memory state against the DB.
        """
        with self._lock:
            return list(self._cache.keys())

    def __contains__(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._cache


# Module-level singleton
session_store = SessionKeyStore()
