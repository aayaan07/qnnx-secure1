"""
secrets_store.py — Secure, env-independent storage for QVPN client credentials.

The client requires three secrets to operate:
  * GATEWAY_API_KEY     — authenticates REST calls to the Gateway
  * PQC_API_KEY         — Bearer token for the PQC API
  * PQC_SIGNING_SECRET  — HMAC signing secret for PQC signed-request auth

Historically these were read from a .env file, which is insecure (plaintext on
disk, easy to leak) and makes the build environment-dependent. They are now
stored in the OS credential vault via the `keyring` library. On Windows this is
the Windows Credential Manager, so the values are encrypted at rest under the
user's login and never touch the project directory.

First run flow:
  1. UI shows a setup modal (device id is pre-filled from the hostname).
  2. User enters the three secrets.
  3. `verify_credentials()` proves they actually work against the live
     Gateway + PQC APIs (real handshake init + PQC keygen).
  4. Only on success are they written to keyring via `store_credentials()`.

Subsequent runs read them straight from keyring — no user interaction needed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timezone

import httpx
import keyring

# Transient network/DNS failures (e.g. a flaky resolver returning a brief
# NXDOMAIN, or a dropped connection) should not fail credential setup on the
# first attempt. We retry the reachability POSTs a few times with backoff.
# Genuine auth failures (401/403) and HTTP error responses are NOT retried —
# they come back as a normal response, not a RequestError.
_HTTP_RETRIES = 3
_HTTP_RETRY_BACKOFF = 1.0  # seconds, multiplied by attempt number

logger = logging.getLogger("QVPN_Secrets")

# Service name (namespace) under which all QVPN secrets live in the OS vault.
_SERVICE = "QVPN"

# Keys under the service namespace.
KEY_GATEWAY_API_KEY = "GATEWAY_API_KEY"
KEY_PQC_API_KEY = "PQC_API_KEY"
KEY_PQC_SIGNING_SECRET = "PQC_SIGNING_SECRET"

_ALL_KEYS = (KEY_GATEWAY_API_KEY, KEY_PQC_API_KEY, KEY_PQC_SIGNING_SECRET)


# ---------------------------------------------------------------------------
# Keyring read / write
# ---------------------------------------------------------------------------
def load_credentials() -> dict[str, str | None]:
    """Return the three secrets from the OS vault (values may be None if unset)."""
    return {key: keyring.get_password(_SERVICE, key) for key in _ALL_KEYS}


def credentials_present() -> bool:
    """True only when all three secrets exist and are non-empty in the vault."""
    creds = load_credentials()
    return all(creds.get(k) for k in _ALL_KEYS)


def store_credentials(gateway_api_key: str, pqc_api_key: str, pqc_signing_secret: str) -> None:
    """Persist the three secrets to the OS credential vault."""
    keyring.set_password(_SERVICE, KEY_GATEWAY_API_KEY, gateway_api_key)
    keyring.set_password(_SERVICE, KEY_PQC_API_KEY, pqc_api_key)
    keyring.set_password(_SERVICE, KEY_PQC_SIGNING_SECRET, pqc_signing_secret)
    logger.info("Credentials stored securely in OS credential vault (service=%s).", _SERVICE)


def clear_credentials() -> None:
    """Remove all QVPN secrets from the OS vault. Used by 'reset credentials'."""
    for key in _ALL_KEYS:
        try:
            keyring.delete_password(_SERVICE, key)
        except keyring.errors.PasswordDeleteError:
            pass  # Not set — nothing to delete.
    logger.info("Credentials cleared from OS credential vault.")


# ---------------------------------------------------------------------------
# Verification against live services (run BEFORE storing)
# ---------------------------------------------------------------------------
def _sign_pqc_request(method: str, path: str, timestamp: str, nonce: str,
                      body_bytes: bytes, secret: str) -> str:
    payload = (
        method.upper().encode("utf-8")
        + path.encode("utf-8")
        + timestamp.encode("utf-8")
        + nonce.encode("utf-8")
        + body_bytes
    )
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _post_with_retry(url: str, *, service_name: str, build_kwargs=None, **kwargs) -> httpx.Response:
    """POST with retries on transient connection/DNS errors.

    Retries only on httpx.RequestError (connection refused, DNS failure,
    timeout). Any HTTP status (including 401/403) is returned to the caller —
    those are decided upstream and never retried here. Raises ValueError with a
    user-facing message if all attempts fail to connect.

    `build_kwargs`, if given, is a callable returning the per-attempt request
    kwargs. Used for signed requests so a fresh timestamp/nonce/signature is
    generated on each retry (avoids server-side clock-skew/replay rejection).
    """
    last_exc: httpx.RequestError | None = None
    for attempt in range(1, _HTTP_RETRIES + 1):
        try:
            call_kwargs = build_kwargs() if build_kwargs is not None else kwargs
            return httpx.post(url, **call_kwargs)
        except httpx.RequestError as exc:
            last_exc = exc
            logger.warning("%s reachability attempt %d/%d failed: %s",
                           service_name, attempt, _HTTP_RETRIES, exc)
            if attempt < _HTTP_RETRIES:
                time.sleep(_HTTP_RETRY_BACKOFF * attempt)
    raise ValueError(
        f"Could not reach the {service_name} at {url} after {_HTTP_RETRIES} attempts. "
        f"Check your internet connection and try again. ({last_exc})"
    )


def _verify_gateway_key(gateway_api_url: str, gateway_api_key: str,
                        client_identifier: str) -> None:
    """Prove GATEWAY_API_KEY works by running a real /handshake/init call.

    A wrong key returns 401/403; a correct key returns 200 (the gateway
    auto-registers the client). Raises ValueError with a user-facing message
    on any failure.
    """
    url = f"{gateway_api_url}/handshake/init"
    resp = _post_with_retry(
        url,
        service_name="Gateway",
        json={"client_identifier": client_identifier},
        headers={"X-API-Key": gateway_api_key},
        timeout=15.0,
    )

    if resp.status_code in (401, 403):
        raise ValueError("Gateway rejected the API key (unauthorized). Check GATEWAY_API_KEY.")
    if resp.status_code != 200:
        raise ValueError(
            f"Gateway verification failed (HTTP {resp.status_code}): {resp.text[:200]}"
        )


def _verify_pqc_keys(pqc_api_url: str, pqc_api_key: str, pqc_signing_secret: str) -> None:
    """Prove PQC_API_KEY + PQC_SIGNING_SECRET work by running a real /keygen call.

    Both secrets are exercised together: the Bearer token authenticates and the
    signing secret produces the HMAC signature. A wrong key or secret yields
    401/signature-verification errors. Raises ValueError on failure.
    """
    path = "/api/v1/keygen"
    url = f"{pqc_api_url}/keygen"

    body_bytes = json.dumps(
        {"algorithm": "ML-KEM-768", "storage_mode": "customer_managed"},
        separators=(",", ":"),
    ).encode("utf-8")

    def _build_kwargs() -> dict:
        # Fresh timestamp/nonce/signature per attempt so a retry isn't rejected
        # for clock skew or nonce replay.
        timestamp = datetime.now(timezone.utc).isoformat()
        if timestamp.endswith("+00:00"):
            timestamp = timestamp[:-6] + "Z"
        nonce = str(uuid.uuid4())
        signature = _sign_pqc_request("POST", path, timestamp, nonce, body_bytes, pqc_signing_secret)
        headers = {
            "Authorization": f"Bearer {pqc_api_key}",
            "X-QNNX-Timestamp": timestamp,
            "X-QNNX-Nonce": nonce,
            "X-QNNX-Signature": signature,
            "Content-Type": "application/json",
        }
        return {"content": body_bytes, "headers": headers, "timeout": 15.0}

    resp = _post_with_retry(url, service_name="PQC API", build_kwargs=_build_kwargs)

    if resp.status_code in (401, 403):
        raise ValueError("PQC API rejected the key or signature. Check PQC_API_KEY and PQC_SIGNING_SECRET.")
    if resp.status_code != 200:
        raise ValueError(
            f"PQC API verification failed (HTTP {resp.status_code}): {resp.text[:200]}"
        )


def verify_credentials(*, gateway_api_url: str, pqc_api_url: str,
                       client_identifier: str, gateway_api_key: str,
                       pqc_api_key: str, pqc_signing_secret: str) -> None:
    """Verify all three secrets against the live services.

    Raises ValueError (with a user-facing message) if any secret is missing or
    invalid. Returns None on success.
    """
    if not gateway_api_key or not pqc_api_key or not pqc_signing_secret:
        raise ValueError("All three fields are required.")

    _verify_gateway_key(gateway_api_url, gateway_api_key, client_identifier)
    _verify_pqc_keys(pqc_api_url, pqc_api_key, pqc_signing_secret)
    logger.info("All credentials verified successfully against live services.")
