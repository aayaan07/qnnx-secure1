"""
pqc_client.py — Async HTTP client for the QVPN PQC API service.

All cryptographic key operations (keygen, decapsulate) happen here.
The gateway NEVER holds raw private key bytes — only the key_id reference
returned by the PQC service.

Endpoints assumed on the PQC service:
  POST /keygen        → KeygenResponse
  POST /kem/decapsulate → DecapsulationResponse

Both endpoints require HMAC-SHA256 signed requests (see HOW.md).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings
from app.core.exceptions import (
    PQCDecapsulationError,
    PQCKeygenError,
    PQCServiceUnavailable,
    PQCSigningError,
    PQCVerificationError,
)

logger = logging.getLogger("qvpn.pqc_client")

# ---------------------------------------------------------------------------
# Pydantic models for PQC API request/response
# ---------------------------------------------------------------------------


class KeygenRequest(BaseModel):
    algorithm: str
    storage_mode: str = "customer_managed"


class KeygenResponse(BaseModel):
    """
    Response from POST /keygen.

    When storage_mode='customer_managed', the PQC service returns the raw
    public key and key_id reference.
    """
    key_id: str
    algorithm: str
    public_key: str   # base64-encoded
    private_key: str | None = None  # Make optional/None since PQC API no longer returns it


class DecapsulationRequest(BaseModel):
    algorithm: str
    ciphertext: str    # base64-encoded
    private_key: str   # key_id reference; PQC API field name is private_key


class DecapsulationResponse(BaseModel):
    algorithm: str
    shared_secret: str  # base64-encoded


class SigningRequest(BaseModel):
    algorithm: str
    message: str
    private_key: str   # key_id reference; PQC API field name is private_key


class SigningResponse(BaseModel):
    signature: str


class VerificationRequest(BaseModel):
    algorithm: str
    message: str
    signature: str
    public_key: str


class VerificationResponse(BaseModel):
    is_valid: bool


# ---------------------------------------------------------------------------
# HMAC-SHA256 request signing (per HOW.md)
# ---------------------------------------------------------------------------


def _build_signature(method: str, path: str, timestamp: str, nonce: str, body_bytes: bytes) -> str:
    payload = (
        method.upper().encode("utf-8")
        + path.encode("utf-8")
        + timestamp.encode("utf-8")
        + nonce.encode("utf-8")
        + body_bytes
    )
    return hmac.new(
        settings.QNNX_SIGNING_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()


def _signed_headers(method: str, path: str, body_bytes: bytes) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).isoformat()
    if timestamp.endswith("+00:00"):
        timestamp = timestamp[:-6] + "Z"
    nonce = str(uuid.uuid4())
    signature = _build_signature(method, path, timestamp, nonce, body_bytes)
    return {
        "Authorization": f"Bearer {settings.QNNX_API_KEY}",
        "X-QNNX-Timestamp": timestamp,
        "X-QNNX-Nonce": nonce,
        "X-QNNX-Signature": signature,
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# Retry predicate — only retry on transient failures
# ---------------------------------------------------------------------------

def _is_transient(exc: BaseException) -> bool:
    if isinstance(exc, (httpx.ConnectError, httpx.TimeoutException)):
        return True
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code >= 500:
        return True
    return False


_retry_decorator = retry(
    retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError)),
    stop=stop_after_attempt(settings.PQC_RETRY_ATTEMPTS),
    wait=wait_exponential(multiplier=settings.PQC_RETRY_WAIT_SECONDS, min=0.2, max=5.0),
    reraise=True,
)


# ---------------------------------------------------------------------------
# The client — use as an async context manager or via module-level helpers
# ---------------------------------------------------------------------------


class PQCClient:
    """
    Async HTTP client wrapping the PQC API service.

    Usage (within an async function):
        async with PQCClient() as client:
            response = await client.keygen("ML-KEM-768")

    Or use the module-level helpers (keygen / decapsulate) which create a
    fresh client per call — suitable for low-traffic paths like handshake init.
    """

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "PQCClient":
        self._client = httpx.AsyncClient(timeout=settings.PQC_TIMEOUT_SECONDS)
        return self

    async def __aexit__(self, *_) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _resolve(self, endpoint: str) -> tuple[str, str]:
        """Returns (api_url, path) for an endpoint name like 'keygen'."""
        parsed = urlparse(settings.PQC_API_URL)
        path = f"{parsed.path.rstrip('/')}/{endpoint.lstrip('/')}"
        api_url = f"{settings.PQC_API_URL.rstrip('/')}/{endpoint.lstrip('/')}"
        return api_url, path

    async def _post(self, endpoint: str, body: dict) -> dict:
        assert self._client is not None, "PQCClient must be used as a context manager"
        body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
        api_url, path = self._resolve(endpoint)
        headers = _signed_headers("POST", path, body_bytes)

        try:
            response = await self._client.post(api_url, content=body_bytes, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.ConnectError as exc:
            raise PQCServiceUnavailable(f"Cannot reach PQC API at {api_url}: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise PQCServiceUnavailable(f"PQC API timed out after {settings.PQC_TIMEOUT_SECONDS}s: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            body_text = exc.response.text[:200]
            if status >= 500:
                raise PQCServiceUnavailable(f"PQC API returned {status}: {body_text}") from exc
            raise  # 4xx — let callers handle

    async def keygen(self, algorithm: str) -> KeygenResponse:
        """
        Request a new keypair from the PQC service.

        Returns a KeygenResponse containing key_id, public_key (b64).
        """
        body = KeygenRequest(algorithm=algorithm, storage_mode="sentinel_managed").model_dump()
        try:
            data = await self._post("keygen", body)
            return KeygenResponse(**data)
        except PQCServiceUnavailable:
            raise
        except Exception as exc:
            raise PQCKeygenError(f"Keygen failed for {algorithm}: {exc}") from exc

    async def decapsulate(self, algorithm: str, ciphertext_bytes: bytes, key_id: str) -> bytes:
        """
        Ask the PQC service to decapsulate a KEM ciphertext using the key_id reference.

        Returns the raw shared_secret bytes.
        """
        body = DecapsulationRequest(
            algorithm=algorithm,
            ciphertext=base64.b64encode(ciphertext_bytes).decode("ascii"),
            private_key=key_id,
        ).model_dump()
        try:
            data = await self._post("kem/decapsulate", body)
            resp = DecapsulationResponse(**data)
            return base64.b64decode(resp.shared_secret)
        except PQCServiceUnavailable:
            raise
        except Exception as exc:
            raise PQCDecapsulationError(f"Decapsulation failed for {algorithm}: {exc}") from exc

    async def sign(self, algorithm: str, message: str, key_id: str) -> str:
        """
        Ask the PQC service to sign a message using the key ID reference.

        Returns the signature string.
        """
        body = SigningRequest(
            algorithm=algorithm,
            message=message,
            private_key=key_id,
        ).model_dump()
        try:
            data = await self._post("sign", body)
            resp = SigningResponse(**data)
            return resp.signature
        except PQCServiceUnavailable:
            raise
        except Exception as exc:
            raise PQCSigningError(f"Signing failed for {algorithm}: {exc}") from exc

    async def verify(self, algorithm: str, message: str, signature: str, public_key: str) -> bool:
        """
        Ask the PQC service to verify a signature.

        Returns whether the signature is valid.
        """
        body = VerificationRequest(
            algorithm=algorithm,
            message=message,
            signature=signature,
            public_key=public_key,
        ).model_dump()
        try:
            data = await self._post("verify", body)
            resp = VerificationResponse(**data)
            return resp.is_valid
        except PQCServiceUnavailable:
            raise
        except Exception as exc:
            raise PQCVerificationError(f"Verification failed for {algorithm}: {exc}") from exc


# ---------------------------------------------------------------------------
# Convenience module-level helpers (create a fresh client per call)
# ---------------------------------------------------------------------------


async def keygen(algorithm: str) -> KeygenResponse:
    """Module-level shortcut — creates a short-lived client and calls keygen."""
    async with PQCClient() as client:
        return await client.keygen(algorithm)


async def decapsulate(algorithm: str, ciphertext_bytes: bytes, key_id: str) -> bytes:
    """Module-level shortcut — creates a short-lived client and decapsulates."""
    async with PQCClient() as client:
        return await client.decapsulate(algorithm, ciphertext_bytes, key_id)


async def sign(algorithm: str, message: str, key_id: str) -> str:
    """Module-level shortcut — creates a short-lived client and signs."""
    async with PQCClient() as client:
        return await client.sign(algorithm, message, key_id)


async def verify(algorithm: str, message: str, signature: str, public_key: str) -> bool:
    """Module-level shortcut — creates a short-lived client and verifies."""
    async with PQCClient() as client:
        return await client.verify(algorithm, message, signature, public_key)
