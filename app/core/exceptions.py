"""
Centralized exceptions for the QVPN Gateway.

All HTTP-layer exceptions produce a consistent JSON shape:
  { "error": "<error_type>", "detail": "<human-readable message>" }
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------

class GatewayError(Exception):
    """Base class for all gateway errors."""


class PQCServiceUnavailable(GatewayError):
    """Raised when the PQC API is unreachable or returns a non-retryable error."""


class PQCDecapsulationError(GatewayError):
    """Raised when the PQC API fails to decapsulate a ciphertext."""


class PQCKeygenError(GatewayError):
    """Raised when the PQC API fails to generate a keypair."""


class PQCSigningError(GatewayError):
    """Raised when the PQC API fails to sign a message."""


class PQCVerificationError(GatewayError):
    """Raised when the PQC API fails to verify a signature."""


class HandshakeError(GatewayError):
    """Raised when a VPN handshake cannot be completed."""


class SessionNotFound(GatewayError):
    """Raised when a session_id does not exist or has expired."""


class SessionExpired(GatewayError):
    """Raised when a session exists but its TTL has elapsed."""


class DuplicateHandshake(GatewayError):
    """Raised when a second handshake/complete is attempted for an already-established session."""


class AEADError(GatewayError):
    """Raised on encrypt/decrypt failures (authentication tag mismatch, nonce reuse, etc.)."""


class ClientNotRegistered(GatewayError):
    """Raised when a VPN client_identifier is not found in the DB."""


class InvalidApiKey(GatewayError):
    """Raised when the API key is not valid."""


class ApiKeyExpired(GatewayError):
    """Raised when the API key has expired."""


class ApiKeyRevoked(GatewayError):
    """Raised when the API key has been revoked."""



# ---------------------------------------------------------------------------
# FastAPI exception handlers
# ---------------------------------------------------------------------------

def _json_error(error_type: str, detail: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": error_type, "detail": detail},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """
    Register all gateway exception handlers onto a FastAPI app.
    Call this from main.py after creating the app object.
    """

    @app.exception_handler(PQCServiceUnavailable)
    async def pqc_unavailable_handler(request: Request, exc: PQCServiceUnavailable):
        return _json_error("pqc_service_unavailable", str(exc), 503)

    @app.exception_handler(PQCDecapsulationError)
    async def pqc_decap_handler(request: Request, exc: PQCDecapsulationError):
        return _json_error("pqc_decapsulation_error", str(exc), 502)

    @app.exception_handler(PQCKeygenError)
    async def pqc_keygen_handler(request: Request, exc: PQCKeygenError):
        return _json_error("pqc_keygen_error", str(exc), 502)

    @app.exception_handler(PQCSigningError)
    async def pqc_signing_handler(request: Request, exc: PQCSigningError):
        return _json_error("pqc_signing_error", str(exc), 502)

    @app.exception_handler(PQCVerificationError)
    async def pqc_verification_handler(request: Request, exc: PQCVerificationError):
        return _json_error("pqc_verification_error", str(exc), 502)

    @app.exception_handler(HandshakeError)
    async def handshake_handler(request: Request, exc: HandshakeError):
        return _json_error("handshake_error", str(exc), 400)

    @app.exception_handler(SessionNotFound)
    async def session_not_found_handler(request: Request, exc: SessionNotFound):
        return _json_error("session_not_found", str(exc), 404)

    @app.exception_handler(SessionExpired)
    async def session_expired_handler(request: Request, exc: SessionExpired):
        return _json_error("session_expired", str(exc), 410)

    @app.exception_handler(DuplicateHandshake)
    async def duplicate_handshake_handler(request: Request, exc: DuplicateHandshake):
        return _json_error("duplicate_handshake", str(exc), 409)

    @app.exception_handler(ClientNotRegistered)
    async def client_not_registered_handler(request: Request, exc: ClientNotRegistered):
        return _json_error("client_not_registered", str(exc), 401)

    @app.exception_handler(AEADError)
    async def aead_handler(request: Request, exc: AEADError):
        return _json_error("aead_error", str(exc), 400)

    @app.exception_handler(InvalidApiKey)
    async def invalid_api_key_handler(request: Request, exc: InvalidApiKey):
        return _json_error("invalid_api_key", str(exc), 401)

    @app.exception_handler(ApiKeyExpired)
    async def api_key_expired_handler(request: Request, exc: ApiKeyExpired):
        return _json_error("api_key_expired", str(exc), 403)

    @app.exception_handler(ApiKeyRevoked)
    async def api_key_revoked_handler(request: Request, exc: ApiKeyRevoked):
        return _json_error("api_key_revoked", str(exc), 403)

