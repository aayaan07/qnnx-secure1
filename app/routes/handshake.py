"""
routes/handshake.py — REST API for the two-phase VPN handshake.

Endpoints:
  POST /api/v1/handshake/init      — Phase 1: generate keypair, return public_key
  POST /api/v1/handshake/complete  — Phase 2: decapsulate ciphertext, return session_id

These endpoints are called by the VPN client management layer BEFORE the
raw TCP socket connection. The flow is:

  1. Client calls POST /handshake/init  → receives { session_id, public_key }
  2. Client generates ciphertext by encapsulating a shared secret using public_key
  3. Client opens TCP connection to port 5151, sends session_id + ciphertext
  4. Gateway's socket_server.py calls handshake_service.complete_handshake()
     internally (the POST /handshake/complete endpoint is an alternative
     REST-only path for clients that don't use the raw TCP tunnel)

Both endpoints are protected by the standard request authentication flow
(via the Authorization header or API key — extend with your auth middleware).
"""
from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session as DBSession

from app.core.database import get_db
from app.core.exceptions import (
    ClientNotRegistered,
    DuplicateHandshake,
    HandshakeError,
    PQCDecapsulationError,
    PQCKeygenError,
    PQCServiceUnavailable,
    SessionNotFound,
)
from app.services.handshake_service import init_handshake, complete_handshake

logger = logging.getLogger("qvpn.routes.handshake")

router = APIRouter(prefix="/handshake", tags=["Handshake"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class HandshakeInitRequest(BaseModel):
    client_identifier: str


class HandshakeInitResponse(BaseModel):
    session_id: str
    algorithm: str
    public_key: str  # base64-encoded; send to VPN client for encapsulation


class HandshakeCompleteRequest(BaseModel):
    session_id: str
    kem_ciphertext: str   # base64-encoded ciphertext from the client's encapsulation
    remote_ip: str = "127.0.0.1"
    remote_port: int = 0


class HandshakeCompleteResponse(BaseModel):
    session_id: str
    status: str  # "ESTABLISHED"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/init",
    response_model=HandshakeInitResponse,
    summary="Handshake Phase 1 — Generate KEM keypair",
    description=(
        "Generate a fresh KEM keypair for the given client. Returns the session_id "
        "and the public_key (base64) that the VPN client should use for encapsulation."
    ),
)
async def handshake_init(
    payload: HandshakeInitRequest,
):
    try:
        result = await init_handshake(client_identifier=payload.client_identifier)
        return HandshakeInitResponse(
            session_id=result["session_id"],
            algorithm=result["algorithm"],
            public_key=base64.b64encode(result["public_key"]).decode("ascii"),
        )
    except ClientNotRegistered as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except PQCServiceUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except PQCKeygenError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        logger.error("[HANDSHAKE] Init error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal handshake error")


@router.post(
    "/complete",
    response_model=HandshakeCompleteResponse,
    summary="Handshake Phase 2 — Decapsulate and establish session",
    description=(
        "Complete the handshake by decapsulating the client's KEM ciphertext. "
        "The shared secret is derived into an AES-256 key and stored in memory. "
        "The AES key is NOT returned — the client uses the socket tunnel (port 5151) "
        "for encrypted data transfer."
    ),
)
async def handshake_complete(
    payload: HandshakeCompleteRequest,
):
    try:
        ciphertext_bytes = base64.b64decode(payload.kem_ciphertext)
        result = await complete_handshake(
            session_id=payload.session_id,
            kem_ciphertext=ciphertext_bytes,
            remote_ip=payload.remote_ip,
            remote_port=payload.remote_port,
        )
        return HandshakeCompleteResponse(session_id=result["session_id"], status="ESTABLISHED")
    except SessionNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except DuplicateHandshake as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ClientNotRegistered as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except PQCServiceUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except PQCDecapsulationError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except HandshakeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.error("[HANDSHAKE] Complete error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal handshake error")
