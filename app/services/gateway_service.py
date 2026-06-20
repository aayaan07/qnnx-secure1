"""
gateway_service.py — Legacy compatibility shim.

This module previously contained the VPN handshake logic inline.
It has been superseded by:
  app.services.handshake_service  — async two-phase handshake
  app.services.session_service    — session lifecycle management

This shim re-exports HandshakeError and the establish_session function
to avoid breaking any existing imports while the migration completes.

DO NOT add new logic here — use handshake_service instead.
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session as DBSession

from app.core.exceptions import HandshakeError  # re-export
from app.services.handshake_service import complete_handshake

logger = logging.getLogger("qvpn.gateway_service")


def establish_session(
    db: DBSession,
    client_identifier: str,
    kem_ciphertext: bytes,
    remote_ip: str,
    remote_port: int,
) -> dict:
    """
    DEPRECATED — synchronous wrapper around complete_handshake().

    Left here so old code that calls establish_session via asyncio.to_thread
    continues to work during the migration. Once socket_server.py is fully
    migrated to call handshake_service.complete_handshake() directly, this
    function can be removed.
    """
    logger.warning(
        "[gateway_service] establish_session() is deprecated; "
        "call handshake_service.complete_handshake() directly"
    )
    # complete_handshake is async; run it synchronously for legacy callers
    return asyncio.get_event_loop().run_until_complete(
        complete_handshake(
            db=db,
            session_id=client_identifier,
            kem_ciphertext=kem_ciphertext,
            remote_ip=remote_ip,
            remote_port=remote_port,
        )
    )