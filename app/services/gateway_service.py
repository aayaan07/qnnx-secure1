import uuid
import base64
import requests
from datetime import datetime, timezone

from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.repositories.client_repo import ClientRepository
from app.repositories.session_repo import SessionRepository
from app.repositories.tunnel_state_repo import TunnelStateRepository

client_repo = ClientRepository()
session_repo = SessionRepository()
tunnel_state_repo = TunnelStateRepository()

# --- GATEWAY CONFIGURATION ---
# Replace with the actual deployed URL when your senior provides it.
# Leaving it as local host for now so you can test it locally if needed.
PQC_API_BASE_URL = getattr(settings, "PQC_API_BASE_URL", "http://127.0.0.1:8000")

# ⚠️ PASTE YOUR RAW API KEY HERE ⚠️
GATEWAY_API_KEY = "qnnx_mock_vpn_token_abc123" 

class HandshakeError(Exception):
    """Raised whenever the handshake can't proceed (unknown client, API failure, etc.)"""
    pass


def establish_session(db: DBSession, client_identifier: str, kem_ciphertext: bytes,
                       remote_ip: str, remote_port: int) -> dict:
    """
    Runs the full server-side handshake for one incoming client connection by 
    reaching out to the deployed PQC API for decapsulation.
    """

    # Step 1: Look up the client
    client = client_repo.get_by_identifier(db, client_identifier)
    if not client:
        raise HandshakeError(f"Unknown client_identifier: {client_identifier}")

    if not client.is_active:
        raise HandshakeError(f"Client {client_identifier} is disabled")

    # Step 2: Create the session row in PENDING state
    session_id = uuid.uuid4()
    session_repo.create(db, {
        "id": session_id,
        "client_id": client.id,
        "kem_algorithm": client.kem_algorithm,
        "kem_state": "PENDING",
        "kem_ciphertext": kem_ciphertext,
    })

    # Step 3: Make the HTTP call to the deployed PQC API
    try:
        # Base64 encode the raw bytes so they can travel safely in JSON
        b64_ciphertext = base64.b64encode(kem_ciphertext).decode("utf-8")
        b64_private_key = base64.b64encode(client.private_key).decode("utf-8")

        api_url = f"{PQC_API_BASE_URL}{settings.API_V1_STR}/kem/decapsulate"
        
        headers = {
            "Authorization": f"Bearer {GATEWAY_API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "algorithm": client.kem_algorithm,
            "ciphertext": b64_ciphertext,
            "private_key": b64_private_key
        }

        # Send the request
        response = requests.post(api_url, json=payload, headers=headers)
        response.raise_for_status()  # Automatically raises an exception for 4xx/5xx errors
        
        data = response.json()
        
        # Decode the returned shared secret string back to raw bytes
        shared_secret = base64.b64decode(data["shared_secret"])

    except requests.RequestException as exc:
        session_repo.update(db, session_id, {"kem_state": "FAILED"})
        raise HandshakeError(f"HTTP call to PQC API failed: {exc}") from exc
    except Exception as exc:
        session_repo.update(db, session_id, {"kem_state": "FAILED"})
        raise HandshakeError(f"Decapsulation data processing failed: {exc}") from exc

    # Step 4: Mark session established
    session_repo.update(db, session_id, {"kem_state": "ESTABLISHED"})

    # Step 5: Initialize tunnel state
    tunnel_state_repo.create(db, {
        "id": uuid.uuid4(),
        "session_id": session_id,
        "status": "ACTIVE",
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "last_heartbeat": datetime.now(timezone.utc),
    })

    # Step 5b: Initialize traffic statistics
    from app.repositories.traffic_stat_repo import TrafficStatRepository
    ts_stat_repo = TrafficStatRepository()
    ts_stat_repo.create(db, {
        "id": uuid.uuid4(),
        "session_id": session_id,
        "bytes_sent": 0,
        "bytes_received": 0,
        "packets_sent": 0,
        "packets_received": 0,
    })

    # Step 6: Update client last seen
    client_repo.update(db, client.id, {"last_seen": datetime.now(timezone.utc)})

    return {
        "session_id": str(session_id),
        "shared_secret": shared_secret,
    }