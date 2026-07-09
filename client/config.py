"""
config.py — QVPN client configuration.

The client is now ENVIRONMENT-INDEPENDENT: it no longer reads a .env file.

  * Endpoint URLs, gateway IP/port and other operational parameters are
    HARDCODED below (they are the same for every install).
  * The three secrets (GATEWAY_API_KEY, PQC_API_KEY, PQC_SIGNING_SECRET) are
    loaded from the OS credential vault via `secrets_store` (Windows Credential
    Manager). On first run they are empty; the UI setup modal collects, verifies
    and stores them. `reload_secrets()` refreshes the in-memory copies after the
    modal saves new values.
"""
import socket
import logging
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes

from client import secrets_store

logger = logging.getLogger("QVPN_Config")

# ---------------------------------------------------------------------------
# Hardcoded endpoints (same for every deployment)
# ---------------------------------------------------------------------------
GATEWAY_API_URL = "https://gateway.qnnx.in/api/v1"
PQC_API_URL = "https://pqcapi.qnnx.in/api/v1"

# Raw TCP VPN tunnel endpoint. The gateway serves the tunnel on port 5151 at the
# same host as its REST API, so we derive the host from GATEWAY_API_URL to keep
# a single source of truth for "where the gateway lives".
GATEWAY_IP = urlparse(GATEWAY_API_URL).hostname or "127.0.0.1"
GATEWAY_PORT = 5151

# Client identifier defaults to this device's hostname so each machine is
# uniquely identified without manual configuration.
CLIENT_IDENTIFIER = socket.gethostname()

# Local proxy and UI (hardcoded operational defaults).
LOCAL_PROXY_ADDRESS = "127.0.0.1:8080"
EEL_PORT = 8085

# ---------------------------------------------------------------------------
# Secrets — loaded from the OS credential vault, never from disk/env.
# These are module-level for backward compatibility with existing imports.
# Call reload_secrets() after the setup modal stores new values.
# ---------------------------------------------------------------------------
GATEWAY_API_KEY: str | None = None
PQC_API_KEY: str | None = None
PQC_SIGNING_SECRET: str | None = None


def reload_secrets() -> None:
    """Refresh the module-level secret values from the OS credential vault."""
    global GATEWAY_API_KEY, PQC_API_KEY, PQC_SIGNING_SECRET
    creds = secrets_store.load_credentials()
    GATEWAY_API_KEY = creds.get(secrets_store.KEY_GATEWAY_API_KEY)
    PQC_API_KEY = creds.get(secrets_store.KEY_PQC_API_KEY)
    PQC_SIGNING_SECRET = creds.get(secrets_store.KEY_PQC_SIGNING_SECRET)


def secrets_present() -> bool:
    """True when all three secrets are available (in the vault)."""
    return secrets_store.credentials_present()


# Load whatever is already stored at import time.
reload_secrets()

# ---------------------------------------------------------------------------
# HKDF parameters (Shared parameters for key derivation)
# ---------------------------------------------------------------------------
HKDF_SALT = b"qvpn-hkdf-salt-v1"
HKDF_INFO = b"qvpn-tunnel-key-v1"

HKDF_KEY_LENGTH = 32
HKDF_ALGORITHM = hashes.SHA256()
