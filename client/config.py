import os
import sys
import logging
from cryptography.hazmat.primitives import hashes

# Load .env from the project root (qvpn-client/) so that env vars are available
# to os.getenv() calls below even when the process is not started with explicit
# environment variables set.
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass  # python-dotenv not installed — rely on OS environment variables

logger = logging.getLogger("QVPN_Config")

# Gateway API Configuration
GATEWAY_API_URL = os.getenv("GATEWAY_API_URL", "http://localhost:8001/api/v1").rstrip("/")
GATEWAY_API_KEY = os.getenv("GATEWAY_API_KEY")
CLIENT_IDENTIFIER = os.getenv("CLIENT_IDENTIFIER", "test-client-1")

# PQC API Configuration (pointing to Sentinel production by default)
PQC_API_URL = os.getenv("PQC_API_URL", "https://qnnx-sentinel-production.up.railway.app/api/v1").rstrip("/")
# API Key and signing secret for the PQC API (QNNX Sentinel)
PQC_API_KEY = os.getenv("PQC_API_KEY")
PQC_SIGNING_SECRET = os.getenv("PQC_SIGNING_SECRET")

# HKDF parameters (Shared parameters for key derivation)
# Dynamically load from Gateway shared config if possible, fallback to Gateway defaults
HKDF_SALT = None
HKDF_INFO = None

try:
    # Try importing app.core.config by adding the gateway directory to sys.path
    GATEWAY_DIR = os.environ.get(
        "GATEWAY_PATH" # Local dev default
    )
    if os.path.exists(GATEWAY_DIR) and GATEWAY_DIR not in sys.path:
        sys.path.insert(0, GATEWAY_DIR)
    
    from app.core.config import settings
    HKDF_SALT = settings.HKDF_SALT
    HKDF_INFO = settings.HKDF_INFO
except Exception as e:
    # Fallback to Gateway's default parameters
    HKDF_SALT = b"qvpn-hkdf-salt-v1"
    HKDF_INFO = b"qvpn-tunnel-key-v1"

HKDF_KEY_LENGTH = 32
HKDF_ALGORITHM = hashes.SHA256()

