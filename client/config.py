import os
import sys
import logging
from cryptography.hazmat.primitives import hashes

def get_writeable_app_dir(app_name="QVPN"):
    """
    Returns a secure, writeable path for application data on Windows.
    Defaults to %LOCALAPPDATA% (per-user) or falls back to %ProgramData% (machine-wide).
    """
    base_dir = os.environ.get("LOCALAPPDATA") or os.environ.get("PROGRAMDATA")
    if not base_dir:
        base_dir = os.path.expanduser("~")
    app_dir = os.path.join(base_dir, app_name)
    os.makedirs(app_dir, exist_ok=True)
    return app_dir

writeable_dir = get_writeable_app_dir("QVPN")
DB_PATH = os.path.join(writeable_dir, "qvpn_threats.db")
LOG_PATH = os.path.join(writeable_dir, "gateway.log")

# Determine the correct root directory based on whether it's running as an .exe or script
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(dotenv_path=os.path.join(application_path, ".env"))
except ImportError:
    pass  # python-dotenv not installed — rely on OS environment variables

logger = logging.getLogger("QVPN_Config")

# Gateway API Configuration
GATEWAY_API_URL = os.getenv("GATEWAY_API_URL", "").rstrip("/")
GATEWAY_API_KEY = os.getenv("GATEWAY_API_KEY")
GATEWAY_IP = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "5151"))
CLIENT_IDENTIFIER = os.getenv("CLIENT_IDENTIFIER", "")

# PQC API Configuration
PQC_API_URL = os.getenv("PQC_API_URL", "").rstrip("/")
PQC_API_KEY = os.getenv("PQC_API_KEY")
PQC_SIGNING_SECRET = os.getenv("PQC_SIGNING_SECRET")

# Local proxy and UI
LOCAL_PROXY_ADDRESS = os.getenv("LOCAL_PROXY_ADDRESS", "127.0.0.1:8080")
EEL_PORT = int(os.getenv("EEL_PORT", "8085"))

# HKDF parameters (Shared parameters for key derivation)
# Dynamically load from Gateway shared config if possible, fallback to Gateway defaults
HKDF_SALT = None
HKDF_INFO = None

HKDF_SALT = b"qvpn-hkdf-salt-v1"
HKDF_INFO = b"qvpn-tunnel-key-v1"

HKDF_KEY_LENGTH = 32
HKDF_ALGORITHM = hashes.SHA256()