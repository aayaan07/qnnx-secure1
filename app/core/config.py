import logging
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_cfg_logger = logging.getLogger("qvpn.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Project
    PROJECT_NAME: str = "QVPN-Gateway"
    VERSION: str = "2.0.0"
    DESCRIPTION: str = "Post-Quantum Secured VPN Gateway Control Plane"
    ENVIRONMENT: str = "development"
    API_V1_STR: str = "/api/v1"

    # Database
    DATABASE_URL: str

    # PQC API — the external Sentinel service that owns all crypto operations
    # Set PQC_API_URL=http://localhost:8000/api/v1 in .env for local dev
    # Replace with the cloud URL before deploying
    PQC_API_URL: str = "http://localhost:8000/api/v1"
    QNNX_API_KEY: str
    QNNX_SIGNING_SECRET: str

    # httpx client settings for PQC API calls
    PQC_TIMEOUT_SECONDS: float = 10.0
    PQC_RETRY_ATTEMPTS: int = 3          # retries on 5xx / connect error
    PQC_RETRY_WAIT_SECONDS: float = 0.5  # initial wait between retries (exponential)

    # HKDF constants for AES-256 session key derivation
    # These are used in session_key.py — change both gateway and client if you rotate them
    HKDF_SALT: bytes = b"qvpn-hkdf-salt-v1"
    HKDF_INFO: bytes = b"qvpn-tunnel-key-v1"

    # In-memory session key store TTL — how long an AES key is kept after last use
    SESSION_TTL_SECONDS: int = 3600  # 1 hour

    # Tunnel heartbeat — sessions older than this with no heartbeat are expired
    HEARTBEAT_TIMEOUT_SECONDS: int = 60

    # ---------------------------------------------------------------------------
    # PQC Debug Mode — bypass all PQC operations for testing without Sentinel
    #
    # DEBUG_MODE_PQC=true  → skip ML-KEM handshake; use MASTER_KEY as AES-256 key.
    # MASTER_KEY           → 64-character hex string (32 bytes).
    #
    # Both Client and Gateway must share the same MASTER_KEY.
    # WARNING: Never enable in production.
    # ---------------------------------------------------------------------------
    DEBUG_MODE_PQC: bool = False
    MASTER_KEY: str = ""  # hex string, 64 chars = 32 bytes AES-256
    DEBUG_AES: bool = False

    @model_validator(mode="after")
    def _validate_debug_mode(self) -> "Settings":
        if not self.DEBUG_MODE_PQC:
            return self
        # MASTER_KEY is required when debug mode is active
        if not self.MASTER_KEY:
            raise ValueError(
                "DEBUG_MODE_PQC=true but MASTER_KEY is not set. "
                "Provide a 64-character hex string (32 bytes)."
            )
        try:
            key_bytes = bytes.fromhex(self.MASTER_KEY)
        except ValueError:
            raise ValueError(
                "MASTER_KEY is not valid hex. "
                "Provide exactly 64 hex characters (32 bytes)."
            )
        if len(key_bytes) != 32:
            raise ValueError(
                f"MASTER_KEY must be exactly 32 bytes (64 hex chars), "
                f"got {len(key_bytes)} bytes ({len(self.MASTER_KEY)} hex chars)."
            )
        return self

    @property
    def master_key_bytes(self) -> bytes:
        """Return the MASTER_KEY as raw bytes. Only valid when DEBUG_MODE_PQC=True."""
        return bytes.fromhex(self.MASTER_KEY) if self.MASTER_KEY else b""


settings = Settings()
