import logging
from pydantic_settings import BaseSettings, SettingsConfigDict

_cfg_logger = logging.getLogger("qvpn.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ------------------------------------------------------------------ #
    # Project                                                              #
    # ------------------------------------------------------------------ #
    PROJECT_NAME: str = "QVPN-Gateway"
    VERSION:      str = "2.0.0"
    DESCRIPTION:  str = "Post-Quantum Secured VPN Gateway Control Plane"
    ENVIRONMENT:  str = "development"
    API_V1_STR:   str = "/api/v1"

    # ------------------------------------------------------------------ #
    # Database                                                             #
    # ------------------------------------------------------------------ #
    DATABASE_URL: str

    # ------------------------------------------------------------------ #
    # PQC API (external Sentinel service that owns all crypto operations)  #
    # ------------------------------------------------------------------ #
    PQC_API_URL:          str   = "http://localhost:8000/api/v1"
    QNNX_API_KEY:         str
    QNNX_SIGNING_SECRET:  str

    PQC_TIMEOUT_SECONDS:    float = 10.0
    PQC_RETRY_ATTEMPTS:     int   = 3
    PQC_RETRY_WAIT_SECONDS: float = 0.5

    # ------------------------------------------------------------------ #
    # Session / AES key derivation (HKDF)                                 #
    # ------------------------------------------------------------------ #
    HKDF_SALT: bytes = b"qvpn-hkdf-salt-v1"
    HKDF_INFO: bytes = b"qvpn-tunnel-key-v1"

    # AES key eviction TTL (seconds of inactivity before key is dropped from memory)
    SESSION_TTL_SECONDS: int = 3600

    # Heartbeat watchdog — sessions with no heartbeat for this long are expired
    HEARTBEAT_TIMEOUT_SECONDS: int = 60

    # ------------------------------------------------------------------ #
    # Audit logging                                                        #
    # ------------------------------------------------------------------ #
    # Set AUDIT_LOG_ENABLED=false in .env to disable (e.g. load-test env)
    AUDIT_LOG_ENABLED: bool = True

    # Paths that are never written to audit_logs (comma-separated prefixes)
    AUDIT_SKIP_PATHS: str = "/health,/docs,/redoc,/openapi.json,/"


settings = Settings()
