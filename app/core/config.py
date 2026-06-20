from pydantic_settings import BaseSettings, SettingsConfigDict


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


settings = Settings()
