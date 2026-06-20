from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "QNNX-Sentinel"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Post-Quantum Cryptography API for QNNX-Sentinel"
    ENVIRONMENT: str = "development"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: str
    DISABLE_SIGNED_REQUEST_GUARDS: bool = False
    KEYGEN_RATE_LIMIT: str = "30/minute"
    KEM_RATE_LIMIT: str = "100/minute"
    SIGN_RATE_LIMIT: str = "60/minute"
    VERIFY_RATE_LIMIT: str = "120/minute"

settings = Settings()
