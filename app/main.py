import logging
import base64
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter, HTTPException
from pydantic import BaseModel

from app.core.config import settings
from app.services.kem_service import decapsulate_secret
from app.gateway.socket_server import start_gateway_server

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("qvpn.main")

# In lifespan context, we start and stop the raw TCP socket VPN gateway listener
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Launch socket server
    gateway_server = await start_gateway_server()
    app.state.gateway_server = gateway_server
    yield
    # Shutdown: Close socket server
    logger.info("[MAIN] Shutting down gateway server...")
    gateway_server.close()
    await gateway_server.wait_closed()
    logger.info("[MAIN] Gateway server shut down successfully.")

app = FastAPI(
    title="QVPN-Gateway-Control-Plane",
    version="1.0.0",
    description="Minimal Control Plane and data plane lifecycle manager for QVPN Gateway",
    lifespan=lifespan
)

# Minimal router for local KEM decapsulation endpoint
router = APIRouter()

class DecapsulationRequest(BaseModel):
    algorithm: str
    ciphertext: str
    private_key: str

class DecapsulationResponse(BaseModel):
    algorithm: str
    shared_secret: str

@router.post(
    "/kem/decapsulate",
    response_model=DecapsulationResponse,
    summary="Minimal KEM Decapsulate",
    description="Minimal endpoint for KEM decapsulation, bypassing guards for local testing."
)
def kem_decapsulate(payload: DecapsulationRequest):
    try:
        logger.info(f"[CONTROL_PLANE] Received decapsulation request for algorithm={payload.algorithm}")
        # Decode base64 payloads to bytes
        ciphertext_bytes = base64.b64decode(payload.ciphertext)
        private_key_bytes = base64.b64decode(payload.private_key)
        
        # Execute decapsulation
        result = decapsulate_secret(payload.algorithm, ciphertext_bytes, private_key_bytes)
        
        # Encode shared secret back to base64
        shared_secret_b64 = base64.b64encode(result["shared_secret"]).decode("utf-8")
        
        return DecapsulationResponse(
            algorithm=result["algorithm"],
            shared_secret=shared_secret_b64
        )
    except Exception as exc:
        logger.error(f"[CONTROL_PLANE] Decapsulation error: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))

# Include router on API v1 string
app.include_router(router, prefix=settings.API_V1_STR, tags=["KEM"])

@app.get("/", include_in_schema=False)
def root():
    return {"message": "Welcome to QVPN Gateway Control Plane. Visit /docs for documentation."}
