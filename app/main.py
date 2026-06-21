"""
main.py — QVPN Gateway Control Plane entry point.

Starts:
  1. FastAPI HTTP control plane (this process, port 8001 by default)
  2. Raw TCP VPN socket server (port 5151, launched in lifespan)

Routes:
  /api/v1/handshake/*  — Two-phase KEM handshake (init + complete)
  /api/v1/sessions/*   — Session lifecycle management
  /api/v1/monitoring/* — System metrics and monitoring (existing)
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends

from app.core.auth import get_api_key
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.gateway.socket_server import start_gateway_server
from app.routes.agent import router as agent_router
from app.routes.handshake import router as handshake_router
from app.routes.sessions import router as sessions_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("qvpn.main")


# ---------------------------------------------------------------------------
# Lifespan — start/stop the raw TCP VPN socket server
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("[MAIN] Starting QVPN Gateway v%s (%s)", settings.VERSION, settings.ENVIRONMENT)

    gateway_server = await start_gateway_server()
    app.state.gateway_server = gateway_server

    if settings.DEBUG_MODE_PQC:
        logger.warning("=" * 60)
        logger.warning("[MAIN] ⚠  PQC DEBUG MODE IS ENABLED")
        logger.warning("[MAIN] ⚠  PQC key exchange is BYPASSED on this gateway.")
        logger.warning("[MAIN] ⚠  MASTER_KEY is used for all AES-GCM operations.")
        logger.warning("[MAIN] ⚠  DO NOT run this configuration in production.")
        logger.warning("=" * 60)

    logger.info("[MAIN] Gateway ready. HTTP control plane: /docs | VPN tunnel: port 5151")
    yield

    # Shutdown
    logger.info("[MAIN] Shutting down gateway...")
    gateway_server.close()
    await gateway_server.wait_closed()
    logger.info("[MAIN] Gateway stopped.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


app = FastAPI(
    title="QVPN Gateway Control Plane",
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Register domain exception → HTTP response handlers
register_exception_handlers(app)

app.include_router(
    handshake_router,
    prefix=settings.API_V1_STR,
    dependencies=[Depends(get_api_key)],
)
app.include_router(
    sessions_router,
    prefix=settings.API_V1_STR,
    dependencies=[Depends(get_api_key)],
)
app.include_router(
    agent_router,
    prefix=settings.API_V1_STR,
    dependencies=[Depends(get_api_key)],
)


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
def root():
    return {
        "service": "QVPN Gateway Control Plane",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "docs": "/docs",
        "vpn_tunnel_port": 5151,
    }


@app.get("/health", tags=["Health"])
def health():
    from app.gateway.session_store import session_store
    return {
        "status": "ok",
        "active_sessions_in_memory": session_store.size(),
    }
