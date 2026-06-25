"""
main.py — QVPN Gateway Control Plane entry point.

HTTP control plane routes (port 8001):
  /api/v1/handshake/*          — Two-phase PQC KEM handshake
  /api/v1/sessions/*           — Session lifecycle + heartbeats + stats
  /api/v1/agent/*              — Monitoring agent data ingestion
  /api/v1/alerts               — Security alerts (ingest + management)
  /api/v1/clients/{id}/alerts  — Per-client alert queries
  /api/v1/audit                — Audit log queries (every request is logged)

VPN data plane:
  Raw TCP socket server (port 5151) — launched in lifespan context manager

Middleware:
  AuditLogMiddleware — writes one audit_logs row per HTTP request,
  after the response is dispatched (non-blocking background thread).
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends

from app.core.auth import get_api_key
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.middleware import AuditLogMiddleware
from app.gateway.socket_server import start_gateway_server
from app.routes.agent import router as agent_router
from app.routes.alerts import router as alerts_router
from app.routes.audit import router as audit_router
from app.routes.handshake import router as handshake_router
from app.routes.sessions import router as sessions_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("qvpn.main")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("[MAIN] Starting QVPN Gateway v%s (%s)", settings.VERSION, settings.ENVIRONMENT)

    gateway_server = await start_gateway_server()
    app.state.gateway_server = gateway_server

    logger.info("[MAIN] Gateway ready. HTTP: /docs | VPN tunnel: port 5151")
    yield

    import asyncio
    logger.info("[MAIN] Shutting down gateway...")
    gateway_server.close()

    from app.gateway.socket_server import _expiry_task, _active_tasks
    if _expiry_task and not _expiry_task.done():
        _expiry_task.cancel()

    if _active_tasks:
        for task in list(_active_tasks):
            if not task.done():
                task.cancel()
        await asyncio.gather(*_active_tasks, return_exceptions=True)

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

# Middleware — runs on every request, writes audit_logs row in background
app.add_middleware(AuditLogMiddleware)

# Domain exception → structured JSON response handlers
register_exception_handlers(app)

# All API routes require a valid X-API-Key (enforced at router level)
_auth = [Depends(get_api_key)]

app.include_router(handshake_router, prefix=settings.API_V1_STR, dependencies=_auth)
app.include_router(sessions_router,  prefix=settings.API_V1_STR, dependencies=_auth)
app.include_router(agent_router,     prefix=settings.API_V1_STR, dependencies=_auth)
app.include_router(alerts_router,    prefix=settings.API_V1_STR, dependencies=_auth)
app.include_router(audit_router,     prefix=settings.API_V1_STR, dependencies=_auth)


# ---------------------------------------------------------------------------
# Root / health
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def root():
    return {
        "service":         "QVPN Gateway Control Plane",
        "version":         settings.VERSION,
        "environment":     settings.ENVIRONMENT,
        "docs":            "/docs",
        "vpn_tunnel_port": 5151,
    }


@app.get("/health", tags=["Health"])
def health():
    from app.gateway.session_store import session_store
    return {
        "status":                    "ok",
        "active_sessions_in_memory": session_store.size(),
    }
