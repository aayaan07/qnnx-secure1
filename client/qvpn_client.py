import asyncio
import logging
import time
import uuid
import json
import threading
import os
import sys
import signal
import atexit
import httpx
import base64
from dataclasses import dataclass, asdict
import eel

from client.config import (
    GATEWAY_API_URL,
    GATEWAY_API_KEY,
    CLIENT_IDENTIFIER,
    PQC_API_URL,
    HKDF_ALGORITHM,
    HKDF_SALT,
    HKDF_INFO,
    DEBUG_MODE_PQC,
    MASTER_KEY_BYTES,
    DEBUG_AES,
)
from client.pqc_client import PQCClient, PQCServiceUnavailable, EncapsulationError
from client.session_key import derive_session_key
from client.system_proxy import set_system_proxy, clear_system_proxy

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [QVPN] - %(levelname)s - %(message)s")
logger = logging.getLogger("QVPN_Client")

# Maximum seconds allowed for each blocking step of the gateway session-resumption handshake.
# Any individual step that exceeds this will raise asyncio.TimeoutError and abort the connection.
GATEWAY_RESUME_TIMEOUT_SECONDS: float = 15.0


@dataclass
class QVPNState:
    client_id: str
    session_id: str | None = None
    tunnel_status: str = "disconnected"  # disconnected, connecting, active, error
    connection_time: float | None = None
    heartbeat_status: str = "offline"  # offline, healthy, lost
    packets_sent: int = 0
    packets_received: int = 0


# Safe Eel caller to avoid AttributeErrors when browser is disconnected or running in tests
def call_eel(func_name, *args):
    try:
        func = getattr(eel, func_name)
        res = func(*args)
        if func_name == "trigger_heartbeat" and callable(res):
            res()
    except AttributeError:
        pass
    except Exception as e:
        logger.debug(f"Eel communication error on {func_name}: {e}")


class QVPNClient:
    def __init__(self, gateway_ip: str = "127.0.0.1", gateway_port: int = 5151):
        self.gateway_ip = gateway_ip
        self.gateway_port = gateway_port

        self.state = QVPNState(
            client_id=CLIENT_IDENTIFIER
        )

        # Hold AES key in memory only (never write to disk, never log)
        self._session_key: bytes | None = None
        self._kem_ciphertext: bytes | None = None
        self._keep_running: bool = True

        # Connection lifecycle guards
        self._connect_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._local_server: asyncio.Server | None = None
        self._local_server_task: asyncio.Task | None = None

        # Signals when port 8282 is actually bound and ready to accept connections.
        # Prevents RC-3: system proxy being activated before the local server is listening.
        self._local_server_ready: asyncio.Event = asyncio.Event()

        # Double-disconnect guard: set to True when disconnect() starts, prevents
        # a concurrent second call from running cleanup twice.
        self._disconnecting: bool = False

    # -------------------------------------------------------------------------
    # Public state accessors
    # -------------------------------------------------------------------------

    def get_state(self) -> dict:
        return asdict(self.state)

    @property
    def session_key(self) -> bytes | None:
        return self._session_key

    def _emit_tunnel_event(self, event_type: str, details: dict = None):
        event_payload = {
            "event_type": event_type,
            "peer_id": self.state.client_id,
            "ip_address": self.gateway_ip,
            "details": details or {}
        }
        logger.warning(f"TUNNEL EVENT: {json.dumps(event_payload)}")

    # -------------------------------------------------------------------------
    # Connection lifecycle
    # -------------------------------------------------------------------------

    async def connect(self):
        """
        Establish a new VPN tunnel.

        Resets all stale session state at the start so that reconnects never
        send an expired session_id or use an old AES key (RC-2 fix).
        Awaits the local data server to be bound before activating the system
        proxy (RC-3 fix).
        """
        if self._connect_task and not self._connect_task.done():
            logger.info("Connection task is already running — ignoring duplicate request.")
            return
        self._connect_task = asyncio.current_task()

        try:
            # Reset stale session state before every connect attempt
            self.state.session_id = None
            self._session_key = None
            self._kem_ciphertext = None
            self._disconnecting = False
            self._keep_running = True
            self.state.tunnel_status = "connecting"
            call_eel("update_ui_state", "connecting")

            backoff = 1.0
            max_backoff = 30.0

            while self._keep_running:
                try:
                    logger.info("Initiating handshake...")
                    await self._perform_rest_handshake()

                    # Handshake succeeded — update state
                    backoff = 1.0
                    self.state.tunnel_status = "active"
                    self.state.connection_time = time.time()
                    self.state.heartbeat_status = "healthy"
                    logger.info("Handshake complete. Secure session active: %s", self.state.session_id)
                    self._emit_tunnel_event("TUNNEL_UP", {"session_id": self.state.session_id})

                    call_eel("update_ui_state", "active")

                    # Start heartbeat and UI sync loops
                    self._heartbeat_task = asyncio.create_task(
                        self._heartbeat_loop(), name="heartbeat"
                    )
                    asyncio.create_task(self._ui_sync_loop(), name="ui_sync")

                    # Start local proxy data interface TCP server.
                    # Wait for the server to be bound before activating the system
                    # proxy so that the first browser request does not get refused (RC-3).
                    self._local_server_ready.clear()
                    self._local_server_task = asyncio.create_task(
                        self._start_local_data_server(), name="local_server"
                    )
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(self._local_server_ready.wait()),
                            timeout=5.0,
                        )
                    except asyncio.TimeoutError:
                        logger.warning(
                            "Local proxy server did not signal readiness within 5 s — "
                            "activating system proxy anyway."
                        )

                    # Activate Windows system proxy AFTER the local server is ready
                    try:
                        set_system_proxy("127.0.0.1:8080")
                    except Exception as exc:
                        logger.error("Failed to set system proxy: %s", exc)

                    break

                except (PQCServiceUnavailable, EncapsulationError) as e:
                    logger.error("Handshake failed — PQC API error: %s", e)
                    self.state.tunnel_status = "error"
                    self._emit_tunnel_event("TUNNEL_DOWN", {"reason": f"PQC Handshake Failure: {type(e).__name__}"})
                    call_eel("update_ui_state", "error")
                    logger.info("Reconnecting in %.0fs...", backoff)
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)

                except asyncio.CancelledError:
                    logger.info("Connect task cancelled during handshake.")
                    raise

                except Exception as e:
                    logger.error("Handshake failed — Gateway/Network error: %s", e)
                    self.state.tunnel_status = "error"
                    self._emit_tunnel_event("TUNNEL_DOWN", {"reason": f"Gateway Handshake Failure: {str(e)}"})
                    call_eel("update_ui_state", "error")
                    logger.info("Reconnecting in %.0fs...", backoff)
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)

        except asyncio.CancelledError:
            logger.info("Connect coroutine cancelled — stopping reconnect loop.")
        finally:
            self._connect_task = None

    # -------------------------------------------------------------------------
    # Handshake
    # -------------------------------------------------------------------------

    async def _perform_rest_handshake(self):
        """
        Executes the two-phase handshake against the Gateway and PQC API.

        In PQC debug mode (DEBUG_MODE_PQC=true) the entire handshake is skipped.
        A random session_id is generated locally and MASTER_KEY_BYTES is used
        directly as the AES-256 session key — no PQC API calls are made.
        """
        if DEBUG_MODE_PQC:
            # ── DEBUG MODE ──────────────────────────────────────────────────────
            # Bypass all PQC operations. Generate a random session_id and use
            # MASTER_KEY_BYTES as the AES-256 session key.
            self.state.session_id = str(uuid.uuid4())
            self._session_key = MASTER_KEY_BYTES
            self._kem_ciphertext = None
            logger.warning(
                "[DEBUG] PQC handshake bypassed. session_id=%s — "
                "MASTER_KEY is used as session key. (Key value NOT logged.)",
                self.state.session_id,
            )
            return

        # ── NORMAL MODE ─────────────────────────────────────────────────────────
        headers = {"X-API-Key": GATEWAY_API_KEY}

        async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
            # Phase 1: POST /handshake/init
            init_url = f"{GATEWAY_API_URL}/handshake/init"
            logger.info("Calling Gateway REST init: %s", init_url)
            init_resp = await client.post(
                init_url,
                json={"client_identifier": CLIENT_IDENTIFIER},
                headers=headers
            )
            if init_resp.status_code != 200:
                raise Exception(f"Gateway /handshake/init failed (HTTP {init_resp.status_code}): {init_resp.text}")

            init_data = init_resp.json()
            session_id = init_data["session_id"]
            algorithm = init_data["algorithm"]
            public_key_b64 = init_data["public_key"]
            public_key_bytes = base64.b64decode(public_key_b64)

            # Encapsulate using PQCClient
            logger.info("Calling PQC API /kem/encapsulate...")
            pqc_client = PQCClient()
            ciphertext_bytes, shared_secret_bytes = await pqc_client.encapsulate(algorithm, public_key_bytes)

            # Phase 2: POST /handshake/complete
            kem_ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("ascii")
            complete_url = f"{GATEWAY_API_URL}/handshake/complete"
            logger.info("Calling Gateway REST complete: %s", complete_url)
            complete_resp = await client.post(
                complete_url,
                json={"session_id": session_id, "kem_ciphertext": kem_ciphertext_b64},
                headers=headers
            )
            if complete_resp.status_code != 200:
                raise Exception(f"Gateway /handshake/complete failed (HTTP {complete_resp.status_code}): {complete_resp.text}")

            # Derive session key locally using shared HKDF parameters.
            # Key is held strictly in memory — never logged, never written to disk.
            self._session_key = derive_session_key(shared_secret_bytes)
            self._kem_ciphertext = ciphertext_bytes
            self.state.session_id = session_id

    # -------------------------------------------------------------------------
    # Heartbeat loop
    # -------------------------------------------------------------------------

    async def _heartbeat_loop(self):
        """
        Periodically POST to the Gateway heartbeat endpoint.

        Disabled in PQC debug mode because there is no real session row in the DB.
        Catches CancelledError cleanly (fired by disconnect()) so it does not
        trigger an unwanted reconnect.
        """
        if DEBUG_MODE_PQC:
            logger.warning("[DEBUG] Heartbeat loop disabled in PQC debug mode.")
            return

        headers = {"X-API-Key": GATEWAY_API_KEY}
        logger.info("[Heartbeat] Loop started for session=%s", self.state.session_id)

        while self._keep_running and self.state.tunnel_status == "active":
            try:
                heartbeat_url = f"{GATEWAY_API_URL}/sessions/{self.state.session_id}/heartbeat"
                async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
                    resp = await client.post(heartbeat_url, headers=headers)
                    if resp.status_code == 200:
                        self.state.heartbeat_status = "healthy"
                        call_eel("trigger_heartbeat")
                    else:
                        raise Exception(f"Heartbeat HTTP error: {resp.status_code}")
                await asyncio.sleep(10.0)

            except asyncio.CancelledError:
                # disconnect() cancelled this task intentionally — exit cleanly.
                logger.info("[Heartbeat] Loop cancelled cleanly for session=%s.", self.state.session_id)
                return

            except Exception as e:
                logger.error(
                    "[Heartbeat] Transmission failed for session=%s: %s: %s",
                    self.state.session_id, type(e).__name__, e,
                )
                self.state.heartbeat_status = "lost"
                self.state.tunnel_status = "error"
                self._emit_tunnel_event("HEARTBEAT_LOSS", {"session_id": self.state.session_id})

                # Deactivate system proxy before triggering reconnect
                try:
                    clear_system_proxy()
                except Exception as exc:
                    logger.debug("[Heartbeat] clear_system_proxy failed: %s", exc)

                call_eel("update_ui_state", "error")

                # Trigger full reconnect only if we are not already disconnecting
                if not self._disconnecting:
                    logger.info("[Heartbeat] Scheduling reconnect for session=%s.", self.state.session_id)
                    asyncio.create_task(self.connect(), name="reconnect")
                break

        logger.info("[Heartbeat] Loop exited for session=%s.", self.state.session_id)

    # -------------------------------------------------------------------------
    # UI sync loop
    # -------------------------------------------------------------------------

    async def _ui_sync_loop(self):
        while self._keep_running and self.state.tunnel_status == "active":
            call_eel("update_metrics", self.state.packets_sent, self.state.packets_received)
            await asyncio.sleep(1)

    # -------------------------------------------------------------------------
    # Local TCP data server (port 8282)
    # -------------------------------------------------------------------------

    async def _start_local_data_server(self):
        """
        Start the local TCP server that receives forwarded traffic from the Local Proxy.

        Sets _local_server_ready after asyncio.start_server() returns so that
        connect() knows the port is actually bound before it activates the system proxy.
        """
        if self._local_server and self._local_server.is_serving():
            logger.info("Local proxy socket server is already listening on 127.0.0.1:8282")
            self._local_server_ready.set()
            return

        try:
            self._local_server = await asyncio.start_server(
                self._handle_proxy_connection, "127.0.0.1", 8282
            )
            # Signal readiness BEFORE entering serve_forever so connect() can proceed
            self._local_server_ready.set()
            logger.info("Local proxy socket server listening on 127.0.0.1:8282")
            async with self._local_server:
                await self._local_server.serve_forever()
        except asyncio.CancelledError:
            logger.info("Local proxy server task cancelled.")
        except Exception as exc:
            logger.error("Local proxy server failed: %s", exc)
            self._local_server_ready.set()  # unblock connect() even on failure

    # -------------------------------------------------------------------------
    # Per-connection proxy handler
    # -------------------------------------------------------------------------

    async def _handle_proxy_connection(
        self, proxy_reader: asyncio.StreamReader, proxy_writer: asyncio.StreamWriter
    ):
        """
        Handle a single browser connection forwarded by the Local Proxy.

        Guard at top: if the tunnel is not active or session state is not ready,
        immediately reject with ERROR\\n (RC-2 fix — prevents AttributeError when
        session_id or _session_key is None during reconnect).

        All writers are closed in a finally block to prevent socket leaks, with
        wait_closed() called to ensure the OS releases descriptors (RC-9 fix).
        """
        gateway_writer: asyncio.StreamWriter | None = None
        target_str = "unknown"
        conn_id = uuid.uuid4().hex[:8]  # short ID for correlating log lines
        logger.info("[conn=%s] New proxy connection received.", conn_id)

        # ── Pre-flight guard ─────────────────────────────────────────────────
        # Reject immediately if the tunnel is not fully established.
        if (
            self.state.tunnel_status != "active"
            or self.state.session_id is None
            or self._session_key is None
        ):
            logger.warning(
                "[conn=%s] Tunnel not ready (status=%s, session_id=%s) — rejecting connection.",
                conn_id,
                self.state.tunnel_status,
                "set" if self.state.session_id else "None",
            )
            try:
                proxy_writer.write(b"ERROR\n")
                await proxy_writer.drain()
            except Exception:
                pass
            try:
                proxy_writer.close()
                await proxy_writer.wait_closed()
            except Exception:
                pass
            return
        # ────────────────────────────────────────────────────────────────────

        try:
            # 1. Read target destination header (e.g. "google.com:443\n")
            logger.debug("[conn=%s] Waiting for target header from local proxy...", conn_id)
            target_line = await asyncio.wait_for(
                proxy_reader.readline(),
                timeout=GATEWAY_RESUME_TIMEOUT_SECONDS
            )
            if not target_line:
                logger.warning("[conn=%s] Empty target header — dropping connection.", conn_id)
                return
            target_str = target_line.decode("utf-8").strip()
            if not target_str or ":" not in target_str:
                logger.warning("[conn=%s] Malformed target header '%s' — dropping.", conn_id, target_str)
                return

            host, port_str = target_str.split(":", 1)
            port = int(port_str)
            logger.info("[conn=%s] Local Proxy requested tunnel to %s:%d", conn_id, host, port)

            # 2. Open TCP connection to Gateway tunnel endpoint
            logger.info(
                "[conn=%s] Opening TCP connection to Gateway %s:%d (timeout=%.0fs)...",
                conn_id, self.gateway_ip, self.gateway_port, GATEWAY_RESUME_TIMEOUT_SECONDS,
            )
            gw_reader, gw_writer = await asyncio.wait_for(
                asyncio.open_connection(self.gateway_ip, self.gateway_port),
                timeout=GATEWAY_RESUME_TIMEOUT_SECONDS
            )
            gateway_writer = gw_writer
            logger.info("[conn=%s] TCP connection to Gateway established.", conn_id)

            # 3. Session Resumption — send session_id
            # CLIENT → GATEWAY: [4-byte length][session_id]
            logger.debug("[conn=%s] Sending session_id to Gateway...", conn_id)
            session_bytes = self.state.session_id.encode("utf-8")
            gw_writer.write(len(session_bytes).to_bytes(4, byteorder="big"))
            gw_writer.write(session_bytes)
            await asyncio.wait_for(gw_writer.drain(), timeout=GATEWAY_RESUME_TIMEOUT_SECONDS)
            self.state.packets_sent += 1
            logger.debug("[conn=%s] session_id sent. Awaiting Gateway confirmation...", conn_id)

            # Read Gateway confirmation (session echo or SESSION_NOT_ESTABLISHED)
            confirm_len_bytes = await asyncio.wait_for(
                gw_reader.readexactly(4),
                timeout=GATEWAY_RESUME_TIMEOUT_SECONDS
            )
            confirm_len = int.from_bytes(confirm_len_bytes, byteorder="big")
            confirm_session = await asyncio.wait_for(
                gw_reader.readexactly(confirm_len),
                timeout=GATEWAY_RESUME_TIMEOUT_SECONDS
            )
            confirm_session = confirm_session.decode("utf-8")
            self.state.packets_received += 1
            logger.debug("[conn=%s] Gateway confirmation received: '%s'", conn_id, confirm_session)

            if confirm_session == "SESSION_NOT_ESTABLISHED":
                logger.error(
                    "[conn=%s] Gateway rejected session resumption (SESSION_NOT_ESTABLISHED). "
                    "Triggering full reconnect...",
                    conn_id,
                )
                self.state.heartbeat_status = "lost"
                self.state.tunnel_status = "error"
                self._emit_tunnel_event("SESSION_NOT_ESTABLISHED")
                try:
                    clear_system_proxy()
                except Exception as exc:
                    logger.debug("[conn=%s] clear_system_proxy failed: %s", conn_id, exc)
                call_eel("update_ui_state", "error")
                if not self._disconnecting:
                    asyncio.create_task(self.connect(), name="reconnect-session-lost")
                raise Exception("Gateway session is not established (SESSION_NOT_ESTABLISHED)")

            if confirm_session != self.state.session_id:
                raise Exception(
                    f"[conn={conn_id}] Gateway session confirmation mismatch: "
                    f"expected '{self.state.session_id}', got '{confirm_session}'"
                )
            logger.info("[conn=%s] Session resumed successfully.", conn_id)

            # 4. Encrypt and send target JSON
            # CLIENT → GATEWAY: [4-byte length][nonce(12) + encrypted(target_json)]
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            cipher = AESGCM(self._session_key)

            target_json = json.dumps({"host": host, "port": port}).encode("utf-8")
            if DEBUG_AES:
                target_payload = target_json
            else:
                target_nonce = os.urandom(12)
                target_ciphertext = cipher.encrypt(target_nonce, target_json, None)
                target_payload = target_nonce + target_ciphertext

            logger.debug(
                "[conn=%s] Sending target to Gateway (%d bytes)...",
                conn_id, len(target_payload),
            )
            gw_writer.write(len(target_payload).to_bytes(4, byteorder="big"))
            gw_writer.write(target_payload)
            await asyncio.wait_for(gw_writer.drain(), timeout=GATEWAY_RESUME_TIMEOUT_SECONDS)
            self.state.packets_sent += 1
            logger.info("[conn=%s] Target '%s:%d' sent to Gateway. Tunnel handshake complete.", conn_id, host, port)

            # 5. Signal Local Proxy that the tunnel is ready
            proxy_writer.write(b"OK\n")
            await proxy_writer.drain()

            # 6. Bi-directionally pipe traffic (no per-packet timeout — streaming phase)

            async def pipe_proxy_to_gateway():
                try:
                    while True:
                        data = await proxy_reader.read(65536)
                        if not data:
                            break
                        if DEBUG_AES:
                            payload = data
                        else:
                            nonce = os.urandom(12)
                            ciphertext = cipher.encrypt(nonce, data, None)
                            payload = nonce + ciphertext

                        gw_writer.write(len(payload).to_bytes(4, byteorder="big") + payload)
                        if len(payload) > 262144: 
                            await gw_writer.drain()
                        self.state.packets_sent += 1
                except asyncio.CancelledError:
                    logger.debug("[conn=%s] proxy→gateway pipe cancelled.", conn_id)
                except Exception as ex:
                    logger.debug("[conn=%s] proxy→gateway pipe closed: %s: %s", conn_id, type(ex).__name__, ex)
                finally:
                    try:
                        gw_writer.close()
                        await gw_writer.wait_closed()
                    except Exception:
                        pass

            async def pipe_gateway_to_proxy():
                try:
                    while True:
                        length_bytes = await gw_reader.readexactly(4)
                        length = int.from_bytes(length_bytes, byteorder="big")
                        encrypted_payload = await gw_reader.readexactly(length)
                        self.state.packets_received += 1
                        
                        if DEBUG_AES:
                            decrypted = encrypted_payload
                        else:
                            nonce = encrypted_payload[:12]
                            ciphertext = encrypted_payload[12:]
                            decrypted = cipher.decrypt(nonce, ciphertext, None)

                        proxy_writer.write(decrypted)
                        await proxy_writer.drain()
                except asyncio.CancelledError:
                    logger.debug("[conn=%s] gateway→proxy pipe cancelled.", conn_id)
                except Exception as ex:
                    logger.debug("[conn=%s] gateway→proxy pipe closed: %s: %s", conn_id, type(ex).__name__, ex)
                finally:
                    try:
                        proxy_writer.close()
                        await proxy_writer.wait_closed()
                    except Exception:
                        pass

            logger.info("[conn=%s] Entering bidirectional pipe for %s:%d.", conn_id, host, port)
            await asyncio.gather(pipe_proxy_to_gateway(), pipe_gateway_to_proxy())
            logger.info("[conn=%s] Bidirectional pipe closed for %s:%d.", conn_id, host, port)

        except asyncio.CancelledError:
            logger.info("[conn=%s] Proxy connection handler cancelled.", conn_id)

        except asyncio.TimeoutError:
            logger.error(
                "[conn=%s] TIMEOUT (%.0fs) during gateway handshake for target '%s'. "
                "Possible Gateway-side latency or blocking DB call.",
                conn_id, GATEWAY_RESUME_TIMEOUT_SECONDS, target_str,
            )

        except Exception as e:
            logger.error(
                "[conn=%s] Error handling tunnel for '%s': %s: %s",
                conn_id, target_str, type(e).__name__, e,
            )

        finally:
            # Always close both writers — each step is individually guarded.
            # wait_closed() ensures the OS releases socket descriptors (RC-9 fix).
            _had_error_in_setup = not (
                gateway_writer is not None  # gateway was reached
            )
            # Send ERROR\n to proxy only if we failed before sending OK\n.
            # We detect this by checking whether gateway_writer exists (proxy was notified
            # of OK only after gw_writer was assigned AND session resumed).
            # Use a best-effort write — the pipe finalizers may have already closed proxy_writer.
            if _had_error_in_setup:
                try:
                    proxy_writer.write(b"ERROR\n")
                    await proxy_writer.drain()
                except Exception:
                    pass

            try:
                proxy_writer.close()
                await proxy_writer.wait_closed()
            except Exception:
                pass

            if gateway_writer:
                try:
                    gateway_writer.close()
                    await gateway_writer.wait_closed()
                except Exception:
                    pass

            logger.debug("[conn=%s] Proxy connection cleanup complete.", conn_id)

    # -------------------------------------------------------------------------
    # Disconnect
    # -------------------------------------------------------------------------

    async def disconnect(self):
        """
        Gracefully tear down the VPN tunnel.

        Double-disconnect guard: if disconnect() is already running (concurrent call
        or re-entrant call from a reconnect path), the second call returns immediately.

        Each cleanup step (proxy, heartbeat, local server, state reset, UI) runs
        in its own try/except so that a failure in one step does not skip the rest.
        """
        if self._disconnecting:
            logger.info("disconnect() called but cleanup is already in progress — ignoring.")
            return
        self._disconnecting = True
        self._keep_running = False

        logger.info("[Disconnect] Cleanup started (session=%s).", self.state.session_id)

        # Step 1 — deactivate Windows system proxy
        try:
            clear_system_proxy()
        except Exception as exc:
            logger.error("[Disconnect] Failed to clear system proxy: %s", exc)

        # Step 2 — cancel heartbeat task
        try:
            if self._heartbeat_task and not self._heartbeat_task.done():
                self._heartbeat_task.cancel()
                await asyncio.wait([self._heartbeat_task], timeout=2.0)
        except Exception as exc:
            logger.error("[Disconnect] Failed to cancel heartbeat task: %s", exc)

        # Step 3 — close local proxy server (stops accepting new connections)
        try:
            if self._local_server:
                self._local_server.close()
                await self._local_server.wait_closed()
        except Exception as exc:
            logger.error("[Disconnect] Failed to close local proxy server: %s", exc)

        # Step 4 — cancel local server task
        try:
            if self._local_server_task and not self._local_server_task.done():
                self._local_server_task.cancel()
                await asyncio.wait([self._local_server_task], timeout=2.0)
        except Exception as exc:
            logger.error("[Disconnect] Failed to cancel local server task: %s", exc)

        # Step 5 — reset session state and in-memory key
        try:
            self.state.tunnel_status = "disconnected"
            self.state.heartbeat_status = "offline"
            self.state.session_id = None
            self._session_key = None
            self._kem_ciphertext = None
            self._local_server = None
            self._local_server_ready.clear()
        except Exception as exc:
            logger.error("[Disconnect] Failed to reset session state: %s", exc)

        # Step 6 — notify UI
        try:
            self._emit_tunnel_event("TUNNEL_DOWN", {"reason": "Client initiated disconnect"})
            call_eel("update_ui_state", "disconnected")
        except Exception as exc:
            logger.error("[Disconnect] Failed to update UI state: %s", exc)

        logger.info("[Disconnect] Cleanup complete.")


# ==========================================
# OBSERVABILITY HTTP STATE SERVER
# ==========================================

class StatusHTTPHandler(httpx.AsyncClient):
    pass  # Placeholder for reference


def run_status_http_server(client: QVPNClient):
    import http.server
    import socketserver

    class StatusHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/status":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(client.get_state()).encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass  # Suppress logging to prevent noise

    server = socketserver.TCPServer(("127.0.0.1", 8283), StatusHandler)
    server.serve_forever()


# ==========================================
# EEL TO ASYNCIO BRIDGE
# ==========================================

global_vpn_client = QVPNClient(gateway_ip="127.0.0.1", gateway_port=5151)
asyncio_loop = asyncio.new_event_loop()


def run_asyncio_thread(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


@eel.expose
def start_vpn_connection(*args, **kwargs):
    if global_vpn_client._connect_task and not global_vpn_client._connect_task.done():
        logger.info("Tunnel connection task is already running, ignoring request.")
        call_eel("update_ui_state", global_vpn_client.state.tunnel_status)
        return
    if global_vpn_client.state.tunnel_status == "active":
        logger.info("Tunnel already active, ignoring request.")
        call_eel("update_ui_state", global_vpn_client.state.tunnel_status)
        return
    logger.info("UI requested tunnel start.")
    asyncio.run_coroutine_threadsafe(global_vpn_client.connect(), asyncio_loop)


@eel.expose
def stop_vpn_connection(*args, **kwargs):
    logger.info("UI requested tunnel disconnect.")
    asyncio.run_coroutine_threadsafe(global_vpn_client.disconnect(), asyncio_loop)


# ==========================================
# CLEANUP HANDLERS (CRITICAL PATH)
# ==========================================

def emergency_cleanup():
    logger.warning("Emergency cleanup triggered. Clearing system proxy...")
    try:
        clear_system_proxy()
    except Exception as exc:
        logger.error("Emergency cleanup: clear_system_proxy failed: %s", exc)


def sig_handler(signum, frame):
    logger.warning(f"Signal {signum} received. Cleaning up and exiting...")
    emergency_cleanup()
    sys.exit(0)


# Register with atexit and signal handlers
atexit.register(emergency_cleanup)
signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)


# ==========================================
# MAIN RUNNER
# ==========================================

if __name__ == "__main__":
    # Start status HTTP server in a daemon thread
    status_thread = threading.Thread(target=run_status_http_server, args=(global_vpn_client,), daemon=True)
    status_thread.start()
    logger.info("Observability HTTP status server started on http://127.0.0.1:8283/status")

    # Start dedicated asyncio network thread
    t = threading.Thread(target=run_asyncio_thread, args=(asyncio_loop,), daemon=True)
    t.start()

    # Initialize Eel UI
    eel.init('ui')

    print("Launching QVPN UI...")
    try:
        # Port 8085 mode Edge
        eel.start('index.html', size=(850, 600), mode='edge', port=8085)
    except (SystemExit, MemoryError, KeyboardInterrupt):
        logger.info("UI Closed. Shutting down background tasks...")
        asyncio.run_coroutine_threadsafe(global_vpn_client.disconnect(), asyncio_loop)
        asyncio_loop.call_soon_threadsafe(asyncio_loop.stop)
        emergency_cleanup()