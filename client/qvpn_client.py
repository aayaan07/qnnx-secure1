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
    HKDF_INFO
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
        self._session_key = None
        self._kem_ciphertext = None
        self._keep_running = True
        self._connect_task = None
        self._heartbeat_task = None
        self._local_server = None

    def get_state(self) -> dict:
        return asdict(self.state)

    @property
    def session_key(self):
        return self._session_key

    def _emit_tunnel_event(self, event_type: str, details: dict = None):
        event_payload = {
            "event_type": event_type,
            "peer_id": self.state.client_id,
            "ip_address": self.gateway_ip,
            "details": details or {}
        }
        logger.warning(f"TUNNEL EVENT: {json.dumps(event_payload)}")

    async def connect(self):
        if self._connect_task and not self._connect_task.done():
            logger.info("Connection task is already running.")
            return
        self._connect_task = asyncio.current_task()
        
        try:
            self._keep_running = True
            self.state.tunnel_status = "connecting"
            call_eel("update_ui_state", "connecting")
            
            backoff = 1.0
            max_backoff = 30.0
            
            while self._keep_running:
                try:
                    logger.info("Initiating handshake REST calls...")
                    await self._perform_rest_handshake()
                    
                    # Handshake succeeded, clear backoff and start background tasks
                    backoff = 1.0
                    self.state.tunnel_status = "active"
                    self.state.connection_time = time.time()
                    self.state.heartbeat_status = "healthy"
                    logger.info(f"Handshake complete. Secure session active: {self.state.session_id}")
                    self._emit_tunnel_event("TUNNEL_UP", {"session_id": self.state.session_id})
                    
                    # Activate the Windows system proxy programmatically
                    set_system_proxy("127.0.0.1:8080")
                    
                    call_eel("update_ui_state", "active")
                    
                    # Start heartbeat and UI sync loops
                    self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
                    asyncio.create_task(self._ui_sync_loop())
                    
                    # Start local proxy data interface TCP server in the background
                    self._local_server_task = asyncio.create_task(self._start_local_data_server())
                    break
                    
                except (PQCServiceUnavailable, EncapsulationError) as e:
                    logger.error("Handshake failed due to PQC API error:", exc_info=True)
                    self.state.tunnel_status = "error"
                    self._emit_tunnel_event("TUNNEL_DOWN", {"reason": f"PQC Handshake Failure: {type(e).__name__}"})
                    call_eel("update_ui_state", "error")
                    # Attempt reconnection with backoff
                    logger.info(f"Reconnecting in {backoff} seconds...")
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)
                    
                except Exception as e:
                    logger.error("Handshake failed due to Gateway/Network error:", exc_info=True)
                    self.state.tunnel_status = "error"
                    self._emit_tunnel_event("TUNNEL_DOWN", {"reason": f"Gateway Handshake Failure: {str(e)}"})
                    call_eel("update_ui_state", "error")
                    # Attempt reconnection with backoff
                    logger.info(f"Reconnecting in {backoff} seconds...")
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)
        finally:
            self._connect_task = None

    async def _perform_rest_handshake(self):
        """Executes the two-phase handshake REST calls against Gateway and Sentinel PQC API."""
        headers = {"X-API-Key": GATEWAY_API_KEY}
        
        async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
            # Phase 1: POST /handshake/init
            init_url = f"{GATEWAY_API_URL}/handshake/init"
            logger.info(f"Calling Gateway REST init: {init_url}")
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
            logger.info(f"Calling Gateway REST complete: {complete_url}")
            complete_resp = await client.post(
                complete_url,
                json={"session_id": session_id, "kem_ciphertext": kem_ciphertext_b64},
                headers=headers
            )
            if complete_resp.status_code != 200:
                raise Exception(f"Gateway /handshake/complete failed (HTTP {complete_resp.status_code}): {complete_resp.text}")
                
            # Derive session key locally using shared config HKDF parameters
            # Key is held strictly in memory
            self._session_key = derive_session_key(shared_secret_bytes)
            self._kem_ciphertext = ciphertext_bytes
            self.state.session_id = session_id

    async def _heartbeat_loop(self):
        headers = {"X-API-Key": GATEWAY_API_KEY}
        while self._keep_running and self.state.tunnel_status == "active":
            try:
                # Call Gateway REST heartbeat
                heartbeat_url = f"{GATEWAY_API_URL}/sessions/{self.state.session_id}/heartbeat"
                async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
                    resp = await client.post(heartbeat_url, headers=headers)
                    if resp.status_code == 200:
                        self.state.heartbeat_status = "healthy"
                        call_eel("trigger_heartbeat")
                    else:
                        raise Exception(f"Heartbeat HTTP error: {resp.status_code}")
                await asyncio.sleep(10.0)
            except Exception as e:
                logger.error(f"Heartbeat transmission failed: {type(e).__name__}: {e}")
                self.state.heartbeat_status = "lost"
                self.state.tunnel_status = "error"
                self._emit_tunnel_event("HEARTBEAT_LOSS")
                # Deactivate system proxy
                clear_system_proxy()
                call_eel("update_ui_state", "error")
                # Attempt re-handshake and reconnect
                asyncio.create_task(self.connect())
                break

    async def _ui_sync_loop(self):
        while self._keep_running and self.state.tunnel_status == "active":
            call_eel("update_metrics", self.state.packets_sent, self.state.packets_received)
            await asyncio.sleep(1)

    async def _start_local_data_server(self):
        """Starts the local TCP server that receives traffic from the Local Proxy."""
        if self._local_server and self._local_server.is_serving():
            logger.info("Local proxy socket server is already listening on 127.0.0.1:8282")
            return

        self._local_server = await asyncio.start_server(
            self._handle_proxy_connection, "127.0.0.1", 8282
        )
        logger.info("Local proxy socket server listening on 127.0.0.1:8282")
        async with self._local_server:
            await self._local_server.serve_forever()

    async def _handle_proxy_connection(self, proxy_reader: asyncio.StreamReader, proxy_writer: asyncio.StreamWriter):
        """Handles a single browser connection forwarded by the Local Proxy.

        Every blocking network step during the session-resumption handshake is wrapped
        with asyncio.wait_for(GATEWAY_RESUME_TIMEOUT_SECONDS) so that silent hangs are
        converted into logged, bounded failures.
        """
        gateway_writer = None
        target_str = "unknown"
        conn_id = uuid.uuid4().hex[:8]  # short unique ID for correlating log lines
        logger.info(f"[conn={conn_id}] New proxy connection received.")
        try:
            # 1. Read target destination header (e.g. "google.com:443\n")
            logger.debug(f"[conn={conn_id}] Waiting for target header from local proxy...")
            target_line = await asyncio.wait_for(
                proxy_reader.readline(),
                timeout=GATEWAY_RESUME_TIMEOUT_SECONDS
            )
            if not target_line:
                logger.warning(f"[conn={conn_id}] Empty target header — dropping connection.")
                return
            target_str = target_line.decode("utf-8").strip()
            if not target_str or ":" not in target_str:
                logger.warning(f"[conn={conn_id}] Malformed target header '{target_str}' — dropping connection.")
                return

            host, port_str = target_str.split(":", 1)
            port = int(port_str)
            logger.info(f"[conn={conn_id}] Local Proxy requested tunnel to {host}:{port}")

            # 2. Open TCP connection to Gateway tunnel endpoint
            logger.info(
                f"[conn={conn_id}] Opening TCP connection to Gateway "
                f"{self.gateway_ip}:{self.gateway_port} (timeout={GATEWAY_RESUME_TIMEOUT_SECONDS}s)..."
            )
            gw_reader, gw_writer = await asyncio.wait_for(
                asyncio.open_connection(self.gateway_ip, self.gateway_port),
                timeout=GATEWAY_RESUME_TIMEOUT_SECONDS
            )
            gateway_writer = gw_writer
            logger.info(f"[conn={conn_id}] TCP connection to Gateway established.")

            # 3. Session Resumption — send session_id
            # CLIENT -> GATEWAY: [4-byte length][session_id]
            logger.debug(f"[conn={conn_id}] Sending session_id '{self.state.session_id}' to Gateway...")
            session_bytes = self.state.session_id.encode("utf-8")
            gw_writer.write(len(session_bytes).to_bytes(4, byteorder="big"))
            gw_writer.write(session_bytes)
            await asyncio.wait_for(gw_writer.drain(), timeout=GATEWAY_RESUME_TIMEOUT_SECONDS)
            self.state.packets_sent += 1
            logger.debug(f"[conn={conn_id}] session_id sent. Awaiting Gateway confirmation...")

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
            logger.debug(f"[conn={conn_id}] Gateway confirmation received: '{confirm_session}'")

            if confirm_session == "SESSION_NOT_ESTABLISHED":
                logger.error(
                    f"[conn={conn_id}] Gateway rejected session resumption "
                    f"(SESSION_NOT_ESTABLISHED). Triggering full reconnect..."
                )
                self.state.heartbeat_status = "lost"
                self.state.tunnel_status = "error"
                self._emit_tunnel_event("SESSION_NOT_ESTABLISHED")
                clear_system_proxy()
                call_eel("update_ui_state", "error")
                asyncio.create_task(self.connect())
                raise Exception("Gateway session is not established (SESSION_NOT_ESTABLISHED)")

            if confirm_session != self.state.session_id:
                raise Exception(
                    f"[conn={conn_id}] Gateway session confirmation mismatch: "
                    f"expected '{self.state.session_id}', got '{confirm_session}'"
                )
            logger.info(f"[conn={conn_id}] Session resumed successfully.")

            # 4. Encrypt and send target JSON
            # CLIENT -> GATEWAY: [4-byte length][nonce(12) + encrypted(target_json)]
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            cipher = AESGCM(self._session_key)

            target_json = json.dumps({"host": host, "port": port}).encode("utf-8")
            target_nonce = os.urandom(12)
            target_ciphertext = cipher.encrypt(target_nonce, target_json, None)
            target_payload = target_nonce + target_ciphertext

            logger.debug(f"[conn={conn_id}] Sending encrypted target to Gateway ({len(target_payload)} bytes)...")
            gw_writer.write(len(target_payload).to_bytes(4, byteorder="big"))
            gw_writer.write(target_payload)
            await asyncio.wait_for(gw_writer.drain(), timeout=GATEWAY_RESUME_TIMEOUT_SECONDS)
            self.state.packets_sent += 1
            logger.info(f"[conn={conn_id}] Target '{host}:{port}' sent to Gateway. Tunnel handshake complete.")

            # 5. Signal Local Proxy that the tunnel is ready
            proxy_writer.write(b"OK\n")
            await proxy_writer.drain()

            # 6. Bi-directionally pipe traffic (no per-packet timeout — streaming phase)
            async def pipe_proxy_to_gateway():
                try:
                    while True:
                        data = await proxy_reader.read(4096)
                        if not data:
                            break
                        nonce = os.urandom(12)
                        ciphertext = cipher.encrypt(nonce, data, None)
                        payload = nonce + ciphertext
                        gw_writer.write(len(payload).to_bytes(4, byteorder="big"))
                        gw_writer.write(payload)
                        await gw_writer.drain()
                        self.state.packets_sent += 1
                except Exception as ex:
                    logger.debug(f"[conn={conn_id}] proxy->gateway pipe closed: {type(ex).__name__}: {ex}")
                finally:
                    gw_writer.close()

            async def pipe_gateway_to_proxy():
                try:
                    while True:
                        length_bytes = await gw_reader.readexactly(4)
                        length = int.from_bytes(length_bytes, byteorder="big")
                        encrypted_payload = await gw_reader.readexactly(length)
                        self.state.packets_received += 1
                        nonce = encrypted_payload[:12]
                        ciphertext = encrypted_payload[12:]
                        decrypted = cipher.decrypt(nonce, ciphertext, None)
                        proxy_writer.write(decrypted)
                        await proxy_writer.drain()
                except Exception as ex:
                    logger.debug(f"[conn={conn_id}] gateway->proxy pipe closed: {type(ex).__name__}: {ex}")
                finally:
                    proxy_writer.close()

            logger.info(f"[conn={conn_id}] Entering bidirectional pipe for {host}:{port}.")
            await asyncio.gather(pipe_proxy_to_gateway(), pipe_gateway_to_proxy())
            logger.info(f"[conn={conn_id}] Bidirectional pipe closed for {host}:{port}.")

        except asyncio.TimeoutError:
            logger.error(
                f"[conn={conn_id}] TIMEOUT ({GATEWAY_RESUME_TIMEOUT_SECONDS}s) during "
                f"gateway handshake/setup for target '{target_str}'. "
                "This may indicate Gateway-side latency or a blocking DB call."
            )
            try:
                proxy_writer.write(b"ERROR\n")
                await proxy_writer.drain()
            except Exception:
                pass
            proxy_writer.close()
            if gateway_writer:
                gateway_writer.close()
                logger.debug(f"[conn={conn_id}] Gateway writer closed after timeout.")

        except Exception as e:
            logger.error(
                f"[conn={conn_id}] Error handling tunnel for '{target_str}': "
                f"{type(e).__name__}: {e}"
            )
            try:
                proxy_writer.write(b"ERROR\n")
                await proxy_writer.drain()
            except Exception:
                pass
            proxy_writer.close()
            if gateway_writer:
                gateway_writer.close()

    async def disconnect(self):
        self._keep_running = False
        
        # Deactivate Windows system proxy immediately on disconnect
        clear_system_proxy()
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._local_server:
            self._local_server.close()
            await self._local_server.wait_closed()
            
        self.state.tunnel_status = "disconnected"
        self.state.heartbeat_status = "offline"
        logger.info("QVPN Client disconnected.")
        self._emit_tunnel_event("TUNNEL_DOWN", {"reason": "Client initiated disconnect"})
        call_eel("update_ui_state", "disconnected")


# ==========================================
# OBSERVABILITY HTTP STATE SERVER
# ==========================================

class StatusHTTPHandler(httpx.AsyncClient):
    pass # Placeholder for reference

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
            pass # Suppress logging to prevent noise
            
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
    clear_system_proxy()

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