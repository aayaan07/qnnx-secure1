import asyncio
import logging
import os
import sys
import time
import uuid
import json
import threading
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dataclasses import dataclass, asdict
import eel

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from security.Threat_detection import QVPNThreatEngine

THREAT_ENGINE = QVPNThreatEngine()
PROXY_LISTENER_PORT = 5000

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [QVPN] - %(levelname)s - %(message)s")
logger = logging.getLogger("QVPN_Client")

@dataclass
class QVPNState:
    client_id: str
    session_id: str | None = None
    tunnel_status: str = "disconnected"
    connection_time: float | None = None
    heartbeat_status: str = "offline"
    packets_sent: int = 0
    packets_received: int = 0

class QVPNClient:
    def __init__(self, gateway_ip: str, gateway_port: int, client_id: str = None):
        self.gateway_ip = gateway_ip
        self.gateway_port = gateway_port
        
        self.state = QVPNState(
            client_id=client_id or str(uuid.uuid4())
        )
        
        self.session_key = None
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._keep_running = True

    def get_state(self) -> dict:
        return asdict(self.state)

    def _emit_tunnel_event(self, event_type: str, details: dict = None):
        event_payload = {
            "event_type": event_type,
            "peer_id": self.state.client_id,
            "ip_address": self.gateway_ip,
            "details": details or {}
        }
        logger.warning(f"TUNNEL EVENT: {json.dumps(event_payload)}")

        # Route to threat detection engine
        threat_event = {"type": event_type, "client_id": self.state.client_id, "details": details or {}}
        if event_type in ("TUNNEL_DOWN", "TUNNEL_UP"):
            threat_event["type"] = "TUNNEL_FAILURE" if event_type == "TUNNEL_DOWN" else event_type
            THREAT_ENGINE.process_qvpn_client_event(threat_event)
        elif event_type == "HEARTBEAT_LOSS":
            THREAT_ENGINE.process_qvpn_client_event(threat_event)

    async def connect(self):
        self._keep_running = True
        try:
            logger.info(f"Connecting to QVPN Gateway at {self.gateway_ip}:{self.gateway_port}...")
            self.reader, self.writer = await asyncio.open_connection(self.gateway_ip, self.gateway_port)
            logger.info("Socket connected. Initiating ML-KEM handshake...")
            await self._perform_handshake()
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self._emit_tunnel_event("TUNNEL_DOWN", {"reason": str(e)})
            self.state.tunnel_status = "error"
            # Tell UI the connection failed
            eel.update_ui_state(False)

    async def _perform_handshake(self):
        kem_alg = "ML-KEM-768"
        try:
            server_pubkey = await self.reader.readexactly(1184)
            self.state.packets_received += 1
            
            with oqs.KeyEncapsulation(kem_alg) as client_kem:
                ciphertext, shared_secret = client_kem.encap_secret(server_pubkey)
            
            self.writer.write(ciphertext)
            await self.writer.drain()
            self.state.packets_sent += 1
            
            self._derive_session_key(shared_secret)
            
            self.state.session_id = str(uuid.uuid4())
            self.state.tunnel_status = "up"
            self.state.connection_time = time.time()
            self.state.heartbeat_status = "healthy"
            
            logger.info(f"Handshake complete. Secure session established: {self.state.session_id}")
            self._emit_tunnel_event("TUNNEL_UP", {"session_id": self.state.session_id})
            
            # Tell the HTML UI we successfully connected
            eel.update_ui_state(True)
            
            asyncio.create_task(self._heartbeat_loop())
            asyncio.create_task(self._listen_loop())
            asyncio.create_task(self._ui_sync_loop()) # New loop to push metrics to UI

        except Exception as e:
            logger.error(f"Handshake failed: {e}")
            self.state.tunnel_status = "failed"
            self._emit_tunnel_event("TUNNEL_DOWN", {"reason": "Handshake failure"})
            eel.update_ui_state(False)

    def _derive_session_key(self, shared_secret: bytes):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"qvpn-session-key-derivation",
        )
        self.session_key = hkdf.derive(shared_secret)

    def _encrypt_packet(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self.session_key).encrypt(nonce, plaintext, None)

    def _decrypt_packet(self, data: bytes) -> bytes:
        return AESGCM(self.session_key).decrypt(data[:12], data[12:], None)

    async def _heartbeat_loop(self):
        while self._keep_running and self.state.tunnel_status == "up":
            try:
                self.writer.write(self._encrypt_packet(b"PING"))
                await self.writer.drain()
                self.state.packets_sent += 1

                eel.trigger_heartbeat()
                
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Heartbeat transmission failed: {e}")
                self.state.heartbeat_status = "lost"
                self.state.tunnel_status = "down"
                self._emit_tunnel_event("HEARTBEAT_LOSS")
                eel.update_ui_state(False)
                break

    async def _listen_loop(self):
        while self._keep_running and self.state.tunnel_status == "up":
            try:
                data = await self.reader.read(4096)
                if not data:
                    logger.warning("Gateway closed the connection.")
                    break
                
                self.state.packets_received += 1

                try:
                    decrypted = self._decrypt_packet(data)
                    if decrypted == b"PONG":
                        self.state.heartbeat_status = "healthy"
                except Exception:
                    logger.warning("Failed to decrypt incoming packet — ignoring.")
                    
            except Exception as e:
                logger.error(f"Tunnel read error: {e}")
                break
                
        if self.state.tunnel_status == "up":
            self.state.tunnel_status = "down"
            self.state.heartbeat_status = "offline"
            self._emit_tunnel_event("TUNNEL_DOWN", {"reason": "Connection dropped by peer"})
            eel.update_ui_state(False)

    async def _ui_sync_loop(self):
        """Pushes exact packet metrics to the dashboard every second."""
        while self._keep_running and self.state.tunnel_status == "up":
            eel.update_metrics(self.state.packets_sent, self.state.packets_received)
            await asyncio.sleep(1)

    async def disconnect(self):
        self._keep_running = False
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
        self.state.tunnel_status = "disconnected"
        self.state.heartbeat_status = "offline"
        logger.info("QVPN Client disconnected.")
        self._emit_tunnel_event("TUNNEL_DOWN", {"reason": "Client initiated disconnect"})
        eel.update_ui_state(False)

    async def _handle_proxy_connection(self, proxy_reader, proxy_writer):
        """
        Called for each browser connection forwarded by the local proxy.
        Reads 'DEST host:port', opens a fresh encrypted tunnel to the gateway,
        sends the destination encrypted, then pipes traffic both ways.
        """
        peer = proxy_writer.get_extra_info("peername")
        try:
            line = await proxy_reader.readline()
            header = line.decode().strip()
            if not header.startswith("DEST "):
                proxy_writer.close()
                return
            dest = header[5:]  # "host:port"
            logger.info(f"[Proxy→Tunnel] {peer} → {dest}")

            # Open a fresh encrypted tunnel connection to the gateway for this request
            gw_reader, gw_writer = await asyncio.open_connection(self.gateway_ip, self.gateway_port)

            # Run ML-KEM handshake to get a session key for this connection
            kem_alg = "ML-KEM-768"
            server_pubkey = await gw_reader.readexactly(1184)
            with oqs.KeyEncapsulation(kem_alg) as kem:
                ciphertext, shared_secret = kem.encap_secret(server_pubkey)
            gw_writer.write(ciphertext)
            await gw_writer.drain()

            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qvpn-session-key-derivation")
            conn_key = hkdf.derive(shared_secret)

            def enc(data):
                nonce = os.urandom(12)
                return nonce + AESGCM(conn_key).encrypt(nonce, data, None)

            def dec(data):
                return AESGCM(conn_key).decrypt(data[:12], data[12:], None)

            # Tell the gateway where to forward this connection
            gw_writer.write(enc(f"CONNECT {dest}\n".encode()))
            await gw_writer.drain()

            # Wait for gateway OK
            raw = await gw_reader.read(4096)
            if dec(raw).strip() != b"OK":
                proxy_writer.close()
                gw_writer.close()
                return

            # Signal the proxy that the encrypted tunnel to the gateway is ready
            proxy_writer.write(b"READY\n")
            await proxy_writer.drain()

            # Pipe traffic: proxy↔client encrypted↔gateway
            async def forward(src_reader, dst_writer, encrypt):
                try:
                    while True:
                        data = await src_reader.read(4096)
                        if not data:
                            break
                        dst_writer.write(enc(data) if encrypt else dec(data))
                        await dst_writer.drain()
                        self.state.packets_sent += 1
                except Exception:
                    pass
                finally:
                    try:
                        dst_writer.close()
                    except Exception:
                        pass

            await asyncio.gather(
                forward(proxy_reader, gw_writer, encrypt=True),
                forward(gw_reader, proxy_writer, encrypt=False),
            )
        except Exception as e:
            logger.error(f"[Proxy→Tunnel] Error: {e}")
            try:
                proxy_writer.close()
            except Exception:
                pass

    async def start_proxy_listener(self):
        """Listen for connections from the local SOCKS5 proxy and tunnel them."""
        server = await asyncio.start_server(
            self._handle_proxy_connection, "127.0.0.1", PROXY_LISTENER_PORT
        )
        logger.info(f"QVPN proxy listener active on 127.0.0.1:{PROXY_LISTENER_PORT}")
        async with server:
            await server.serve_forever()


# ==========================================
# EEL TO ASYNCIO BRIDGE
# ==========================================

# Global reference to the client and its dedicated event loop
global_vpn_client = QVPNClient(gateway_ip="127.0.0.1", gateway_port=8443)
asyncio_loop = asyncio.new_event_loop()

def run_asyncio_thread(loop):
    """Runs the asyncio event loop indefinitely in a background thread."""
    asyncio.set_event_loop(loop)
    loop.run_forever()

@eel.expose
def start_vpn_connection(*args, **_kwargs):
    """Called by JavaScript when the user clicks 'CONNECT'."""
    logger.info(f"UI requested tunnel start. (Absorbed JS args: {args})")
    asyncio.run_coroutine_threadsafe(global_vpn_client.connect(), asyncio_loop)

@eel.expose
def stop_vpn_connection(*_args, **_kwargs):
    """Called by JavaScript when the user clicks 'SECURE' to disconnect."""
    logger.info("UI requested tunnel disconnect.")
    asyncio.run_coroutine_threadsafe(global_vpn_client.disconnect(), asyncio_loop)

@eel.expose
def get_vpn_state(*_args, **_kwargs):
    """Called by JavaScript to query current tunnel state (client_id, session_id, status, etc.)."""
    return global_vpn_client.get_state()
if __name__ == "__main__":
    # 1. Start the dedicated asyncio network thread
    t = threading.Thread(target=run_asyncio_thread, args=(asyncio_loop,), daemon=True)
    t.start()

    # 2. Start the proxy listener so the SOCKS5 proxy can forward browser traffic
    asyncio.run_coroutine_threadsafe(global_vpn_client.start_proxy_listener(), asyncio_loop)

    # 3. Tell Eel where the frontend files are (the 'ui' folder you created)
    eel.init('UI')
    
    print("Launching QVPN UI...")
    # 3. Start the UI loop on the main thread
    # Depending on your system, you can use mode='edge', 'chrome', or 'default'
    try:
        eel.start('index.html', size=(850, 600), mode='edge', port = 8080)
    except (SystemExit, MemoryError, KeyboardInterrupt):
        # Clean up the background thread when the window is closed
        logger.info("UI Closed. Shutting down background tasks...")
        asyncio.run_coroutine_threadsafe(global_vpn_client.disconnect(), asyncio_loop)
        asyncio_loop.call_soon_threadsafe(asyncio_loop.stop)