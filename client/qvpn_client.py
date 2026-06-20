import asyncio
import logging
import time
import uuid
import json
import threading
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dataclasses import dataclass, asdict
import eel

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
            "client_identifier": self.state.client_id,
            "event_type": event_type,
            "ip_address": self.gateway_ip,
            "details": details or {}
        }
        logger.warning(f"TUNNEL EVENT: {json.dumps(event_payload)}")
        
        # Dispatch HTTP post asynchronously in a background thread
        def send_event():
            try:
                import requests
                requests.post("http://127.0.0.1:8000/api/v1/monitoring/vpn_events", json=event_payload, timeout=2)
            except Exception as e:
                logger.error(f"Failed to transmit tunnel event to backend: {e}")
                
        threading.Thread(target=send_event, daemon=True).start()

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

    async def _heartbeat_loop(self):
        while self._keep_running and self.state.tunnel_status == "up":
            try:
                heartbeat_pkt = b"PING"
                self.writer.write(heartbeat_pkt)
                await self.writer.drain()
                self.state.packets_sent += 1
                
                # Trigger the visual UI heartbeat pulse
                eel.trigger_heartbeat()()
                
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
                
                if data == b"PONG":
                    self.state.heartbeat_status = "healthy"
                    
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
def start_vpn_connection(*args, **kwargs):
    """Called by JavaScript when the user clicks 'CONNECT'."""
    # We log the args here so you can see exactly what JavaScript was trying to send!
    logger.info(f"UI requested tunnel start. (Absorbed JS args: {args})") 
    asyncio.run_coroutine_threadsafe(global_vpn_client.connect(), asyncio_loop)

@eel.expose
def stop_vpn_connection(*args, **kwargs):
    """Called by JavaScript when the user clicks 'SECURE' to disconnect."""
    logger.info("UI requested tunnel disconnect.")
    asyncio.run_coroutine_threadsafe(global_vpn_client.disconnect(), asyncio_loop)
if __name__ == "__main__":
    # 1. Start the dedicated asyncio network thread
    t = threading.Thread(target=run_asyncio_thread, args=(asyncio_loop,), daemon=True)
    t.start()
    
    # 2. Tell Eel where the frontend files are (the 'ui' folder you created)
    eel.init('ui')
    
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