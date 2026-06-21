import asyncio
import logging
import os
import sys
import time
import json
import threading
import socket
import pythoncom
import win32evtlog
import pywintypes
import psutil
import httpx
import wmi
from datetime import datetime, timezone

from client.config import GATEWAY_API_URL, GATEWAY_API_KEY, CLIENT_IDENTIFIER

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [Agent] - %(levelname)s - %(message)s")
logger = logging.getLogger("Windows_Agent")

STATUS_URL = "http://127.0.0.1:8283/status"
QUEUE_FILE = "agent_queue.json"

class WindowsAgent:
    def __init__(self):
        self.queue = []
        self.queue_lock = threading.Lock()
        self.last_security_record = None
        self.last_public_ip = None
        self.keep_running = True
        self._load_queue()
        
        # WMI threads
        self.process_thread = None
        self.usb_thread = None

    def _load_queue(self):
        """Loads unsent events from the local queue file."""
        if os.path.exists(QUEUE_FILE):
            try:
                with open(QUEUE_FILE, "r") as f:
                    self.queue = json.load(f)
                logger.info(f"Loaded {len(self.queue)} unsent events from local queue.")
            except Exception as e:
                logger.error(f"Failed to load queue file: {e}")
                self.queue = []

    def _save_queue(self):
        """Persists the current queue to the local queue file."""
        try:
            with open(QUEUE_FILE, "w") as f:
                json.dump(self.queue, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save queue file: {e}")

    def enqueue_event(self, event_type: str, details: dict):
        """Enqueues a new event and persists the queue."""
        event = {
            "id": str(uuid_4_fallback()),
            "event_type": event_type,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        with self.queue_lock:
            self.queue.append(event)
            self._save_queue()
        logger.info(f"Enqueued event type '{event_type}'")

    async def fetch_active_session(self) -> str | None:
        """Queries the QVPN Client status endpoint to get the active session ID."""
        try:
            async with httpx.AsyncClient(timeout=2.0, trust_env=False) as client:
                resp = await client.get(STATUS_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("tunnel_status") == "active":
                        return data.get("session_id")
        except Exception:
            pass
        return None

    async def push_queued_events(self):
        """Attempts to push all queued events to the backend Gateway API."""
        session_id = await self.fetch_active_session()
        if not session_id:
            logger.debug("QVPN Tunnel is not active. Postponing data push.")
            return
            
        with self.queue_lock:
            if not self.queue:
                return
                
            logger.info(f"Attempting to push {len(self.queue)} queued event(s)...")
            headers = {
                "X-API-Key": GATEWAY_API_KEY,
                "Content-Type": "application/json"
            }
            
            pushed_indices = []
            
            # Send events one by one to the Gateway
            for idx, event in enumerate(self.queue):
                url = f"{GATEWAY_API_URL}/sessions/{session_id}/events"
                payload = {
                    "event_type": event["event_type"],
                    "details": event["details"]
                }
                try:
                    async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
                        resp = await client.post(url, json=payload, headers=headers)
                        if resp.status_code in (200, 201):
                            pushed_indices.append(idx)
                        else:
                            logger.error(f"Gateway rejected event: status={resp.status_code}, response={resp.text}")
                            # Stop push sequence on API rejection to verify connection issues or bad payload
                            break
                except Exception as e:
                    logger.error(f"Failed to connect to Gateway for data push: {e}")
                    # Stop pushing on connection failure
                    break
                    
            # Remove successfully pushed events
            if pushed_indices:
                for idx in sorted(pushed_indices, reverse=True):
                    self.queue.pop(idx)
                self._save_queue()
                logger.info(f"Successfully pushed {len(pushed_indices)} event(s) to Gateway.")

    def poll_system_metrics(self):
        """Collects CPU, RAM, and disk utilization metrics."""
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage(os.path.splitdrive(sys.executable)[0] or "C:").percent
        
        details = {
            "client_identifier": CLIENT_IDENTIFIER,
            "cpu_usage": cpu,
            "ram_usage": ram,
            "disk_usage": disk,
            "recorded_at": datetime.now(timezone.utc).isoformat()
        }
        self.enqueue_event("SYSTEM_METRICS", details)

    def poll_network_connections(self):
        """Enumerates active TCP connections and enqueues network activities."""
        try:
            conns = psutil.net_connections(kind="inet")
            for conn in conns:
                if conn.status == "ESTABLISHED" and conn.raddr:
                    details = {
                        "client_identifier": CLIENT_IDENTIFIER,
                        "pid": conn.pid or 0,
                        "local_port": conn.laddr.port,
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "recorded_at": datetime.now(timezone.utc).isoformat()
                    }
                    self.enqueue_event("NETWORK_ACTIVITY", details)
        except Exception as e:
            logger.error(f"Failed to enumerate network connections: {e}")

    async def poll_public_ip(self):
        """Checks for changes in the public IP address."""
        try:
            async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
                resp = await client.get("https://api.ipify.org?format=json")
                if resp.status_code == 200:
                    current_ip = resp.json().get("ip")
                    if self.last_public_ip and current_ip != self.last_public_ip:
                        logger.warning(f"Public IP changed: {self.last_public_ip} -> {current_ip}")
                        self.enqueue_event("IP_CHANGE", {
                            "client_id": CLIENT_IDENTIFIER,
                            "details": {
                                "old_ip": self.last_public_ip,
                                "new_ip": current_ip
                            }
                        })
                    self.last_public_ip = current_ip
        except Exception as e:
            logger.debug(f"Failed to poll public IP: {e}")

    def poll_security_events(self):
        """Polls the Windows Security Event log for logon/logoff events."""
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # If we don't have a record pointer yet, query the current total records
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            start_rec = self.last_security_record or total
            
            events = win32evtlog.ReadEventLog(hand, flags, start_rec)
            for ev in events:
                event_id = ev.EventID & 0xFFFF
                if event_id in (4624, 4625, 4634, 4647):
                    details = {
                        "client_identifier": CLIENT_IDENTIFIER,
                        "event_id": event_id,
                        "time_generated": ev.TimeGenerated.isoformat(),
                        "record_number": ev.RecordNumber
                    }
                    self.enqueue_event("USER_ACTIVITY", details)
                if not self.last_security_record or ev.RecordNumber > self.last_security_record:
                    self.last_security_record = ev.RecordNumber
        except pywintypes.error as e:
            if e.winerror == 1314:
                logger.debug("Security Event Log requires Administrator privileges. Skipping polling.")
            else:
                logger.error(f"Windows Event Log error: {e}")
        except Exception as e:
            logger.error(f"Error polling Security Event Log: {e}")

    def start_wmi_watchers(self):
        """Spins up background threads to monitor WMI process creations and USB insertions."""
        self.process_thread = threading.Thread(target=self._wmi_process_watcher, daemon=True)
        self.process_thread.start()
        
        self.usb_thread = threading.Thread(target=self._wmi_usb_watcher, daemon=True)
        self.usb_thread.start()
        logger.info("WMI Process and USB insertion watchers started.")

    def _wmi_process_watcher(self):
        """Background thread watching for new processes via WMI."""
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            watcher = c.Win32_Process.watch_for("creation")
            while self.keep_running:
                try:
                    proc = watcher(timeout_ms=2000)
                    details = {
                        "client_identifier": CLIENT_IDENTIFIER,
                        "process_name": proc.Name,
                        "pid": proc.ProcessId
                    }
                    self.enqueue_event("UNKNOWN_PROCESS_LAUNCH", details)
                except wmi.x_wmi_timed_out:
                    continue
        except Exception as e:
            logger.error(f"WMI process watcher error: {e}")
        finally:
            pythoncom.CoUninitialize()

    def _wmi_usb_watcher(self):
        """Background thread watching for USB insertion/removals via WMI."""
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            watcher = c.Win32_DeviceChangeEvent.watch_for()
            while self.keep_running:
                try:
                    evt = watcher(timeout_ms=2000)
                    # EventType: 2 = Arrival (Insertion), 3 = Removal
                    if evt.EventType == 2:
                        details = {
                            "client_identifier": CLIENT_IDENTIFIER,
                            "hardware_id": f"USB_Arrival_Event_{evt.time_created}"
                        }
                        self.enqueue_event("USB_INSERTION", details)
                    elif evt.EventType == 3:
                        details = {
                            "client_identifier": CLIENT_IDENTIFIER,
                            "hardware_id": f"USB_Removal_Event_{evt.time_created}"
                        }
                        self.enqueue_event("USB_REMOVAL", details)
                except wmi.x_wmi_timed_out:
                    continue
        except Exception as e:
            logger.error(f"WMI USB watcher error: {e}")
        finally:
            pythoncom.CoUninitialize()

def uuid_4_fallback() -> str:
    """Standard random UUID string fallback."""
    import uuid
    return str(uuid.uuid4())

async def agent_main_loop(agent: WindowsAgent):
    agent.start_wmi_watchers()
    
    poll_interval = 10.0  # System metrics interval
    net_interval = 20.0   # Network connection list interval
    ip_interval = 30.0    # Public IP check interval
    
    last_poll = 0
    last_net = 0
    last_ip = 0
    
    while agent.keep_running:
        now = time.time()
        
        # 1. Poll metrics
        if now - last_poll >= poll_interval:
            agent.poll_system_metrics()
            agent.poll_security_events()
            last_poll = now
            
        # 2. Poll connections
        if now - last_net >= net_interval:
            agent.poll_network_connections()
            last_net = now
            
        # 3. Poll public IP
        if now - last_ip >= ip_interval:
            await agent.poll_public_ip()
            last_ip = now
            
        # 4. Push queued events to Gateway
        await agent.push_queued_events()
        
        # Short sleep to prevent busy loop
        await asyncio.sleep(1.0)

if __name__ == "__main__":
    agent = WindowsAgent()
    logger.info("Windows Monitoring Agent started.")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(agent_main_loop(agent))
    except KeyboardInterrupt:
        logger.info("Agent shutting down...")
        agent.keep_running = False
        time.sleep(1.0)
