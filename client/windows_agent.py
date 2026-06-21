import asyncio
import logging
import os
import sys
import time
import json
import threading
import socket
import urllib.parse as _urlparse
import pythoncom
import win32evtlog
import pywintypes
import psutil
import httpx
import wmi
from datetime import datetime, timezone
from collections import defaultdict

from client.config import GATEWAY_API_URL, GATEWAY_API_KEY, CLIENT_IDENTIFIER

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [Agent] - %(levelname)s - %(message)s")
logger = logging.getLogger("Windows_Agent")

STATUS_URL = "http://127.0.0.1:8283/status"
QUEUE_FILE = "agent_queue.json"

# ---------------------------------------------------------------------------
# Queue / upload tuneable limits
# ---------------------------------------------------------------------------
MAX_QUEUE_BYTES  = 15 * 1024   # 15 KB hard cap on agent_queue.json
MAX_BATCH_BYTES  = 10 * 1024   # 10 KB max payload per HTTP POST
MAX_BATCH_EVENTS = 50          # max events per single batch upload
RETRY_DELAYS     = (2, 5, 10)  # exponential backoff wait times in seconds

# Self-traffic exclusion — derive Gateway host / port from GATEWAY_API_URL
# so that connections from this agent to the Gateway are never re-captured
# as NETWORK_ACTIVITY events (prevents recursive event generation loops).
_gw_parsed   = _urlparse.urlparse(GATEWAY_API_URL)
GATEWAY_HOST = _gw_parsed.hostname or "localhost"
GATEWAY_PORT = _gw_parsed.port or 8001

# ---------------------------------------------------------------------------
# Endpoint routing table
# Maps the internal event_type label used in the queue to:
#   (gateway_endpoint_path, body_builder_fn)
# The body_builder_fn receives (client_identifier, list_of_event_dicts)
# and returns the JSON-serialisable request body.
# ---------------------------------------------------------------------------

def _build_metrics_body(client_identifier: str, events: list) -> dict:
    """POST /api/v1/agent/metrics — one reading per SYSTEM_METRICS event."""
    readings = [
        {
            "cpu_usage": ev["details"].get("cpu_usage", 0.0),
            "ram_usage": ev["details"].get("ram_usage", 0.0),
            "disk_usage": ev["details"].get("disk_usage", 0.0),
            "recorded_at": ev["details"].get("recorded_at", ev["timestamp"]),
        }
        for ev in events
    ]
    return {"client_identifier": client_identifier, "readings": readings}


def _build_activity_body(client_identifier: str, events: list) -> dict:
    """POST /api/v1/agent/activity — one entry per USER_ACTIVITY event."""
    activity_events = [
        {
            "event_id": ev["details"].get("event_id"),
            "time_generated": ev["details"].get("time_generated", ev["timestamp"]),
            "record_number": ev["details"].get("record_number"),
            "username": ev["details"].get("username", "UNKNOWN"),
        }
        for ev in events
    ]
    return {"client_identifier": client_identifier, "events": activity_events}


def _build_network_body(client_identifier: str, events: list) -> dict:
    """POST /api/v1/agent/network — NETWORK_ACTIVITY and IP_CHANGE events."""
    network_events = []
    for ev in events:
        d = ev["details"]
        entry = {
            "event_type": ev["event_type"],
            "timestamp": d.get("recorded_at") or d.get("timestamp") or ev["timestamp"],
        }
        if ev["event_type"] == "NETWORK_ACTIVITY":
            entry.update({
                "pid": d.get("pid", 0),
                "local_port": d.get("local_port", 0),
                "remote_ip": d.get("remote_ip", ""),
                "remote_port": d.get("remote_port", 0),
            })
        elif ev["event_type"] == "IP_CHANGE":
            # Flatten nested details if present (old format had details.details)
            inner = d.get("details", d)
            entry.update({
                "old_ip": inner.get("old_ip", ""),
                "new_ip": inner.get("new_ip", ""),
            })
        network_events.append(entry)
    return {"client_identifier": client_identifier, "events": network_events}


def _build_process_body(client_identifier: str, events: list) -> dict:
    """POST /api/v1/agent/process — UNKNOWN_PROCESS_LAUNCH events."""
    process_events = [
        {
            "process_name": ev["details"].get("process_name", "unknown"),
            "pid": ev["details"].get("pid", 0),
            "action": "launched",
            "timestamp": ev["timestamp"],
        }
        for ev in events
    ]
    return {"client_identifier": client_identifier, "events": process_events}


def _build_device_body(client_identifier: str, events: list) -> dict:
    """POST /api/v1/agent/device — USB_INSERTION and USB_REMOVAL events."""
    device_events = [
        {
            "action": "inserted" if ev["event_type"] == "USB_INSERTION" else "removed",
            "hardware_id": ev["details"].get("hardware_id", "unknown"),
            "device_info": {},
            "timestamp": ev["timestamp"],
        }
        for ev in events
    ]
    return {"client_identifier": client_identifier, "events": device_events}


# Maps event_type → (api_path_suffix, body_builder)
_ENDPOINT_ROUTING: dict[str, tuple[str, callable]] = {
    "SYSTEM_METRICS":        ("agent/metrics",   _build_metrics_body),
    "USER_ACTIVITY":         ("agent/activity",  _build_activity_body),
    "NETWORK_ACTIVITY":      ("agent/network",   _build_network_body),
    "IP_CHANGE":             ("agent/network",   _build_network_body),
    "UNKNOWN_PROCESS_LAUNCH":("agent/process",   _build_process_body),
    "USB_INSERTION":         ("agent/device",    _build_device_body),
    "USB_REMOVAL":           ("agent/device",    _build_device_body),
}


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
        """Loads unsent events from the local queue file.

        If the file is corrupted (invalid JSON), it is renamed to
        ``agent_queue.json.corrupt`` and a fresh empty queue is started so
        that the agent can continue operating without manual intervention.
        """
        if os.path.exists(QUEUE_FILE):
            try:
                with open(QUEUE_FILE, "r") as f:
                    self.queue = json.load(f)
                if not isinstance(self.queue, list):
                    raise ValueError("Queue root is not a list")
                logger.info(f"Loaded {len(self.queue)} unsent events from local queue.")
            except (json.JSONDecodeError, ValueError):
                corrupt_path = QUEUE_FILE + ".corrupt"
                try:
                    os.replace(QUEUE_FILE, corrupt_path)
                    logger.warning(
                        f"Corrupted queue file renamed to '{corrupt_path}'. "
                        "Starting with an empty queue."
                    )
                except OSError as rename_err:
                    logger.error(f"Could not rename corrupt queue: {rename_err}")
                self.queue = []
            except Exception as e:
                logger.error(f"Failed to load queue file: {type(e).__name__}: {e}", exc_info=True)
                self.queue = []

    def _save_queue(self):
        """Persists the current in-memory queue to disk, enforcing the
        ``MAX_QUEUE_BYTES`` (15 KB) size cap via FIFO eviction.

        Must be called while ``self.queue_lock`` is held, because it mutates
        ``self.queue`` in-place when eviction is needed.
        """
        try:
            # Use compact JSON (no indent) to minimise file size.
            serialised = json.dumps(self.queue)
            evicted = 0
            while len(serialised.encode("utf-8")) > MAX_QUEUE_BYTES and self.queue:
                dropped = self.queue.pop(0)   # FIFO: remove the oldest event
                evicted += 1
                logger.debug(
                    f"Queue cap enforced: dropped oldest event "
                    f"type={dropped.get('event_type')} id={dropped.get('id')}"
                )
                serialised = json.dumps(self.queue)

            if evicted:
                logger.warning(
                    f"Queue exceeded {MAX_QUEUE_BYTES // 1024} KB — "
                    f"evicted {evicted} oldest event(s) to stay within limit."
                )

            with open(QUEUE_FILE, "w") as f:
                f.write(serialised)

            size_bytes = len(serialised.encode("utf-8"))
            logger.debug(
                f"Queue saved: {len(self.queue)} events, {size_bytes} bytes "
                f"({size_bytes / 1024:.1f} KB)"
            )
        except Exception as e:
            logger.error(f"Failed to save queue file: {type(e).__name__}: {e}", exc_info=True)

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

    def enqueue_events_batch(self, events_list: list):
        """Enqueues multiple events in bulk and persists the queue once."""
        if not events_list:
            return
        formatted_events = []
        for event_type, details in events_list:
            formatted_events.append({
                "id": str(uuid_4_fallback()),
                "event_type": event_type,
                "details": details,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        with self.queue_lock:
            self.queue.extend(formatted_events)
            self._save_queue()
        logger.info(f"Enqueued {len(formatted_events)} events in bulk")

    async def fetch_active_session(self) -> str | None:
        """Queries the QVPN Client status endpoint to verify the tunnel is active."""
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

    # -----------------------------------------------------------------------
    # Self-traffic exclusion
    # -----------------------------------------------------------------------

    def _is_self_traffic(self, remote_ip: str, remote_port: int) -> bool:
        """Return True when a connection targets the Gateway API.

        Such connections are produced by this agent's own HTTP uploads and
        must not be re-captured as NETWORK_ACTIVITY events, otherwise a
        recursive event-generation loop would form.
        """
        try:
            gateway_ips = {GATEWAY_HOST, socket.gethostbyname(GATEWAY_HOST)}
        except OSError:
            gateway_ips = {GATEWAY_HOST}
        return remote_ip in gateway_ips and remote_port == GATEWAY_PORT

    # -----------------------------------------------------------------------
    # Upload helpers
    # -----------------------------------------------------------------------

    def _chunked_batches(self, events: list) -> list:
        """Split *events* into upload batches that each respect both
        ``MAX_BATCH_BYTES`` (10 KB) and ``MAX_BATCH_EVENTS`` (50 events).

        Returns a list of lists.  Each inner list is one batch ready for a
        single HTTP POST.
        """
        batches: list = []
        current: list = []
        current_size: int = 0

        for ev in events:
            ev_size = len(json.dumps(ev).encode("utf-8"))
            # Start a new batch if adding this event would breach either limit
            if current and (
                current_size + ev_size > MAX_BATCH_BYTES
                or len(current) >= MAX_BATCH_EVENTS
            ):
                batches.append(current)
                current = []
                current_size = 0
            current.append(ev)
            current_size += ev_size

        if current:
            batches.append(current)

        return batches

    async def _post_with_retry(
        self,
        client: httpx.AsyncClient,
        url: str,
        body: dict,
        headers: dict,
    ) -> tuple:
        """POST *body* to *url* with exponential-backoff retries.

        Returns ``(success: bool, elapsed: float)``.
        Logs payload size and event count on every timeout so that
        oversized payloads are immediately visible in the log stream.
        """
        payload_bytes = len(json.dumps(body).encode("utf-8"))
        # Heuristic event count: sum the lengths of any list values in body
        event_count = sum(
            len(v) for v in body.values() if isinstance(v, list)
        )

        logger.info(
            f"Uploading → {url} | "
            f"events={event_count} | payload={payload_bytes} bytes"
        )

        last_exc: Exception | None = None
        all_delays = list(RETRY_DELAYS) + [None]   # None = final attempt, no sleep after

        for attempt, delay in enumerate(all_delays, start=1):
            start = time.time()
            try:
                resp = await client.post(url, json=body, headers=headers)
                elapsed = time.time() - start
                logger.info(
                    f"Gateway responded in {elapsed:.2f}s | "
                    f"status={resp.status_code} | url={url}"
                )
                return resp.status_code in (200, 201), elapsed

            except httpx.TimeoutException as exc:
                elapsed = time.time() - start
                logger.warning(
                    f"POST timeout after {elapsed:.2f}s "
                    f"(attempt {attempt}/{len(all_delays)}) | "
                    f"payload={payload_bytes} bytes | events={event_count} | "
                    f"url={url}"
                )
                last_exc = exc

            except Exception as exc:
                elapsed = time.time() - start
                logger.error(
                    f"POST error after {elapsed:.2f}s "
                    f"(attempt {attempt}/{len(all_delays)}): "
                    f"{type(exc).__name__}: {exc} | url={url}"
                )
                last_exc = exc

            if delay is not None:
                logger.debug(f"Retrying in {delay}s...")
                await asyncio.sleep(delay)

        logger.error(
            f"All {len(all_delays)} upload attempt(s) failed for {url}. "
            f"Events will be retained in queue for the next push cycle."
        )
        return False, 0.0

    # -----------------------------------------------------------------------
    # Main push cycle
    # -----------------------------------------------------------------------

    async def push_queued_events(self):
        """Push queued events to the backend Gateway API.

        Key design decisions
        --------------------
        * Events are snapshotted at the start of the cycle so that background
          collectors can keep enqueuing without blocking.
        * Events are grouped by endpoint, then split into ≤10 KB / ≤50-event
          batches (``_chunked_batches``).  Each batch is uploaded individually
          via ``_post_with_retry``.
        * Only successfully uploaded event IDs are removed from the persistent
          queue.  Partially-successful cycles leave the remaining events in
          place for the next cycle.
        * The legacy /sessions/{session_id}/events path is NOT used for
          routine monitoring data.
        """
        with self.queue_lock:
            if not self.queue:
                return
            # Snapshot — so collectors can keep running while we upload
            queue_snapshot = list(self.queue)

        logger.info(
            f"Push cycle start: {len(queue_snapshot)} event(s) in queue "
            f"(~{os.path.getsize(QUEUE_FILE) if os.path.exists(QUEUE_FILE) else 0} bytes on disk)"
        )

        # Gate: only push when the VPN tunnel is active
        session_id = await self.fetch_active_session()
        if not session_id:
            logger.debug("QVPN Tunnel is not active. Postponing data push.")
            return

        headers = {
            "X-API-Key": GATEWAY_API_KEY,
            "Content-Type": "application/json",
        }

        # Route each event to its endpoint; drop unrecognised types immediately
        endpoint_to_events: dict = defaultdict(list)
        endpoint_to_builder: dict = {}
        pushed_ids: list = []

        for ev in queue_snapshot:
            etype = ev.get("event_type", "")
            if etype in _ENDPOINT_ROUTING:
                path_suffix, builder = _ENDPOINT_ROUTING[etype]
                endpoint_to_events[path_suffix].append(ev)
                endpoint_to_builder[path_suffix] = builder
            else:
                logger.warning(
                    f"Event type '{etype}' (id={ev.get('id')}) has no routing "
                    "entry — dropping (will not be retried)."
                )
                pushed_ids.append(ev["id"])   # treat as consumed so it is removed

        # Upload each endpoint's events in small, size-bounded batches
        async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
            for path_suffix, evs in endpoint_to_events.items():
                builder  = endpoint_to_builder[path_suffix]
                url      = f"{GATEWAY_API_URL}/{path_suffix}"
                batches  = self._chunked_batches(evs)

                logger.info(
                    f"{path_suffix}: {len(evs)} event(s) → "
                    f"{len(batches)} batch(es)"
                )

                for batch_num, batch in enumerate(batches, start=1):
                    body = builder(CLIENT_IDENTIFIER, batch)
                    ok, _elapsed = await self._post_with_retry(
                        client, url, body, headers
                    )
                    if ok:
                        pushed_ids.extend(ev["id"] for ev in batch)
                    else:
                        logger.warning(
                            f"{path_suffix} batch {batch_num}/{len(batches)} "
                            f"failed — {len(batch)} event(s) kept in queue."
                        )

        # Persist: remove only the successfully uploaded / dropped events
        if pushed_ids:
            with self.queue_lock:
                pushed_set = set(pushed_ids)
                before = len(self.queue)
                self.queue = [
                    ev for ev in self.queue if ev["id"] not in pushed_set
                ]
                self._save_queue()   # also enforces 15 KB cap
                after = len(self.queue)

            disk_bytes = (
                os.path.getsize(QUEUE_FILE) if os.path.exists(QUEUE_FILE) else 0
            )
            logger.info(
                f"Push cycle done: removed {before - after} event(s). "
                f"Queue remaining: {after} events, {disk_bytes} bytes "
                f"({disk_bytes / 1024:.1f} KB on disk)"
            )

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
        """Enumerates active TCP connections and enqueues network activities.

        Connections destined for the Gateway API are silently skipped via
        ``_is_self_traffic`` to prevent the agent's own upload traffic from
        being recursively re-captured as telemetry events.
        """
        try:
            conns = psutil.net_connections(kind="inet")
            events_to_enqueue = []
            for conn in conns:
                if conn.status == "ESTABLISHED" and conn.raddr:
                    # Skip connections that are part of our own Gateway uploads
                    if self._is_self_traffic(conn.raddr.ip, conn.raddr.port):
                        continue
                    details = {
                        "client_identifier": CLIENT_IDENTIFIER,
                        "pid": conn.pid or 0,
                        "local_port": conn.laddr.port,
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "recorded_at": datetime.now(timezone.utc).isoformat()
                    }
                    events_to_enqueue.append(("NETWORK_ACTIVITY", details))
            if events_to_enqueue:
                self.enqueue_events_batch(events_to_enqueue)
        except Exception as e:
            logger.error(
                f"Failed to enumerate network connections: "
                f"{type(e).__name__}: {e}",
                exc_info=True,
            )

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
                            "client_identifier": CLIENT_IDENTIFIER,
                            "old_ip": self.last_public_ip,
                            "new_ip": current_ip,
                        })
                    self.last_public_ip = current_ip
        except Exception as e:
            logger.debug(f"Failed to poll public IP: {type(e).__name__}: {e}")

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
                logger.error(f"Windows Event Log error: {type(e).__name__}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error polling Security Event Log: {type(e).__name__}: {e}", exc_info=True)

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
            logger.error(f"WMI process watcher error: {type(e).__name__}: {e}", exc_info=True)
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
            logger.error(f"WMI USB watcher error: {type(e).__name__}: {e}", exc_info=True)
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

        # 4. Push queued events to Gateway (grouped by type → correct endpoint)
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
