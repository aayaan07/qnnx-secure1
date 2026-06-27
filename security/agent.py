"""
agent.py
--------
QVPN embedded security monitoring agent.

Responsibilities:
  - Poll CPU / RAM / disk every 5 seconds; alert on sudden spikes
  - Monitor Windows Event Log for suspicious process launches and port scans
  - Monitor USB device insertions via WMI
  - Detect brute-force and DoS patterns from gateway webhook events
  - Store all records locally in agent-db.db (SQLite)
  - Push security alerts to the gateway  POST /api/v1/alerts
    which writes them to the qvpn_alerts table in the database

Push flow:
  Alert generated
      ↓
  LocalLogWriter  →  agent-db.db  (always, offline resilience)
      ↓
  GatewayAlertPusher  →  POST /api/v1/alerts  (best-effort, retried)
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import httpx
import psutil

# Optional Windows-only imports — guarded so the module can be imported on
# non-Windows without crashing (e.g. during unit tests).
try:
    import pythoncom
    import wmi
    _WMI_AVAILABLE = True
except ImportError:
    _WMI_AVAILABLE = False

try:
    import win32evtlog
    import subprocess
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False

from client.config import GATEWAY_API_URL, GATEWAY_API_KEY, CLIENT_IDENTIFIER

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("qvpn.agent")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_SECURITY_DIR = Path(__file__).parent
SQLITE_DB_FILE = _SECURITY_DIR / "agent-db.db"
LOG_DIR        = _SECURITY_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOCAL_LOG_FILE = LOG_DIR / "agent_pending.jsonl"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SYSTEM_POLL_INTERVAL_SECONDS = 5.0   # CPU/RAM/disk poll cadence

# Spike detection: alert when reading jumps this many percentage points
# above the rolling baseline in a single poll
CPU_SPIKE_DELTA_PCT  = 30.0   # e.g. 40 % → 72 % in one tick
RAM_SPIKE_DELTA_PCT  = 20.0

# Absolute thresholds (regardless of baseline)
CPU_CRITICAL_PCT  = 95.0
CPU_HIGH_PCT      = 85.0
CPU_WARN_PCT      = 75.0
RAM_CRITICAL_PCT  = 95.0
RAM_HIGH_PCT      = 85.0
DISK_HIGH_PCT     = 85.0
DISK_CRITICAL_PCT = 95.0

# Rolling baseline window (number of 5-second ticks)
BASELINE_WINDOW = 12   # 60 seconds of history

BRUTE_FORCE_THRESHOLD      = 5
BRUTE_FORCE_WINDOW_SECONDS = 300
DOS_THRESHOLD              = 20
DOS_WINDOW_SECONDS         = 60
THREAT_RESOLVE_SECONDS     = 300

RESTRICTED_PROCESSES = {
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wt.exe", "bash.exe", "wsl.exe",
}

# Gateway push
GATEWAY_ALERTS_URL = f"{GATEWAY_API_URL}/alerts"
PUSH_RETRY_INTERVAL = 30.0   # seconds between retry attempts for failed pushes


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class SecurityAlert:
    alert_id:    str = field(default_factory=lambda: str(uuid.uuid4()))
    client_id:   str = field(default_factory=lambda: CLIENT_IDENTIFIER)
    severity:    str = "LOW"
    description: str = ""
    status:      str = "open"
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Local log writer  (JSONL file → SQLite)
# ---------------------------------------------------------------------------
class LocalLogWriter:
    """Thread-safe append-only log. Records are flushed to SQLite by SQLiteStore."""

    def __init__(self, log_file: Path = LOCAL_LOG_FILE):
        self._path = log_file
        self._lock = threading.Lock()

    def append(self, record: dict) -> None:
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

    def drain(self) -> list[dict]:
        """Return all pending records and truncate the file atomically."""
        with self._lock:
            if not self._path.exists():
                return []
            with open(self._path, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
            self._path.write_text("", encoding="utf-8")
        records = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return records


# ---------------------------------------------------------------------------
# Local SQLite store
# ---------------------------------------------------------------------------
class SQLiteStore:
    """Persists alerts to agent-db.db for offline inspection and retry."""

    def __init__(self, db_path: Path = SQLITE_DB_FILE):
        self._db = db_path
        self._init()

    def _init(self):
        with sqlite3.connect(self._db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id    TEXT PRIMARY KEY,
                    client_id   TEXT NOT NULL,
                    timestamp   TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'open',
                    pushed      INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id           TEXT PRIMARY KEY,
                    client_id    TEXT NOT NULL,
                    timestamp    TEXT NOT NULL,
                    cpu_percent  REAL NOT NULL,
                    ram_percent  REAL NOT NULL,
                    disk_percent REAL NOT NULL
                )
            """)

    def save_alert(self, alert: dict) -> None:
        with sqlite3.connect(self._db) as conn:
            conn.execute(
                """INSERT OR IGNORE INTO security_alerts
                   (alert_id, client_id, timestamp, severity, description, status, pushed)
                   VALUES (:alert_id, :client_id, :timestamp, :severity, :description, :status, 0)""",
                alert,
            )

    def mark_pushed(self, alert_id: str) -> None:
        with sqlite3.connect(self._db) as conn:
            conn.execute("UPDATE security_alerts SET pushed=1 WHERE alert_id=?", (alert_id,))

    def get_unpushed(self) -> list[dict]:
        with sqlite3.connect(self._db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM security_alerts WHERE pushed=0 ORDER BY timestamp ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def save_metric(self, metric: dict) -> None:
        with sqlite3.connect(self._db) as conn:
            conn.execute(
                """INSERT OR IGNORE INTO system_metrics
                   (id, client_id, timestamp, cpu_percent, ram_percent, disk_percent)
                   VALUES (:id, :client_id, :timestamp, :cpu_percent, :ram_percent, :disk_percent)""",
                metric,
            )


# ---------------------------------------------------------------------------
# Gateway alert pusher
# ---------------------------------------------------------------------------
class GatewayAlertPusher:
    """
    Pushes SecurityAlert records to POST /api/v1/alerts on the gateway.

    On success the alert is marked pushed=1 in SQLite so it won't be retried.
    On failure the alert stays pushed=0 and will be retried on the next cycle.
    """

    def __init__(self, store: SQLiteStore):
        self._store = store
        self._headers = {
            "X-API-Key": GATEWAY_API_KEY,
            "Content-Type": "application/json",
        }

    def push(self, alert: dict) -> bool:
        """Push a single alert. Returns True on success."""
        payload = {
            "alert_id":    alert["alert_id"],
            "client_id":   alert["client_id"],
            "timestamp":   alert["timestamp"],
            "severity":    alert["severity"],
            "description": alert["description"],
            "status":      alert.get("status", "open"),
        }
        try:
            resp = httpx.post(
                GATEWAY_ALERTS_URL,
                json=payload,
                headers=self._headers,
                timeout=10.0,
                trust_env=False,
            )
            if resp.status_code in (200, 201):
                self._store.mark_pushed(alert["alert_id"])
                return True
            log.warning("[Agent→GW] Push failed HTTP %d for alert %s", resp.status_code, alert["alert_id"])
        except Exception as exc:
            log.warning("[Agent→GW] Push error for alert %s: %s", alert["alert_id"], exc)
        return False

    def retry_unpushed(self) -> None:
        """Attempt to push all alerts that haven't been delivered yet."""
        pending = self._store.get_unpushed()
        if not pending:
            return
        log.info("[Agent→GW] Retrying %d unpushed alert(s)...", len(pending))
        for alert in pending:
            self.push(alert)


# ---------------------------------------------------------------------------
# System Monitor  (CPU / RAM / disk, every 5 seconds)
# ---------------------------------------------------------------------------
class SystemMonitor:
    """
    Polls system resources every SYSTEM_POLL_INTERVAL_SECONDS (5 s).

    Alert logic:
      - Absolute threshold breach  → emit alert at appropriate severity
      - Sudden spike above rolling baseline  → emit SPIKE alert
      - Re-alerts only when severity level changes (avoids flood)
    """

    def __init__(self, emit_alert: Callable, store: SQLiteStore):
        self._emit   = emit_alert
        self._store  = store
        self._stop   = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._cpu_baseline:  deque[float] = deque(maxlen=BASELINE_WINDOW)
        self._ram_baseline:  deque[float] = deque(maxlen=BASELINE_WINDOW)

        self._cpu_state      = "NORMAL"
        self._cpu_alert_count = 0
        self._ram_alerted    = False
        self._disk_alerted   = False
        self._alerted_pids   = set()

        # Prime the psutil CPU counter so first reading is meaningful
        psutil.cpu_percent(interval=None)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="agent-sysmon")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as exc:
                log.error("[SysMon] Poll error: %s", exc)
            self._stop.wait(SYSTEM_POLL_INTERVAL_SECONDS)

    def _poll(self):
        cpu  = psutil.cpu_percent(interval=0.5)
        ram  = psutil.virtual_memory().percent
        disk = psutil.disk_usage(os.path.abspath(os.sep)).percent

        # Save metric snapshot to local SQLite (no gateway push for metrics)
        self._store.save_metric({
            "id":           str(uuid.uuid4()),
            "client_id":    CLIENT_IDENTIFIER,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "cpu_percent":  round(cpu, 1),
            "ram_percent":  round(ram, 1),
            "disk_percent": round(disk, 1),
        })

        self._check_cpu(cpu)
        self._check_ram(ram)
        self._check_disk(disk)
        self._check_restricted_processes()

        # Update baselines after checks (so spike compares against previous state)
        self._cpu_baseline.append(cpu)
        self._ram_baseline.append(ram)

    # -- CPU ----------------------------------------------------------------

    def _check_cpu(self, cpu: float):
        # Spike detection
        if len(self._cpu_baseline) >= 3:
            baseline_avg = sum(self._cpu_baseline) / len(self._cpu_baseline)
            if cpu - baseline_avg >= CPU_SPIKE_DELTA_PCT and cpu >= CPU_WARN_PCT:
                self._emit(
                    "CPU_SPIKE", "HIGH",
                    f"Sudden CPU spike detected: {baseline_avg:.1f}% → {cpu:.1f}% "
                    f"(+{cpu - baseline_avg:.1f}%)",
                )

        # Absolute thresholds
        if cpu >= CPU_CRITICAL_PCT:
            if self._cpu_state != "CRITICAL":
                self._emit("CPU_HIGH_USAGE", "CRITICAL", f"CPU critically high: {cpu:.1f}%")
                self._cpu_state = "CRITICAL"
                self._cpu_alert_count = 1
            elif self._cpu_alert_count < 3:
                self._emit("CPU_HIGH_USAGE", "CRITICAL", f"CPU critically high: {cpu:.1f}%")
                self._cpu_alert_count += 1
        elif cpu >= CPU_HIGH_PCT:
            if self._cpu_state != "HIGH":
                self._emit("CPU_HIGH_USAGE", "HIGH", f"CPU usage high: {cpu:.1f}%")
                self._cpu_state = "HIGH"
                self._cpu_alert_count = 1
        elif cpu >= CPU_WARN_PCT:
            if self._cpu_state not in ("WARNING", "HIGH", "CRITICAL"):
                self._emit("CPU_HIGH_USAGE", "MEDIUM", f"CPU usage elevated: {cpu:.1f}%")
                self._cpu_state = "WARNING"
        else:
            self._cpu_state = "NORMAL"
            self._cpu_alert_count = 0

    # -- RAM ----------------------------------------------------------------

    def _check_ram(self, ram: float):
        # Spike detection
        if len(self._ram_baseline) >= 3:
            baseline_avg = sum(self._ram_baseline) / len(self._ram_baseline)
            if ram - baseline_avg >= RAM_SPIKE_DELTA_PCT and ram >= RAM_HIGH_PCT:
                self._emit(
                    "RAM_SPIKE", "HIGH",
                    f"Sudden RAM spike detected: {baseline_avg:.1f}% → {ram:.1f}% "
                    f"(+{ram - baseline_avg:.1f}%)",
                )

        if ram >= RAM_CRITICAL_PCT:
            severity = "CRITICAL"
        elif ram >= RAM_HIGH_PCT:
            severity = "HIGH"
        else:
            self._ram_alerted = False
            return

        if not self._ram_alerted:
            self._emit("RAM_HIGH_USAGE", severity, f"RAM usage high: {ram:.1f}%")
            self._ram_alerted = True

    # -- Disk ---------------------------------------------------------------

    def _check_disk(self, disk: float):
        if disk >= DISK_CRITICAL_PCT:
            severity = "CRITICAL"
        elif disk >= DISK_HIGH_PCT:
            severity = "HIGH"
        else:
            self._disk_alerted = False
            return

        if not self._disk_alerted:
            self._emit("DISK_HIGH_USAGE", severity, f"Disk usage high: {disk:.1f}%")
            self._disk_alerted = True

    # -- Restricted processes ----------------------------------------------

    def _check_restricted_processes(self):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = proc.info["name"].lower()
                pid  = proc.info["pid"]
                if name in RESTRICTED_PROCESSES and pid not in self._alerted_pids:
                    self._emit(
                        "RESTRICTED_PROCESS", "CRITICAL",
                        f"Restricted process detected: {name} (PID {pid})",
                    )
                    self._alerted_pids.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass


# ---------------------------------------------------------------------------
# USB Monitor
# ---------------------------------------------------------------------------
class USBMonitor:
    def __init__(self, on_insert: Callable[[str], None]):
        self._on_insert = on_insert
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if not _WMI_AVAILABLE:
            log.warning("[USBMonitor] WMI not available — USB monitoring disabled.")
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="agent-usb")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            existing = {d.DeviceID for d in c.Win32_LogicalDisk(DriveType=2)}
            while not self._stop.is_set():
                try:
                    current = {d.DeviceID for d in c.Win32_LogicalDisk(DriveType=2)}
                    for drive in current - existing:
                        self._on_insert(f"Drive {drive}")
                    existing = current
                except Exception as exc:
                    log.error("[USBMonitor] WMI error: %s", exc)
                self._stop.wait(2.0)
        except Exception as exc:
            log.error("[USBMonitor] Init error: %s", exc)
        finally:
            if _WMI_AVAILABLE:
                pythoncom.CoUninitialize()


# ---------------------------------------------------------------------------
# Windows Event Log Monitor
# ---------------------------------------------------------------------------
class WindowsLogMonitor:
    def __init__(self, on_unknown_process: Callable[[str], None], on_port_scan: Callable):
        self._on_process   = on_unknown_process
        self._on_port_scan = on_port_scan
        self._stop         = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_record  = 0
        self._port_drops   = 0
        self._drop_window_start = time.time()

    def start(self):
        if not _WIN32_AVAILABLE:
            log.warning("[WinLog] win32evtlog not available — Windows log monitoring disabled.")
            return
        self._enable_auditing()
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            total  = win32evtlog.GetNumberOfEventLogRecords(hand)
            oldest = win32evtlog.GetOldestEventLogRecord(hand)
            self._last_record = oldest + total - 1
            win32evtlog.CloseEventLog(hand)
        except Exception as exc:
            log.warning("[WinLog] Could not read Security log baseline (run as admin?): %s", exc)

        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="agent-winlog")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _enable_auditing(self):
        try:
            subprocess.run(
                ["auditpol", "/set", "/subcategory:Process Creation",
                 "/success:enable", "/failure:enable"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["auditpol", "/set", "/subcategory:Filtering Platform Packet Drop",
                 "/success:enable", "/failure:enable"],
                capture_output=True, check=True,
            )
        except Exception as exc:
            log.warning("[WinLog] Could not enable auditing (run as admin?): %s", exc)

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as exc:
                log.debug("[WinLog] Poll error: %s", exc)
            # Reset port-drop window every 10 seconds
            if time.time() - self._drop_window_start > 10:
                self._port_drops = 0
                self._drop_window_start = time.time()
            self._stop.wait(2.0)

    def _poll(self):
        hand = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        new_events = []
        try:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            while events:
                for ev in events:
                    if ev.RecordNumber <= self._last_record:
                        break
                    new_events.append(ev)
                else:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    continue
                break
        finally:
            win32evtlog.CloseEventLog(hand)

        if not new_events:
            return

        self._last_record = max(e.RecordNumber for e in new_events)
        for ev in reversed(new_events):
            self._process_event(ev)

    def _process_event(self, event):
        event_id = event.EventID & 0xFFFF

        if event_id == 4688:  # Process creation
            if event.StringInserts and len(event.StringInserts) > 5:
                path = event.StringInserts[5].lower()
                if "c:\\windows\\" not in path and "c:\\program files" not in path:
                    self._on_process(path)

        elif event_id == 5152:  # Firewall packet drop
            self._port_drops += 1
            if self._port_drops > 50:
                self._on_port_scan()
                self._port_drops = 0


# ---------------------------------------------------------------------------
# Threat Engine
# ---------------------------------------------------------------------------
class QVPNThreatEngine:
    """
    Central event processor. Receives events from all sources, runs pattern
    detection, and emits SecurityAlert objects via emit_alert().
    """

    def __init__(self, store: SQLiteStore, pusher: GatewayAlertPusher):
        self._store  = store
        self._pusher = pusher

        self._failed_logins:       dict[str, list[float]] = {}
        self._connection_attempts: dict[str, list[float]] = {}
        self._last_threat_time = 0.0

        self._sysmon    = SystemMonitor(emit_alert=self.emit_alert, store=store)
        self._usb       = USBMonitor(on_insert=self._on_usb_insert)
        self._win_log   = WindowsLogMonitor(
            on_unknown_process=self._on_unknown_process,
            on_port_scan=self._on_port_scan,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        self._sysmon.start()
        self._usb.start()
        self._win_log.start()
        log.info("[Agent] System monitor, USB monitor, Windows log monitor started.")

    def stop(self):
        self._sysmon.stop()
        self._usb.stop()
        self._win_log.stop()

    def has_active_threats(self) -> bool:
        return (time.time() - self._last_threat_time) < THREAT_RESOLVE_SECONDS

    # ------------------------------------------------------------------
    # Alert emission
    # ------------------------------------------------------------------

    def emit_alert(self, alert_type: str, severity: str, description: str):
        alert = SecurityAlert(
            client_id=CLIENT_IDENTIFIER,
            severity=severity,
            description=f"[{alert_type}] {description}",
        )
        record = alert.to_dict()
        # 1. Write to local SQLite
        self._store.save_alert(record)
        # 2. Attempt immediate gateway push
        pushed = self._pusher.push(record)
        log.info(
            "[Alert] [%s] %s → gateway:%s",
            severity, alert.description, "OK" if pushed else "queued",
        )
        if severity != "INFO":
            self._last_threat_time = time.time()

    # ------------------------------------------------------------------
    # Event handlers (called by monitors)
    # ------------------------------------------------------------------

    def _on_usb_insert(self, drive_id: str):
        self.emit_alert("USB_INSERTION", "HIGH", f"USB device inserted: {drive_id}")

    def _on_unknown_process(self, process_path: str):
        self.emit_alert(
            "UNKNOWN_PROCESS_LAUNCH", "CRITICAL",
            f"Non-system executable launched: {process_path}",
        )

    def _on_port_scan(self):
        self.emit_alert("PORT_SCAN_DETECTED", "HIGH", "Firewall packet drop flood — possible port scan")

    # ------------------------------------------------------------------
    # External event ingestion (called by qvpn_client tunnel events)
    # ------------------------------------------------------------------

    def process_tunnel_event(self, event_type: str, details: dict):
        """Feed VPN tunnel events into the threat engine."""
        client_id = details.get("client_id", CLIENT_IDENTIFIER)
        if event_type == "TUNNEL_DOWN":
            reason = details.get("reason", "unknown")
            self.emit_alert("TUNNEL_FAILURE", "HIGH", f"Tunnel down for {client_id}: {reason}")
        elif event_type == "HEARTBEAT_LOSS":
            self.emit_alert("HEARTBEAT_LOSS", "MEDIUM", f"Heartbeat lost for {client_id}")
        elif event_type == "IP_CHANGE":
            old_ip = details.get("old_ip", "?")
            new_ip = details.get("new_ip", "?")
            self.emit_alert("IP_CHANGE", "MEDIUM", f"IP change for {client_id}: {old_ip} → {new_ip}")

    def process_gateway_event(self, event: dict):
        """Feed gateway-side events (brute-force, DoS) into the threat engine."""
        event_type = event.get("type")
        src_ip     = event.get("source_ip", "unknown")
        now        = time.time()

        if event_type == "FAILED_LOGIN":
            attempts = [t for t in self._failed_logins.get(src_ip, [])
                        if now - t <= BRUTE_FORCE_WINDOW_SECONDS]
            attempts.append(now)
            self._failed_logins[src_ip] = attempts
            if len(attempts) >= BRUTE_FORCE_THRESHOLD:
                self.emit_alert(
                    "BRUTE_FORCE", "CRITICAL",
                    f"Brute-force detected: {len(attempts)} failed logins in "
                    f"{BRUTE_FORCE_WINDOW_SECONDS}s from {src_ip}",
                )
                self._failed_logins[src_ip] = []

        elif event_type == "CONNECTION_ATTEMPT":
            attempts = [t for t in self._connection_attempts.get(src_ip, [])
                        if now - t <= DOS_WINDOW_SECONDS]
            attempts.append(now)
            self._connection_attempts[src_ip] = attempts
            if len(attempts) >= DOS_THRESHOLD:
                self.emit_alert(
                    "DOS_DETECTED", "HIGH",
                    f"DoS/port-scan: {len(attempts)} connection attempts in "
                    f"{DOS_WINDOW_SECONDS}s from {src_ip}",
                )
                self._connection_attempts[src_ip] = []


# ---------------------------------------------------------------------------
# Background retry loop
# ---------------------------------------------------------------------------
class AgentRetryWorker:
    """Periodically retries alerts that failed to push to the gateway."""

    def __init__(self, pusher: GatewayAlertPusher, interval: float = PUSH_RETRY_INTERVAL):
        self._pusher   = pusher
        self._interval = interval
        self._stop     = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="agent-retry")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while not self._stop.is_set():
            self._stop.wait(self._interval)
            if not self._stop.is_set():
                self._pusher.retry_unpushed()


# ---------------------------------------------------------------------------
# Public API — used by qvpn_client.py
# ---------------------------------------------------------------------------
class SecurityAgent:
    """
    Facade that qvpn_client.py uses.

    Usage:
        agent = SecurityAgent()
        agent.start()                              # called once at startup
        agent.notify_tunnel_event("TUNNEL_DOWN", {...})   # from client events
        agent.stop()                               # called at shutdown
    """

    def __init__(self):
        self._store  = SQLiteStore()
        self._pusher = GatewayAlertPusher(self._store)
        self._engine = QVPNThreatEngine(self._store, self._pusher)
        self._retry  = AgentRetryWorker(self._pusher)

    def start(self):
        self._engine.start()
        self._retry.start()
        log.info("[SecurityAgent] Started (client_id=%s, db=%s)", CLIENT_IDENTIFIER, SQLITE_DB_FILE)

    def stop(self):
        self._engine.stop()
        self._retry.stop()
        # Final retry pass before exit
        self._pusher.retry_unpushed()
        log.info("[SecurityAgent] Stopped.")

    def notify_tunnel_event(self, event_type: str, details: dict):
        """Forward VPN tunnel events to the threat engine."""
        self._engine.process_tunnel_event(event_type, details)

    def notify_gateway_event(self, event: dict):
        """Forward gateway-side events (FAILED_LOGIN, CONNECTION_ATTEMPT) to the engine."""
        self._engine.process_gateway_event(event)
