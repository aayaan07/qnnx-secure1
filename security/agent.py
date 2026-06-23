"""
agent.py
--------
Unified monitoring agent for QVPN.
Handles local threat detection, system resource polling, and database synchronisation.
Records are logged to a single local JSONL file, then synced to separate tables:
 - security_alerts
 - system_metrics
"""
import json
import logging
import os
import shutil
import sqlite3
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

import psutil

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PACKAGE_DIR = Path(__file__).parent
LOG_DIR = PACKAGE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOCAL_SQLITE_LOG_FILE = LOG_DIR / "sqlite_logs.json"
SUPABASE_LOG_FILE = LOG_DIR / "supabase_logs.jsonb"
SQLITE_DB_FILE = PACKAGE_DIR / "local_test.db"

# Agent Client ID (for system metrics)
AGENT_CLIENT_ID = "00000000-0000-0000-0000-000000000000"  # Can be overridden or dynamically generated

# Polling configuration
SYSTEM_POLL_INTERVAL_SECONDS = 30.0

# Thresholds
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 300
DOS_THRESHOLD = 20
DOS_WINDOW_SECONDS = 60

CPU_HIGH_THRESHOLD_PCT = 85.0
CPU_CRITICAL_THRESHOLD_PCT = 95.0
CPU_SUSTAINED_READINGS = 3

RAM_HIGH_THRESHOLD_PCT = 85.0
RAM_CRITICAL_THRESHOLD_PCT = 95.0

DISK_HIGH_THRESHOLD_PCT = 85.0
DISK_CRITICAL_THRESHOLD_PCT = 95.0

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
@dataclass
class SecurityAlert:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_types: str = ""
    severity: str = "LOW"
    description: str = ""
    status: str = "open"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    # Internal routing tag
    _record_type: str = "alert"

    def to_dict(self):
        return asdict(self)

@dataclass
class SystemMetric:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str = AGENT_CLIENT_ID
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cpu_percent: float = 0.0
    ram_percent: float = 0.0
    disk_percent: float = 0.0
    
    # Internal routing tag
    _record_type: str = "metric"

    def to_dict(self):
        return asdict(self)

# ---------------------------------------------------------------------------
# Log Writer
# ---------------------------------------------------------------------------
class LocalLogWriter:
    def __init__(self, sqlite_log_file: Path = LOCAL_SQLITE_LOG_FILE, supabase_log_file: Path = SUPABASE_LOG_FILE):
        self._sqlite_log = sqlite_log_file
        self._supabase_log = supabase_log_file
        self._lock = threading.Lock()

    def write_record(self, record: dict) -> None:
        with self._lock:
            record_str = json.dumps(record) + "\n"
            # Write for local SQLite sync
            with open(self._sqlite_log, "a", encoding="utf-8") as f:
                f.write(record_str)
            # Write for Supabase sync
            with open(self._supabase_log, "a", encoding="utf-8") as f:
                f.write(record_str)

    def read_and_clear(self) -> list[dict]:
        """Reads and clears the local SQLite log. The Supabase log remains untouched."""
        with self._lock:
            if not self._sqlite_log.exists():
                return []
            with open(self._sqlite_log, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            
            # Clear file
            with open(self._sqlite_log, "w", encoding="utf-8") as f:
                pass
            
            records = []
            for line in lines:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return records

# ---------------------------------------------------------------------------
# System Monitor
# ---------------------------------------------------------------------------
class SystemMonitor:
    def __init__(self, log_writer: LocalLogWriter, emit_alert: Callable, poll_interval: float = SYSTEM_POLL_INTERVAL_SECONDS):
        self._writer = log_writer
        self._emit_alert = emit_alert
        self._interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._cpu_over_threshold_count = 0
        self._last_alert = {}
        self._alert_cooldown_seconds = poll_interval * 2

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()

    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                self._collect_and_evaluate()
            except Exception as e:
                logging.getLogger("agent").error(f"System monitor error: {e}")
            self._stop_event.wait(timeout=self._interval)

    def _collect_and_evaluate(self):
        metric = SystemMetric()
        metric.cpu_percent = psutil.cpu_percent(interval=None)
        
        mem = psutil.virtual_memory()
        metric.ram_percent = mem.percent

        disk_path = os.path.abspath(os.sep)
        disk = shutil.disk_usage(disk_path)
        if disk.total > 0:
            metric.disk_percent = round((disk.used / disk.total) * 100, 1)
        
        # Write the metric to the log
        self._writer.write_record(metric.to_dict())

        # Evaluate thresholds for alerts
        self._check_cpu(metric.cpu_percent)
        self._check_ram(metric.ram_percent)
        self._check_disk(metric.disk_percent)

    def _check_cpu(self, cpu: float):
        if cpu >= CPU_CRITICAL_THRESHOLD_PCT or cpu >= CPU_HIGH_THRESHOLD_PCT:
            self._cpu_over_threshold_count += 1
        else:
            self._cpu_over_threshold_count = 0
            return

        if self._cpu_over_threshold_count < CPU_SUSTAINED_READINGS:
            return

        severity = "CRITICAL" if cpu >= CPU_CRITICAL_THRESHOLD_PCT else "HIGH"
        if not self._in_cooldown("cpu"):
            self._emit_alert(alert_type="CPU_HIGH_USAGE", severity=severity, description=f"CPU usage critically high: {cpu:.1f}%")
            self._set_cooldown("cpu")
            self._cpu_over_threshold_count = 0

    def _check_ram(self, ram: float):
        if ram >= RAM_CRITICAL_THRESHOLD_PCT:
            severity = "CRITICAL"
        elif ram >= RAM_HIGH_THRESHOLD_PCT:
            severity = "HIGH"
        else:
            return

        if not self._in_cooldown("ram"):
            self._emit_alert(alert_type="RAM_HIGH_USAGE", severity=severity, description=f"RAM usage high: {ram:.1f}%")
            self._set_cooldown("ram")

    def _check_disk(self, disk: float):
        if disk >= DISK_CRITICAL_THRESHOLD_PCT:
            severity = "CRITICAL"
        elif disk >= DISK_HIGH_THRESHOLD_PCT:
            severity = "HIGH"
        else:
            return

        if not self._in_cooldown("disk"):
            self._emit_alert(alert_type="DISK_HIGH_USAGE", severity=severity, description=f"Disk usage high: {disk:.1f}%")
            self._set_cooldown("disk")

    def _in_cooldown(self, key: str) -> bool:
        last = self._last_alert.get(key)
        if last is None: return False
        return (time.monotonic() - last) < self._alert_cooldown_seconds

    def _set_cooldown(self, key: str) -> None:
        self._last_alert[key] = time.monotonic()


# ---------------------------------------------------------------------------
# Threat Engine
# ---------------------------------------------------------------------------
class QVPNThreatEngine:
    def __init__(self, log_writer: LocalLogWriter, enable_sysmon: bool = True):
        self._writer = log_writer
        
        self._failed_logins = {}
        self._connection_attempts = {}

        self._sysmon = None
        if enable_sysmon:
            self._sysmon = SystemMonitor(log_writer=self._writer, emit_alert=self.emit_alert)
            self._sysmon.start()

    def shutdown(self):
        if self._sysmon:
            self._sysmon.stop()

    def emit_alert(self, alert_type: str, severity: str, description: str):
        alert = SecurityAlert(alert_types=alert_type, severity=severity, description=description)
        self._writer.write_record(alert.to_dict())
        logging.getLogger("agent").info(f"Generated Alert: [{severity}] {description}")

    def process_monitoring_agent_event(self, event: dict):
        event_type = event.get("type")
        details = event.get("details", {})
        
        if event_type == "USB_INSERTION":
            hw_id = details.get("hardware_id", "unknown")
            self.emit_alert("USB_INSERTION", "HIGH", f"Unauthorised USB insertion detected: {hw_id}")
        
        elif event_type == "UNKNOWN_PROCESS_LAUNCH":
            pname = details.get("process_name", "unknown")
            self.emit_alert("UNKNOWN_PROCESS_LAUNCH", "CRITICAL", f"Suspicious process execution detected: {pname}")

    def process_qvpn_client_event(self, event: dict):
        event_type = event.get("type")
        client_id = event.get("client_id", "unknown")
        details = event.get("details", {})

        if event_type == "TUNNEL_FAILURE":
            reason = details.get("reason", "unknown")
            self.emit_alert("TUNNEL_FAILURE", "HIGH", f"Tunnel failure for Client {client_id}. Reason: {reason}")
        
        elif event_type == "HEARTBEAT_LOSS":
            self.emit_alert("HEARTBEAT_LOSS", "MEDIUM", f"Heartbeat lost for Client {client_id}. Tunnel may be unresponsive.")
            
        elif event_type == "IP_CHANGE":
            old_ip = details.get("old_ip", "?")
            new_ip = details.get("new_ip", "?")
            self.emit_alert("IP_CHANGE", "MEDIUM", f"IP address change detected for Client {client_id}: {old_ip} -> {new_ip}")

    def process_gateway_event(self, event: dict):
        event_type = event.get("type")
        src_ip = event.get("source_ip")
        if not src_ip: return

        now = time.time()

        if event_type == "FAILED_LOGIN":
            attempts = self._failed_logins.get(src_ip, [])
            attempts = [t for t in attempts if now - t <= BRUTE_FORCE_WINDOW_SECONDS]
            attempts.append(now)
            self._failed_logins[src_ip] = attempts

            if len(attempts) >= BRUTE_FORCE_THRESHOLD:
                self.emit_alert("BRUTE_FORCE_DETECTED", "CRITICAL", f"Brute-force login attempt detected: {len(attempts)} failed logins within {BRUTE_FORCE_WINDOW_SECONDS}s from {src_ip}")
                self._failed_logins[src_ip] = [] # reset
                
        elif event_type == "CONNECTION_ATTEMPT":
            attempts = self._connection_attempts.get(src_ip, [])
            attempts = [t for t in attempts if now - t <= DOS_WINDOW_SECONDS]
            attempts.append(now)
            self._connection_attempts[src_ip] = attempts

            if len(attempts) >= DOS_THRESHOLD:
                self.emit_alert("DOS_DETECTED", "HIGH", f"Potential DoS / port-scan detected: {len(attempts)} connection attempts within {DOS_WINDOW_SECONDS}s from {src_ip}")
                self._connection_attempts[src_ip] = []


# ---------------------------------------------------------------------------
# Database Synchronisation
# ---------------------------------------------------------------------------
class SQLiteSync:
    def __init__(self, log_writer: LocalLogWriter, db_path: Path = SQLITE_DB_FILE):
        self._writer = log_writer
        self._db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id TEXT PRIMARY KEY,
                    alert_types TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    cpu_percent REAL NOT NULL,
                    ram_percent REAL NOT NULL,
                    disk_percent REAL NOT NULL
                )
            ''')

    def push_pending(self) -> dict:
        records = self._writer.read_and_clear()
        if not records:
            return {"alerts": 0, "metrics": 0}

        alerts = [r for r in records if r.get("_record_type") == "alert"]
        metrics = [r for r in records if r.get("_record_type") == "metric"]

        with sqlite3.connect(self._db_path) as conn:
            if alerts:
                conn.executemany('''
                    INSERT OR IGNORE INTO security_alerts (id, alert_types, severity, description, status, timestamp)
                    VALUES (:id, :alert_types, :severity, :description, :status, :timestamp)
                ''', alerts)
            
            if metrics:
                conn.executemany('''
                    INSERT OR IGNORE INTO system_metrics (id, client_id, timestamp, cpu_percent, ram_percent, disk_percent)
                    VALUES (:id, :client_id, :timestamp, :cpu_percent, :ram_percent, :disk_percent)
                ''', metrics)

        logging.getLogger("agent").info(f"Pushed {len(alerts)} alerts and {len(metrics)} metrics to SQLite.")
        return {"alerts": len(alerts), "metrics": len(metrics)}

    def query_alerts(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute("SELECT * FROM security_alerts ORDER BY timestamp DESC").fetchall()]
            
    def query_metrics(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute("SELECT * FROM system_metrics ORDER BY timestamp DESC").fetchall()]

# ---------------------------------------------------------------------------
# Demo Runner
# ---------------------------------------------------------------------------
def run_demo():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    logger = logging.getLogger("agent")
    
    logger.info("Starting QVPN Agent Demo...")
    writer = LocalLogWriter()
    engine = QVPNThreatEngine(log_writer=writer, enable_sysmon=True)

    # Let the sysmon run for a moment to gather a metric (since we set it to 30s, we will trigger it manually once for the demo)
    logger.info("Triggering manual system metric collection...")
    engine._sysmon._collect_and_evaluate()

    logger.info("Feeding simulated security events...")
    engine.process_monitoring_agent_event({"type": "UNKNOWN_PROCESS_LAUNCH", "details": {"process_name": "evil.exe"}})
    engine.process_qvpn_client_event({"type": "TUNNEL_FAILURE", "client_id": "CLI-001", "details": {"reason": "Timeout"}})
    for _ in range(5):
        engine.process_gateway_event({"type": "FAILED_LOGIN", "source_ip": "10.0.0.99"})

    engine.shutdown()

    logger.info("Syncing records to SQLite...")
    sync = SQLiteSync(log_writer=writer)
    pushed = sync.push_pending()
    
    logger.info(f"SQLite Sync Complete: {pushed['alerts']} alerts, {pushed['metrics']} metrics stored.")
    
    logger.info("--- Recent Security Alerts ---")
    for alert in sync.query_alerts()[:3]:
        logger.info(f"[{alert['severity']}] {alert['alert_types']}: {alert['description']}")

    logger.info("--- Recent System Metrics ---")
    for metric in sync.query_metrics()[:3]:
        logger.info(f"CPU: {metric['cpu_percent']}%, RAM: {metric['ram_percent']}%, Disk: {metric['disk_percent']}%")
        
    logger.info("--- Log Files ---")
    logger.info(f"Supabase JSONB file size: {writer._supabase_log.stat().st_size} bytes (ready for push)")
    logger.info(f"SQLite JSON file size: {writer._sqlite_log.stat().st_size if writer._sqlite_log.exists() else 0} bytes (cleared after sync)")

if __name__ == "__main__":
    run_demo()
