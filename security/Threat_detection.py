import uuid
import time
from datetime import datetime, timezone
from collections import defaultdict
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

# --- Database Setup ---
Base = declarative_base()

class AlertRecord(Base):
    """Database model for storing QVPN threat alerts."""
    __tablename__ = 'qvpn_alerts'
    
    alert_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    severity = Column(String, nullable=False)
    description = Column(String, nullable=False)
    status = Column(String, default="ACTIVE")

# --- Event Processing Layer ---
class QVPNThreatEngine:
    def __init__(self, db_url="sqlite:///qvpn_threats.db"):
        # Initialize Database
        self.engine = create_engine(db_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        
        # In-Memory State Trackers for Time-Based Thresholds
        self.failed_logins = defaultdict(list)
        self.connection_attempts = defaultdict(list)
        self.client_ips = {}

    def _generate_alert(self, severity: str, description: str):
        """Generates the alert and stores it securely in the database."""
        session = self.Session()
        try:
            new_alert = AlertRecord(
                severity=severity,
                description=description,
                status="ACTIVE"
            )
            session.add(new_alert)
            session.commit()
            print(f"[ALERT GENERATED] [{severity}] {description} (ID: {new_alert.alert_id})")
        except Exception as e:
            session.rollback()
            print(f"[!] Failed to store alert: {e}")
        finally:
            session.close()

    # --- 1. Monitoring Agent Events (Host-Level) ---
    def process_monitoring_agent_event(self, event: dict):
        event_type = event.get("type")
        details = event.get("details", {})
        
        if event_type == "UNKNOWN_PROCESS_LAUNCH":
            process_name = details.get("process_name", "UnknownBinary.exe")
            self._generate_alert("CRITICAL", f"Suspicious process execution detected: {process_name}")
            
        elif event_type == "USB_INSERTION":
            device_id = details.get("hardware_id", "Unknown_USB_Device")
            self._generate_alert("HIGH", f"Unauthorized USB insertion detected: {device_id}")

    # --- 2. QVPN Client Events (Data Plane/Network Level) ---
    def process_qvpn_client_event(self, event: dict):
        event_type = event.get("type")
        client_id = event.get("client_id", "Unknown_Client")
        details = event.get("details", {})
        
        if event_type == "TUNNEL_FAILURE":
            reason = details.get("reason", "Connection dropped")
            self._generate_alert("HIGH", f"Tunnel failure for Client {client_id}. Reason: {reason}")
            
        elif event_type == "HEARTBEAT_LOSS":
            self._generate_alert("MEDIUM", f"Heartbeat lost for Client {client_id}. Tunnel may be unresponsive.")
            
        elif event_type == "IP_CHANGE":
            old_ip = details.get("old_ip")
            new_ip = details.get("new_ip")
            self._generate_alert("MEDIUM", f"IP Address change detected for Client {client_id}: {old_ip} -> {new_ip}")

    # --- 3. Gateway Events (Control Plane/API Level) ---
    def process_gateway_event(self, event: dict):
        event_type = event.get("type")
        source_ip = event.get("source_ip", "Unknown_IP")
        current_time = time.time()
        
        if event_type == "FAILED_LOGIN":
            # Track failed logins per IP
            self.failed_logins[source_ip].append(current_time)
            # Clean up attempts older than 5 minutes (300 seconds)
            self.failed_logins[source_ip] = [t for t in self.failed_logins[source_ip] if current_time - t < 300]
            
            # Threshold: 5 failed logins within 5 minutes
            if len(self.failed_logins[source_ip]) >= 5:
                self._generate_alert("CRITICAL", f"Multiple failed logins (Brute-Force attempt) from IP: {source_ip}")
                self.failed_logins[source_ip].clear() # Reset tracker after triggering alert
                
        elif event_type == "CONNECTION_ATTEMPT":
            # Track connection flooding
            self.connection_attempts[source_ip].append(current_time)
            # Clean up attempts older than 1 minute (60 seconds)
            self.connection_attempts[source_ip] = [t for t in self.connection_attempts[source_ip] if current_time - t < 60]
            
            # Threshold: 20 connection attempts within 1 minute
            if len(self.connection_attempts[source_ip]) >= 20:
                self._generate_alert("HIGH", f"Excessive connection attempts (Potential DoS/Scan) from IP: {source_ip}")
                self.connection_attempts[source_ip].clear() # Reset tracker