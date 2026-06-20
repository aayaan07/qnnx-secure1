import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.Threat_detection import QVPNThreatEngine, AlertRecord

def run_tests():
    # 1. Initialize Engine
    engine = QVPNThreatEngine()
    print("[*] Engine initialized. Running full simulation...\n")

    # 2. Monitoring Agent (Host-Level)
    engine.process_monitoring_agent_event({
        "type": "USB_INSERTION",
        "details": {"hardware_id": "USB-DISK-9988"}
    })
    engine.process_monitoring_agent_event({
        "type": "UNKNOWN_PROCESS_LAUNCH",
        "details": {"process_name": "malicious_script.exe"}
    })

    # 3. QVPN Client (Data Plane)
    engine.process_qvpn_client_event({
        "type": "TUNNEL_FAILURE",
        "client_id": "CLI-001",
        "details": {"reason": "Timeout"}
    })
    engine.process_qvpn_client_event({
        "type": "HEARTBEAT_LOSS",
        "client_id": "CLI-001"
    })
    engine.process_qvpn_client_event({
        "type": "IP_CHANGE",
        "client_id": "CLI-001",
        "details": {"old_ip": "10.0.0.1", "new_ip": "10.0.0.2"}
    })

    # 4. Gateway (Control Plane)
    print("[*] Simulating Brute Force (5 failed logins)...")
    for _ in range(5):
        engine.process_gateway_event({
            "type": "FAILED_LOGIN",
            "source_ip": "192.168.1.100"
        })

    print("[*] Simulating Connection Flooding (20 attempts)...")
    for _ in range(20):
        engine.process_gateway_event({
            "type": "CONNECTION_ATTEMPT",
            "source_ip": "192.168.1.50"
        })

    # 5. Verify the Database
    print("\n[*] Fetching alerts from database...")
    session = engine.Session()
    alerts = session.query(AlertRecord).all()
    
    print(f"[*] Total alerts generated: {len(alerts)}")
    for alert in alerts:
        print(f"ID: {alert.alert_id[:8]}... | {alert.severity:8} | {alert.description}")
    
    session.close()

if __name__ == "__main__":
    run_tests()