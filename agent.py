import os
import socket
import datetime
import json
import psutil
import time
import urllib.request
import win32evtlog

class EnterpriseMonitoringAgent:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.current_user = os.getlogin()

    def get_public_ip(self):
        """Retrieves the machine's external public IP address using a lightweight API call."""
        try:
            return urllib.request.urlopen('https://api.ipify.org', timeout=3).read().decode('utf-8')
        except Exception:
            return "Unavailable (Offline)"

    def get_system_health(self):
        """Queries the OS for CPU, RAM, and primary disk usage metrics."""
        try:
            disk_info = psutil.disk_usage('C:\\').percent
        except Exception:
            disk_info = 0.0
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "ram_used_percent": psutil.virtual_memory().percent,
            "disk_c_percent": disk_info
        }

    def get_active_processes(self, limit=5):
        """Finds all running processes, sorts them by CPU usage, and returns top hits."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                if proc.info['cpu_percent'] is not None:
                    processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        sorted_processes = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)
        return sorted_processes[:limit]

    def get_network_connections(self, limit=5):
        """Gathers active internet connections currently established on the machine."""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    connections.append({
                        "pid": conn.pid,
                        "local_port": conn.laddr.port,
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port
                    })
                if len(connections) >= limit:
                    break
        except Exception:
            pass
        return connections

    def get_windows_event_logs(self, log_type, target_event_ids, limit=2):
        """Queries native Windows Event Logs for specific targeted security and system IDs."""
        events_found = []
        try:
            hand = win32evtlog.OpenEventLog(self.hostname, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for record in records:
                if record.EventID in target_event_ids:
                    events_found.append({
                        "event_id": record.EventID,
                        "time_generated": record.TimeGenerated.Format(),
                        "record_number": record.RecordNumber
                    })
                if len(events_found) >= limit:
                    break
        except Exception as e:
            return [{"error": f"Access Denied on {log_type} channel. Run terminal as Administrator."}]
        return events_found

    def generate_report(self):
        """Compiles all requested telemetry points into a structured JSON dictionary."""
        return {
            "agent_metadata": {
                "hostname": self.hostname,
                "current_user": self.current_user,
                "public_ip": self.get_public_ip(),
                "scan_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()
            },
            "system_health": self.get_system_health(),
            "top_active_processes": self.get_active_processes(),
            "active_network_connections": self.get_network_connections(),
            "authentication_events": {
                "successful_logins_and_logouts": self.get_windows_event_logs("Security", [4624, 4634], limit=3),
                "failed_login_attempts": self.get_windows_event_logs("Security", [4625], limit=3)
            },
            "hardware_events": {
                "usb_pnp_activity": self.get_windows_event_logs("System", [20001], limit=3)
            }
        }

def push_to_backend(payload):
    """Encapsulates and transmits the JSON payload over HTTP POST to the ingestion server."""
    target_url = "http://127.0.0.1:8000/api/v1/monitoring/metrics"
    try:
        # Convert the dictionary payload to raw byte strings
        stringified_data = json.dumps(payload).encode('utf-8')
        
        # Build out structural HTTP headers matching standard SIEM schemas
        req = urllib.request.Request(
            target_url, 
            data=stringified_data, 
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        
        # Execute the network submission and catch the status response
        with urllib.request.urlopen(req, timeout=4) as response:
            server_feedback = response.read().decode('utf-8')
            print(f"[+] Data successfully transmitted to backend. Server response: {server_feedback}")
            
    except Exception as e:
        print(f"[!] Network Transport Error: Failed to connect to server pipeline. Reason: {e}")


if __name__ == "__main__":
    agent = EnterpriseMonitoringAgent()
    print("[*] Continuous Monitoring Agent active. Press Ctrl+C to terminate application.\n")
    
    LOOP_INTERVAL_SECONDS = 10
    
    try:
        while True:
            report_payload = agent.generate_report()
            print(f"[*] Local Snapshot Generated at: {report_payload['agent_metadata']['scan_time_utc']}")
            
            # Fire the upgraded live network ingestion execution path
            push_to_backend(report_payload)
            
            time.sleep(LOOP_INTERVAL_SECONDS)
            print("-" * 60)
            
    except KeyboardInterrupt:
        print("\n[*] Agent tracking suspended gracefully.")
