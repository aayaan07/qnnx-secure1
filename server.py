import http.server
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from security.Threat_detection import QVPNThreatEngine

threat_engine = QVPNThreatEngine()


class TelemetryReceiverHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        payload = json.loads(post_data.decode('utf-8'))

        metadata = payload.get("agent_metadata", {})
        health   = payload.get("system_health", {})

        print(f"\n[SERVER] From {metadata.get('hostname')} ({metadata.get('public_ip')})")
        print(f"  Timestamp : {metadata.get('scan_time_utc')}")
        print(f"  Health    : CPU {health.get('cpu_percent')}% | RAM {health.get('ram_used_percent')}%")

        # Route failed login events to the threat engine
        for event in payload.get("authentication_events", {}).get("failed_login_attempts", []):
            if "error" not in event:
                threat_engine.process_gateway_event({
                    "type": "FAILED_LOGIN",
                    "source_ip": metadata.get("public_ip", "unknown")
                })

        # Route USB insertion events to the threat engine
        for event in payload.get("hardware_events", {}).get("usb_pnp_activity", []):
            if "error" not in event:
                threat_engine.process_monitoring_agent_event({
                    "type": "USB_INSERTION",
                    "details": {"hardware_id": str(event.get("record_number", "unknown"))}
                })

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "success", "message": "Telemetry ingested successfully"}')

    def log_message(self, _format, *_args):
        pass  # suppress default per-request stdout noise


if __name__ == "__main__":
    server_address = ('127.0.0.1', 8000)
    httpd = http.server.HTTPServer(server_address, TelemetryReceiverHandler)
    print("[*] Backend Telemetry Receiver listening on http://127.0.0.1:8000...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Receiver shut down.")
