import http.server
import json

class TelemetryReceiverHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the size of the incoming JSON payload
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        # Decode and parse the JSON data sent by our agent
        telemetry_payload = json.loads(post_data.decode('utf-8'))
        
        # Extract metadata metrics for verification
        metadata = telemetry_payload.get("agent_metadata", {})
        health = telemetry_payload.get("system_health", {})
        
        print(f"\n[SERVER RECEIVER] Incoming connection from {metadata.get('hostname')} ({metadata.get('public_ip')})")
        print(f"    [+] Timestamp: {metadata.get('scan_time_utc')}")
        print(f"    [+] Live Health Metrics -> CPU: {health.get('cpu_percent')}% | RAM: {health.get('ram_used_percent')}%")
        
        # Send a standard HTTP 200 OK success response back to the agent
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "success", "message": "Telemetry ingested successfully"}')

if __name__ == "__main__":
    server_address = ('127.0.0.1', 8000)
    httpd = http.server.HTTPServer(server_address, TelemetryReceiverHandler)
    print("[*] Backend Telemetry Receiver listening on http://127.0.0.1:8000...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Receiver shut down.")
