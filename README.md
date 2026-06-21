# Component 1 — QVPN Client

The QVPN Client is an asyncio-based tunnel manager that performs the post-quantum handshake against the Gateway API, derives an AES-256 session key, programmatically manages the Windows system proxy, and bi-directionally forwards encrypted proxy data.

## Configuration & Environment Variables

Create or update the `.env` file in the project root:

```env
# Gateway API Key (supplied to X-API-Key header)
GATEWAY_API_KEY=qvpn_live_k3QkE7APJgFTpXEafOzeLR3NYDie0wHP-IOGn_JE0Og
GATEWAY_API_URL=http://localhost:8001/api/v1
CLIENT_IDENTIFIER=test-client-1

# Post-Quantum API Configuration
PQC_API_URL=https://qnnx-sentinel-production.up.railway.app/api/v1
PQC_API_KEY=qnnx_T-jfvqServyQKVNp0IjvPB0PG9C8KvZTzoBiLCQg2ks
PQC_SIGNING_SECRET=qnnxsig_JtRadgK84riOp73H4nwxz6N11Hph6TzHObGkxbotdAo
```

## How to Run

Ensure the virtual environment is activated and dependencies are installed, then run the client as a module:

```powershell
# From the qvpn-client root directory
venv\Scripts\python -m client.qvpn_client
```

This starts:
1. The Eel Graphical Dashboard (opens Edge browser on port `8085`).
2. An async TCP proxy interface on `127.0.0.1:8282`.
3. An observability status endpoint on `http://127.0.0.1:8283/status`.

## Verification

1. In the opened Eel UI, click **CONNECT**.
2. Once connection succeeds, verify that the status on the central button changes to **SECURE**.
3. Perform a GET request to the observability endpoint to verify state values:
   ```powershell
   curl http://127.0.0.1:8283/status
   ```
   *Expected Output:*
   ```json
   {
     "client_id": "test-client-1",
     "session_id": "...",
     "tunnel_status": "active",
     "heartbeat_status": "healthy"
   }
   ```
4. Verify Windows Proxy Settings:
   * Open Settings > Network & Internet > Proxy.
   * "Use a proxy server" should be toggled **ON** and point to `127.0.0.1:8080`.
5. Revert verification:
   * Close the UI window or stop the Python process.
   * Verify "Use a proxy server" is toggled **OFF** in Windows Proxy Settings.
