# Component 2 — Local Proxy

The Local Proxy intercepts HTTP/HTTPS traffic from the system/browser, parses target destinations, and routes them through the QVPN Client's local interface (`127.0.0.1:8282`) to the encrypted Gateway tunnel.

## Configuration & Environment Variables

No configuration or `.env` files are required. The Local Proxy defaults to:
* Listening on local interface: `127.0.0.1:8080`
* Forwarding to QVPN Client: `127.0.0.1:8282`

## How to Run

Activate the virtual environment and start the proxy module:

```powershell
# From the qvpn-client root directory
venv\Scripts\python -m client.local_proxy
```

## Browser Configuration

The QVPN Client automatically configures Chrome, Edge, and other system-proxy-compliant browsers when it connects.

If you are using **Mozilla Firefox** (which ignores system proxy settings by default) or want to configure a browser manually:
1. Open your browser's proxy settings.
2. Select **Manual proxy configuration**.
3. Set **HTTP Proxy** to `127.0.0.1` and **Port** to `8080`.
4. Check **Also use this proxy for HTTPS**.
5. Save settings.

## Verification

1. Ensure the QVPN Client has successfully connected (Eel UI shows **SECURE**).
2. Open a browser configured to use the proxy (Edge/Chrome will use it automatically via system settings).
3. Navigate to `https://httpbin.org/ip`.
4. Verify that the page loads correctly and displays your remote gateway's IP address.
5. In the QVPN Client UI, verify that `Tx Pkts` and `Rx Pkts` counters increment as you browse.
6. Stop the QVPN Client. Navigate in the browser and verify you receive a **502 Bad Gateway** page.
