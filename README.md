Traffic Routing Module

A local SOCKS5 proxy server that intercepts browser traffic and forwards it either directly to the internet (current mode) or through the QVPN encrypted tunnel (once Task 1's client is ready).

## How it fits into the QVPN architecture

```
Browser → SOCKS5 proxy (this module, port 1080)
               │
               ├─ USE_QVPN_TUNNEL=False → direct TCP to internet
               └─ USE_QVPN_TUNNEL=True  → QVPN client (Task 1, port 5000) → encrypted tunnel
```

Traffic statistics are recorded per destination host and printed on shutdown, feeding into Task 6 (Data Collection APIs).

## Setup (macOS)

```bash
cd task3-proxy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the proxy

```bash
python3 main.py
```

Expected startup output:
```
2026-06-19 12:00:00,000 [INFO] QVPN Proxy running on 127.0.0.1:1080
2026-06-19 12:00:00,001 [INFO] Browser proxy: SOCKS5 → 127.0.0.1:1080
```

Press **Ctrl+C** to stop — a traffic summary table prints before exit.

## Configuring your browser to use the proxy

### Chrome / Brave (macOS System Preferences shortcut)
1. Open **System Settings → Network → Wi-Fi (or Ethernet) → Details → Proxies**
2. Enable **SOCKS Proxy**, set server `127.0.0.1`, port `1080`
3. Click OK / Apply

Or launch Chrome with a flag (no system-wide change):
```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --proxy-server="socks5://127.0.0.1:1080"
```

### Firefox
1. **Settings → General → Network Settings → Manual proxy configuration**
2. SOCKS Host: `127.0.0.1`, Port: `1080`, SOCKS v5
3. Check **Proxy DNS when using SOCKS v5**

### Safari
Safari uses macOS system proxies — follow the System Settings steps above.

## Verifying it works

With the proxy running, open a browser tab. In the terminal you should see lines like:

```
2026-06-19 12:01:05,123 [INFO] ('127.0.0.1', 54321) → example.com:443
2026-06-19 12:01:05,124 [INFO] Direct mode → example.com:443
```

Each new destination host logged = the proxy is intercepting and forwarding correctly.

When you press Ctrl+C:
```
--- Traffic Summary ---
example.com: 3 conns | ↑12KB ↓340KB
--- Traffic Summary ---
```

## Configuration options

Edit `config/settings.py`:

| Setting | Default | Purpose |
|---|---|---|
| `PROXY_HOST` | `127.0.0.1` | Interface the proxy listens on |
| `PROXY_PORT` | `1080` | Port browsers point at |
| `USE_QVPN_TUNNEL` | `False` | `False` = direct, `True` = route via QVPN client |
| `QVPN_CLIENT_HOST` | `127.0.0.1` | Where the QVPN client (Task 1) listens |
| `QVPN_CLIENT_PORT` | `5000` | Port of the QVPN client |
| `LOG_LEVEL` | `INFO` | Python logging level |

## Integrating with the QVPN client (Task 1)

1. Confirm the metadata format with the Task 1 owner (how to pass `dest_host:dest_port` over the tunnel connection — see the TODO in `proxy/handler.py`).
2. In `config/settings.py`, set:
   ```python
   USE_QVPN_TUNNEL = True
   QVPN_CLIENT_PORT = <port Task 1 listens on>
   ```
3. Start the QVPN client first, then start this proxy.

## Running tests

```bash
pytest tests/
```

All tests are pure stdlib + pytest — no network connections required.
