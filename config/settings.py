# Proxy listens here — browser will point to this
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080

# When QVPN client is ready, this is where we'll forward to
# For now we forward directly to internet (bypass mode)
QVPN_CLIENT_HOST = "127.0.0.1"
QVPN_CLIENT_PORT = 5000

# Toggle: True = forward to QVPN client, False = direct to internet
USE_QVPN_TUNNEL = True

LOG_LEVEL = "INFO"