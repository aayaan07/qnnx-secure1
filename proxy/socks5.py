"""
Parses the SOCKS5 handshake from the browser.
Reference: RFC 1928
"""

SOCKS_VERSION = 5

async def do_handshake(reader, writer):
    """
    Step 1: Browser says hello and lists supported auth methods.
    We always respond with 'no auth required'.
    """
    # Read version + number of auth methods
    header = await reader.readexactly(2)
    version, num_methods = header[0], header[1]

    if version != SOCKS_VERSION:
        writer.close()
        raise ValueError(f"Unsupported SOCKS version: {version}")

    # Read the auth methods list (we ignore them, always pick 'no auth')
    await reader.readexactly(num_methods)

    # Reply: version=5, method=0 (no auth)
    writer.write(bytes([SOCKS_VERSION, 0x00]))
    await writer.drain()


async def read_request(reader):
    """
    Step 2: Browser tells us where it wants to connect.
    Returns (destination_host, destination_port)
    """
    # VER, CMD, RSV, ATYP
    header = await reader.readexactly(4)
    version, cmd, _, addr_type = header

    if version != SOCKS_VERSION:
        raise ValueError("Bad SOCKS version in request")

    # CMD 0x01 = CONNECT (what browsers always send)
    if cmd != 0x01:
        raise ValueError(f"Unsupported command: {cmd}")

    # Parse the destination address
    if addr_type == 0x01:
        # IPv4 — 4 bytes
        raw = await reader.readexactly(4)
        host = ".".join(str(b) for b in raw)

    elif addr_type == 0x03:
        # Domain name — first byte is length
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode()

    elif addr_type == 0x04:
        # IPv6 — 16 bytes
        raw = await reader.readexactly(16)
        import socket
        host = socket.inet_ntop(socket.AF_INET6, raw)

    else:
        raise ValueError(f"Unknown address type: {addr_type}")

    # Port is always 2 bytes big-endian
    port_raw = await reader.readexactly(2)
    port = int.from_bytes(port_raw, "big")

    return host, port


async def send_success(writer):
    """
    Tell the browser 'yes, connected successfully'.
    """
    # VER, REP=success, RSV, ATYP=IPv4, BIND.ADDR, BIND.PORT
    reply = bytes([
        SOCKS_VERSION, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,  # 0.0.0.0
        0x00, 0x00               # port 0
    ])
    writer.write(reply)
    await writer.drain()


async def send_failure(writer):
    """
    Tell the browser 'connection failed'.
    """
    reply = bytes([
        SOCKS_VERSION, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ])
    writer.write(reply)
    await writer.drain()