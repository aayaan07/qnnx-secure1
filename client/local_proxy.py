import asyncio
import logging
import sys
import os

# Load .env configuration
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [LocalProxy] - %(levelname)s - %(message)s")
logger = logging.getLogger("Local_Proxy")

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
QVPN_CLIENT_HOST = "127.0.0.1"
QVPN_CLIENT_PORT = 8282

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handles a single connection from a browser or application client."""
    client_addr = writer.get_extra_info("peername")
    logger.debug(f"Received connection from {client_addr}")
    
    qvpn_writer = None
    try:
        # 1. Read the initial headers from the client
        # We need to parse the request line (e.g. "CONNECT google.com:443 HTTP/1.1")
        header_data = b""
        while b"\r\n\r\n" not in header_data:
            chunk = await reader.read(65536)
            if not chunk:
                break
            header_data += chunk
            if len(header_data) > 131072:  # Prevent buffer flooding
                break
                
        if not header_data:
            writer.close()
            return
            
        # Split headers
        parts = header_data.split(b"\r\n", 1)
        request_line = parts[0].decode("utf-8", errors="ignore")
        logger.info(f"Request: {request_line}")
        
        req_parts = request_line.split()
        if len(req_parts) < 2:
            writer.close()
            return
            
        method, url = req_parts[0], req_parts[1]
        
        # 2. Extract destination host and port
        host = None
        port = 80
        
        if method.upper() == "CONNECT":
            # HTTPS Tunneling CONNECT method
            # url is "host:port" (e.g. "google.com:443")
            if ":" in url:
                host, port_str = url.split(":", 1)
                port = int(port_str)
            else:
                host = url
                port = 443
        else:
            # Plain HTTP request
            # url is a full URL e.g. "http://example.com/index.html"
            # Parse the host from URL or Host header
            host_header = None
            for line in parts[1].split(b"\r\n"):
                if line.lower().startswith(b"host:"):
                    host_header = line.split(b":", 1)[1].strip().decode("utf-8", errors="ignore")
                    break
            
            if host_header:
                if ":" in host_header:
                    host, port_str = host_header.split(":", 1)
                    port = int(port_str)
                else:
                    host = host_header
                    port = 80
            else:
                # Fallback parse from URL
                temp = url
                if temp.startswith("http://"):
                    temp = temp[7:]
                elif temp.startswith("https://"):
                    temp = temp[8:]
                    port = 443
                
                path_start = temp.find("/")
                host_part = temp[:path_start] if path_start != -1 else temp
                if ":" in host_part:
                    host, port_str = host_part.split(":", 1)
                    port = int(port_str)
                else:
                    host = host_part
        
        if not host:
            logger.warning("No target host found in request headers.")
            writer.close()
            return
            
        # 3. Connect to the target destination via QVPN Client
        try:
            logger.info(f"Connecting to QVPN Client at {QVPN_CLIENT_HOST}:{QVPN_CLIENT_PORT} for target {host}:{port}")
            qv_reader, qv_writer = await asyncio.open_connection(QVPN_CLIENT_HOST, QVPN_CLIENT_PORT)
            qvpn_writer = qv_writer
        except Exception as e:
            logger.error(f"QVPN Client is unreachable: {e}")
            await send_502_bad_gateway(writer)
            return

        # 4. Transmit the target destination header (e.g. "google.com:443\n")
        dest_header = f"{host}:{port}\n".encode("utf-8")
        qv_writer.write(dest_header)
        await qv_writer.drain()

        # 5. Read confirmation from QVPN Client
        response_line = await asyncio.wait_for(qv_reader.readline(), timeout=15.0)
        if response_line.strip() != b"OK":
            logger.error(f"QVPN Client rejected connection: {response_line.decode('utf-8').strip()}")
            await send_502_bad_gateway(writer)
            try:
                qv_writer.close()
                await qv_writer.wait_closed()
            except Exception:
                pass
            return

        # 6. Establish data pipe
        if method.upper() == "CONNECT":
            # Respond to browser that the tunnel is established
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        else:
            # Forward the initial HTTP request buffer (which we already read) to QVPN Client
            qv_writer.write(header_data)
            await qv_writer.drain()

        # Bi-directional pipe
        async def pipe_client_to_qvpn():
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    qv_writer.write(data)
                    await qv_writer.drain()
            except Exception as ex:
                logger.debug(f"Pipe client -> QVPN error: {ex}")
            finally:
                try:
                    qv_writer.close()
                    await qv_writer.wait_closed()
                except Exception:
                    pass

        async def pipe_qvpn_to_client():
            try:
                while True:
                    data = await qv_reader.read(65536)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception as ex:
                logger.debug(f"Pipe QVPN -> client error: {ex}")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        await asyncio.gather(pipe_client_to_qvpn(), pipe_qvpn_to_client())
        
    except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
        logger.info(f"Client connection reset or closed: {e}")
        try:
            writer.close()
        except Exception:
            pass
        if qvpn_writer:
            try:
                qvpn_writer.close()
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Unexpected error in client handler: {e}", exc_info=True)
        try:
            writer.close()
        except Exception:
            pass
        if qvpn_writer:
            try:
                qvpn_writer.close()
            except Exception:
                pass

async def send_502_bad_gateway(writer: asyncio.StreamWriter):
    """Helper to return a clean 502 Bad Gateway response to the client."""
    response = (
        "HTTP/1.1 502 Bad Gateway\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><head><title>502 Bad Gateway</title></head>"
        "<body><center><h1>502 Bad Gateway</h1><hr>"
        "QVPN Client is unreachable or connection establishment failed.</center></body></html>"
    )
    try:
        writer.write(response.encode("utf-8"))
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def main():
    server = await asyncio.start_server(
        handle_client,
        PROXY_HOST,
        PROXY_PORT,
        limit=262144,  # 256 KB stream reader buffer
    )
    logger.info(f"Local HTTP/HTTPS Proxy listening on http://{PROXY_HOST}:{PROXY_PORT}")
    logger.info(f"Ensure your browser proxy is configured to use {PROXY_HOST}:{PROXY_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Local Proxy stopping...")
        sys.exit(0)
