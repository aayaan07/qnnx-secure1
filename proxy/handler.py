"""
For each browser connection:
1. Do SOCKS5 handshake
2. Find out where browser wants to go
3. Connect there (direct for now, QVPN tunnel later)
4. Pipe data both ways and track stats
"""
import asyncio
import logging
from proxy.socks5 import do_handshake, read_request, send_success, send_failure
from proxy.stats import tracker
from config.settings import USE_QVPN_TUNNEL, QVPN_CLIENT_HOST, QVPN_CLIENT_PORT

logger = logging.getLogger(__name__)


async def pipe(reader, writer, host, direction):
    """Copy bytes from reader to writer until connection closes."""
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()

            # Track stats
            if direction == "sent":
                tracker.record_sent(host, len(data))
            else:
                tracker.record_received(host, len(data))
    except (asyncio.CancelledError, ConnectionResetError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_connection(browser_reader, browser_writer):
    """Entry point for each new browser connection."""
    peer = browser_writer.get_extra_info("peername")
    dest_host = "unknown"

    try:
        # Step 1: SOCKS5 handshake
        await do_handshake(browser_reader, browser_writer)

        # Step 2: Read where browser wants to go
        dest_host, dest_port = await read_request(browser_reader)
        logger.info(f"[{peer}] → {dest_host}:{dest_port}")
        tracker.record_connection(dest_host)

        # Step 3: Connect to destination
        if USE_QVPN_TUNNEL:
            # Future: connect to QVPN client, pass dest_host/port as metadata
            logger.info(f"Routing via QVPN tunnel → {QVPN_CLIENT_HOST}:{QVPN_CLIENT_PORT}")
            dest_reader, dest_writer = await asyncio.open_connection(
                QVPN_CLIENT_HOST, QVPN_CLIENT_PORT
            )
            # TODO: send dest_host:dest_port to QVPN client first
            # (agree on this format with Task 1 owner)
        else:
            # Direct to internet — works today, no QVPN needed
            logger.info(f"Direct mode → {dest_host}:{dest_port}")
            dest_reader, dest_writer = await asyncio.open_connection(
                dest_host, dest_port
            )

        # Step 4: Tell browser "connected!"
        await send_success(browser_writer)

        # Step 5: Pipe bytes both ways simultaneously
        await asyncio.gather(
            pipe(browser_reader, dest_writer, dest_host, "sent"),
            pipe(dest_reader, browser_writer, dest_host, "received"),
        )

    except Exception as e:
        logger.error(f"[{peer}] Error for {dest_host}: {e}")
        try:
            await send_failure(browser_writer)
        except Exception:
            pass
    finally:
        try:
            browser_writer.close()
        except Exception:
            pass