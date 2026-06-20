import asyncio
import logging
from proxy.handler import handle_connection
from proxy.stats import tracker
from config.settings import PROXY_HOST, PROXY_PORT

logger = logging.getLogger(__name__)


async def start():
    server = await asyncio.start_server(
        handle_connection,
        PROXY_HOST,
        PROXY_PORT
    )
    logger.info(f"QVPN Proxy running on {PROXY_HOST}:{PROXY_PORT}")
    logger.info("Browser proxy: SOCKS5 → 127.0.0.1:1080")

    async with server:
        await server.serve_forever()