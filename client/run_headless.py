import asyncio
import time
import threading
import sys
from client.qvpn_client import global_vpn_client, asyncio_loop, run_asyncio_thread

def main():
    # 1. Start the dedicated asyncio network thread
    t = threading.Thread(target=run_asyncio_thread, args=(asyncio_loop,), daemon=True)
    t.start()
    
    # 2. Trigger connection
    print("Initiating connection to Gateway...")
    asyncio.run_coroutine_threadsafe(global_vpn_client.connect(), asyncio_loop)
    
    # 3. Keep running and print status periodically
    try:
        while True:
            state = global_vpn_client.get_state()
            print(f"[{time.strftime('%X')}] Status: {state['tunnel_status']} | Sent: {state['packets_sent']} | Recv: {state['packets_received']}")
            time.sleep(5)
    except KeyboardInterrupt:
        print("Shutting down tunnel...")
        asyncio.run_coroutine_threadsafe(global_vpn_client.disconnect(), asyncio_loop)
        time.sleep(1.0)
        sys.exit(0)

if __name__ == "__main__":
    main()
