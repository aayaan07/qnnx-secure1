"""
Tracks bytes in/out per destination host.
This feeds into Task 6 (Data Collection APIs) later.
"""
import time
from collections import defaultdict

class StatsTracker:
    def __init__(self):
        # host -> {bytes_sent, bytes_received, connections, last_seen}
        self._data = defaultdict(lambda: {
            "bytes_sent": 0,
            "bytes_received": 0,
            "connections": 0,
            "last_seen": None
        })

    def record_connection(self, host: str):
        self._data[host]["connections"] += 1
        self._data[host]["last_seen"] = time.time()

    def record_sent(self, host: str, num_bytes: int):
        self._data[host]["bytes_sent"] += num_bytes

    def record_received(self, host: str, num_bytes: int):
        self._data[host]["bytes_received"] += num_bytes

    def get_all(self) -> dict:
        return dict(self._data)

    def summary(self):
        print("\n--- Traffic Summary ---")
        for host, s in self._data.items():
            print(
                f"{host}: "
                f"{s['connections']} conns | "
                f"↑{s['bytes_sent']//1024}KB "
                f"↓{s['bytes_received']//1024}KB"
            )
        print("----------------------\n")


# Single global instance shared across all connections
tracker = StatsTracker()