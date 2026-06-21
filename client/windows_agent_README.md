# Component 3 — Windows Monitoring Agent

The Windows Monitoring Agent is a background daemon that monitors local system metrics, active network connections, process launches, USB inserts/removals, public IP changes, and Windows Security logon/logoff events. It batches collected telemetry and pushes it to the Gateway's database.

## Prerequisites

Running WMI watchers and reading the Security Log requires:
* Windows OS.
* python packages: `psutil`, `pywin32`, `wmi` (automatically installed in the virtual environment).
* **Administrator Privileges** are required to query the Security Event log (Event IDs 4624, 4625, etc.). If run as a standard user, the agent will skip event log queries gracefully but still poll metrics and WMI watchers.

## How to Run

1. Open PowerShell or Command Prompt.
2. If polling the Windows Security Log, run the shell **as Administrator**.
3. Execute the agent:

```powershell
# From the qvpn-client root directory
venv\Scripts\python -m client.windows_agent
```

## Telemetry Schemas & Event Types

Pushed JSON details match backend database definitions:

1. **`SYSTEM_METRICS`**:
   - `cpu_usage`: float (%)
   - `ram_usage`: float (%)
   - `disk_usage`: float (%)
   - `recorded_at`: ISO timestamp

2. **`NETWORK_ACTIVITY`**:
   - `pid`: int (process ID)
   - `local_port`: int
   - `remote_ip`: str
   - `remote_port`: int
   - `recorded_at`: ISO timestamp

3. **`USER_ACTIVITY`**:
   - `event_id`: int (4624/4625/4634/4647)
   - `time_generated`: ISO timestamp
   - `record_number`: int

4. **`USB_INSERTION` / `USB_REMOVAL`**:
   - `hardware_id`: str (identifies the event sequence)

5. **`UNKNOWN_PROCESS_LAUNCH`**:
   - `process_name`: str
   - `pid`: int

## Verification

1. Start the agent while the QVPN Client is disconnected. Verify that it queues metrics locally inside `agent_queue.json` in the workspace directory.
2. Connect the QVPN Client (status becomes `active`).
3. Verify that the agent detects the active session, batches the queued entries, and pushes them to the Gateway API (logs show: `Successfully pushed X event(s) to Gateway.`).
4. Query the Gateway database to confirm telemetry insertion:
   ```powershell
   # From the qnnx-secure1 directory
   venv\Scripts\python -c "from app.core.database import SessionLocal; from app.models.tunnel_event import TunnelEvent; db=SessionLocal(); print([e.event_type for e in db.query(TunnelEvent).all()]); db.close()"
   ```
   *Expected Output should contain:* `['SYSTEM_METRICS', 'NETWORK_ACTIVITY', ...]`
