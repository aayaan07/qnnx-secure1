# QVPN Gateway API Reference (ROUTES.md)

This document provides a comprehensive specification of all endpoints exposed by the QVPN Gateway Control Plane.

## Table of Contents
1. [Authentication](#authentication)
2. [General / System Endpoints](#general--system-endpoints)
3. [Handshake API](#handshake-api)
4. [Sessions API](#sessions-api)
5. [Monitoring Agent Ingestion API](#monitoring-agent-ingestion-api)
6. [Client Monitoring Query API](#client-monitoring-query-api)

---

## Authentication

Except for the basic system/health endpoints, all routes require API Key authentication.
* **Header Name**: `X-API-Key`
* **Type**: `String`
* **Behavior**: Missing or invalid API keys result in a `401 Unauthorized` response.

---

## General / System Endpoints

### 1. Root Information
* **Path**: `GET /`
* **Authentication**: None
* **Response (200 OK)**:
  ```json
  {
    "service": "QVPN Gateway Control Plane",
    "version": "1.0.0",
    "environment": "development",
    "docs": "/docs",
    "vpn_tunnel_port": 5151
  }
  ```

### 2. Service Health
* **Path**: `GET /health`
* **Authentication**: None
* **Response (200 OK)**:
  ```json
  {
    "status": "ok",
    "active_sessions_in_memory": 0
  }
  ```

---

## Handshake API
Manages the two-phase post-quantum cryptographic (PQC) key exchange.

### 1. Phase 1 — Initialize Handshake
* **Path**: `POST /api/v1/handshake/init`
* **Authentication**: Required (`X-API-Key` header)
* **Request Body**:
  ```json
  {
    "client_identifier": "CLIENT-001"
  }
  ```
* **Response (200 OK)**:
  ```json
  {
    "session_id": "a3bb1234-abcd-4a5f-9e23-77dd88ee99ff",
    "algorithm": "ML-KEM-768",
    "public_key": "MIIB...[Base64 Encoded Key]..."
  }
  ```

### 2. Phase 2 — Complete Handshake
* **Path**: `POST /api/v1/handshake/complete`
* **Authentication**: Required (`X-API-Key` header)
* **Request Body**:
  ```json
  {
    "session_id": "a3bb1234-abcd-4a5f-9e23-77dd88ee99ff",
    "kem_ciphertext": "U0VD...[Base64 Encoded Ciphertext]...",
    "remote_ip": "192.168.1.50",
    "remote_port": 58392
  }
  ```
* **Response (200 OK)**:
  ```json
  {
    "session_id": "a3bb1234-abcd-4a5f-9e23-77dd88ee99ff",
    "status": "ESTABLISHED"
  }
  ```

---

## Sessions API
Allows querying and controlling active VPN sessions and historical logs.

### 1. List VPN Sessions
* **Path**: `GET /api/v1/sessions`
* **Authentication**: Required (`X-API-Key` header)
* **Query Parameters**:
  * `tunnel_status` (Optional string): Filter sessions (e.g., `ACTIVE`, `CLOSED`).
* **Response (200 OK)**:
  ```json
  [
    {
      "session_id": "a3bb1234-abcd-4a5f-9e23-77dd88ee99ff",
      "client_id": "c1aa5555-bbbb-4cc4-8888-223344556677",
      "kem_algorithm": "ML-KEM-768",
      "kem_state": "COMPLETED",
      "tunnel_status": "ACTIVE",
      "pqc_key_id": "key-987",
      "created_at": "2026-06-21T08:00:00Z",
      "established_at": "2026-06-21T08:01:00Z",
      "closed_at": null,
      "aes_key_active": true
    }
  ]
  ```

### 2. Get Session Details
* **Path**: `GET /api/v1/sessions/{session_id}`
* **Authentication**: Required (`X-API-Key` header)
* **Response (200 OK)**:
  ```json
  {
    "session_id": "a3bb1234-abcd-4a5f-9e23-77dd88ee99ff",
    "client_id": "c1aa5555-bbbb-4cc4-8888-223344556677",
    "kem_algorithm": "ML-KEM-768",
    "kem_state": "COMPLETED",
    "tunnel_status": "ACTIVE",
    "pqc_key_id": "key-987",
    "created_at": "2026-06-21T08:00:00Z",
    "established_at": "2026-06-21T08:01:00Z",
    "closed_at": null,
    "aes_key_active": true,
    "tunnel_state": {
      "status": "ACTIVE",
      "remote_ip": "192.168.1.50",
      "remote_port": 58392,
      "assigned_virtual_ip": "10.8.0.2",
      "last_heartbeat": "2026-06-21T08:15:00Z",
      "missed_heartbeats": 0,
      "established_at": "2026-06-21T08:01:00Z"
    }
  }
  ```

### 3. Close Session (Disconnect)
* **Path**: `DELETE /api/v1/sessions/{session_id}`
* **Authentication**: Required (`X-API-Key` header)
* **Response**: `204 No Content` on success. (Also evicts key from memory and marks status as `CLOSED`).

### 4. Record Heartbeat
* **Path**: `POST /api/v1/sessions/{session_id}/heartbeat`
* **Authentication**: Required (`X-API-Key` header)
* **Request Body (Optional)**:
  ```json
  {
    "sequence_number": 42,
    "packets_sent": 1000,
    "packets_received": 950
  }
  ```
* **Response (200 OK)**:
  ```json
  {
    "session_id": "a3bb1234-abcd-4a5f-9e23-77dd88ee99ff",
    "status": "ok",
    "heartbeat_id": "hb-55aa2233..."
  }
  ```

### 5. Query Session Heartbeat Log
* **Path**: `GET /api/v1/sessions/{session_id}/heartbeats`
* **Authentication**: Required (`X-API-Key` header)
* **Query Parameters**:
  * `since` (Optional ISO-8601 string): Filter records recorded after this time.
  * `limit` (Optional integer, default `100`, max `1000`): Maximum records to return.
* **Response (200 OK)**:
  ```json
  [
    {
      "id": "hb-55aa2233...",
      "session_id": "a3bb1234-abcd-4a5f-9e23-77dd88ee99ff",
      "timestamp": "2026-06-21T08:15:00Z",
      "sequence_number": 42,
      "packets_sent": 1000,
      "packets_received": 950
    }
  ]
  ```

### 6. Query Session Tunnel Events
* **Path**: `GET /api/v1/sessions/{session_id}/events`
* **Authentication**: Required (`X-API-Key` header)
* **Query Parameters**:
  * `limit` (Optional integer, default `100`, max `1000`): Number of events to return.
* **Response (200 OK)**:
  ```json
  [
    {
      "event_id": "evt-77bb88cc...",
      "session_id": "a3bb1234-abcd-4a5f-9e23-77dd88ee99ff",
      "event_type": "TUNNEL_ESTABLISHED",
      "details": { "virtual_ip": "10.8.0.2" },
      "occurred_at": "2026-06-21T08:01:00Z"
    }
  ]
  ```

### 7. Append Custom Tunnel Event
* **Path**: `POST /api/v1/sessions/{session_id}/events`
* **Authentication**: Required (`X-API-Key` header)
* **Request Body**:
  ```json
  {
    "event_type": "USER_INTERACTION",
    "details": { "action": "clicked_reconnect" }
  }
  ```
* **Response (201 Created)**:
  ```json
  {
    "event_id": "evt-88cc99dd...",
    "session_id": "a3bb1234-abcd-4a5f-9e23-77dd88ee99ff",
    "event_type": "USER_INTERACTION",
    "details": { "action": "clicked_reconnect" },
    "occurred_at": "2026-06-21T08:20:00Z"
  }
  ```

### 8. Get Traffic Statistics
* **Path**: `GET /api/v1/sessions/{session_id}/stats`
* **Authentication**: Required (`X-API-Key` header)
* **Response (200 OK)**:
  ```json
  {
    "bytes_sent": 40960,
    "bytes_received": 81920,
    "packets_sent": 1000,
    "packets_received": 950,
    "recorded_at": "2026-06-21T08:15:00Z"
  }
  ```

---

## Monitoring Agent Ingestion API

These endpoints accept raw metrics and activity event logs pushed by the Windows Monitoring Agent. 
* **Validation**: Payload schemas support either a single item or a batch array of items.
* **All-or-Nothing Rule**: Transactional logic ensures that if *any* record in a batch fails validation, the entire ingestion transaction is aborted (`422 Unprocessable Entity`), and zero rows are stored.

### 1. Ingest System Metrics
* **Path**: `POST /api/v1/agent/metrics`
* **Authentication**: Required (`X-API-Key` header)
* **Request Body**:
  ```json
  {
    "client_identifier": "CLIENT-001",
    "readings": [
      {
        "cpu_usage": 12.5,
        "ram_usage": 58.2,
        "disk_usage": 44.9,
        "recorded_at": "2026-06-21T08:20:00Z"
      }
    ]
  }
  ```
  *(Also accepts a single object for `readings` rather than an array).*
* **Response (201 Created)**:
  ```json
  {
    "inserted": 1
  }
  ```

### 2. Ingest User Activity
* **Path**: `POST /api/v1/agent/activity`
* **Authentication**: Required (`X-API-Key` header)
* **Request Body**:
  ```json
  {
    "client_identifier": "CLIENT-001",
    "events": [
      {
        "event_id": 4624,
        "time_generated": "2026-06-21T08:20:00Z",
        "record_number": 10248,
        "username": "SYSTEM"
      }
    ]
  }
  ```
  *Windows security log event IDs are mapped to `login` (4624), `failed_login` (4625), and `logout` (4634/4647).*
* **Response (201 Created)**:
  ```json
  {
    "inserted": 1
  }
  ```

### 3. Ingest Network Activity
* **Path**: `POST /api/v1/agent/network`
* **Authentication**: Required (`X-API-Key` header)
* **Request Body**:
  ```json
  {
    "client_identifier": "CLIENT-001",
    "events": [
      {
        "event_type": "NETWORK_ACTIVITY",
        "pid": 4120,
        "local_port": 50021,
        "remote_ip": "8.8.8.8",
        "remote_port": 53,
        "timestamp": "2026-06-21T08:20:00Z"
      }
    ]
  }
  ```
  *(Accepts `event_type` of `NETWORK_ACTIVITY` or `IP_CHANGE`).*
* **Response (201 Created)**:
  ```json
  {
    "inserted": 1
  }
  ```

### 4. Ingest Process Events
* **Path**: `POST /api/v1/agent/process`
* **Authentication**: Required (`X-API-Key` header)
* **Request Body**:
  ```json
  {
    "client_identifier": "CLIENT-001",
    "events": [
      {
        "process_name": "notepad.exe",
        "pid": 7894,
        "action": "launched",
        "timestamp": "2026-06-21T08:20:00Z"
      }
    ]
  }
  ```
* **Response (201 Created)**:
  ```json
  {
    "inserted": 1
  }
  ```

### 5. Ingest USB Device Events
* **Path**: `POST /api/v1/agent/device`
* **Authentication**: Required (`X-API-Key` header)
* **Request Body**:
  ```json
  {
    "client_identifier": "CLIENT-001",
    "events": [
      {
        "action": "inserted",
        "hardware_id": "USB\\VID_0951&PID_1666",
        "device_info": { "friendly_name": "Kingston DataTraveler" },
        "timestamp": "2026-06-21T08:20:00Z"
      }
    ]
  }
  ```
* **Response (201 Created)**:
  ```json
  {
    "inserted": 1
  }
  ```

---

## Client Monitoring Query API

Retrieve telemetry data collected from the Monitoring Agents. Suitable for dashboards.

### Common Query Parameters
* `since` (Optional ISO-8601 string): Filter records recorded after this time.
* `limit` (Optional integer, default `100`, max `1000`): Maximum records to return.

### 1. Get Client Metrics
* **Path**: `GET /api/v1/clients/{client_id}/metrics`
* **Authentication**: Required (`X-API-Key` header)
* **Response (200 OK)**:
  ```json
  [
    {
      "id": "metric-uuid...",
      "client_id": "c1aa5555-bbbb-4cc4-8888-223344556677",
      "timestamp": "2026-06-21T08:20:00Z",
      "cpu_percent": 12.5,
      "ram_percent": 58.2,
      "disk_percent": 44.9
    }
  ]
  ```

### 2. Get Client User Activity
* **Path**: `GET /api/v1/clients/{client_id}/activity`
* **Authentication**: Required (`X-API-Key` header)
* **Response (200 OK)**:
  ```json
  [
    {
      "id": "act-uuid...",
      "client_id": "c1aa5555-bbbb-4cc4-8888-223344556677",
      "event_type": "login",
      "username": "SYSTEM",
      "timestamp": "2026-06-21T08:20:00Z",
      "details": {
        "event_id": 4624,
        "record_number": 10248
      }
    }
  ]
  ```

### 3. Get Client Network Activity
* **Path**: `GET /api/v1/clients/{client_id}/network`
* **Authentication**: Required (`X-API-Key` header)
* **Response (200 OK)**:
  ```json
  [
    {
      "id": "net-uuid...",
      "client_id": "c1aa5555-bbbb-4cc4-8888-223344556677",
      "timestamp": "2026-06-21T08:20:00Z",
      "event_type": "NETWORK_ACTIVITY",
      "details": {
        "pid": 4120,
        "local_port": 50021,
        "remote_ip": "8.8.8.8",
        "remote_port": 53
      }
    }
  ]
  ```

### 4. Get Client Process Events
* **Path**: `GET /api/v1/clients/{client_id}/process`
* **Authentication**: Required (`X-API-Key` header)
* **Response (200 OK)**:
  ```json
  [
    {
      "id": "proc-uuid...",
      "client_id": "c1aa5555-bbbb-4cc4-8888-223344556677",
      "process_name": "notepad.exe",
      "pid": 7894,
      "action": "launched",
      "timestamp": "2026-06-21T08:20:00Z"
    }
  ]
  ```

### 5. Get Client USB Device Events
* **Path**: `GET /api/v1/clients/{client_id}/device`
* **Authentication**: Required (`X-API-Key` header)
* **Response (200 OK)**:
  ```json
  [
    {
      "id": "dev-uuid...",
      "client_id": "c1aa5555-bbbb-4cc4-8888-223344556677",
      "timestamp": "2026-06-21T08:20:00Z",
      "action": "inserted",
      "device_info": {
        "hardware_id": "USB\\VID_0951&PID_1666",
        "friendly_name": "Kingston DataTraveler"
      }
    }
  ]
  ```
