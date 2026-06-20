# QVPN Gateway API & Integration Guide

The QVPN Gateway serves as the control plane for post-quantum secured VPN tunnels. It handles client handshakes, session lifecycle management, and acts as the interface to the raw TCP VPN socket server.

## 1. Gateway Scope & Network Ports

*   **HTTP Control Plane (API)**: Port `8001` (by default)
*   **VPN TCP Socket Server**: Port `5151`

---

## 2. Gateway API Authentication

All HTTP routes under `/api/v1/handshake/*` and `/api/v1/sessions/*` require an API Key supplied in the `X-API-Key` header:

*   **Required Header:** `X-API-Key: qvpn_live_<token>`

API keys are provisioned out-of-band using the standalone provisioning script.

---

## 3. Gateway Endpoints

### A. Handshake Operations
*   `POST /api/v1/handshake/init` — Phase 1: generate KEM keypair and return the `session_id` and public key.
*   `POST /api/v1/handshake/complete` — Phase 2: decapsulate client's KEM ciphertext and establish the tunnel session.

### B. Session Management
*   `GET /api/v1/sessions` — List all active/inactive VPN sessions.
*   `GET /api/v1/sessions/{session_id}` — Get details of a specific session.
*   `DELETE /api/v1/sessions/{session_id}` — Explicitly close a session.
*   `POST /api/v1/sessions/{session_id}/heartbeat` — Record a heartbeat to prevent timeout.
*   `GET /api/v1/sessions/{session_id}/events` — List audit/connection events.
*   `POST /api/v1/sessions/{session_id}/events` — Append a custom connection event.
*   `GET /api/v1/sessions/{session_id}/stats` — Get traffic statistics.

### C. Health Check
*   `GET /health` — Simple health status check (unauthenticated).

---

# Appendix: QNNX-Sentinel (PQC Service) API Overview

QNNX-Sentinel is a Post-Quantum Cryptography (PQC) API service built using Python FastAPI and LibOQS. It offers cryptographic key generation, Key Encapsulation Mechanisms (KEM), and Digital Signature Algorithms (DSA) alongside usage tracking and auditing.

---

## 1. Authentication Models

The API uses two distinct authentication mechanisms depending on the route.

### A. Signed Request Authentication (Cryptographic Operations)
For all security-sensitive cryptographic routes, requests must be authenticated and signed using your client API key and signing secret to prevent tampering and replay attacks.

**Required Headers:**
*   `Authorization`: `Bearer <API_KEY>` (e.g. `Bearer qnnx_key_abc123...`)
*   `X-QNNX-Timestamp`: Current UTC ISO 8601 timestamp (e.g., `2026-06-20T12:00:00Z` or `2026-06-20T12:00:00+00:00`). Must be within **±300 seconds** of server time.
*   `X-QNNX-Nonce`: A unique request identifier (such as a UUID) to prevent replay attacks.
*   `X-QNNX-Signature`: HMAC-SHA256 signature (hex format) computed using your API key's signing secret.

> [!WARNING]
> **Do NOT send the signing secret in the headers.** Any request containing an `X-QNNX-Signing-Secret` header is automatically rejected.

#### How to Construct the Signature
1.  **Build the payload** by concatenating these components (as UTF-8 bytes) in order:
    $$\text{Payload} = \text{HTTP\_METHOD} \mathbin{\Vert} \text{PATH} \mathbin{\Vert} \text{TIMESTAMP} \mathbin{\Vert} \text{NONCE} \mathbin{\Vert} \text{BODY\_BYTES}$$
2.  **Compute the HMAC-SHA256** of the payload using your **signing secret** as the key.
3.  Format the resulting HMAC signature as a hexadecimal string.

### B. User Session Authentication (Auditing & Usage Metrics)
For viewing analytics, usage history, and audit logs, authenticate using a standard bearer token.

**Required Header:**
*   `Authorization`: `Bearer <USER_UUID>` (The UUID of the authenticated user).

---

## 2. Core Endpoints & Route Specifications

### A. Cryptographic Operations
All routes below require **Signed Request Authentication**.

#### 1. Key Generation
*   **Endpoint**: `POST /api/v1/keygen`
*   **Request Parameters (JSON)**:
    *   `algorithm` (string, Required): The PQC algorithm name (e.g., `"ML-KEM-768"`).
    *   `storage_mode` (string, Optional): `"customer_managed"` (keys returned in response) or `"sentinel_managed"` (private key kept secure, returns reference). Defaults to `"customer_managed"`.
*   **Response**: Contains generated `public_key`, `private_key` (if customer managed), or `private_key_ref`.

#### 2. KEM Encapsulate
*   **Endpoint**: `POST /api/v1/kem/encapsulate`
*   **Request Parameters (JSON)**:
    *   `algorithm` (string, Required): KEM algorithm name.
    *   `public_key` (string, Required): Public key for encapsulating the shared secret.
*   **Response**: Contains `ciphertext` and the generated `shared_secret`.

#### 3. KEM Decapsulate
*   **Endpoint**: `POST /api/v1/kem/decapsulate`
*   **Request Parameters (JSON)**:
    *   `algorithm` (string, Required): KEM algorithm name.
    *   `ciphertext` (string, Required): Encapsulated shared secret.
    *   `private_key` (string, Required): Private key (or key reference) to decrypt the ciphertext.
*   **Response**: Contains the decapsulated `shared_secret`.

#### 4. DSA Sign Message
*   **Endpoint**: `POST /api/v1/sign`
*   **Request Parameters (JSON)**:
    *   `algorithm` (string, Required): DSA algorithm name.
    *   `message` (string, Required): Message string to sign.
    *   `private_key` (string, Required): Private key used to sign the message.
*   **Response**: Contains the `signature`.

#### 5. DSA Verify Signature
*   **Endpoint**: `POST /api/v1/verify`
*   **Request Parameters (JSON)**:
    *   `algorithm` (string, Required): DSA algorithm name.
    *   `message` (string, Required): Original message string.
    *   `signature` (string, Required): Signature to verify.
    *   `public_key` (string, Required): Signer's public key.
*   **Response**: Returns `is_valid` (boolean).

---

### B. Informational & Audit Logs

#### 1. List Algorithms
*   **Endpoint**: `GET /api/v1/algorithms` (No auth required)
*   **Response**: List of all supported and enabled PQC mechanisms.

#### 2. Audit Logs
*   **Endpoint**: `GET /api/v1/audit-logs` (Requires User Session Auth)
*   **Response**: List of recent security and operational audit logs.

#### 3. API Usage Summary
*   **Endpoint**: `GET /api/v1/api-usage/summary` (Requires User Session Auth)
*   **Response**: Aggregate count and throughput metrics of API requests.

---

## 3. Python Integration Example

Here is a short, complete Python snippet demonstrating how to sign and make a request to `/api/v1/keygen`:

```python
import hmac
import hashlib
import json
import uuid
from datetime import datetime, timezone
import requests

# Configuration
API_URL = "http://127.0.0.1:8000/api/v1/keygen"
API_KEY = "your_api_key_here"
SIGNING_SECRET = "your_signing_secret_here"

# 1. Prepare request body
body = {
    "algorithm": "ML-KEM-768",
    "storage_mode": "customer_managed"
}
body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")

# 2. Prepare headers metadata
timestamp = datetime.now(timezone.utc).isoformat()
nonce = str(uuid.uuid4())
method = "POST"
path = "/api/v1/keygen"

# 3. Build signature payload
# Concatenation: METHOD + PATH + TIMESTAMP + NONCE + BODY
payload = (
    method.upper().encode("utf-8")
    + path.encode("utf-8")
    + timestamp.encode("utf-8")
    + nonce.encode("utf-8")
    + body_bytes
)

# 4. Generate HMAC-SHA256 signature
signature = hmac.new(
    SIGNING_SECRET.encode("utf-8"),
    payload,
    hashlib.sha256
).hexdigest()

# 5. Execute request
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "X-QNNX-Timestamp": timestamp,
    "X-QNNX-Nonce": nonce,
    "X-QNNX-Signature": signature,
    "Content-Type": "application/json",
}

response = requests.post(API_URL, data=body_bytes, headers=headers)
print("Status Code:", response.status_code)
print("Response JSON:", response.json())
```
