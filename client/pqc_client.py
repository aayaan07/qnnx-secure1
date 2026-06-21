import asyncio
import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
import httpx
from pydantic import BaseModel, Field

# Custom exceptions
class PQCClientError(Exception):
    """Base exception for PQC API client errors."""
    pass

class PQCServiceUnavailable(PQCClientError):
    """Raised when the PQC API service is unreachable or times out."""
    pass

class EncapsulationError(PQCClientError):
    """Raised when KEM encapsulation fails or returns a non-success response."""
    pass

# Pydantic models
class KEMEncapsulateRequest(BaseModel):
    algorithm: str
    public_key: str = Field(..., description="Base64-encoded public key")

class KEMEncapsulateResponse(BaseModel):
    algorithm: str
    ciphertext: str = Field(..., description="Base64-encoded ciphertext")
    shared_secret: str = Field(..., description="Base64-encoded shared secret")
    status: str

def sign_request(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body_bytes: bytes,
    secret: str
) -> str:
    """Computes the HMAC-SHA256 signature for Signed Request Authentication."""
    payload = (
        method.upper().encode("utf-8")
        + path.encode("utf-8")
        + timestamp.encode("utf-8")
        + nonce.encode("utf-8")
        + body_bytes
    )
    return hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()

class PQCClient:
    def __init__(self, api_url: str = None, api_key: str = None, signing_secret: str = None):
        from client.config import PQC_API_URL, PQC_API_KEY, PQC_SIGNING_SECRET
        self.api_url = api_url or PQC_API_URL
        self.api_key = api_key or PQC_API_KEY
        self.signing_secret = signing_secret or PQC_SIGNING_SECRET

    async def encapsulate(self, algorithm: str, public_key_bytes: bytes) -> tuple[bytes, bytes]:
        """
        Calls the PQC API's encapsulation endpoint with the gateway public key.
        Returns the derived (ciphertext, shared_secret) as bytes.
        """
        path = "/api/v1/kem/encapsulate"
        url = f"{self.api_url}/kem/encapsulate"

        # 1. Base64 encode the public key
        b64_pubkey = base64.b64encode(public_key_bytes).decode("ascii")

        # 2. Prepare JSON body bytes using compact separators
        req_model = KEMEncapsulateRequest(algorithm=algorithm, public_key=b64_pubkey)
        body_bytes = json.dumps(req_model.model_dump(), separators=(",", ":")).encode("utf-8")

        # 3. Create metadata and compute HMAC signature
        timestamp = datetime.now(timezone.utc).isoformat()
        nonce = str(uuid.uuid4())
        signature = sign_request("POST", path, timestamp, nonce, body_bytes, self.signing_secret)

        # 4. Construct headers (X-QNNX headers required)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "X-QNNX-Timestamp": timestamp,
            "X-QNNX-Nonce": nonce,
            "X-QNNX-Signature": signature,
            "Content-Type": "application/json",
        }

        max_retries = 3
        timeout = 5.0

        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.post(url, content=body_bytes, headers=headers)

                if response.status_code == 200:
                    resp_data = response.json()
                    resp_model = KEMEncapsulateResponse.model_validate(resp_data)

                    # Decode response fields from base64
                    ciphertext = base64.b64decode(resp_model.ciphertext)
                    shared_secret = base64.b64decode(resp_model.shared_secret)
                    return ciphertext, shared_secret

                elif response.status_code in (400, 401, 422, 500):
                    # Direct client/server errors that won't resolve on retry
                    try:
                        err_msg = response.json().get("error", {}).get("message", "Unknown error")
                    except Exception:
                        err_msg = response.text
                    raise EncapsulationError(
                        f"PQC API returned error during encapsulation (HTTP {response.status_code}): {err_msg}"
                    )
                else:
                    response.raise_for_status()

            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                if attempt == max_retries - 1:
                    raise PQCServiceUnavailable(
                        f"PQC API service unavailable after {max_retries} attempts. Reason: {exc}"
                    ) from exc
                await asyncio.sleep(0.5 * (attempt + 1))

        raise PQCServiceUnavailable("Failed to perform KEM encapsulation after retries.")
