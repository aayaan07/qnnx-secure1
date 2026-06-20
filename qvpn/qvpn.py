import os
import subprocess
import sys
import httpx
import hmac
import hashlib
import uuid
import json
from datetime import datetime, timezone

# --- Configuration ---
API_BASE_URL = "https://crops-garmin-created-junior.trycloudflare.com/api/v1"
API_TOKEN = "QNNX_SOMIL123" 
SIGNING_SECRET = "GODisGREAT"
ALGORITHM = "ML-KEM-768"

TEMPLATE_PATH = "templates/wg0.conf.tmpl"
OUTPUT_PATH = "wg0.conf"

def get_signature(method: str, path: str, timestamp: str, nonce: str, body_bytes: bytes) -> str:
    """Matches build_signature_payload in request_signature.py exactly."""
    payload = (
        method.upper().encode("utf-8")
        + path.encode("utf-8")
        + timestamp.encode("utf-8")
        + nonce.encode("utf-8")
        + body_bytes
    )
    return hmac.new(SIGNING_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()

def generate_shared_secret() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = str(uuid.uuid4())
    
    # --- 1. Generate Keypair ---
    method = "POST"
    
    # FIX: Explicitly remove the trailing slash here so it matches the exact route layout
    path_gen = "/api/v1/keygen" 
    
    payload_gen_dict = {
        "algorithm": ALGORITHM, 
        "storage_mode": "sentinel_managed",
        "key_type": "kem"
    }
    
    body_gen_bytes = json.dumps(payload_gen_dict, separators=(',', ':')).encode("utf-8")
    sig_gen = get_signature(method, path_gen, timestamp, nonce, body_gen_bytes)
    
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "X-QNNX-Signing-Secret": SIGNING_SECRET,
        "X-QNNX-Timestamp": timestamp,
        "X-QNNX-Nonce": nonce,
        "X-QNNX-Signature": sig_gen,
        "Content-Type": "application/json"
    }

    try:
        with httpx.Client(base_url=API_BASE_URL, headers=headers, timeout=30.0) as client:
            print("[*] Generating Keypair...")
            
            # FIX: Ensure the post request matches the string path exactly without a trailing slash
            gen_res = client.post("/keygen", content=body_gen_bytes)
            gen_res.raise_for_status()
            pub_key = gen_res.json()["public_key"]

            # --- 2. Encapsulate ---
            timestamp_enc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            nonce_enc = str(uuid.uuid4())
            
            path_enc = "/api/v1/kem/encapsulate"
            payload_enc_dict = {"algorithm": ALGORITHM, "public_key": pub_key}
            body_enc_bytes = json.dumps(payload_enc_dict, separators=(',', ':')).encode("utf-8")
            
            sig_enc = get_signature(method, path_enc, timestamp_enc, nonce_enc, body_enc_bytes)
            
            client.headers.update({
                "X-QNNX-Timestamp": timestamp_enc,
                "X-QNNX-Nonce": nonce_enc,
                "X-QNNX-Signature": sig_enc
            })
            
            print("[*] Encapsulating Shared Secret...")
            enc_res = client.post("/kem/encapsulate", content=body_enc_bytes)
            enc_res.raise_for_status()
            
            return enc_res.json()["shared_secret"]
    except httpx.HTTPStatusError as e:
        print(f"\n[!] API Error {e.response.status_code}: {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Network/System Error: {e}")
        sys.exit(1)
def build_wireguard_config(shared_secret: str):
    if not os.path.exists(TEMPLATE_PATH):
        print(f"[!] Template not found at {TEMPLATE_PATH}")
        sys.exit(1)

    print("[*] Reading WireGuard template...")
    with open(TEMPLATE_PATH, "r") as file:
        template_content = file.read()

    config_content = template_content.replace("{{ PQC_SHARED_SECRET }}", shared_secret)

    with open(OUTPUT_PATH, "w") as file:
        file.write(config_content)
    
    if sys.platform != "win32":
        os.chmod(OUTPUT_PATH, 0o600)
        
    print(f"[+] Dynamic WireGuard config written to {OUTPUT_PATH}")

def start_vpn_tunnel():
    print("[*] Bringing up the QVPN interface...")
    try:
        command = ["wg-quick", "up", f"./{OUTPUT_PATH}"]
        if sys.platform != "win32":
            command.insert(0, "sudo")
            
        subprocess.run(command, check=True)
        print("\n[SUCCESS] QVPN Quantum Tunnel is LIVE! 🚀")
    except subprocess.CalledProcessError:
        print("[!] Failed to bring up the WireGuard interface.")
        sys.exit(1)

if __name__ == "__main__":
    print("=== QVPN Data Plane Initializer ===")
    pqc_secret = generate_shared_secret()
    build_wireguard_config(pqc_secret)
    start_vpn_tunnel()