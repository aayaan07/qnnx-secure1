"""
crypto — Post-Quantum cryptography layer for the QVPN Gateway.

  pqc_client   — Async HTTP client for the external PQC API service.
  session_key  — HKDF-SHA256 session key derivation from KEM shared secrets.
  aead         — AES-256-GCM encrypt/decrypt helpers for VPN tunnel payloads.
  kem          — Legacy thin shim around pqc_client (kept for compatibility).
"""
