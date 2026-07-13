"""Certificate Transparency source client (Phase 2.5).

Thin wrapper over a crt.sh-compatible JSON API. `list_entries` returns the
CT log entries for a domain (crt.sh gives metadata but NOT a SHA-256
fingerprint in the list output, so the caller fetches each cert via
`fetch_der` and computes the fingerprint itself). The base URL is
configurable (`settings.ct_source_url`) so air-gapped sites can use a mirror
and tests can point at a MockTransport -- no real network in tests.

ponytail: crt.sh JSON only -- no RFC 6962 log tailing / Merkle proofs.
Upgrade to direct log tailing only if crt.sh rate limits become a real
problem.
"""
from __future__ import annotations

import httpx

# crt.sh returns all historical certs; exclude=expired bounds the first sync
# to the actionable (currently-valid) shadow set.
_TIMEOUT = 30.0


def list_entries(base_url: str, domain: str, client: httpx.Client | None = None) -> list[dict]:
    if not base_url:
        return []
    url = f"{base_url.rstrip('/')}/"
    params = {"q": f"%.{domain}", "output": "json", "exclude": "expired"}
    owns = client is None
    client = client or httpx.Client(timeout=_TIMEOUT)
    try:
        resp = client.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
    finally:
        if owns:
            client.close()
    return data if isinstance(data, list) else []


def fetch_der(base_url: str, crtsh_id: int, client: httpx.Client | None = None) -> bytes:
    """Fetch one certificate's DER bytes. crt.sh's `?d=<id>` returns the raw
    certificate; handle both DER (application/pkix-cert) and PEM responses."""
    url = f"{base_url.rstrip('/')}/"
    owns = client is None
    client = client or httpx.Client(timeout=_TIMEOUT)
    try:
        resp = client.get(url, params={"d": crtsh_id})
        resp.raise_for_status()
        content = resp.content
    finally:
        if owns:
            client.close()
    if b"-----BEGIN CERTIFICATE-----" in content:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        return x509.load_pem_x509_certificate(content).public_bytes(serialization.Encoding.DER)
    return content
