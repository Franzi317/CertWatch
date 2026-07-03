"""AD CS issuer adapter (Windows Active Directory Certificate Services via
the certsrv web enrollment pages).

This is CertWatch's primary CA integration. It talks to the classic ASP
enrollment endpoints (`certsrv/certfnsh.asp`, `certsrv/certnew.cer`) that ship
with the AD CS "Certification Authority Web Enrollment" role service.

All network I/O is isolated behind `_http_get`/`_http_post` so tests can
monkeypatch them with canned `(status, text)` tuples and never touch a real
CA.
"""
from __future__ import annotations

import re

import httpx
from cryptography import x509

from app.issuers.base import IssuedCert, IssuerAdapter, IssuerError

_REQID_RE = re.compile(r"certnew\.cer\?ReqID=(\d+)&")


class ADCSAdapter(IssuerAdapter):
    """Issuer adapter for AD CS certsrv web enrollment.

    Expected `issuer.config` fields:
      - server_url: e.g. "https://ca.corp.local"
      - ca_config: the "CAName\\hostname" string certsrv's certfnsh.asp needs
      - template: certificate template name
      - username / password: service-account credentials, encrypted at rest
        via `app.secrets` and decrypted only at the point of use.
    """

    def __init__(self, issuer) -> None:
        config = issuer.config if hasattr(issuer, "config") else issuer
        self._server_url = config["server_url"].rstrip("/")
        self._ca_config = config.get("ca_config", "")
        self._template = config.get("template", "")
        self._username_enc = config.get("username", "")
        self._password_enc = config.get("password", "")

    def _auth(self) -> httpx.BasicAuth:
        # ponytail: real AD CS deployments require NTLM/Negotiate, not basic
        # auth. httpx has no built-in NTLM support and adding one (e.g.
        # httpx-ntlm) is out of scope for this task -- basic auth is the
        # ceiling here until this is tested against a real DC, at which
        # point swap this for an NTLM-capable auth object.
        from app.secrets import SecretsNotConfigured, decrypt

        try:
            username = decrypt(self._username_enc)
            password = decrypt(self._password_enc)
        except SecretsNotConfigured as e:
            raise IssuerError(f"cannot decrypt AD CS credentials: {e}") from e
        return httpx.BasicAuth(username, password)

    # -- network seam: tests monkeypatch these two methods directly --------
    def _http_get(self, url: str) -> tuple[int, str]:
        resp = httpx.get(url, auth=self._auth(), timeout=30.0)
        return resp.status_code, resp.text

    def _http_post(self, url: str, data: dict) -> tuple[int, str]:
        resp = httpx.post(url, data=data, auth=self._auth(), timeout=30.0)
        return resp.status_code, resp.text

    # -- IssuerAdapter -------------------------------------------------
    def test_connection(self) -> None:
        status, _ = self._http_get(f"{self._server_url}/certsrv/")
        if status in (401, 403):
            raise IssuerError(f"AD CS authentication failed (HTTP {status})")
        if status != 200:
            raise IssuerError(f"AD CS connection test failed (HTTP {status})")

    def issue(self, csr_pem: str, profile: dict) -> IssuedCert:
        template = profile.get("template", self._template) if profile else self._template
        data = {
            "Mode": "newreq",
            "CertRequest": csr_pem,
            "CertAttrib": f"CertificateTemplate:{template}",
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
        }
        status, body = self._http_post(f"{self._server_url}/certsrv/certfnsh.asp", data)
        if status != 200:
            raise IssuerError(f"AD CS certificate submission failed (HTTP {status})")

        match = _REQID_RE.search(body)
        if not match:
            raise IssuerError(f"AD CS certificate request was not issued: {body.strip()[:500]}")
        request_id = match.group(1)

        status, cert_pem = self._http_get(
            f"{self._server_url}/certsrv/certnew.cer?ReqID={request_id}&Enc=b64"
        )
        if status != 200 or not cert_pem.strip():
            raise IssuerError(f"AD CS failed to retrieve issued certificate (ReqID={request_id})")

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        serial = format(cert.serial_number, "x")

        # ponytail: chain retrieval (certnew.p7b?ReqID=...) is left for later
        # -- only needed once a store requires the full chain, not just the
        # leaf cert. chain_pem stays empty until then.
        return IssuedCert(certificate_pem=cert_pem, chain_pem="", serial=serial)

    def revoke(self, serial: str, reason: str) -> None:
        # ponytail: certsrv's web enrollment pages have no revoke endpoint --
        # revocation for AD CS is done directly at the CA (certutil -revoke
        # or the Certification Authority MMC snap-in). Surface that clearly
        # instead of pretending to support it.
        raise IssuerError(
            "AD CS revocation is not supported via certsrv web enrollment; revoke at the CA"
        )
