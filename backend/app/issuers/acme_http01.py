"""ACME HTTP-01 issuer adapter (secondary CA path; AD CS is primary).

Talks to any RFC 8555 ACME CA (Let's Encrypt staging/production, or an
internal ACME server) using the HTTP-01 challenge type. All `acme`-library
and network interaction is isolated behind small seam methods
(`_get_directory`, `_new_order`, `_get_http01_challenges`,
`_answer_challenges`, `_poll_and_finalize`, `_revoke`) so tests can
monkeypatch them and never touch the network or import the real `acme`
client machinery.

The `acme` package (and its `josepy`/`pyOpenSSL` dependencies) is imported
lazily inside those seam methods, not at module top: importing this module
for `get_adapter()` dispatch must stay cheap, and pinning it eagerly here
would also drag in pyOpenSSL/josepy, whose released versions do not all
line up with this repo's pinned `cryptography` release (harmless as long as
the real network path is never exercised at import time or in tests).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.issuers.base import IssuedCert, IssuerAdapter, IssuerError

_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*", re.DOTALL
)

# ACME/RFC 5280 CRL reason codes accepted by the ACME revoke-cert endpoint.
_REVOCATION_REASONS = {
    "unspecified": 0,
    "keyCompromise": 1,
    "affiliationChanged": 3,
    "superseded": 4,
    "cessationOfOperation": 5,
}


def _split_fullchain(fullchain_pem: str) -> list[str]:
    """Split a `fullchain.pem`-style blob into individual cert PEM blocks,
    leaf first (ACME returns them in leaf-then-issuers order)."""
    certs = _CERT_RE.findall(fullchain_pem)
    if not certs:
        raise IssuerError("ACME finalize returned no PEM certificates")
    return certs


@dataclass
class _OrderContext:
    """Opaque handle threaded through the order-flow seams. Real production
    wiring stashes the acme-py client + order/challenge objects here; tests
    monkeypatch every seam that touches it, so its shape is otherwise free."""

    client: object
    order: object
    challbs: list = field(default_factory=list)  # [(challb, response), ...]


class AcmeHttp01Adapter(IssuerAdapter):
    """Issuer adapter for ACME CAs using the HTTP-01 challenge type.

    Expected `issuer.config` fields:
      - directory_url: ACME directory URL (e.g. Let's Encrypt staging:
        https://acme-staging-v02.api.letsencrypt.org/directory)
      - account_key_pem: PEM-encoded ACME account private key, encrypted at
        rest via `app.secrets`. Generated (and the config updated in-place
        with the encrypted PEM) on first use if absent.
      - contact_email: contact email used when registering the ACME account
    """

    def __init__(self, issuer) -> None:
        self._issuer = issuer
        config = issuer.config if hasattr(issuer, "config") else issuer
        self._config = config
        self._directory_url = config.get("directory_url", "")
        self._contact_email = config.get("contact_email", "")
        self._account_key_enc = config.get("account_key_pem", "")

    # -- account key: generated + encrypted on first use --------------------
    def _account_key_pem(self) -> str:
        from app.secrets import SecretsNotConfigured, decrypt, encrypt

        if self._account_key_enc:
            try:
                return decrypt(self._account_key_enc)
            except SecretsNotConfigured as e:
                raise IssuerError(f"cannot decrypt ACME account key: {e}") from e

        from app.crypto_keys import generate_private_key

        key_pem = generate_private_key("rsa", 2048).key_pem
        self._account_key_enc = encrypt(key_pem)
        # ponytail: this only mutates the in-memory config dict; persisting
        # the encrypted account key back onto the `issuers` row is the
        # responsibility of whichever caller holds the SQLAlchemy session
        # (it can read `issuer.config["account_key_pem"]` after `issue()`
        # returns and commit it) -- this adapter has no session of its own
        # for the `Issuer` row itself, only for `AcmeChallenge` bookkeeping.
        self._config["account_key_pem"] = self._account_key_enc
        return key_pem

    # -- network/library seams: tests monkeypatch these directly ------------
    def _get_directory(self) -> dict:
        import httpx

        resp = httpx.get(self._directory_url, timeout=30.0)
        resp.raise_for_status()
        return resp.json()

    def _acme_client(self):
        """Build a real `acme.client.ClientV2` bound to this issuer's account
        key, registering the account if needed. Lazy-imports `acme`/`josepy`."""
        import josepy as jose
        from acme import client, messages

        directory = messages.Directory.from_json(self._get_directory())
        key = serialization.load_pem_private_key(self._account_key_pem().encode(), password=None)
        jwk = jose.JWKRSA(key=jose.ComparableRSAKey(key))
        net = client.ClientNetwork(jwk, user_agent="CertWatch/1.0")
        acme_client = client.ClientV2(directory, net=net)
        acme_client.new_account(
            messages.NewRegistration.from_data(
                email=self._contact_email or None, terms_of_service_agreed=True
            )
        )
        return acme_client

    def _new_order(self, csr_pem: str) -> _OrderContext:
        acme_client = self._acme_client()
        order = acme_client.new_order(csr_pem.encode())
        return _OrderContext(client=acme_client, order=order)

    def _get_http01_challenges(self, order: _OrderContext) -> list[tuple[str, str, str]]:
        from acme import challenges as acme_challenges

        result: list[tuple[str, str, str]] = []
        challbs: list[tuple[object, object]] = []
        for authz in order.order.authorizations:
            domain = authz.body.identifier.value
            for challb in authz.body.challenges:
                if isinstance(challb.chall, acme_challenges.HTTP01):
                    response, validation = challb.response_and_validation(order.client.net.key)
                    token = challb.chall.encode("token")
                    result.append((token, validation, domain))
                    challbs.append((challb, response))
                    break
        order.challbs = challbs
        return result

    def _answer_challenges(self, order: _OrderContext) -> None:
        for challb, response in order.challbs:
            order.client.answer_challenge(challb, response)

    def _poll_and_finalize(self, order: _OrderContext, csr_pem: str) -> str:
        finalized = order.client.poll_and_finalize(order.order)
        return finalized.fullchain_pem

    def _revoke(self, serial: str, reason: str) -> None:
        from app.db import SessionLocal
        from app.models import Certificate

        session = SessionLocal()
        try:
            cert_row = session.query(Certificate).filter(Certificate.serial_number == serial).first()
        finally:
            session.close()
        if cert_row is None or not cert_row.pem:
            raise IssuerError(f"no stored certificate found for serial {serial!r}; cannot revoke via ACME")

        import josepy as jose
        from OpenSSL import crypto as ossl_crypto

        cert = x509.load_pem_x509_certificate(cert_row.pem.encode())
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        ossl_cert = ossl_crypto.load_certificate(ossl_crypto.FILETYPE_ASN1, cert_der)

        acme_client = self._acme_client()
        acme_client.revoke(jose.ComparableX509(ossl_cert), _REVOCATION_REASONS.get(reason, 0))

    # -- IssuerAdapter --------------------------------------------------
    def test_connection(self) -> None:
        try:
            self._get_directory()
        except Exception as e:  # noqa: BLE001 - surface any failure as IssuerError
            raise IssuerError(f"ACME directory fetch failed: {e}") from e

    def issue(self, csr_pem: str, profile: dict) -> IssuedCert:
        order = self._new_order(csr_pem)
        pending = self._get_http01_challenges(order)

        from app.db import SessionLocal
        from app.models import AcmeChallenge

        tokens = [token for token, _key_auth, _domain in pending]

        session = SessionLocal()
        try:
            for token, key_authorization, _domain in pending:
                session.merge(AcmeChallenge(token=token, key_authorization=key_authorization))
            session.commit()
        finally:
            session.close()

        try:
            self._answer_challenges(order)
            fullchain_pem = self._poll_and_finalize(order, csr_pem)
        finally:
            # Best-effort cleanup -- an issuance failure shouldn't leave the
            # challenge route serving stale tokens forever, but a cleanup
            # failure here must not mask the real issuance error.
            session = SessionLocal()
            try:
                session.query(AcmeChallenge).filter(AcmeChallenge.token.in_(tokens)).delete(
                    synchronize_session=False
                )
                session.commit()
            except Exception:  # noqa: BLE001 - best-effort only
                session.rollback()
            finally:
                session.close()

        certs = _split_fullchain(fullchain_pem)
        leaf_pem, chain_pem = certs[0], "".join(certs[1:])
        cert = x509.load_pem_x509_certificate(leaf_pem.encode())
        serial = format(cert.serial_number, "x")
        return IssuedCert(certificate_pem=leaf_pem, chain_pem=chain_pem, serial=serial)

    def revoke(self, serial: str, reason: str) -> None:
        try:
            self._revoke(serial, reason)
        except IssuerError:
            raise
        except Exception as e:  # noqa: BLE001 - surface any failure as IssuerError
            raise IssuerError(f"ACME revoke failed: {e}") from e
