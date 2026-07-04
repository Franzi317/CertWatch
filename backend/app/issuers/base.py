"""Issuer adapter protocol.

Concrete adapters (AD CS, ACME http-01) implement `IssuerAdapter` and are
dispatched via `get_adapter()` based on `Issuer.issuer_type`. Adapters are
imported lazily inside `get_adapter` to avoid circular imports between this
module and the adapter modules (which import `app.models`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from app.models import Issuer


@dataclass
class IssuedCert:
    certificate_pem: str
    chain_pem: str = ""  # intermediate/issuer chain, may be empty
    serial: str = ""


class IssuerError(Exception):
    pass


class IssuerAdapter(Protocol):
    def test_connection(self) -> None: ...  # raise IssuerError on failure

    def issue(self, csr_pem: str, profile: dict) -> IssuedCert: ...

    def revoke(self, serial: str, reason: str) -> None: ...


def get_adapter(issuer: "Issuer") -> IssuerAdapter:
    """Dispatch on `issuer.issuer_type` to the concrete adapter.

    AD CS and ACME adapters land in later tasks; until then every type is
    unimplemented and raises IssuerError.
    """
    issuer_type = issuer.issuer_type

    if issuer_type == "adcs":
        try:
            from app.issuers.adcs import ADCSAdapter
        except ModuleNotFoundError as e:
            if e.name != "app.issuers.adcs":
                raise
            raise IssuerError(f"unknown issuer type: {issuer_type}") from e
        return ADCSAdapter(issuer)

    if issuer_type == "acme":
        try:
            from app.issuers.acme_http01 import AcmeHttp01Adapter
        except ModuleNotFoundError as e:
            if e.name != "app.issuers.acme_http01":
                raise
            raise IssuerError(f"unknown issuer type: {issuer_type}") from e
        return AcmeHttp01Adapter(issuer)

    raise IssuerError(f"unknown issuer type: {issuer_type}")
