"""Serialization helpers that enrich ORM rows with computed status fields."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .models import Certificate, CertificateObservation, Endpoint, Target
from .status import days_until, expiry_phrase, is_internal, severity, status_phrase


def cert_dict(db: Session, cert: Certificate, with_endpoints: bool = False) -> dict:
    days = days_until(cert.not_after)
    eps = db.scalars(select(Endpoint).where(Endpoint.current_cert_id == cert.id)).all()
    out = {
        "id": cert.id,
        "fingerprint_sha256": cert.fingerprint_sha256,
        "common_name": cert.common_name,
        "subject": cert.subject,
        "sans": cert.sans,
        "issuer": cert.issuer,
        "issuer_cn": cert.issuer_cn,
        "serial_number": cert.serial_number,
        "signature_algorithm": cert.signature_algorithm,
        "public_key_algorithm": cert.public_key_algorithm,
        "public_key_size": cert.public_key_size,
        "not_before": cert.not_before,
        "not_after": cert.not_after,
        "self_signed": cert.self_signed,
        "internal_issued": is_internal(cert.issuer, cert.self_signed, settings.internal_ca_pattern_list),
        "is_wildcard": cert.is_wildcard,
        "is_ca": cert.is_ca,
        "chain_length": cert.chain_length,
        "first_seen": cert.first_seen,
        "last_seen": cert.last_seen,
        "days_until_expiry": days,
        "expired": days is not None and days < 0,
        "severity": severity(days),
        "expiry_phrase": expiry_phrase(days),
        "endpoint_count": len(eps),
    }
    if with_endpoints:
        out["pem"] = cert.pem
        out["endpoints"] = [endpoint_dict(db, ep, with_cert=False) for ep in eps]
    return out


def endpoint_dict(db: Session, ep: Endpoint, with_cert: bool = True) -> dict:
    target = db.get(Target, ep.target_id) if ep.target_id else None
    cert = db.get(Certificate, ep.current_cert_id) if ep.current_cert_id else None
    days = days_until(cert.not_after) if cert else None
    out = {
        "id": ep.id,
        "target_id": ep.target_id,
        "target_name": target.name if target else "",
        "environment": target.environment if target else "",
        "owner": target.owner if target else "",
        "host": ep.host,
        "ip": ep.ip,
        "port": ep.port,
        "sni": ep.sni,
        "last_status": ep.last_status,
        "last_status_phrase": status_phrase(ep.last_status),
        "last_error": ep.last_error,
        "consecutive_failures": ep.consecutive_failures,
        "first_seen": ep.first_seen,
        "last_seen": ep.last_seen,
        "current_cert_id": ep.current_cert_id,
        "common_name": cert.common_name if cert else "",
        "issuer_cn": cert.issuer_cn if cert else "",
        "not_after": cert.not_after if cert else None,
        "days_until_expiry": days,
        "severity": severity(days, scan_ok=(ep.last_status == "ok")),
        "expiry_phrase": expiry_phrase(days) if cert else status_phrase(ep.last_status),
    }
    if with_cert and cert:
        out["certificate"] = cert_dict(db, cert)
    return out


def observation_dict(obs: CertificateObservation) -> dict:
    return {
        "id": obs.id,
        "scan_job_id": obs.scan_job_id,
        "certificate_id": obs.certificate_id,
        "status": obs.status,
        "status_phrase": status_phrase(obs.status),
        "error": obs.error,
        "sni_used": obs.sni_used,
        "change_status": obs.change_status,
        "observed_at": obs.observed_at,
    }
