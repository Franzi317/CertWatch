"""Tests for RenewalPolicy + ManagedCertificate models and the promotion flow
that turns an observed inventory Certificate into a lifecycle-managed cert
(Phase 1, Task 6)."""
from __future__ import annotations

from conftest import login_as

from app.models import Certificate, Issuer, utcnow

POLICY = {
    "name": "default-90d",
    "renew_before_days": 30,
    "key_algorithm": "rsa",
    "key_size": 2048,
    "max_retries": 3,
}


def _issuer(db):
    i = Issuer(name="corp-ca", issuer_type="adcs", config={})
    db.add(i)
    db.flush()
    return i


def _cert(db, cn="host.example.com"):
    c = Certificate(
        fingerprint_sha256=f"FP:{cn}", common_name=cn, sans=[cn, f"alt.{cn}"],
        not_after=utcnow(),
    )
    db.add(c)
    db.flush()
    return c


def test_operator_creates_renewal_policy_with_defaults(client, monkeypatch):
    login_as(client, "operator", monkeypatch)
    r = client.post("/api/renewal-policies", json=POLICY)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["require_approval"] is True
    assert body["renew_before_days"] == 30
    assert body["verify_after_deploy"] is True


def test_viewer_can_list_but_not_create_renewal_policy(client, monkeypatch):
    login_as(client, "operator", monkeypatch)
    client.post("/api/renewal-policies", json=POLICY)

    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/renewal-policies")
    assert r.status_code == 200
    assert len(r.json()) == 1

    r = client.post("/api/renewal-policies", json=POLICY)
    assert r.status_code == 403


def test_promote_certificate_creates_managed_certificate(client, monkeypatch, db):
    issuer = _issuer(db)
    cert = _cert(db, "www.example.com")
    db.commit()

    login_as(client, "operator", monkeypatch)
    r = client.post("/api/renewal-policies", json=POLICY)
    policy_id = r.json()["id"]

    r = client.post(
        f"/api/certificates/{cert.id}/manage",
        json={"issuer_id": issuer.id, "renewal_policy_id": policy_id},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["common_name"] == "www.example.com"
    assert body["sans"] == ["www.example.com", "alt.www.example.com"]
    assert body["current_certificate_id"] == cert.id
    assert body["state"] == "active"
    assert body["issuer_id"] == issuer.id
    assert body["renewal_policy_id"] == policy_id

    r = client.get("/api/managed-certificates")
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    assert items[0]["common_name"] == "www.example.com"

    r = client.get(f"/api/managed-certificates/{body['id']}")
    assert r.status_code == 200
    assert r.json()["id"] == body["id"]


def test_promote_nonexistent_certificate_404(client, monkeypatch, db):
    issuer = _issuer(db)
    db.commit()

    login_as(client, "operator", monkeypatch)
    r = client.post("/api/renewal-policies", json=POLICY)
    policy_id = r.json()["id"]

    r = client.post(
        "/api/certificates/999999/manage",
        json={"issuer_id": issuer.id, "renewal_policy_id": policy_id},
    )
    assert r.status_code == 404


def test_promote_with_bad_issuer_or_policy_400(client, monkeypatch, db):
    issuer = _issuer(db)
    cert = _cert(db, "bad.example.com")
    db.commit()

    login_as(client, "operator", monkeypatch)
    r = client.post("/api/renewal-policies", json=POLICY)
    policy_id = r.json()["id"]

    r = client.post(
        f"/api/certificates/{cert.id}/manage",
        json={"issuer_id": 999999, "renewal_policy_id": policy_id},
    )
    assert r.status_code == 400

    r = client.post(
        f"/api/certificates/{cert.id}/manage",
        json={"issuer_id": issuer.id, "renewal_policy_id": 999999},
    )
    assert r.status_code == 400


def test_viewer_cannot_promote(client, monkeypatch, db):
    issuer = _issuer(db)
    cert = _cert(db, "viewer.example.com")
    db.commit()

    login_as(client, "operator", monkeypatch)
    r = client.post("/api/renewal-policies", json=POLICY)
    policy_id = r.json()["id"]

    login_as(client, "viewer", monkeypatch)
    r = client.post(
        f"/api/certificates/{cert.id}/manage",
        json={"issuer_id": issuer.id, "renewal_policy_id": policy_id},
    )
    assert r.status_code == 403


def test_create_managed_certificate_directly(client, monkeypatch, db):
    issuer = _issuer(db)
    db.commit()

    login_as(client, "operator", monkeypatch)
    r = client.post("/api/renewal-policies", json=POLICY)
    policy_id = r.json()["id"]

    r = client.post(
        "/api/managed-certificates",
        json={
            "common_name": "direct.example.com",
            "sans": ["direct.example.com"],
            "issuer_id": issuer.id,
            "renewal_policy_id": policy_id,
            "owner": "platform-team",
            "environment": "staging",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["common_name"] == "direct.example.com"
    assert body["current_certificate_id"] is None
    assert body["state"] == "active"
    assert body["owner"] == "platform-team"
    assert body["environment"] == "staging"
