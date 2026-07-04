"""Tests for CSV export (Phase 2, Task 1): app.exports.rows_to_csv + the
`?format=csv` branch on the certificates/endpoints/lifecycle-orders/audit
list endpoints."""
import datetime

from app.db import SessionLocal
from app.exports import rows_to_csv
from app.models import Certificate, LifecycleOrder
from conftest import login_as


def test_rows_to_csv_header_and_row():
    csv_text = rows_to_csv(["a", "b"], [{"a": 1, "b": "x"}])
    lines = csv_text.splitlines()
    assert lines[0] == "a,b"
    assert lines[1] == "1,x"


def test_rows_to_csv_ignores_extra_keys_and_fills_missing():
    csv_text = rows_to_csv(["a", "b"], [{"a": 1, "c": "extra"}])
    lines = csv_text.splitlines()
    assert lines[0] == "a,b"
    assert lines[1] == "1,"


def _seed_cert(db) -> Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = Certificate(
        fingerprint_sha256="AA:BB:CC",
        common_name="csv.example.com",
        subject="CN=csv.example.com",
        sans=["csv.example.com"],
        issuer="CN=CA", issuer_cn="CA",
        serial_number="1",
        signature_algorithm="sha256WithRSAEncryption",
        public_key_algorithm="RSA", public_key_size=2048,
        not_before=now, not_after=now + datetime.timedelta(days=30),
        self_signed=False,
    )
    db.add(cert)
    db.commit()
    db.refresh(cert)
    return cert


def test_certificates_csv_export(client, monkeypatch):
    sdb = SessionLocal()
    try:
        _seed_cert(sdb)
    finally:
        sdb.close()
    login_as(client, "viewer", monkeypatch)

    r = client.get("/api/certificates?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert "certificates.csv" in r.headers["content-disposition"]
    lines = r.text.splitlines()
    assert lines[0] == (
        "id,common_name,issuer_cn,not_before,not_after,public_key_algorithm,"
        "public_key_size,signature_algorithm,self_signed,fingerprint_sha256"
    )
    assert "csv.example.com" in r.text


def test_certificates_json_format_unchanged(client, monkeypatch):
    sdb = SessionLocal()
    try:
        _seed_cert(sdb)
    finally:
        sdb.close()
    login_as(client, "viewer", monkeypatch)

    r_default = client.get("/api/certificates")
    r_json = client.get("/api/certificates?format=json")
    for r in (r_default, r_json):
        assert r.status_code == 200
        body = r.json()
        assert set(body.keys()) == {"total", "items"}
        assert body["total"] == 1


def test_endpoints_csv_export(client, monkeypatch):
    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/endpoints?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "endpoints.csv" in r.headers["content-disposition"]


def test_lifecycle_orders_csv_export(client, monkeypatch):
    sdb = SessionLocal()
    try:
        order = LifecycleOrder(managed_certificate_id=1, action="issue", status="pending_approval")
        sdb.add(order)
        sdb.commit()
    finally:
        sdb.close()
    login_as(client, "viewer", monkeypatch)

    r = client.get("/api/lifecycle/orders?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "lifecycle-orders.csv" in r.headers["content-disposition"]
    assert "issue" in r.text


def test_lifecycle_orders_json_still_bare_list(client, monkeypatch):
    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/lifecycle/orders")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_audit_csv_requires_admin(client, monkeypatch):
    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/audit?format=csv")
    assert r.status_code == 403


def test_audit_csv_export(client, monkeypatch):
    login_as(client, "admin", monkeypatch)
    r = client.get("/api/audit?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "audit.csv" in r.headers["content-disposition"]
