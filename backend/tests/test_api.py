import pytest

from app import scan_engine, worker
from app.db import SessionLocal
from app.scanner import ScanResult
from conftest import login_as

TARGET = {"name": "Lab box", "target_type": "ip", "value": "10.0.0.5", "ports": [443, 8443]}


# These tests predate RBAC (Phase 0, Task 5) and exercise every route as an
# open API. Rather than rewrite each test to establish its own session, this
# overrides the module-scoped `client` fixture (same name, referencing the
# parent fixture from conftest.py) to log in as admin — admin outranks every
# role, so all previously-open calls stay authorized without touching the
# test bodies below.
@pytest.fixture
def client(client, monkeypatch):
    login_as(client, "admin", monkeypatch)
    return client


def _fake_cert(fp="AB:CD"):
    import datetime
    return {
        "fingerprint_sha256": fp, "common_name": "lab.example.com", "subject": "CN=lab.example.com",
        "sans": ["lab.example.com"], "issuer": "CN=CA", "issuer_cn": "CA", "serial_number": "1",
        "signature_algorithm": "sha256WithRSAEncryption", "public_key_algorithm": "RSA",
        "public_key_size": 2048,
        "not_before": datetime.datetime.now(datetime.timezone.utc),
        "not_after": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10),
        "self_signed": False, "is_wildcard": False, "is_ca": False, "chain_length": 1, "pem": "",
    }


def test_target_crud(client):
    r = client.post("/api/targets", json=TARGET)
    assert r.status_code == 201
    tid = r.json()["id"]
    assert r.json()["ports"] == [443, 8443]

    assert client.get("/api/targets").json()[0]["id"] == tid
    assert client.get(f"/api/targets/{tid}").json()["name"] == "Lab box"

    r = client.put(f"/api/targets/{tid}", json={**TARGET, "name": "Renamed", "owner": "netops"})
    assert r.json()["name"] == "Renamed"
    assert r.json()["owner"] == "netops"

    assert client.delete(f"/api/targets/{tid}").status_code == 204
    assert client.get(f"/api/targets/{tid}").status_code == 404


def test_target_validation_rejects_oversized_cidr(client):
    r = client.post("/api/targets/validate",
                    json={"name": "x", "target_type": "cidr", "value": "10.0.0.0/8"})
    assert r.status_code == 400


def test_validate_endpoint_count(client):
    r = client.post("/api/targets/validate",
                    json={"name": "x", "target_type": "cidr", "value": "10.0.0.0/29", "ports": [443, 8443]})
    body = r.json()
    assert body["host_count"] == 6
    assert body["endpoint_count"] == 12


def test_scan_job_creation_and_dedup(client, monkeypatch):
    monkeypatch.setattr(scan_engine, "scan_endpoint",
                        lambda ip, port, sni="", timeout=5.0: ScanResult(status="ok", cert=_fake_cert()))
    tid = client.post("/api/targets", json=TARGET).json()["id"]

    r = client.post(f"/api/targets/{tid}/scan")
    assert r.status_code == 202
    jid = r.json()["id"]

    # No embedded worker runs during tests (CERTWATCH_EMBEDDED_WORKER=false,
    # see conftest.py) -- drain the queue item explicitly and deterministically.
    wdb = SessionLocal()
    try:
        assert worker.process_one(wdb) is True
    finally:
        wdb.close()

    job = client.get(f"/api/scans/{jid}").json()
    assert job["status"] == "completed"
    assert job["total_endpoints"] == 2          # two ports
    assert job["certs_found"] == 2

    # same fingerprint on both ports -> one deduplicated certificate, two endpoints
    assert client.get("/api/certificates").json()["total"] == 1
    assert client.get("/api/endpoints").json()["total"] == 2


def test_channel_secrets_are_scrubbed(client):
    r = client.post("/api/channels", json={
        "name": "mail", "channel_type": "smtp",
        "config": {"host": "smtp.example.com", "password": "s3cret", "recipients": ["a@b.c"]},
    })
    assert r.status_code == 201
    summary = r.json()["config_summary"]
    assert "password" not in summary           # secret never echoed
    assert summary["password_set"] is True
    assert summary["host"] == "smtp.example.com"

    # editing with a blank password keeps the existing secret
    cid = r.json()["id"]
    client.put(f"/api/channels/{cid}", json={
        "name": "mail", "channel_type": "smtp",
        "config": {"host": "smtp2.example.com", "password": "", "recipients": ["a@b.c"]},
    })
    # nothing crashes; host updated
    assert client.get("/api/channels").json()[0]["config_summary"]["host"] == "smtp2.example.com"


def test_channel_secrets_stored_encrypted(client):
    from app import secrets as app_secrets
    from app.db import SessionLocal
    from app.models import NotificationChannel

    plaintext_password = "s3cret"
    plaintext_url = "https://hooks.example.com/services/T00/B00/XXXX"
    r = client.post("/api/channels", json={
        "name": "hook", "channel_type": "webhook",
        "config": {"url": plaintext_url, "password": plaintext_password, "recipients": ["a@b.c"]},
    })
    assert r.status_code == 201
    cid = r.json()["id"]

    # Bypass the API and read the persisted row directly, so a regression
    # that drops the encrypt() call (but leaves config_summary scrubbing
    # intact) would still be caught.
    session = SessionLocal()
    try:
        row = session.get(NotificationChannel, cid)
        stored_password = row.config["password"]
        stored_url = row.config["url"]
    finally:
        session.close()

    assert app_secrets.is_encrypted(stored_password)
    assert stored_password != plaintext_password

    assert app_secrets.is_encrypted(stored_url)
    assert stored_url != plaintext_url

    # and the ciphertext round-trips back to the original plaintext
    assert app_secrets.decrypt(stored_password) == plaintext_password
    assert app_secrets.decrypt(stored_url) == plaintext_url


def test_dashboard_summary(client):
    body = client.get("/api/dashboard").json()
    for key in ("total_certificates", "total_endpoints", "expiring_90d", "expired", "failed_scans"):
        assert key in body
