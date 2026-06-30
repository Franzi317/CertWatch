import time

import pytest

from app import scan_engine
from app.scanner import ScanResult

TARGET = {"name": "Lab box", "target_type": "ip", "value": "10.0.0.5", "ports": [443, 8443]}


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

    for _ in range(50):
        job = client.get(f"/api/scans/{jid}").json()
        if job["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(0.1)
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


def test_dashboard_summary(client):
    body = client.get("/api/dashboard").json()
    for key in ("total_certificates", "total_endpoints", "expiring_90d", "expired", "failed_scans"):
        assert key in body
