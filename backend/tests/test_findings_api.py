"""Tests for Findings API + disposition workflow + dashboard risk metrics
(Phase 2, Task 3)."""
import datetime

from conftest import login_as

from app import findings
from app.models import Certificate, Endpoint, Target, utcnow


def _cert(db, fp="AA:BB", **kw):
    defaults = dict(
        fingerprint_sha256=fp,
        common_name="host.example.com",
        issuer="CN=Some CA",
        issuer_cn="Some CA",
        public_key_algorithm="RSA",
        public_key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
        not_before=utcnow() - datetime.timedelta(days=10),
        not_after=utcnow() + datetime.timedelta(days=60),
        self_signed=False,
    )
    defaults.update(kw)
    c = Certificate(**defaults)
    db.add(c)
    db.flush()
    return c


def _target(db, environment="prod"):
    t = Target(name="grp", target_type="hostname", value="host.example.com",
               ports=[443], environment=environment)
    db.add(t)
    db.flush()
    return t


def _endpoint(db, target, cert):
    ep = Endpoint(target_id=target.id, host="host.example.com", ip="10.0.0.5", port=443,
                  current_cert_id=cert.id, last_status="ok")
    db.add(ep)
    db.flush()
    return ep


def _seed_critical_and_warning(db):
    """One critical finding (expired cert) and one warning finding (weak key)."""
    expired_cert = _cert(db, fp="EXPIRED", not_after=utcnow() - datetime.timedelta(days=3))
    weak_cert = _cert(db, fp="WEAK", public_key_algorithm="RSA", public_key_size=1024)
    db.commit()
    critical_findings = findings.evaluate_certificate(db, expired_cert)
    warning_findings = findings.evaluate_certificate(db, weak_cert)
    critical = next(f for f in critical_findings if f.rule_id == "expired")
    warning = next(f for f in warning_findings if f.rule_id == "weak_key")
    return critical, warning


def test_viewer_list_findings_filtered_by_severity(client, monkeypatch, db):
    critical, warning = _seed_critical_and_warning(db)

    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/findings?severity=critical")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "total" in body and "items" in body
    assert body["total"] == 1
    assert all(item["severity"] == "critical" for item in body["items"])
    assert any(item["id"] == critical.id for item in body["items"])
    assert all(item["id"] != warning.id for item in body["items"])


def test_viewer_list_findings_default_status_active(client, monkeypatch, db):
    critical, warning = _seed_critical_and_warning(db)
    # clear one finding by making the condition stop firing
    cert = db.get(Certificate, warning.certificate_id)
    cert.public_key_size = 2048
    db.commit()
    findings.evaluate_certificate(db, cert)

    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/findings")
    assert r.status_code == 200
    ids = {item["id"] for item in r.json()["items"]}
    assert critical.id in ids
    assert warning.id not in ids  # cleared, not active


def test_get_finding_detail_and_404(client, monkeypatch, db):
    critical, _ = _seed_critical_and_warning(db)
    login_as(client, "viewer", monkeypatch)

    r = client.get(f"/api/findings/{critical.id}")
    assert r.status_code == 200
    assert r.json()["id"] == critical.id

    r = client.get("/api/findings/999999")
    assert r.status_code == 404


def test_findings_csv_export(client, monkeypatch, db):
    _seed_critical_and_warning(db)
    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/findings?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "rule_id" in r.text


def test_operator_sets_disposition_and_audits(client, monkeypatch, db):
    critical, _ = _seed_critical_and_warning(db)

    operator = login_as(client, "operator", monkeypatch)
    r = client.post(f"/api/findings/{critical.id}/disposition", json={"disposition": "accepted"})
    assert r.status_code == 200, r.text
    assert r.json()["disposition"] == "accepted"

    login_as(client, "admin", monkeypatch)
    r = client.get("/api/audit")
    rows = [row for row in r.json()["items"] if row["action"] == "finding.disposition"]
    assert rows, f"expected a finding.disposition row, got {r.json()['items']}"
    assert rows[0]["actor"] == operator["email"]


def test_viewer_cannot_set_disposition(client, monkeypatch, db):
    critical, _ = _seed_critical_and_warning(db)
    login_as(client, "viewer", monkeypatch)
    r = client.post(f"/api/findings/{critical.id}/disposition", json={"disposition": "accepted"})
    assert r.status_code == 403


def test_disposition_404_for_missing_finding(client, monkeypatch, db):
    login_as(client, "operator", monkeypatch)
    r = client.post("/api/findings/999999/disposition", json={"disposition": "accepted"})
    assert r.status_code == 404


def test_operator_evaluate_endpoint(client, monkeypatch, db):
    cert = _cert(db, fp="EXPIRED", not_after=utcnow() - datetime.timedelta(days=3))
    t = _target(db)
    _endpoint(db, t, cert)
    db.commit()

    login_as(client, "operator", monkeypatch)
    r = client.post("/api/findings/evaluate")
    assert r.status_code == 200, r.text
    assert r.json()["active"] >= 1


def test_viewer_cannot_trigger_evaluate(client, monkeypatch, db):
    login_as(client, "viewer", monkeypatch)
    r = client.post("/api/findings/evaluate")
    assert r.status_code == 403


def test_dashboard_includes_open_findings_and_severity_breakdown(client, monkeypatch, db):
    critical, warning = _seed_critical_and_warning(db)

    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/dashboard")
    assert r.status_code == 200
    body = r.json()
    assert body["open_findings"] == 2
    assert body["findings_by_severity"]["critical"] == 1
    assert body["findings_by_severity"]["warning"] == 1


def test_dashboard_excludes_accepted_findings_from_open_count(client, monkeypatch, db):
    critical, warning = _seed_critical_and_warning(db)
    critical.disposition = "accepted"
    db.commit()

    login_as(client, "viewer", monkeypatch)
    r = client.get("/api/dashboard")
    body = r.json()
    assert body["open_findings"] == 1
    assert body["findings_by_severity"] == {"warning": 1}
