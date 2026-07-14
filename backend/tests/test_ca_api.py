import datetime

from app.db import SessionLocal
from app.models import Certificate, utcnow


def _seed(db):
    soon = utcnow() + datetime.timedelta(days=20)
    far = utcnow() + datetime.timedelta(days=800)
    ca_soon = Certificate(fingerprint_sha256="CA:SOON", common_name="Int Soon", issuer_cn="Root",
                          source="chain", is_ca=True, self_signed=False, not_after=soon)
    ca_far = Certificate(fingerprint_sha256="CA:FAR", common_name="Int Far", issuer_cn="Root",
                         source="chain", is_ca=True, self_signed=False, not_after=far)
    db.add_all([ca_soon, ca_far])
    # two leaves depend on CA:SOON, none on CA:FAR
    db.add(Certificate(fingerprint_sha256="L1", common_name="l1", source="network",
                       chain_ca_fingerprints=["CA:SOON"]))
    db.add(Certificate(fingerprint_sha256="L2", common_name="l2", source="network",
                       chain_ca_fingerprints=["CA:SOON"]))
    db.commit()


def test_ca_certificates_endpoint(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal(); _seed(s); s.close()
    r = client.get("/api/ca-certificates")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert [i["fingerprint_sha256"] for i in items] == ["CA:SOON", "CA:FAR"]  # sorted by expiry
    soon = items[0]
    assert soon["dependent_count"] == 2
    assert soon["is_root"] is False


def test_dashboard_ca_expiring_count(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal(); _seed(s); s.close()
    data = client.get("/api/dashboard").json()
    # CA:SOON (20d, 2 dependents) counts; CA:FAR (800d) does not
    assert data["ca_expiring_90d"] == 1
