import datetime

from app.db import SessionLocal
from app.models import Certificate, Endpoint, Target, utcnow


def _seed(db):
    soon = utcnow() + datetime.timedelta(days=20)
    orphan = utcnow() + datetime.timedelta(days=25)
    root = utcnow() + datetime.timedelta(days=500)
    far = utcnow() + datetime.timedelta(days=800)
    ca_soon = Certificate(fingerprint_sha256="CA:SOON", common_name="Int Soon", issuer_cn="Root",
                          source="chain", is_ca=True, self_signed=False, not_after=soon)
    # near-expiry (within 90d) but ZERO dependents: isolates the dashboard
    # dependent-guard from the expiry window (a dropped guard would count it).
    ca_orphan = Certificate(fingerprint_sha256="CA:SOON_ORPHAN", common_name="Int Orphan",
                            issuer_cn="Root", source="chain", is_ca=True, self_signed=False,
                            not_after=orphan)
    # self-signed root CA (is_root path) with a dependent leaf so it surfaces.
    ca_root = Certificate(fingerprint_sha256="CA:ROOT", common_name="The Root", issuer_cn="The Root",
                          source="chain", is_ca=True, self_signed=True, not_after=root)
    ca_far = Certificate(fingerprint_sha256="CA:FAR", common_name="Int Far", issuer_cn="Root",
                         source="chain", is_ca=True, self_signed=False, not_after=far)
    db.add_all([ca_soon, ca_orphan, ca_root, ca_far])
    # two leaves depend on CA:SOON; one on CA:ROOT; none on CA:SOON_ORPHAN or CA:FAR
    l1 = Certificate(fingerprint_sha256="L1", common_name="l1", source="network",
                     chain_ca_fingerprints=["CA:SOON"])
    l2 = Certificate(fingerprint_sha256="L2", common_name="l2", source="network",
                     chain_ca_fingerprints=["CA:SOON"])
    l3 = Certificate(fingerprint_sha256="L3", common_name="l3", source="network",
                     chain_ca_fingerprints=["CA:ROOT"])
    db.add_all([l1, l2, l3])
    db.flush()
    # bind the dependent leaves to endpoints so they count as LIVE dependents
    # (dependent_counts is live-scoped)
    t = Target(name="grp", target_type="hostname", value="host.example.com",
               ports=[443], environment="prod")
    db.add(t)
    db.flush()
    db.add(Endpoint(target_id=t.id, host="l1.example.com", ip="10.0.0.1", port=443,
                    current_cert_id=l1.id, last_status="ok"))
    db.add(Endpoint(target_id=t.id, host="l2.example.com", ip="10.0.0.2", port=443,
                    current_cert_id=l2.id, last_status="ok"))
    db.add(Endpoint(target_id=t.id, host="l3.example.com", ip="10.0.0.3", port=443,
                    current_cert_id=l3.id, last_status="ok"))
    db.commit()


def test_ca_certificates_endpoint(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal(); _seed(s); s.close()
    r = client.get("/api/ca-certificates")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    # sorted by not_after ascending: SOON(20d) < ORPHAN(25d) < ROOT(500d) < FAR(800d)
    assert [i["fingerprint_sha256"] for i in items] == [
        "CA:SOON", "CA:SOON_ORPHAN", "CA:ROOT", "CA:FAR"
    ]
    by_fp = {i["fingerprint_sha256"]: i for i in items}
    soon = by_fp["CA:SOON"]
    assert soon["dependent_count"] == 2
    assert soon["is_root"] is False
    # zero-default: CA:FAR (intermediate, no dependents) -> dependent_count 0
    assert by_fp["CA:FAR"]["dependent_count"] == 0
    # is_root=True path: self-signed CA:ROOT
    assert by_fp["CA:ROOT"]["is_root"] is True


def test_dashboard_ca_expiring_count(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal(); _seed(s); s.close()
    data = client.get("/api/dashboard").json()
    # Only CA:SOON (20d, 2 dependents) counts. CA:SOON_ORPHAN is also within 90d
    # but has 0 dependents, so it must be excluded by the dependent guard;
    # CA:ROOT (500d) and CA:FAR (800d) are outside the 90d window.
    assert data["ca_expiring_90d"] == 1
