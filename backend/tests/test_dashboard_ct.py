import datetime

from app.models import Certificate, utcnow


def test_dashboard_excludes_ct_certs_from_expiry_counts(client, monkeypatch):
    from tests.conftest import login_as
    from app.db import SessionLocal
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal()
    soon = utcnow() + datetime.timedelta(days=5)
    s.add(Certificate(fingerprint_sha256="N:1", common_name="n", not_after=soon, source="network"))
    s.add(Certificate(fingerprint_sha256="C:1", common_name="c", not_after=soon, source="ct"))
    s.commit(); s.close()
    data = client.get("/api/dashboard").json()
    # exactly one expiring-soon cert counted (the network one); CT one excluded.
    assert data["expiring_7d"] == 1
