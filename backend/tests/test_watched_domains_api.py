def test_crud_watched_domains(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "admin", monkeypatch)

    r = client.post("/api/watched-domains", json={"domain": "example.com"})
    assert r.status_code == 200, r.text
    did = r.json()["id"]

    r = client.get("/api/watched-domains")
    assert any(d["domain"] == "example.com" for d in r.json()["items"])

    r = client.post(f"/api/watched-domains/{did}/check")
    assert r.status_code == 200

    r = client.delete(f"/api/watched-domains/{did}")
    assert r.status_code == 200
    assert all(d["id"] != did for d in client.get("/api/watched-domains").json()["items"])


def test_watched_domains_require_admin(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "operator", monkeypatch)
    r = client.post("/api/watched-domains", json={"domain": "x.com"})
    assert r.status_code == 403


def test_certificates_source_filter(client, monkeypatch):
    from tests.conftest import login_as
    from app.db import SessionLocal
    from app.models import Certificate
    login_as(client, "viewer", monkeypatch)
    s = SessionLocal()
    s.add(Certificate(fingerprint_sha256="Z:1", common_name="n", source="ct"))
    s.add(Certificate(fingerprint_sha256="Z:2", common_name="n", source="network"))
    s.commit(); s.close()
    r = client.get("/api/certificates?source=ct")
    items = r.json()["items"]
    assert items and all(i["source"] == "ct" for i in items)
