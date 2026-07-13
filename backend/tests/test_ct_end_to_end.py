"""Task 12: end-to-end wiring test for CT monitoring.

Each unit (scheduler tick, worker ct_check handler, ct_source client,
unknown_issuance finding) is already covered by its own unit tests
(test_scheduler_ct.py, test_worker_ct.py, test_ct_source.py, ...). This
test proves the seams between them are wired correctly: a WatchedDomain
due for a check gets enqueued by `scheduler.ct_tick()`, the queue item is
drained by `worker.process_one()`, a fake CT source is used to avoid any
real network access, and the ingested certificate produces both a
`source=ct` Certificate row and an active `unknown_issuance` Finding.
"""
import datetime

from app import ct_source, scheduler, worker
from app.models import Certificate, Finding, WatchedDomain, WorkQueue


def _der(cn="shadow.example.com"):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_ct_tick_to_worker_to_ingest_to_finding(db, monkeypatch):
    # Wire both the scheduler tick and the worker to the same test session
    # so the enqueue and the drain operate on the same DB state.
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    monkeypatch.setattr(scheduler.settings, "ct_source_url", "https://crt.sh", raising=False)
    monkeypatch.setattr(worker.settings, "ct_source_url", "https://crt.sh", raising=False)

    # Fake CT source: no real network traffic, one entry, one self-signed DER.
    der = _der()
    monkeypatch.setattr(ct_source, "list_entries", lambda base, dom, **k: [{"id": 100}])
    monkeypatch.setattr(ct_source, "fetch_der", lambda base, cid, **k: der)

    domain = WatchedDomain(domain="example.com", enabled=True)
    db.add(domain)
    db.commit()

    # 1. Scheduler tick enqueues a ct_check for the due domain.
    scheduler.ct_tick()
    assert db.query(WorkQueue).filter_by(kind="ct_check").count() == 1

    # 2. Worker drains the queue until empty.
    iterations = 0
    while worker.process_one(db):
        iterations += 1
        assert iterations < 10  # guard against an infinite loop if draining misbehaves

    # 3. The CT cert was ingested with source=ct and an unknown_issuance
    #    finding was raised for it.
    certs = db.query(Certificate).filter_by(source="ct").all()
    assert len(certs) == 1

    findings = db.query(Finding).filter_by(rule_id="unknown_issuance", status="active").all()
    assert len(findings) == 1

    # Queue item finished processing successfully.
    item = db.query(WorkQueue).filter_by(kind="ct_check").one()
    assert item.status == "done"
