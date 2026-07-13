import datetime

from app import worker, ct_source
from app.models import Certificate, Endpoint, Finding, Target, WatchedDomain, WorkQueue, utcnow
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _der(cn="shadow.example.com"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def _watched(db, domain="example.com", last_id=None):
    w = WatchedDomain(domain=domain, enabled=True, last_crtsh_id=last_id)
    db.add(w); db.commit()
    return w


def _enqueue_ct(db, domain_id):
    item = WorkQueue(kind="ct_check", payload={"domain_id": domain_id})
    db.add(item); db.commit()
    return worker.queue.claim(db)


def test_ct_check_ingests_unknown_cert_and_raises_finding(db, monkeypatch):
    w = _watched(db)
    der = _der()
    monkeypatch.setattr(ct_source, "list_entries", lambda base, dom, **k: [{"id": 100}])
    monkeypatch.setattr(ct_source, "fetch_der", lambda base, cid, **k: der)
    monkeypatch.setattr(worker.settings, "ct_source_url", "https://crt.sh", raising=False)

    item = _enqueue_ct(db, w.id)
    worker._process_ct_check(db, item)

    certs = db.query(Certificate).filter_by(source="ct").all()
    assert len(certs) == 1
    assert db.query(Finding).filter_by(rule_id="unknown_issuance", status="active").count() == 1
    db.refresh(w)
    assert w.last_crtsh_id == 100
    assert w.last_checked_at is not None
    assert db.get(WorkQueue, item.id).status == "done"


def test_ct_check_skips_entries_at_or_below_watermark(db, monkeypatch):
    w = _watched(db, last_id=100)
    monkeypatch.setattr(ct_source, "list_entries", lambda base, dom, **k: [{"id": 100}, {"id": 50}])
    calls = []
    monkeypatch.setattr(ct_source, "fetch_der", lambda base, cid, **k: calls.append(cid) or _der())
    item = _enqueue_ct(db, w.id)
    worker._process_ct_check(db, item)
    assert calls == []  # nothing above watermark -> no fetches
    assert db.query(Certificate).count() == 0


def test_ct_check_known_fingerprint_no_finding(db, monkeypatch):
    # a cert already in inventory (network) that also shows up in CT must NOT
    # create a finding
    der = _der("known.example.com")
    from app.scanner import parse_certificate
    fields = parse_certificate(der)
    existing = Certificate(**fields, source="network")
    db.add(existing); db.commit()
    w = _watched(db)
    monkeypatch.setattr(ct_source, "list_entries", lambda base, dom, **k: [{"id": 200}])
    monkeypatch.setattr(ct_source, "fetch_der", lambda base, cid, **k: der)
    item = _enqueue_ct(db, w.id)
    worker._process_ct_check(db, item)
    assert db.query(Finding).filter_by(rule_id="unknown_issuance").count() == 0
    assert db.query(Certificate).count() == 1  # deduped by fingerprint


def test_ct_check_fetch_error_fails_item(db, monkeypatch):
    w = _watched(db)
    monkeypatch.setattr(ct_source, "list_entries", lambda base, dom, **k: [{"id": 300}])
    def boom(base, cid, **k):
        raise RuntimeError("crt.sh unreachable")
    monkeypatch.setattr(ct_source, "fetch_der", boom)
    item = _enqueue_ct(db, w.id)
    worker._process_ct_check(db, item)
    q = db.get(WorkQueue, item.id)
    assert q.status in ("queued", "failed")  # queue.fail requeues until max_attempts
    assert "crt.sh unreachable" in (q.last_error or "")
