import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import itertools

from app import alerts
from app.models import AlertEvent, Certificate, Endpoint, Target, utcnow
from app.scanner import parse_certificate

_ip_seq = itertools.count(1)


def _target(db, name="grp"):
    t = Target(name=name, target_type="hostname", value="host.example.com",
               ports=[443], environment="prod")
    db.add(t)
    db.flush()
    return t


def _endpoint(db, target, cert, host, ip, port=443):
    ep = Endpoint(target_id=target.id, host=host, ip=ip, port=port,
                  current_cert_id=cert.id, last_status="ok")
    db.add(ep)
    db.flush()
    return ep


def _ca(db, days, fp_leaves=0, cn="Intermediate CA"):
    key, ikey = rsa.generate_private_key(public_exponent=65537, key_size=2048), rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .sign(ikey, hashes.SHA256()))
    fields = parse_certificate(c.public_bytes(serialization.Encoding.DER))
    ca = Certificate(**fields, source="chain")
    db.add(ca); db.flush()
    # attach `fp_leaves` leaves that depend on this CA, bound to endpoints so
    # they count as LIVE dependents (dependent_counts is live-scoped)
    t = _target(db, name=f"grp-{cn}-{next(_ip_seq)}")
    for i in range(fp_leaves):
        leaf = Certificate(fingerprint_sha256=f"LEAF:{cn}:{i}", common_name=f"l{i}",
                           source="network", chain_ca_fingerprints=[ca.fingerprint_sha256])
        db.add(leaf); db.flush()
        n = next(_ip_seq)
        _endpoint(db, t, leaf, host=f"l{i}.{cn}.example.com", ip=f"10.{n // 250}.{n % 250}.1")
    db.commit()
    return ca


def test_issuer_expiring_fires_within_threshold_with_dependents(db):
    ca = _ca(db, days=20, fp_leaves=3)   # 20d out, under 30d band
    alerts.evaluate_alerts(db, dispatch=False)
    ev = db.query(AlertEvent).filter_by(rule_type="issuer_expiring").all()
    assert len(ev) == 1
    assert ev[0].certificate_id == ca.id
    assert "3 dependent" in ev[0].message


def test_issuer_expiring_ignored_without_dependents(db):
    _ca(db, days=20, fp_leaves=0)  # expiring but nothing depends on it
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(AlertEvent).filter_by(rule_type="issuer_expiring").count() == 0


def test_issuer_expiring_ignored_when_far_out(db):
    _ca(db, days=800, fp_leaves=2)  # beyond 180d
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(AlertEvent).filter_by(rule_type="issuer_expiring").count() == 0


def test_issuer_expiring_auto_resolves_when_dependents_drop(db):
    ca = _ca(db, days=20, fp_leaves=1)
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(AlertEvent).filter_by(rule_type="issuer_expiring", resolved=False).count() == 1
    # realistic renewal simulation: the leaf is NOT deleted (certs are never
    # pruned) -- instead the endpoint(s) serving it repoint/clear their
    # current_cert_id, so the old leaf is no longer live. Re-evaluate -> alert
    # auto-resolves because dependent_counts is live-scoped.
    db.query(Endpoint).update({Endpoint.current_cert_id: None})
    db.commit()
    alerts.evaluate_alerts(db, dispatch=False)
    assert db.query(AlertEvent).filter_by(rule_type="issuer_expiring", resolved=False).count() == 0
