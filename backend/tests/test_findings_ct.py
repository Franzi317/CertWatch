from app import findings
from app.models import Certificate, Endpoint, Finding, Target, utcnow
import datetime


def _ct_cert(db, fp="CT:01"):
    c = Certificate(
        fingerprint_sha256=fp, common_name="shadow.example.com", issuer="CN=Public CA",
        issuer_cn="Public CA", public_key_algorithm="RSA", public_key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
        not_before=utcnow() - datetime.timedelta(days=1),
        not_after=utcnow() + datetime.timedelta(days=80),
        self_signed=False, source="ct",
    )
    db.add(c)
    db.flush()
    return c


def test_ct_only_cert_raises_unknown_issuance(db):
    c = _ct_cert(db)
    findings.evaluate_certificate(db, c, endpoint=None)
    rows = db.query(Finding).filter_by(rule_id="unknown_issuance", status="active").all()
    assert len(rows) == 1
    assert rows[0].certificate_id == c.id
    assert rows[0].endpoint_id is None


def test_network_cert_never_raises_unknown_issuance(db):
    c = _ct_cert(db, fp="NET:01")
    c.source = "network"
    db.flush()
    findings.evaluate_certificate(db, c, endpoint=None)
    assert db.query(Finding).filter_by(rule_id="unknown_issuance").count() == 0


def test_unknown_issuance_clears_when_bound_to_endpoint(db):
    c = _ct_cert(db, fp="CT:02")
    findings.evaluate_certificate(db, c, endpoint=None)
    assert db.query(Finding).filter_by(rule_id="unknown_issuance", status="active").count() == 1
    # cert is now observed on the network: bind it to an endpoint and re-evaluate
    t = Target(name="g", target_type="hostname", value="shadow.example.com",
               ports=[443], environment="prod")
    db.add(t); db.flush()
    ep = Endpoint(target_id=t.id, host="shadow.example.com", ip="10.0.0.9", port=443,
                  current_cert_id=c.id, last_status="ok")
    db.add(ep); db.flush()
    findings.evaluate_certificate(db, c, endpoint=ep)
    active = db.query(Finding).filter_by(rule_id="unknown_issuance", status="active").count()
    cleared = db.query(Finding).filter_by(rule_id="unknown_issuance", status="cleared").count()
    assert active == 0 and cleared == 1
