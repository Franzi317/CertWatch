import datetime

from app import findings
from app.models import Certificate, Endpoint, Finding, Target, utcnow


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


def test_weak_key_deprecated_signature_long_lifetime(db):
    c = _cert(
        db,
        public_key_algorithm="RSA",
        public_key_size=1024,
        signature_algorithm="sha1WithRSAEncryption",
        not_before=utcnow() - datetime.timedelta(days=800),
        not_after=utcnow() + datetime.timedelta(days=60),
    )
    db.commit()

    results = findings.evaluate_certificate(db, c)
    by_rule = {f.rule_id: f for f in results}

    assert "weak_key" in by_rule
    assert by_rule["weak_key"].severity == "warning"
    assert by_rule["weak_key"].dedupe_key == f"weak_key:{c.id}"

    assert "deprecated_signature" in by_rule
    assert by_rule["deprecated_signature"].severity == "warning"
    assert by_rule["deprecated_signature"].dedupe_key == f"deprecated_signature:{c.id}"

    assert "long_lifetime" in by_rule
    assert by_rule["long_lifetime"].severity == "info"
    assert by_rule["long_lifetime"].dedupe_key == f"long_lifetime:{c.id}"


def test_weak_key_ec_undersized(db):
    c = _cert(db, public_key_algorithm="EC", public_key_size=192)
    db.commit()
    results = findings.evaluate_certificate(db, c)
    by_rule = {f.rule_id: f for f in results}
    assert "weak_key" in by_rule


def test_weak_key_none_size_guarded(db):
    c = _cert(db, public_key_algorithm="RSA", public_key_size=None)
    db.commit()
    results = findings.evaluate_certificate(db, c)
    assert all(f.rule_id != "weak_key" for f in results)


def test_self_signed_prod_flags_on_prod_endpoint(db):
    c = _cert(db, self_signed=True)
    t = _target(db, environment="prod")
    ep = _endpoint(db, t, c)
    db.commit()

    results = findings.evaluate_certificate(db, c, endpoint=ep)
    by_rule = {f.rule_id: f for f in results}
    assert "self_signed_prod" in by_rule
    assert by_rule["self_signed_prod"].severity == "critical"
    assert by_rule["self_signed_prod"].dedupe_key == f"self_signed_prod:{c.id}:{ep.id}"


def test_self_signed_prod_does_not_flag_on_dev_endpoint(db):
    c = _cert(db, self_signed=True)
    t = _target(db, environment="dev")
    ep = _endpoint(db, t, c)
    db.commit()

    results = findings.evaluate_certificate(db, c, endpoint=ep)
    assert all(f.rule_id != "self_signed_prod" for f in results)


def test_untrusted_issuer_prod(db):
    c = _cert(db, self_signed=False, issuer="CN=Random Public CA")
    t = _target(db, environment="prod")
    ep = _endpoint(db, t, c)
    db.commit()

    results = findings.evaluate_certificate(db, c, endpoint=ep)
    by_rule = {f.rule_id: f for f in results}
    assert "untrusted_issuer_prod" in by_rule
    assert by_rule["untrusted_issuer_prod"].severity == "warning"


def test_expiring_and_expired(db):
    c_expiring = _cert(db, fp="EXPIRING", not_after=utcnow() + datetime.timedelta(days=10))
    c_expired = _cert(db, fp="EXPIRED", not_after=utcnow() - datetime.timedelta(days=3))
    db.commit()

    r1 = {f.rule_id for f in findings.evaluate_certificate(db, c_expiring)}
    assert "expiring" in r1

    r2 = {f.rule_id for f in findings.evaluate_certificate(db, c_expired)}
    assert "expired" in r2


def test_reevaluation_does_not_duplicate_and_updates_last_seen(db):
    c = _cert(db, public_key_algorithm="RSA", public_key_size=1024,
               signature_algorithm="sha1WithRSAEncryption")
    db.commit()

    findings.evaluate_certificate(db, c)
    first = db.query(Finding).filter_by(rule_id="weak_key", certificate_id=c.id).one()
    first_last_seen = first.last_seen

    findings.evaluate_certificate(db, c)
    rows = db.query(Finding).filter_by(rule_id="weak_key", certificate_id=c.id).all()
    assert len(rows) == 1
    assert rows[0].id == first.id
    assert rows[0].last_seen >= first_last_seen
    assert rows[0].status == "active"


def test_condition_cleared_when_no_longer_present(db):
    c = _cert(db, public_key_algorithm="RSA", public_key_size=1024)
    db.commit()

    findings.evaluate_certificate(db, c)
    weak = db.query(Finding).filter_by(rule_id="weak_key", certificate_id=c.id).one()
    assert weak.status == "active"

    c.public_key_size = 2048
    db.commit()

    findings.evaluate_certificate(db, c)
    weak_after = db.query(Finding).filter_by(rule_id="weak_key", certificate_id=c.id).one()
    assert weak_after.status == "cleared"
    # history preserved, not deleted
    assert db.query(Finding).filter_by(rule_id="weak_key", certificate_id=c.id).count() == 1


def test_disposition_preserved_across_reevaluation(db):
    c = _cert(db, public_key_algorithm="RSA", public_key_size=1024)
    db.commit()

    findings.evaluate_certificate(db, c)
    weak = db.query(Finding).filter_by(rule_id="weak_key", certificate_id=c.id).one()
    weak.disposition = "accepted"
    db.commit()

    findings.evaluate_certificate(db, c)
    weak_after = db.query(Finding).filter_by(rule_id="weak_key", certificate_id=c.id).one()
    assert weak_after.disposition == "accepted"
    assert weak_after.status == "active"


def test_evaluate_all_counts_active_findings(db):
    c = _cert(db, public_key_algorithm="RSA", public_key_size=1024)
    t = _target(db, environment="prod")
    _endpoint(db, t, c)
    db.commit()

    count = findings.evaluate_all(db)
    assert count >= 1
    assert count == db.query(Finding).filter_by(status="active").count()
