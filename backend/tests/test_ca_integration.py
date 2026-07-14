import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import findings
from app.models import Certificate, Finding
from app.scanner import parse_certificate


def _chain_cert(db, source="chain", long_lifetime_days=3650):
    key, ikey = rsa.generate_private_key(public_exponent=65537, key_size=2048), rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=long_lifetime_days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .sign(ikey, hashes.SHA256()))
    fields = parse_certificate(c.public_bytes(serialization.Encoding.DER))
    row = Certificate(**fields, source=source)
    db.add(row); db.commit()
    return row


def test_findings_skips_chain_source(db):
    # a chain CA cert with a 10-year lifetime would trip long_lifetime if evaluated
    ca = _chain_cert(db, source="chain")
    findings.evaluate_all(db)
    assert db.query(Finding).filter_by(certificate_id=ca.id).count() == 0


def test_findings_still_runs_on_network_cert(db):
    # sanity: a non-chain cert with a long lifetime DOES get evaluated (control)
    net = _chain_cert(db, source="network")
    findings.evaluate_all(db)
    assert db.query(Finding).filter_by(certificate_id=net.id, rule_id="long_lifetime").count() == 1
