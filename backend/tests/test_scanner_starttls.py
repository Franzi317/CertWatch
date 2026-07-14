import datetime
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import scanner, starttls


def _write_selfsigned(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    certfile = tmp_path / "c.pem"
    keyfile = tmp_path / "k.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    fp = cert.fingerprint(hashes.SHA256()).hex()
    fp_coloned = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)).upper()
    return str(certfile), str(keyfile), fp_coloned


def _readline(conn):
    buf = bytearray()
    while not buf.endswith(b"\n"):
        b = conn.recv(1)
        if not b:
            break
        buf += b
    return bytes(buf)


def _smtp_server(certfile, keyfile, refuse=False):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        try:
            conn, _ = srv.accept()
            conn.sendall(b"220 fake ESMTP\r\n")
            _readline(conn)  # EHLO
            conn.sendall(b"250-fake\r\n250 STARTTLS\r\n")
            _readline(conn)  # STARTTLS
            if refuse:
                conn.sendall(b"502 not supported\r\n")
                conn.close()
                return
            conn.sendall(b"220 go ahead\r\n")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                tls.recv(16)  # drive the handshake; client sends nothing then closes
                tls.close()
            except OSError:
                pass
        except OSError:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, t


def _plain_tls_server(certfile, keyfile):
    """Implicit-TLS server: wraps immediately, no plaintext greeting."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        try:
            conn, _ = srv.accept()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                tls.recv(16)
                tls.close()
            except OSError:
                pass
        except OSError:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, t


def test_scan_endpoint_captures_cert_via_starttls(tmp_path, monkeypatch):
    certfile, keyfile, fp = _write_selfsigned(tmp_path)
    port, t = _smtp_server(certfile, keyfile)
    # port inference is by number; register the ephemeral test port as smtp
    monkeypatch.setitem(starttls.PORT_PROTOCOLS, port, "smtp")
    result = scanner.scan_endpoint("127.0.0.1", port, sni="mail.test", timeout=5.0)
    t.join(timeout=5)
    assert result.status == "ok", result.error
    assert result.cert is not None
    assert result.cert["fingerprint_sha256"] == fp


def test_scan_endpoint_starttls_refused(tmp_path, monkeypatch):
    certfile, keyfile, _ = _write_selfsigned(tmp_path)
    port, t = _smtp_server(certfile, keyfile, refuse=True)
    monkeypatch.setitem(starttls.PORT_PROTOCOLS, port, "smtp")
    result = scanner.scan_endpoint("127.0.0.1", port, sni="mail.test", timeout=5.0)
    t.join(timeout=5)
    assert result.status == "starttls_failed", result.status


def test_scan_endpoint_implicit_port_skips_negotiation(tmp_path, monkeypatch):
    certfile, keyfile, fp = _write_selfsigned(tmp_path)
    port, t = _plain_tls_server(certfile, keyfile)  # NOT registered in PORT_PROTOCOLS
    called = {"negotiate": False}
    real = starttls.negotiate

    def spy(*a, **k):
        called["negotiate"] = True
        return real(*a, **k)

    monkeypatch.setattr(scanner.starttls, "negotiate", spy)
    result = scanner.scan_endpoint("127.0.0.1", port, sni="mail.test", timeout=5.0)
    t.join(timeout=5)
    assert result.status == "ok", result.error
    assert result.cert["fingerprint_sha256"] == fp
    assert called["negotiate"] is False  # ephemeral port not in PORT_PROTOCOLS -> no negotiation
