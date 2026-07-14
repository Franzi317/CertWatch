import socket
import threading

import pytest

from app import starttls
from app.starttls import StartTlsError


def test_protocol_for_port_mapping():
    assert starttls.protocol_for_port(25) == "smtp"
    assert starttls.protocol_for_port(587) == "smtp"
    assert starttls.protocol_for_port(143) == "imap"
    assert starttls.protocol_for_port(110) == "pop3"
    assert starttls.protocol_for_port(389) == "ldap"
    # implicit-TLS and unknown ports never trigger STARTTLS
    for p in (443, 465, 636, 993, 995, 8443, 9443, 3389, 5986, 8080, 22):
        assert starttls.protocol_for_port(p) is None


def _run_peer(script):
    """Start a one-shot localhost TCP server that runs `script(conn)` on the
    accepted connection in a thread. Returns (port, thread). The client side
    is driven by starttls.negotiate in the test."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        try:
            conn, _ = srv.accept()
            with conn:
                script(conn)
        except OSError:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, t


def _readline(conn):
    buf = bytearray()
    while not buf.endswith(b"\n"):
        b = conn.recv(1)
        if not b:
            break
        buf += b
    return bytes(buf)


def _client(port):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    return c


def test_smtp_success_multiline_ehlo():
    sent = {}

    def script(conn):
        conn.sendall(b"220 fake ESMTP ready\r\n")
        sent["ehlo"] = _readline(conn)
        conn.sendall(b"250-fake greets you\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
        sent["starttls"] = _readline(conn)
        conn.sendall(b"220 go ahead\r\n")

    port, t = _run_peer(script)
    c = _client(port)
    starttls.negotiate(c, "smtp", "mail.example.com", 5.0)  # must not raise
    c.close(); t.join(timeout=5)
    assert sent["ehlo"] == b"EHLO mail.example.com\r\n"
    assert sent["starttls"] == b"STARTTLS\r\n"


def test_smtp_ehlo_strips_crlf_injection():
    sent = {}

    def script(conn):
        conn.sendall(b"220 fake ESMTP ready\r\n")
        sent["ehlo"] = _readline(conn)
        conn.sendall(b"250 STARTTLS\r\n")
        _readline(conn)
        conn.sendall(b"220 go ahead\r\n")

    port, t = _run_peer(script)
    c = _client(port)
    starttls.negotiate(c, "smtp", "evil\r\nMAIL FROM:<x>", 5.0)  # must not raise
    c.close(); t.join(timeout=5)
    # CR/LF stripped, so the name collapses to a single EHLO line; no injected command
    assert sent["ehlo"] == b"EHLO evilMAIL FROM:<x>\r\n"
    assert b"\r\nMAIL FROM" not in sent["ehlo"]


def test_smtp_empty_host_uses_placeholder():
    sent = {}

    def script(conn):
        conn.sendall(b"220 fake\r\n")
        sent["ehlo"] = _readline(conn)
        conn.sendall(b"250 STARTTLS\r\n")
        _readline(conn)
        conn.sendall(b"220 ok\r\n")

    port, t = _run_peer(script)
    c = _client(port)
    starttls.negotiate(c, "smtp", "", 5.0)
    c.close(); t.join(timeout=5)
    assert sent["ehlo"] == b"EHLO certwatch\r\n"


def test_smtp_refused_raises():
    def script(conn):
        conn.sendall(b"220 fake\r\n")
        _readline(conn)
        conn.sendall(b"250 STARTTLS\r\n")
        _readline(conn)
        conn.sendall(b"502 command not implemented\r\n")

    port, t = _run_peer(script)
    c = _client(port)
    with pytest.raises(StartTlsError):
        starttls.negotiate(c, "smtp", "h", 5.0)
    c.close(); t.join(timeout=5)


def test_imap_success_and_refusal():
    def ok(conn):
        conn.sendall(b"* OK fake IMAP ready\r\n")
        _readline(conn)
        conn.sendall(b"a001 OK begin TLS\r\n")

    port, t = _run_peer(ok)
    c = _client(port)
    starttls.negotiate(c, "imap", "h", 5.0)
    c.close(); t.join(timeout=5)

    def no(conn):
        conn.sendall(b"* OK fake\r\n")
        _readline(conn)
        conn.sendall(b"a001 NO starttls disabled\r\n")

    port, t = _run_peer(no)
    c = _client(port)
    with pytest.raises(StartTlsError):
        starttls.negotiate(c, "imap", "h", 5.0)
    c.close(); t.join(timeout=5)


def test_pop3_success_and_refusal():
    def ok(conn):
        conn.sendall(b"+OK fake POP3 ready\r\n")
        _readline(conn)
        conn.sendall(b"+OK begin TLS\r\n")

    port, t = _run_peer(ok)
    c = _client(port)
    starttls.negotiate(c, "pop3", "h", 5.0)
    c.close(); t.join(timeout=5)

    def no(conn):
        conn.sendall(b"+OK fake\r\n")
        _readline(conn)
        conn.sendall(b"-ERR no stls\r\n")

    port, t = _run_peer(no)
    c = _client(port)
    with pytest.raises(StartTlsError):
        starttls.negotiate(c, "pop3", "h", 5.0)
    c.close(); t.join(timeout=5)


def test_ldap_sends_fixed_request_and_returns():
    got = {}

    def script(conn):
        got["req"] = conn.recv(64)
        conn.sendall(bytes([0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07,
                            0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]))  # extendedResp resultCode=success

    port, t = _run_peer(script)
    c = _client(port)
    starttls.negotiate(c, "ldap", "h", 5.0)  # must not raise; response is best-effort
    c.close(); t.join(timeout=5)
    assert got["req"] == starttls._LDAP_STARTTLS_REQUEST


def test_connection_closed_during_greeting_raises():
    def script(conn):
        conn.close()  # slam the connection with no greeting

    port, t = _run_peer(script)
    c = _client(port)
    with pytest.raises(StartTlsError):
        starttls.negotiate(c, "smtp", "h", 5.0)
    c.close(); t.join(timeout=5)


def test_unknown_protocol_raises():
    a, b = socket.socketpair()
    with pytest.raises(StartTlsError):
        starttls.negotiate(a, "ftp", "h", 5.0)
    a.close(); b.close()
