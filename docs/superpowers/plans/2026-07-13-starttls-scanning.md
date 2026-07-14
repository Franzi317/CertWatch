# STARTTLS Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture TLS certificates from STARTTLS services (SMTP 25/587, IMAP 143, POP3 110, LDAP 389) that currently misreport as `non_tls_service`, by doing the plaintext protocol dance before the TLS handshake — triggered purely by port number, no config.

**Architecture:** A new `backend/app/starttls.py` module maps well-known ports to a protocol and performs the plaintext negotiation on a raw socket. `scanner.scan_endpoint` calls it after `create_connection` and before `wrap_socket` when the port is a STARTTLS port; a negotiation failure yields a new `starttls_failed` status. Inference is internal to `scan_endpoint`, so scheduled scans and the renewal-verify path get STARTTLS with no call-site changes.

**Tech Stack:** Python 3.13 stdlib `socket`/`ssl` (no new dependencies), `cryptography` (already present, used in tests to stand up a fake TLS server), pytest.

## Global Constraints

- No new production dependencies — stdlib `socket`/`ssl` only.
- Port inference only: `PORT_PROTOCOLS = {25: "smtp", 587: "smtp", 143: "imap", 110: "pop3", 389: "ldap"}`. No per-port config, no explicit override, no auto-fallback probe. Implicit-TLS ports (443, 465, 636, 993, 995, 8443, 9443, 3389, 5986, custom) are untouched.
- New scan status is exactly `starttls_failed` (distinct from `tls_handshake_failed` and `non_tls_service`).
- `scan_endpoint`'s signature does NOT change; inference is internal.
- Fail-closed: any error during negotiation becomes `StartTlsError` → `starttls_failed`; the scanner never crashes.
- Deliberate `ponytail:` ceilings (preserve verbatim in comments): LDAP StartTLS sends the fixed extended-request BER and relies on the subsequent TLS handshake to confirm (no BER response parsing); status-code-level parsing, not full protocol clients; port inference only.
- Test command (Windows, from `backend/`): `./.venv/Scripts/python.exe -m pytest`. Baseline: 281 passing.

---

### Task 1: `starttls.py` module + unit tests

**Files:**
- Create: `backend/app/starttls.py`
- Test: `backend/tests/test_starttls.py`

**Interfaces:**
- Produces:
  - `starttls.PORT_PROTOCOLS: dict[int, str]`
  - `starttls.protocol_for_port(port: int) -> str | None`
  - `starttls.StartTlsError(Exception)`
  - `starttls.negotiate(sock: socket.socket, protocol: str, host: str, timeout: float) -> None` — runs the plaintext dance on an already-connected raw socket, leaving it ready for `wrap_socket`; raises `StartTlsError` on any failure.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_starttls.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_starttls.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.starttls'`.

- [ ] **Step 3: Implement the module**

Create `backend/app/starttls.py`:

```python
"""Plaintext STARTTLS negotiation for the scanner (Phase 2.5.2).

For ports that negotiate TLS *after* a plaintext protocol greeting (SMTP
submission/relay, IMAP, POP3, LDAP), the scanner must speak the protocol far
enough to issue the STARTTLS command, then hand the now-ready raw socket to
ssl.wrap_socket. Which protocol a port speaks is inferred purely from the port
number -- no per-target config.

ponytail: port inference only (no custom-port override); status-code-level
parsing, not full protocol clients; LDAP sends the fixed StartTLS extended
request and lets the subsequent TLS handshake confirm success (no BER response
parsing).
"""
from __future__ import annotations

import socket

PORT_PROTOCOLS: dict[int, str] = {25: "smtp", 587: "smtp", 143: "imap", 110: "pop3", 389: "ldap"}

# LDAP StartTLS extended request: LDAPMessage(messageID=1,
# ExtendedRequest(requestName="1.3.6.1.4.1.1466.20037")), BER-encoded.
_LDAP_STARTTLS_REQUEST = bytes([
    0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16,
    0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e,
    0x31, 0x2e, 0x31, 0x34, 0x36, 0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,
])


class StartTlsError(Exception):
    """The peer did not offer/permit STARTTLS, or the negotiation failed."""


def protocol_for_port(port: int) -> str | None:
    return PORT_PROTOCOLS.get(port)


def negotiate(sock: socket.socket, protocol: str, host: str, timeout: float) -> None:
    """Run the plaintext STARTTLS dance on an already-connected raw socket,
    leaving it ready for ssl.wrap_socket. Raises StartTlsError on any failure."""
    sock.settimeout(timeout)
    try:
        if protocol == "smtp":
            _smtp(sock, host or "certwatch")
        elif protocol == "imap":
            _imap(sock)
        elif protocol == "pop3":
            _pop3(sock)
        elif protocol == "ldap":
            _ldap(sock)
        else:
            raise StartTlsError(f"unknown starttls protocol: {protocol}")
    except StartTlsError:
        raise
    except (OSError, socket.timeout) as e:  # socket.timeout is an OSError subclass on 3.10+
        raise StartTlsError(f"{protocol} STARTTLS negotiation failed: {e}") from e


def _readline(sock: socket.socket) -> bytes:
    """Read one CRLF-terminated line one byte at a time. Byte-at-a-time avoids
    any read-ahead consuming bytes past the STARTTLS-OK line (the following TLS
    ClientHello is sent by us, not the server, so nothing legitimately follows)."""
    buf = bytearray()
    while not buf.endswith(b"\n"):
        b = sock.recv(1)
        if not b:
            raise StartTlsError("connection closed during STARTTLS negotiation")
        buf += b
        if len(buf) > 8192:
            raise StartTlsError("STARTTLS line too long")
    return bytes(buf)


def _smtp(sock: socket.socket, name: str) -> None:
    line = _readline(sock)
    if not line.startswith(b"220"):
        raise StartTlsError(f"unexpected SMTP greeting: {line!r}")
    sock.sendall(b"EHLO " + name.encode("ascii", "ignore") + b"\r\n")
    while True:  # 250-... lines continue; a "250 " line terminates the response
        line = _readline(sock)
        if not line.startswith(b"250"):
            raise StartTlsError(f"unexpected EHLO response: {line!r}")
        if line[3:4] == b" ":
            break
    sock.sendall(b"STARTTLS\r\n")
    line = _readline(sock)
    if not line.startswith(b"220"):
        raise StartTlsError(f"server refused STARTTLS: {line!r}")


def _imap(sock: socket.socket) -> None:
    line = _readline(sock)
    if not line.startswith(b"* OK"):
        raise StartTlsError(f"unexpected IMAP greeting: {line!r}")
    sock.sendall(b"a001 STARTTLS\r\n")
    line = _readline(sock)
    if not line.startswith(b"a001 OK"):
        raise StartTlsError(f"server refused IMAP STARTTLS: {line!r}")


def _pop3(sock: socket.socket) -> None:
    line = _readline(sock)
    if not line.startswith(b"+OK"):
        raise StartTlsError(f"unexpected POP3 greeting: {line!r}")
    sock.sendall(b"STLS\r\n")
    line = _readline(sock)
    if not line.startswith(b"+OK"):
        raise StartTlsError(f"server refused POP3 STLS: {line!r}")


def _ldap(sock: socket.socket) -> None:
    sock.sendall(_LDAP_STARTTLS_REQUEST)
    # Best-effort read of the extended response; a refusal surfaces as the TLS
    # handshake failing after we return. ponytail: no BER response parsing.
    try:
        sock.recv(1024)
    except (OSError, socket.timeout):
        pass
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_starttls.py -v`
Expected: PASS (all cases).

- [ ] **Step 5: Commit**

```bash
git add backend/app/starttls.py backend/tests/test_starttls.py
git commit -m "feat: starttls negotiation module (smtp/imap/pop3/ldap, port-inferred)"
```

---

### Task 2: Wire STARTTLS into `scan_endpoint` + integration tests

**Files:**
- Modify: `backend/app/scanner.py` (import `starttls`; call `negotiate` before `wrap_socket`; add `starttls_failed`; update the taxonomy docstring)
- Test: `backend/tests/test_scanner_starttls.py`

**Interfaces:**
- Consumes: `starttls.protocol_for_port`, `starttls.negotiate`, `starttls.StartTlsError`, `starttls.PORT_PROTOCOLS` (Task 1).
- Produces: `scan_endpoint` returns `status="starttls_failed"` when negotiation fails; returns `status="ok"` with a captured cert when negotiation succeeds and TLS completes. Signature unchanged: `scan_endpoint(ip, port, sni="", timeout=5.0)`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_scanner_starttls.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_scanner_starttls.py -v`
Expected: FAIL — `scan_endpoint` doesn't negotiate STARTTLS yet, so `test_scan_endpoint_captures_cert_via_starttls` gets `non_tls_service`/`tls_handshake_failed` (not `ok`), and the refused test won't return `starttls_failed`.

- [ ] **Step 3: Wire it into the scanner**

In `backend/app/scanner.py`:

(a) Add the import near the other imports (after line 23):

```python
from . import starttls
```

(b) Update the taxonomy docstring (lines 8-10) to include the new status:

```python
Error codes are a stable taxonomy consumed by the UI:
  ok, connection_failed, timeout, tls_handshake_failed, non_tls_service,
  no_certificate, dns_resolution_failed, starttls_failed.
```

(c) In `scan_endpoint`, insert the negotiation between `raw.settimeout(timeout)` (line 146) and the `try:` that wraps the socket (line 147):

```python
    raw.settimeout(timeout)

    proto = starttls.protocol_for_port(port)
    if proto:
        try:
            starttls.negotiate(raw, proto, sni, timeout)  # defaults EHLO name when sni is ""
        except starttls.StartTlsError as e:
            raw.close()
            return ScanResult(status="starttls_failed", error=str(e), sni_used=sni)

    try:
        server_hostname = sni or None
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
```

(Everything from the `try:`/`wrap_socket` onward is unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_scanner_starttls.py tests/test_scanner.py -v`
Expected: PASS (new STARTTLS integration tests + existing scanner tests unaffected).

- [ ] **Step 5: Commit**

```bash
git add backend/app/scanner.py backend/tests/test_scanner_starttls.py
git commit -m "feat: scan_endpoint negotiates STARTTLS on inferred ports; starttls_failed status"
```

---

### Task 3: Docs + frontend status check + full-suite verification

**Files:**
- Modify: `README.md` (troubleshooting-table row + a one-line note that STARTTLS ports are captured automatically)
- Verify: `frontend/src/` renders the new `starttls_failed` status without a code change (or add a label if there's a status map)

- [ ] **Step 1: Add the README troubleshooting row**

In `README.md`, in the "Troubleshooting scanner errors" table, add a row (keep the existing column format):

```
| `starttls_failed` | Port speaks its plaintext protocol (SMTP/IMAP/POP3/LDAP) but STARTTLS was not offered or was refused. The service may have STARTTLS disabled, or requires it be enabled server-side. |
```

And in the scanning/inventory prose where TLS ports are described, add one line:

> Ports that use STARTTLS — SMTP (25, 587), IMAP (143), POP3 (110), and LDAP (389) — are detected automatically by port number; CertWatch performs the plaintext STARTTLS handshake before capturing the certificate. No configuration is needed.

- [ ] **Step 2: Check the frontend renders the new status**

Run: `grep -rn "non_tls_service\|tls_handshake_failed\|scan.*status\|last_status" frontend/src` to find whether statuses are rendered from a fixed map or passed through as free text.

- If statuses pass through as free text (most likely — the backend taxonomy is open): no change needed; note this in the report. The status will render as-is under the `Unknown` severity like other failure statuses.
- If there is an explicit status→label/severity map that would drop an unknown status, add a `starttls_failed` entry mapping to the `Unknown` severity with a human label like "STARTTLS failed", mirroring the neighboring entries. Then run `cd frontend && npm run build` and confirm it passes.

- [ ] **Step 3: Run the full backend suite**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest -q`
Expected: PASS — 281 baseline + the new starttls/scanner tests, all green. Investigate any failure before committing.

- [ ] **Step 4: Commit**

```bash
git add README.md frontend/src
git commit -m "docs: document STARTTLS scanning + starttls_failed status"
```

---

## Self-Review Notes

- **Spec coverage:** module + `protocol_for_port` + `negotiate` for all four protocols (T1); scanner wiring + `starttls_failed` + no-signature-change inference (T2); e2e capture-through-STARTTLS + refused → `starttls_failed` + implicit-port-skips-negotiation tests (T2); taxonomy docstring + README + frontend status check (T2/T3). All spec sections mapped.
- **Ceilings preserved in comments:** LDAP send-then-wrap/no-BER-parse, status-code parsing, port-inference-only (T1 module docstring + `_ldap`).
- **Type consistency:** `negotiate(sock, protocol, host, timeout)` and `protocol_for_port(port)` used identically in T1 and T2; `starttls_failed` string identical across scanner, tests, README; `PORT_PROTOCOLS` mutated via `monkeypatch.setitem` in T2 tests to exercise real inference on an ephemeral port.
- **Testability note:** the e2e test cannot bind port 587 reliably, so it binds an ephemeral port and registers it in `PORT_PROTOCOLS` for the test — this exercises the real `scan_endpoint` inference path rather than bypassing it. The implicit-skip test deliberately does NOT register its port, proving non-STARTTLS ports skip negotiation.
- **Open confirmation for the implementer (not a blocker):** exact frontend status-rendering mechanism (T3 Step 2 resolves by inspection).
