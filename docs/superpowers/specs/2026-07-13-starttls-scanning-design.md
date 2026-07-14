# STARTTLS Scanning — Design

**Phase:** 2.5, item 2.5.2 (see `docs/superpowers/plans/2026-07-03-certwatch-competitive-roadmap.md`).
**Date:** 2026-07-13
**Status:** Approved, ready for implementation planning.

## Goal

Teach the scanner STARTTLS so ports that negotiate TLS *after* a plaintext
protocol greeting — SMTP submission/relay, IMAP, POP3, LDAP — capture their
certificates instead of misreporting as `non_tls_service`. Mail and directory
infrastructure is exactly where forgotten/expiring certs hide, and the target
UI already advertises port 587 as a one-click option while the scanner can only
do implicit TLS.

## Current behavior

`scanner.scan_endpoint(ip, port, sni, timeout)` (`backend/app/scanner.py:127`)
opens a socket and immediately `ctx.wrap_socket(...)` — implicit TLS only. On a
STARTTLS port the server answers with a plaintext greeting, the TLS handshake
sees non-TLS bytes, and the result is `non_tls_service`. So ports 25/587/143/
110/389 never yield a certificate today.

## Scope

**In:** port-number-inferred STARTTLS for SMTP (25, 587), IMAP (143), POP3 (110),
LDAP (389); a new `starttls_failed` scan status; the plaintext negotiation
isolated in a new module; tests.

**Out (deliberate ceilings):**
- Port inference only — no per-port STARTTLS config, no explicit override, no
  auto-fallback probe (the approved trigger is zero-config port inference).
- LDAP StartTLS sends the fixed extended-request BER and relies on the
  subsequent TLS handshake to confirm; no BER response parsing.
- Status-code-level protocol parsing, not full SMTP/IMAP/POP3 clients.

## Trigger: port-number inference (decided)

The scanner maps well-known ports to a STARTTLS protocol itself. Zero config —
no `Target`/schema/UI change. Implicit-TLS ports (443, 465, 636, 993, 995, 8443,
9443, 3389, 5986, and any custom port) are untouched and continue straight to
`wrap_socket`.

| Port(s) | Protocol |
|---|---|
| 25, 587 | smtp |
| 143 | imap |
| 110 | pop3 |
| 389 | ldap |

Port 25 (MTA-to-MTA SMTP) is kept in the set despite frequently being
egress-blocked from server networks — when reachable it serves STARTTLS certs,
and an unreachable 25 simply times out like any other closed port.

## Component 1 — new module `backend/app/starttls.py`

Keeps protocol chatter out of the focused `scanner.py` and is independently
unit-testable.

```python
PORT_PROTOCOLS = {25: "smtp", 587: "smtp", 143: "imap", 110: "pop3", 389: "ldap"}

def protocol_for_port(port: int) -> str | None: ...

class StartTlsError(Exception): ...

def negotiate(sock, protocol: str, host: str, timeout: float) -> None:
    """Run the plaintext STARTTLS dance on an already-connected raw socket,
    leaving it ready for ssl wrap_socket. Raises StartTlsError if the server
    does not offer/permit STARTTLS."""
```

Per-protocol dance (`negotiate` dispatches on `protocol`):

- **smtp** — read `220` greeting; send `EHLO <name>\r\n`; read the `250`
  response (handle multiline continuation: lines `250-...` continue, `250 ...`
  terminates); send `STARTTLS\r\n`; require a `220` reply. `<name>` is the
  `host` argument, or the fixed placeholder `certwatch` when `host` is empty
  (i.e. `host or "certwatch"`, resolved inside `negotiate`).
- **imap** — read `* OK` greeting; send `a001 STARTTLS\r\n`; require a tagged
  `a001 OK` reply.
- **pop3** — read `+OK` greeting; send `STLS\r\n`; require a `+OK` reply.
- **ldap** — send the fixed StartTLS extended-request BER
  (messageID 1, requestName OID `1.3.6.1.4.1.1466.20037`); best-effort read of
  the response; return (proceed to wrap). A server that refuses StartTLS makes
  the subsequent TLS handshake fail, surfacing as `starttls_failed`.

All reads honor `timeout`. Any unexpected/negative reply, missing greeting, or
socket error during the dance raises `StartTlsError`.

## Component 2 — `scanner.scan_endpoint` change

After `socket.create_connection` succeeds and `raw.settimeout(timeout)`, but
before `wrap_socket`:

```python
proto = starttls.protocol_for_port(port)
if proto:
    try:
        starttls.negotiate(raw, proto, sni, timeout)  # negotiate defaults EHLO name when sni is ""
    except starttls.StartTlsError as e:
        raw.close()
        return ScanResult(status="starttls_failed", error=str(e), sni_used=sni)
```

Everything after (`wrap_socket`, cert capture, chain, parse) is unchanged. No
signature change to `scan_endpoint`; inference is internal, so both scheduled
scans (`scan_engine.run_scan_job`) and the renewal-verify path
(`worker._verify_endpoints_serve`) get STARTTLS for free with no call-site edits.

## Component 3 — scan-status taxonomy

Add `starttls_failed` as a distinct status:
- Meaning: the port is open and speaks its plaintext protocol, but STARTTLS was
  not offered/permitted (or the negotiation failed) — operationally different
  from `tls_handshake_failed` (TLS negotiated but failed) and `non_tls_service`
  (spoke a non-TLS protocol on an implicit-TLS port).
- README troubleshooting table gains a row.
- The frontend already renders arbitrary failure statuses as the `Unknown`
  severity; no frontend change required (verify during implementation).

## Testing

- **`protocol_for_port`**: 25/587→smtp, 143→imap, 110→pop3, 389→ldap; implicit
  ports (443/465/636/993/995/8443) and unknown ports → `None`.
- **`negotiate` per protocol** against a scripted in-memory fake socket
  (`socket.socketpair()` or a tiny threaded fake server): a compliant server
  (correct greeting + positive STARTTLS reply) returns cleanly and the bytes
  sent by `negotiate` match the expected command sequence; a server that omits
  the greeting, returns a negative reply, or closes early raises `StartTlsError`.
  Cover SMTP multiline `250-`/`250 ` handling explicitly.
- **End-to-end**: a tiny localhost fake **SMTP-then-real-TLS** server (plaintext
  greeting + EHLO + STARTTLS, then a self-signed TLS cert) proving
  `scan_endpoint(ip, 587, ...)` negotiates and captures the certificate through
  the STARTTLS path (`status="ok"`, cert fingerprint present).
- **Implicit ports skip negotiation**: `scan_endpoint` on an implicit-TLS port
  does not invoke `negotiate` (monkeypatch/assert), preserving current behavior.
- **`starttls_failed` path**: a fake server that speaks its greeting but refuses
  STARTTLS yields `status="starttls_failed"`, not `non_tls_service`.

## Files

- Create: `backend/app/starttls.py`, `backend/tests/test_starttls.py`,
  `backend/tests/test_scanner_starttls.py`.
- Modify: `backend/app/scanner.py` (call negotiate before wrap; new status),
  `README.md` (troubleshooting-table row + a note that STARTTLS ports are
  captured automatically).
