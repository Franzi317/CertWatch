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
    name = name.replace("\r", "").replace("\n", "")  # prevent SMTP command injection via EHLO name
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
