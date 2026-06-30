"""Target parsing, validation, and expansion into (host, ip) scan units.

Pure functions, no I/O — unit-tested in tests/test_targets.py. We never shell
out: all parsing uses the stdlib `ipaddress` module and a strict hostname regex,
which eliminates command-injection surface from user-supplied target values.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# RFC 1123 hostname label, allowing a trailing dot and wildcard not allowed.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)

TARGET_TYPES = ("cidr", "range", "ip", "hostname")


class TargetError(ValueError):
    """Raised for invalid or unsafe target definitions."""


@dataclass(frozen=True)
class ScanUnit:
    """A single thing to connect to. host is the SNI/DNS name (may be empty for
    a bare IP); ip is what we actually dial (empty for hostnames — resolved at
    scan time)."""

    host: str
    ip: str


def is_valid_hostname(value: str) -> bool:
    value = value.strip()
    if not value or len(value) > 253:
        return False
    # Reject things that are actually IPs — those are the "ip" type.
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(value))


def detect_type(value: str) -> str:
    """Best-effort classification of a raw target string."""
    value = value.strip()
    if "/" in value:
        return "cidr"
    if "-" in value and _looks_like_range(value):
        return "range"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "hostname"


def _looks_like_range(value: str) -> bool:
    parts = value.split("-", 1)
    if len(parts) != 2:
        return False
    try:
        ipaddress.ip_address(parts[0].strip())
        return True
    except ValueError:
        return False


def validate(target_type: str, value: str, max_hosts: int) -> int:
    """Validate a target definition and return the number of hosts it expands to.

    Raises TargetError on anything invalid or exceeding the CIDR guardrail.
    """
    if target_type not in TARGET_TYPES:
        raise TargetError(f"unknown target type: {target_type!r}")
    count = len(expand(target_type, value, max_hosts))
    return count


def expand(target_type: str, value: str, max_hosts: int) -> list[ScanUnit]:
    """Expand a target into individual scan units, enforcing size guardrails."""
    value = value.strip()
    if target_type == "hostname":
        if not is_valid_hostname(value):
            raise TargetError(f"invalid hostname: {value!r}")
        return [ScanUnit(host=value, ip="")]

    if target_type == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as e:
            raise TargetError(f"invalid IP address: {value!r}") from e
        return [ScanUnit(host="", ip=str(ip))]

    if target_type == "cidr":
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as e:
            raise TargetError(f"invalid CIDR block: {value!r}") from e
        hosts = list(net.hosts()) or [net.network_address]
        _guard(len(hosts), max_hosts, value)
        return [ScanUnit(host="", ip=str(ip)) for ip in hosts]

    if target_type == "range":
        ips = _expand_range(value)
        _guard(len(ips), max_hosts, value)
        return [ScanUnit(host="", ip=str(ip)) for ip in ips]

    raise TargetError(f"unknown target type: {target_type!r}")


def _expand_range(value: str) -> list:
    """Expand 'A-B'. B may be a full IP or just the final octet(s) shorthand
    (e.g. 10.0.0.10-50)."""
    parts = value.split("-", 1)
    if len(parts) != 2:
        raise TargetError(f"invalid range: {value!r}")
    start_s, end_s = parts[0].strip(), parts[1].strip()
    try:
        start = ipaddress.ip_address(start_s)
    except ValueError as e:
        raise TargetError(f"invalid range start: {start_s!r}") from e

    # Shorthand end: "10.0.0.10-50" -> end octet only.
    if "." not in end_s and ":" not in end_s and isinstance(start, ipaddress.IPv4Address):
        prefix = start_s.rsplit(".", 1)[0]
        end_s = f"{prefix}.{end_s}"
    try:
        end = ipaddress.ip_address(end_s)
    except ValueError as e:
        raise TargetError(f"invalid range end: {end_s!r}") from e

    if type(start) is not type(end):
        raise TargetError("range start and end must be the same IP version")
    if int(end) < int(start):
        raise TargetError("range end must be >= start")
    return [ipaddress.ip_address(i) for i in range(int(start), int(end) + 1)]


def _guard(count: int, max_hosts: int, value: str) -> None:
    if count > max_hosts:
        raise TargetError(
            f"target {value!r} expands to {count} hosts, exceeding the "
            f"max of {max_hosts}. Narrow the range or raise CERTWATCH_MAX_CIDR_HOSTS."
        )


def normalize_ports(ports, default_ports: str) -> list[int]:
    """Coerce a ports list to validated ints, falling back to defaults."""
    if not ports:
        ports = [int(p) for p in default_ports.split(",") if p.strip()]
    out: list[int] = []
    for p in ports:
        try:
            n = int(p)
        except (TypeError, ValueError) as e:
            raise TargetError(f"invalid port: {p!r}") from e
        if not (1 <= n <= 65535):
            raise TargetError(f"port out of range: {n}")
        if n not in out:
            out.append(n)
    return out
