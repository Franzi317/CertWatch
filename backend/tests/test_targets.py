import pytest

from app import targets as t


def test_cidr_expansion():
    units = t.expand("cidr", "10.10.0.0/30", 4096)
    assert [u.ip for u in units] == ["10.10.0.1", "10.10.0.2"]
    # /32 yields the single host
    assert [u.ip for u in t.expand("cidr", "10.0.0.5/32", 4096)] == ["10.0.0.5"]


def test_cidr_guardrail():
    with pytest.raises(t.TargetError):
        t.expand("cidr", "10.0.0.0/8", 4096)


def test_ip_range_expansion_full_and_shorthand():
    full = [u.ip for u in t.expand("range", "10.0.0.10-10.0.0.12", 4096)]
    assert full == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
    short = [u.ip for u in t.expand("range", "10.0.0.10-12", 4096)]
    assert short == full


def test_range_rejects_reversed():
    with pytest.raises(t.TargetError):
        t.expand("range", "10.0.0.50-10", 4096)


def test_hostname_validation():
    assert t.is_valid_hostname("sub.example.com")
    assert t.is_valid_hostname("example.com")
    assert not t.is_valid_hostname("10.0.0.1")       # that's an IP
    assert not t.is_valid_hostname("bad_host!")
    assert not t.is_valid_hostname("")
    assert not t.is_valid_hostname("a..b.com")


def test_detect_type():
    assert t.detect_type("10.0.0.0/24") == "cidr"
    assert t.detect_type("10.0.0.1-50") == "range"
    assert t.detect_type("1.2.3.4") == "ip"
    assert t.detect_type("host.example.com") == "hostname"


def test_normalize_ports():
    assert t.normalize_ports([], "443") == [443]
    assert t.normalize_ports(["443", "8443", 443], "443") == [443, 8443]
    with pytest.raises(t.TargetError):
        t.normalize_ports([99999], "443")


def test_invalid_ip_and_cidr():
    with pytest.raises(t.TargetError):
        t.expand("ip", "999.1.1.1", 4096)
    with pytest.raises(t.TargetError):
        t.expand("cidr", "notacidr", 4096)
