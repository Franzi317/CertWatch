from app.status import is_internal, status_phrase

PATTERNS = ["MyCorp Issuing CA", "SSL Corporation"]


def test_self_signed_is_internal():
    assert is_internal("CN=whatever", True, PATTERNS) is True
    # self-signed wins even with no patterns configured
    assert is_internal("CN=whatever", True, []) is True


def test_issuer_pattern_match_case_insensitive():
    assert is_internal("CN=Issuing CA,O=SSL CORPORATION,C=US", False, PATTERNS) is True
    assert is_internal("CN=mycorp issuing ca 3", False, PATTERNS) is True


def test_public_ca_is_external():
    assert is_internal("CN=Cloudflare TLS Issuing ECC CA 3", False, PATTERNS) is False
    # empty issuer, no patterns -> external
    assert is_internal("", False, []) is False


def test_starttls_failed_has_friendly_phrase():
    phrase = status_phrase("starttls_failed")
    assert phrase == "Scan failed: STARTTLS not offered or refused"
    # must not fall through to the raw status slug
    assert phrase != "starttls_failed"
