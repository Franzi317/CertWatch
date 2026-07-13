from app.config import Settings


def test_ct_defaults():
    s = Settings()
    assert s.ct_source_url == "https://crt.sh"
    assert s.ct_check_frequency_hours == 24
    assert s.ct_finding_severity == "warning"


def test_ct_source_url_env(monkeypatch):
    monkeypatch.setenv("CERTWATCH_CT_SOURCE_URL", "http://ct.internal")
    assert Settings().ct_source_url == "http://ct.internal"
