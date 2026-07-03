"""Security hardening regression tests (SEC-1 CIDR/range DoS, SEC-2 SPA path traversal).

SEC-1: targets.expand()/validate() must guard on a CHEAP count (num_addresses /
end-start+1) BEFORE materializing the host list, so huge blocks like 0.0.0.0/0
raise TargetError immediately instead of exhausting memory.

SEC-2: the SPA catch-all must never serve a file outside static_dir, even for
traversal-style paths, falling back to index.html instead.
"""
import pytest

from app import targets as t
from app.main import _safe_static_path


# --------------------------------------------------------------------------- #
# SEC-1: CIDR / range DoS guard must fire before materialization.
# --------------------------------------------------------------------------- #

def test_huge_cidr_raises_fast():
    with pytest.raises(t.TargetError):
        t.validate("cidr", "0.0.0.0/0", 4096)


def test_huge_range_raises_fast():
    with pytest.raises(t.TargetError):
        t.validate("range", "10.0.0.0-10.255.255.255", 4096)


def test_small_cidr_regression():
    assert t.validate("cidr", "10.0.0.0/29", 4096) == 6


def test_small_range_regression():
    assert t.validate("range", "10.0.0.10-10.0.0.13", 4096) == 4


# --------------------------------------------------------------------------- #
# SEC-2: SPA path traversal guard.
# --------------------------------------------------------------------------- #

def _make_static_tree(tmp_path):
    static_dir = tmp_path / "static"
    (static_dir / "assets").mkdir(parents=True)
    (static_dir / "index.html").write_text("<html>index</html>")
    (static_dir / "assets" / "app.js").write_text("console.log('app')")
    # Secret file OUTSIDE static_dir, as a sibling.
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    return static_dir, secret


def test_safe_static_path_serves_real_asset(tmp_path):
    static_dir, _secret = _make_static_tree(tmp_path)
    result = _safe_static_path(str(static_dir), "assets/app.js")
    assert result is not None
    assert result.endswith("app.js")


def test_safe_static_path_rejects_dotdot_traversal(tmp_path):
    static_dir, _secret = _make_static_tree(tmp_path)
    assert _safe_static_path(str(static_dir), "../secret.txt") is None


def test_safe_static_path_rejects_encoded_and_nested_traversal(tmp_path):
    static_dir, _secret = _make_static_tree(tmp_path)
    assert _safe_static_path(str(static_dir), "..%2f..%2fsecret.txt") is None
    assert _safe_static_path(str(static_dir), "../../secret.txt") is None
    assert _safe_static_path(str(static_dir), "assets/../../secret.txt") is None


def test_safe_static_path_rejects_absolute_path(tmp_path):
    static_dir, secret = _make_static_tree(tmp_path)
    assert _safe_static_path(str(static_dir), str(secret)) is None


def test_safe_static_path_rejects_missing_file(tmp_path):
    static_dir, _secret = _make_static_tree(tmp_path)
    assert _safe_static_path(str(static_dir), "does/not/exist.js") is None


def test_safe_static_path_rejects_empty(tmp_path):
    static_dir, _secret = _make_static_tree(tmp_path)
    assert _safe_static_path(str(static_dir), "") is None
