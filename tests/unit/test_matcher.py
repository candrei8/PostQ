"""Tests for the pattern matching engine."""

from quant_scan.core.enums import QuantumRisk, Severity
from quant_scan.rules.loader import load_source_rules
from quant_scan.rules.matcher import RuleMatcher


def _make_matcher() -> RuleMatcher:
    rules = load_source_rules("python")
    return RuleMatcher(rules)


def test_match_rsa_generate():
    m = _make_matcher()
    findings = m.match_line(
        "private_key = rsa.generate_private_key(",
        "test.py",
        5,
    )
    assert len(findings) >= 1
    assert any(f.rule_id == "PY-RSA-GENERATE" for f in findings)


def test_match_md5():
    m = _make_matcher()
    findings = m.match_line(
        'digest = hashlib.md5(b"data").hexdigest()',
        "hash.py",
        10,
    )
    assert len(findings) >= 1
    assert any(f.algorithm.name == "MD5" for f in findings)


def test_match_sha1():
    m = _make_matcher()
    findings = m.match_line(
        "h = hashlib.sha1(data)",
        "hash.py",
        3,
    )
    assert len(findings) >= 1


def test_no_match_safe_code():
    m = _make_matcher()
    findings = m.match_line(
        "result = sum(values)",
        "safe.py",
        1,
    )
    assert findings == []


def test_match_file_vulnerable(vulnerable_python_path):
    m = _make_matcher()
    content = vulnerable_python_path.read_text(encoding="utf-8")
    findings = m.match_file(str(vulnerable_python_path), content)
    assert len(findings) > 5

    rule_ids = {f.rule_id for f in findings}
    assert "PY-RSA-GENERATE" in rule_ids
    assert "PY-MD5-USE" in rule_ids
    assert "PY-SHA1-USE" in rule_ids


def test_match_file_safe(safe_python_path):
    m = _make_matcher()
    content = safe_python_path.read_text(encoding="utf-8")
    findings = m.match_file(str(safe_python_path), content)
    assert findings == []
