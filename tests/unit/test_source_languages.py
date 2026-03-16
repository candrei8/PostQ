"""Tests for multi-language source code scanning."""

from pathlib import Path

from quant_scan.rules.loader import load_source_rules
from quant_scan.rules.matcher import RuleMatcher

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# ── Java ────────────────────────────────────────────────────────────────


def test_java_rules_load():
    rules = load_source_rules("java")
    assert len(rules) > 0
    ids = [r.id for r in rules]
    assert any("JAVA" in i for i in ids)


def test_java_rsa_detection():
    rules = load_source_rules("java")
    m = RuleMatcher(rules)
    findings = m.match_line(
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
        "Test.java",
        10,
    )
    assert len(findings) >= 1


def test_java_md5_detection():
    rules = load_source_rules("java")
    m = RuleMatcher(rules)
    findings = m.match_line(
        'MessageDigest md = MessageDigest.getInstance("MD5");',
        "Test.java",
        15,
    )
    assert len(findings) >= 1


def test_java_fixture_file():
    rules = load_source_rules("java")
    if not rules:
        return  # rules not yet created
    m = RuleMatcher(rules)
    fixture = FIXTURES_DIR / "vulnerable_java.java"
    content = fixture.read_text(encoding="utf-8")
    findings = m.match_file(str(fixture), content)
    assert len(findings) >= 5


# ── JavaScript ──────────────────────────────────────────────────────────


def test_javascript_rules_load():
    rules = load_source_rules("javascript")
    assert len(rules) > 0


def test_javascript_md5_detection():
    rules = load_source_rules("javascript")
    m = RuleMatcher(rules)
    findings = m.match_line(
        "const hash = crypto.createHash('md5');",
        "app.js",
        5,
    )
    assert len(findings) >= 1


def test_javascript_fixture_file():
    rules = load_source_rules("javascript")
    if not rules:
        return
    m = RuleMatcher(rules)
    fixture = FIXTURES_DIR / "vulnerable_javascript.js"
    content = fixture.read_text(encoding="utf-8")
    findings = m.match_file(str(fixture), content)
    assert len(findings) >= 5


# ── Go ──────────────────────────────────────────────────────────────────


def test_golang_rules_load():
    rules = load_source_rules("golang")
    assert len(rules) > 0


def test_golang_md5_detection():
    rules = load_source_rules("golang")
    m = RuleMatcher(rules)
    findings = m.match_line(
        'hash := md5.Sum([]byte("data"))',
        "main.go",
        10,
    )
    assert len(findings) >= 1


def test_golang_fixture_file():
    rules = load_source_rules("golang")
    if not rules:
        return
    m = RuleMatcher(rules)
    fixture = FIXTURES_DIR / "vulnerable_go.go"
    content = fixture.read_text(encoding="utf-8")
    findings = m.match_file(str(fixture), content)
    assert len(findings) >= 5


# ── C/C++ ───────────────────────────────────────────────────────────────


def test_cpp_rules_load():
    rules = load_source_rules("cpp")
    assert len(rules) > 0


def test_cpp_md5_detection():
    rules = load_source_rules("cpp")
    m = RuleMatcher(rules)
    findings = m.match_line(
        "MD5_Init(&ctx);",
        "crypto.c",
        20,
    )
    assert len(findings) >= 1


def test_cpp_fixture_file():
    rules = load_source_rules("cpp")
    if not rules:
        return
    m = RuleMatcher(rules)
    fixture = FIXTURES_DIR / "vulnerable_cpp.cpp"
    content = fixture.read_text(encoding="utf-8")
    findings = m.match_file(str(fixture), content)
    assert len(findings) >= 5


# ── C# ──────────────────────────────────────────────────────────────────


def test_csharp_rules_load():
    rules = load_source_rules("csharp")
    assert len(rules) > 0


def test_csharp_md5_detection():
    rules = load_source_rules("csharp")
    m = RuleMatcher(rules)
    findings = m.match_line(
        "using var md5 = MD5.Create();",
        "Crypto.cs",
        10,
    )
    assert len(findings) >= 1


def test_csharp_fixture_file():
    rules = load_source_rules("csharp")
    if not rules:
        return
    m = RuleMatcher(rules)
    fixture = FIXTURES_DIR / "vulnerable_csharp.cs"
    content = fixture.read_text(encoding="utf-8")
    findings = m.match_file(str(fixture), content)
    assert len(findings) >= 5
