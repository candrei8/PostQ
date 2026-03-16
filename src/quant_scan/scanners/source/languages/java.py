"""Java language analyzer — loads rules from java.yml."""

from __future__ import annotations

from quant_scan.core.models import Finding
from quant_scan.rules.loader import load_source_rules
from quant_scan.rules.matcher import RuleMatcher
from quant_scan.scanners.source.languages.base import LanguageAnalyzer


class JavaAnalyzer(LanguageAnalyzer):
    """Detect cryptographic usage in Java source files."""

    language = "java"

    def __init__(self) -> None:
        rules = load_source_rules("java")
        self._matcher = RuleMatcher(rules)

    def analyze(self, file_path: str, content: str) -> list[Finding]:
        return self._matcher.match_file(file_path, content)
