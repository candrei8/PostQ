"""PHP language analyzer — loads rules from php.yml."""
from __future__ import annotations

from quant_scan.core.models import Finding
from quant_scan.rules.loader import load_source_rules
from quant_scan.rules.matcher import RuleMatcher
from quant_scan.scanners.source.languages.base import LanguageAnalyzer


class PhpAnalyzer(LanguageAnalyzer):
    language = "php"

    def __init__(self) -> None:
        rules = load_source_rules("php")
        self._matcher = RuleMatcher(rules)

    def analyze(self, file_path: str, content: str) -> list[Finding]:
        return self._matcher.match_file(file_path, content)
