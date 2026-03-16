"""Source code scanner — detects crypto usage in source files."""

from __future__ import annotations

from quant_scan.core.context import ScanContext
from quant_scan.core.models import Finding
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.registry import register
from quant_scan.scanners.source.languages import get_language_analyzer


# Map file extensions to language names
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "golang",
    ".c": "cpp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".rb": "ruby",
    ".scala": "scala",
    ".sc": "scala",
    ".dart": "dart",
}


@register("source")
class SourceCodeScanner(BaseScanner):
    """Scans source code files for cryptographic algorithm usage."""

    name = "source"

    def scan(self, context: ScanContext) -> list[Finding]:
        # Determine which languages to scan
        if context.languages:
            langs = set(context.languages)
            exts = {ext for ext, lang in _EXT_TO_LANG.items() if lang in langs}
        else:
            exts = set(_EXT_TO_LANG.keys())

        files = self.collect_files(context, exts)
        findings: list[Finding] = []

        for file_path in files:
            lang = _EXT_TO_LANG.get(file_path.suffix)
            if lang is None:
                continue

            analyzer = get_language_analyzer(lang)
            if analyzer is None:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            file_findings = analyzer.analyze(str(file_path), content)
            for f in file_findings:
                f.scanner_type = self.name
            findings.extend(file_findings)

        return findings
