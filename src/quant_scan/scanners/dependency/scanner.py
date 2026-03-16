"""Dependency scanner — detects crypto libraries in dependency manifest files."""

from __future__ import annotations

from pathlib import Path

from quant_scan.core.context import ScanContext
from quant_scan.core.models import Finding
from quant_scan.scanners.base import BaseScanner
from quant_scan.scanners.dependency.analyzers.go_deps import analyze_go_deps
from quant_scan.scanners.dependency.analyzers.java_deps import analyze_java_deps
from quant_scan.scanners.dependency.analyzers.node_deps import analyze_node_deps
from quant_scan.scanners.dependency.analyzers.python_deps import analyze_python_deps
from quant_scan.scanners.registry import register

# ---------------------------------------------------------------------------
# Dependency file routing
# ---------------------------------------------------------------------------

# Map dependency file names to their analyzer functions and language labels
_DEP_FILES: dict[str, tuple[str, callable]] = {
    # Python
    "requirements.txt": ("python", analyze_python_deps),
    "pipfile": ("python", analyze_python_deps),
    "pyproject.toml": ("python", analyze_python_deps),
    "setup.cfg": ("python", analyze_python_deps),
    # Node.js
    "package.json": ("node", analyze_node_deps),
    # Java
    "pom.xml": ("java", analyze_java_deps),
    "build.gradle": ("java", analyze_java_deps),
    "build.gradle.kts": ("java", analyze_java_deps),
    # Go
    "go.mod": ("go", analyze_go_deps),
}


def _collect_dep_files(context: ScanContext) -> list[Path]:
    """Walk targets and return dependency manifest files."""
    import pathspec

    dep_filenames = set(_DEP_FILES.keys())
    files: list[Path] = []
    spec = pathspec.PathSpec.from_lines("gitwildmatch", context.exclude_patterns) if context.exclude_patterns else None

    for target in context.targets:
        if target.is_file():
            if target.name.lower() in dep_filenames:
                files.append(target)
            continue
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if p.name.lower() not in dep_filenames:
                continue
            try:
                rel = p.relative_to(target)
            except ValueError:
                rel = p
            if spec and spec.match_file(str(rel)):
                continue
            files.append(p)

    return files


@register("dependency")
class DependencyScanner(BaseScanner):
    """Scans dependency manifest files for cryptographic library usage."""

    name = "dependency"

    def scan(self, context: ScanContext) -> list[Finding]:
        files = _collect_dep_files(context)
        findings: list[Finding] = []

        for file_path in files:
            fname = file_path.name.lower()
            entry = _DEP_FILES.get(fname)
            if entry is None:
                continue

            _lang, analyzer_fn = entry

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            file_findings = analyzer_fn(str(file_path), content)
            for f in file_findings:
                f.scanner_type = self.name
            findings.extend(file_findings)

        return findings
