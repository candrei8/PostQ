"""Abstract base class for all scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from quant_scan.core.context import ScanContext
from quant_scan.core.models import Finding


class BaseScanner(ABC):
    """Interface that all scanner types must implement."""

    name: str = "base"

    @abstractmethod
    def scan(self, context: ScanContext) -> list[Finding]:
        """Run the scan and return findings."""

    def collect_files(
        self,
        context: ScanContext,
        extensions: set[str],
    ) -> list[Path]:
        """Walk targets and return files matching the given extensions."""
        import pathspec

        files: list[Path] = []
        spec = (
            pathspec.PathSpec.from_lines("gitwildmatch", context.exclude_patterns)
            if context.exclude_patterns
            else None
        )

        for target in context.targets:
            if target.is_file():
                if target.suffix in extensions:
                    files.append(target)
                continue
            for p in target.rglob("*"):
                if not p.is_file():
                    continue
                if p.suffix not in extensions:
                    continue
                try:
                    rel = p.relative_to(target)
                except ValueError:
                    rel = p
                if spec and spec.match_file(str(rel)):
                    continue
                files.append(p)
        return files
