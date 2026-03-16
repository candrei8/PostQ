"""Load YAML rule files and the master algorithm database."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from quant_scan.core.enums import AlgorithmFamily, QuantumRisk, Severity
from quant_scan.core.models import Algorithm

_DATA_DIR = Path(__file__).parent / "data"

# ---------------------------------------------------------------------------
# Algorithm DB
# ---------------------------------------------------------------------------

_algorithm_cache: dict[str, Algorithm] | None = None


def load_algorithms() -> dict[str, Algorithm]:
    """Load the master algorithm database from algorithms.yml."""
    global _algorithm_cache
    if _algorithm_cache is not None:
        return _algorithm_cache

    path = _DATA_DIR / "algorithms.yml"
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))

    db: dict[str, Algorithm] = {}
    for name, attrs in raw.get("algorithms", {}).items():
        db[name] = Algorithm(
            name=name,
            family=AlgorithmFamily(attrs["family"]),
            key_size=attrs.get("key_size"),
            quantum_risk=QuantumRisk(attrs["quantum_risk"]),
            pqc_replacements=attrs.get("pqc_replacements", []),
            eu_deadline=attrs.get("eu_deadline"),
            description=attrs.get("description", ""),
        )
    _algorithm_cache = db
    return db


# ---------------------------------------------------------------------------
# Source-code rules
# ---------------------------------------------------------------------------


class SourceRule:
    """A compiled detection rule for source code scanning."""

    __slots__ = (
        "id",
        "algorithm_key",
        "pattern",
        "message",
        "recommendation",
        "severity_override",
        "quantum_risk_override",
    )

    def __init__(
        self,
        id: str,
        algorithm_key: str,
        pattern: str,
        message: str,
        recommendation: str = "",
        severity_override: str | None = None,
        quantum_risk_override: str | None = None,
    ) -> None:
        self.id = id
        self.algorithm_key = algorithm_key
        self.pattern = pattern
        self.message = message
        self.recommendation = recommendation
        self.severity_override = (
            Severity(severity_override) if severity_override else None
        )
        self.quantum_risk_override = (
            QuantumRisk(quantum_risk_override) if quantum_risk_override else None
        )


def load_source_rules(language: str) -> list[SourceRule]:
    """Load source-code rules for a given language from YAML."""
    path = _DATA_DIR / "source" / f"{language}.yml"
    if not path.exists():
        return []

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules: list[SourceRule] = []
    for r in raw.get("rules", []):
        rules.append(
            SourceRule(
                id=r["id"],
                algorithm_key=r["algorithm"],
                pattern=r["pattern"],
                message=r["message"],
                recommendation=r.get("recommendation", ""),
                severity_override=r.get("severity_override"),
                quantum_risk_override=r.get("quantum_risk_override"),
            )
        )
    return rules
