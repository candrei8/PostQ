"""Scanner registry — auto-discovery of scanner implementations."""

from __future__ import annotations

from quant_scan.scanners.base import BaseScanner

_registry: dict[str, type[BaseScanner]] = {}


def register(name: str):
    """Class decorator to register a scanner type."""

    def decorator(cls: type[BaseScanner]):
        _registry[name] = cls
        return cls

    return decorator


def get_scanner(name: str) -> BaseScanner:
    """Instantiate a registered scanner by name."""
    cls = _registry.get(name)
    if cls is None:
        raise KeyError(f"Unknown scanner: {name}. Available: {list(_registry.keys())}")
    return cls()


def get_all_scanners() -> list[BaseScanner]:
    """Instantiate all registered scanners."""
    return [cls() for cls in _registry.values()]


def available_scanners() -> list[str]:
    """Return names of all registered scanners."""
    return list(_registry.keys())
