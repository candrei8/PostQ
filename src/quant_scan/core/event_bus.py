"""Event bus — lightweight pub/sub for scan pipeline events."""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Callable

from quant_scan.core.events import ScanEvent

logger = logging.getLogger(__name__)

# Type alias for event handlers
EventHandler = Callable[[ScanEvent], None]


class EventBus:
    """Simple synchronous event bus for scan pipeline events."""

    def __init__(self) -> None:
        self._handlers: dict[type[ScanEvent], list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: type[ScanEvent], handler: EventHandler) -> None:
        """Register a handler for a specific event type."""
        self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: type[ScanEvent], handler: EventHandler) -> None:
        """Remove a handler for a specific event type."""
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    def emit(self, event: ScanEvent) -> None:
        """Emit an event to all registered handlers."""
        for handler in self._handlers.get(type(event), []):
            try:
                handler(event)
            except Exception:
                logger.exception("Event handler failed for %s", type(event).__name__)

    def clear(self) -> None:
        """Remove all handlers."""
        self._handlers.clear()
