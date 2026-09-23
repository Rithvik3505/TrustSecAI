"""Simple in-memory cache for graph retrieval results."""

from __future__ import annotations

from typing import Any


class RetrievalCache:
    """Tiny process-local cache keyed by IDS label."""

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}

    def get(self, label: str) -> Any | None:
        """Return cached value for label, if present."""

        return self._store.get(label)

    def set(self, label: str, value: Any) -> None:
        """Cache value for label."""

        self._store[label] = value

    def clear(self) -> None:
        """Clear cache."""

        self._store.clear()

