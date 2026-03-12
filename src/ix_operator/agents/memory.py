from __future__ import annotations

from copy import deepcopy
from threading import RLock
from typing import TypeAlias


MemoryValue: TypeAlias = str | int | float | bool | None


class AgentMemoryStore:
    def __init__(self, *, namespace: str) -> None:
        normalized_namespace = namespace.strip()
        if not normalized_namespace:
            raise ValueError("namespace must not be empty")

        self._namespace = normalized_namespace
        self._lock = RLock()
        self._values: dict[str, MemoryValue] = {}

    @property
    def namespace(self) -> str:
        return self._namespace

    def remember(self, key: str, value: MemoryValue) -> None:
        normalized_key = self._normalize_key(key)
        self._validate_value(value)

        with self._lock:
            self._values[normalized_key] = value

    def recall(self, key: str, default: MemoryValue = None) -> MemoryValue:
        normalized_key = self._normalize_key(key)

        with self._lock:
            return deepcopy(self._values.get(normalized_key, default))

    def forget(self, key: str) -> bool:
        normalized_key = self._normalize_key(key)

        with self._lock:
            return self._values.pop(normalized_key, None) is not None

    def contains(self, key: str) -> bool:
        normalized_key = self._normalize_key(key)

        with self._lock:
            return normalized_key in self._values

    def snapshot(self) -> dict[str, MemoryValue]:
        with self._lock:
            return deepcopy(self._values)

    def clear(self) -> None:
        with self._lock:
            self._values.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._values)

    def _normalize_key(self, key: str) -> str:
        normalized_key = key.strip()
        if not normalized_key:
            raise ValueError("memory key must not be empty")
        return normalized_key

    def _validate_value(self, value: MemoryValue) -> None:
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            raise ValueError("memory value must be str, int, float, bool, or None")
