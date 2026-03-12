from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import json
from pathlib import Path
import threading
from typing import Any
from uuid import uuid4

from ix_operator.config import OperatorConfig


class AuditSeverity(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditCategory(StrEnum):
    SYSTEM = "system"
    CONFIG = "config"
    SESSION = "session"
    TRANSPORT = "transport"
    RUNTIME = "runtime"
    SECURITY = "security"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    timestamp_utc: str
    severity: AuditSeverity
    category: AuditCategory
    action: str
    outcome: str
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        severity: AuditSeverity,
        category: AuditCategory,
        action: str,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> "AuditEvent":
        return cls(
            event_id=str(uuid4()),
            timestamp_utc=datetime.now(UTC).isoformat(),
            severity=severity,
            category=category,
            action=action,
            outcome=outcome,
            details=details or {},
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)


class AuditLogger:
    def __init__(self, config: OperatorConfig) -> None:
        self._config = config
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        self._config.runtime_paths.create()
        return self._config.runtime_paths.logs / "audit.jsonl"

    def write(self, event: AuditEvent) -> None:
        line = event.to_json()
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.write("\n")
