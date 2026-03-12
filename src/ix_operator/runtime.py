from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from ix_operator.audit import AuditCategory, AuditEvent, AuditLogger, AuditSeverity
from ix_operator.config import OperatorConfig
from ix_operator.logging import configure_logging, get_logger


@dataclass(frozen=True, slots=True)
class RuntimeContext:
    boot_id: str
    boot_time_utc: str
    config: OperatorConfig
    audit: AuditLogger

    @property
    def state_file(self) -> Path:
        self.config.runtime_paths.create()
        return self.config.runtime_paths.state / "runtime.json"

    @classmethod
    def bootstrap(cls, config: OperatorConfig) -> "RuntimeContext":
        config.runtime_paths.create()
        logger = configure_logging(config)

        context = cls(
            boot_id=str(uuid4()),
            boot_time_utc=datetime.now(UTC).isoformat(),
            config=config,
            audit=AuditLogger(config),
        )

        logger.info(
            "runtime_bootstrap boot_id=%s mode=%s transport=%s",
            context.boot_id,
            config.mode.value,
            config.transport_backend.value,
        )

        context.audit.write(
            AuditEvent.create(
                severity=AuditSeverity.INFO,
                category=AuditCategory.SYSTEM,
                action="runtime.bootstrap",
                outcome="success",
                details={
                    "boot_id": context.boot_id,
                    "mode": config.mode.value,
                    "transport": config.transport_backend.value,
                    "runtime_root": str(config.runtime_paths.root),
                },
            )
        )

        return context

    def record_event(
        self,
        *,
        severity: AuditSeverity,
        category: AuditCategory,
        action: str,
        outcome: str,
        details: dict[str, object] | None = None,
    ) -> None:
        self.audit.write(
            AuditEvent.create(
                severity=severity,
                category=category,
                action=action,
                outcome=outcome,
                details={"boot_id": self.boot_id, **(details or {})},
            )
        )
        get_logger().log(
            _to_logging_level(severity),
            "audit_event category=%s action=%s outcome=%s",
            category.value,
            action,
            outcome,
        )


def _to_logging_level(severity: AuditSeverity) -> int:
    if severity == AuditSeverity.DEBUG:
        return 10
    if severity == AuditSeverity.INFO:
        return 20
    if severity == AuditSeverity.WARNING:
        return 30
    if severity == AuditSeverity.ERROR:
        return 40
    return 50
