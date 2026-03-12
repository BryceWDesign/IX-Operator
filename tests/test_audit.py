from __future__ import annotations

import json
from pathlib import Path

from ix_operator.audit import AuditCategory, AuditEvent, AuditLogger, AuditSeverity
from ix_operator.config import OperatorConfig, OperatorMode, RuntimePaths, TransportBackend
from ix_operator.runtime import RuntimeContext


def _config_for_test(root: Path) -> OperatorConfig:
    return OperatorConfig(
        app_name="IX-Operator",
        mode=OperatorMode.DEVELOPMENT,
        transport_backend=TransportBackend.LOCAL,
        runtime_paths=RuntimePaths.from_root(root),
        log_level="DEBUG",
        enable_color_logs=False,
        session_timeout_seconds=10,
        packet_size_bytes=1024,
        tor_socks_host="127.0.0.1",
        tor_socks_port=9050,
    )


def test_audit_event_serializes_to_json() -> None:
    event = AuditEvent.create(
        severity=AuditSeverity.INFO,
        category=AuditCategory.SYSTEM,
        action="runtime.bootstrap",
        outcome="success",
        details={"example": "value"},
    )

    payload = json.loads(event.to_json())

    assert payload["severity"] == "info"
    assert payload["category"] == "system"
    assert payload["action"] == "runtime.bootstrap"
    assert payload["outcome"] == "success"
    assert payload["details"]["example"] == "value"


def test_audit_logger_writes_jsonl(tmp_path: Path) -> None:
    config = _config_for_test(tmp_path / "runtime")
    logger = AuditLogger(config)

    logger.write(
        AuditEvent.create(
            severity=AuditSeverity.WARNING,
            category=AuditCategory.CONFIG,
            action="config.load",
            outcome="fallback",
            details={"field": "packet_size_bytes"},
        )
    )

    lines = logger.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    payload = json.loads(lines[0])
    assert payload["category"] == "config"
    assert payload["severity"] == "warning"
    assert payload["details"]["field"] == "packet_size_bytes"


def test_runtime_context_bootstrap_writes_startup_audit_event(tmp_path: Path) -> None:
    config = _config_for_test(tmp_path / "runtime")

    context = RuntimeContext.bootstrap(config)

    assert context.boot_id
    assert context.audit.path.is_file()

    lines = context.audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    payload = json.loads(lines[0])
    assert payload["action"] == "runtime.bootstrap"
    assert payload["outcome"] == "success"
    assert payload["details"]["boot_id"] == context.boot_id


def test_runtime_context_record_event_appends(tmp_path: Path) -> None:
    config = _config_for_test(tmp_path / "runtime")
    context = RuntimeContext.bootstrap(config)

    context.record_event(
        severity=AuditSeverity.INFO,
        category=AuditCategory.RUNTIME,
        action="runtime.healthcheck",
        outcome="ok",
        details={"component": "main"},
    )

    lines = context.audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    last_payload = json.loads(lines[-1])
    assert last_payload["category"] == "runtime"
    assert last_payload["action"] == "runtime.healthcheck"
    assert last_payload["details"]["component"] == "main"
    assert last_payload["details"]["boot_id"] == context.boot_id
