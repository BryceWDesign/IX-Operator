from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
import os
from typing import Final


class OperatorMode(StrEnum):
    DEVELOPMENT = "development"
    STANDARD = "standard"
    HARDENED = "hardened"


class TransportBackend(StrEnum):
    LOCAL = "local"
    TCP = "tcp"
    TOR = "tor"


IMPLEMENTED_TRANSPORT_BACKENDS: Final[tuple[TransportBackend, ...]] = (
    TransportBackend.LOCAL,
)


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    root: Path
    data: Path
    logs: Path
    state: Path
    sockets: Path

    @classmethod
    def from_root(cls, root: Path) -> "RuntimePaths":
        resolved_root = root.expanduser().resolve()
        return cls(
            root=resolved_root,
            data=resolved_root / "data",
            logs=resolved_root / "logs",
            state=resolved_root / "state",
            sockets=resolved_root / "sockets",
        )

    def create(self) -> None:
        for path in (self.root, self.data, self.logs, self.state, self.sockets):
            path.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True, slots=True)
class OperatorConfig:
    app_name: str
    mode: OperatorMode
    transport_backend: TransportBackend
    runtime_paths: RuntimePaths
    log_level: str
    enable_color_logs: bool
    session_timeout_seconds: int
    packet_size_bytes: int
    tor_socks_host: str
    tor_socks_port: int

    def validate(self) -> None:
        if self.session_timeout_seconds <= 0:
            raise ValueError("session_timeout_seconds must be greater than 0")

        if self.packet_size_bytes < 256:
            raise ValueError("packet_size_bytes must be at least 256 bytes")

        if not (1 <= self.tor_socks_port <= 65535):
            raise ValueError("tor_socks_port must be within 1..65535")

    @classmethod
    def from_env(cls) -> "OperatorConfig":
        mode = OperatorMode(_get_env("IX_OPERATOR_MODE", OperatorMode.DEVELOPMENT.value))
        transport_backend = TransportBackend(
            _get_env("IX_OPERATOR_TRANSPORT", TransportBackend.LOCAL.value)
        )

        runtime_root = Path(_get_env("IX_OPERATOR_RUNTIME_DIR", "./runtime"))
        runtime_paths = RuntimePaths.from_root(runtime_root)

        config = cls(
            app_name="IX-Operator",
            mode=mode,
            transport_backend=transport_backend,
            runtime_paths=runtime_paths,
            log_level=_get_env("IX_OPERATOR_LOG_LEVEL", _default_log_level(mode)),
            enable_color_logs=_get_bool_env("IX_OPERATOR_COLOR_LOGS", True),
            session_timeout_seconds=_get_int_env("IX_OPERATOR_SESSION_TIMEOUT", 10),
            packet_size_bytes=_get_int_env("IX_OPERATOR_PACKET_SIZE", 1024),
            tor_socks_host=_get_env("IX_OPERATOR_TOR_SOCKS_HOST", "127.0.0.1"),
            tor_socks_port=_get_int_env("IX_OPERATOR_TOR_SOCKS_PORT", 9050),
        )
        config.validate()
        return config


def _get_env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip() or default


def _get_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    stripped = raw_value.strip()
    if not stripped:
        return default

    try:
        return int(stripped)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _get_bool_env(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False

    raise ValueError(f"{name} must be a boolean-like value")


def _default_log_level(mode: OperatorMode) -> str:
    if mode == OperatorMode.DEVELOPMENT:
        return "DEBUG"
    if mode == OperatorMode.HARDENED:
        return "WARNING"
    return "INFO"
