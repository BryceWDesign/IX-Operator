from __future__ import annotations

from pathlib import Path

import pytest

from ix_operator.config import (
    IMPLEMENTED_TRANSPORT_BACKENDS,
    OperatorConfig,
    OperatorMode,
    RuntimePaths,
    TransportBackend,
)


def test_runtime_paths_create_directories(tmp_path: Path) -> None:
    paths = RuntimePaths.from_root(tmp_path / "runtime")
    paths.create()

    assert paths.root.is_dir()
    assert paths.data.is_dir()
    assert paths.logs.is_dir()
    assert paths.state.is_dir()
    assert paths.sockets.is_dir()


def test_from_env_uses_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))

    config = OperatorConfig.from_env()

    assert config.app_name == "IX-Operator"
    assert config.mode == OperatorMode.DEVELOPMENT
    assert config.transport_backend == TransportBackend.LOCAL
    assert config.packet_size_bytes == 1024
    assert config.session_timeout_seconds == 10


def test_from_env_parses_hardened_local_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IX_OPERATOR_MODE", "hardened")
    monkeypatch.setenv("IX_OPERATOR_TRANSPORT", "local")
    monkeypatch.setenv("IX_OPERATOR_LOG_LEVEL", "warning")
    monkeypatch.setenv("IX_OPERATOR_TOR_SOCKS_PORT", "9150")
    monkeypatch.setenv("IX_OPERATOR_SESSION_TIMEOUT", "15")
    monkeypatch.setenv("IX_OPERATOR_PACKET_SIZE", "2048")

    config = OperatorConfig.from_env()

    assert config.mode == OperatorMode.HARDENED
    assert config.transport_backend == TransportBackend.LOCAL
    assert config.log_level == "warning"
    assert config.tor_socks_port == 9150
    assert config.session_timeout_seconds == 15
    assert config.packet_size_bytes == 2048


def test_implemented_transport_backends_only_include_local() -> None:
    assert IMPLEMENTED_TRANSPORT_BACKENDS == (TransportBackend.LOCAL,)


def test_invalid_integer_env_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IX_OPERATOR_PACKET_SIZE", "ten-twenty-four")

    with pytest.raises(ValueError, match="IX_OPERATOR_PACKET_SIZE must be an integer"):
        OperatorConfig.from_env()
