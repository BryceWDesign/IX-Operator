from __future__ import annotations

from pathlib import Path

import pytest

from ix_operator.__main__ import main


def test_main_prints_bootstrap_banner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IX_OPERATOR_MODE", "development")
    monkeypatch.setenv("IX_OPERATOR_TRANSPORT", "local")

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "IX-Operator v0.1.0" in captured.out
    assert "Mode: development" in captured.out
    assert "Transport: local" in captured.out
    assert "Boot ID:" in captured.out
    assert str((tmp_path / "runtime").resolve()) in captured.out
