from __future__ import annotations

import logging
from pathlib import Path

from ix_operator.config import OperatorConfig


_LOGGER_NAME = "ix_operator"


def configure_logging(config: OperatorConfig) -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(_normalize_log_level(config.log_level))
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(_normalize_log_level(config.log_level))
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(_log_file_path(config), encoding="utf-8")
    file_handler.setLevel(_normalize_log_level(config.log_level))
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)


def _log_file_path(config: OperatorConfig) -> Path:
    config.runtime_paths.create()
    return config.runtime_paths.logs / "ix_operator.log"


def _normalize_log_level(value: str) -> int:
    normalized = value.strip().upper()
    if normalized not in logging.getLevelNamesMapping():
        raise ValueError(f"Unsupported log level: {value}")
    return logging.getLevelNamesMapping()[normalized]
