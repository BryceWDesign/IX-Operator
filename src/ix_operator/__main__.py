from __future__ import annotations

from ix_operator import PRODUCT_NAME, __version__
from ix_operator.config import OperatorConfig
from ix_operator.logging import configure_logging


def main() -> int:
    config = OperatorConfig.from_env()
    config.runtime_paths.create()

    logger = configure_logging(config)
    logger.info(
        "startup app=%s version=%s mode=%s transport=%s runtime_root=%s",
        PRODUCT_NAME,
        __version__,
        config.mode.value,
        config.transport_backend.value,
        config.runtime_paths.root,
    )

    banner = f"""{PRODUCT_NAME} v{__version__}
Bootstrap initialized.

Mode: {config.mode.value}
Transport: {config.transport_backend.value}
Runtime root: {config.runtime_paths.root}

Current scope:
- Rust crypto crate scaffold
- Python package scaffold
- Safe configuration and logging foundation
- Secure rebuild from square one
"""
    print(banner.rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
