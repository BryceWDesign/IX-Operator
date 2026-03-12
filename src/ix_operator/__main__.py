from __future__ import annotations

from ix_operator import PRODUCT_NAME, __version__
from ix_operator.config import OperatorConfig
from ix_operator.runtime import RuntimeContext


def main() -> int:
    config = OperatorConfig.from_env()
    context = RuntimeContext.bootstrap(config)

    banner = f"""{PRODUCT_NAME} v{__version__}
Bootstrap initialized.

Mode: {config.mode.value}
Transport: {config.transport_backend.value}
Runtime root: {config.runtime_paths.root}
Boot ID: {context.boot_id}

Current scope:
- Rust crypto crate scaffold
- Python package scaffold
- Safe configuration and logging foundation
- Structured audit trail and runtime context
- Secure rebuild from square one
"""
    print(banner.rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
