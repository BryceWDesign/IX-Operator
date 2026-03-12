from __future__ import annotations

from ix_operator import PRODUCT_NAME, __version__


def main() -> int:
    banner = f"""{PRODUCT_NAME} v{__version__}
Bootstrap initialized.

Current scope:
- Rust crypto crate scaffold
- Python package scaffold
- Honest v1 boundaries
- Secure rebuild from square one
"""
    print(banner.rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
