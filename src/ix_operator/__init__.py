"""
IX-Operator package bootstrap.
"""

from __future__ import annotations

from ix_operator.config import OperatorConfig, OperatorMode, RuntimePaths, TransportBackend

__all__ = [
    "__version__",
    "PRODUCT_NAME",
    "OperatorConfig",
    "OperatorMode",
    "RuntimePaths",
    "TransportBackend",
]

PRODUCT_NAME = "IX-Operator"
__version__ = "0.1.0"
