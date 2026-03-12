"""
IX-Operator package bootstrap.
"""

from __future__ import annotations

from ix_operator.audit import AuditCategory, AuditEvent, AuditLogger, AuditSeverity
from ix_operator.config import OperatorConfig, OperatorMode, RuntimePaths, TransportBackend
from ix_operator.runtime import RuntimeContext

__all__ = [
    "__version__",
    "PRODUCT_NAME",
    "AuditCategory",
    "AuditEvent",
    "AuditLogger",
    "AuditSeverity",
    "OperatorConfig",
    "OperatorMode",
    "RuntimeContext",
    "RuntimePaths",
    "TransportBackend",
]

PRODUCT_NAME = "IX-Operator"
__version__ = "0.1.0"
