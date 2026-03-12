"""
IX-Operator package bootstrap.
"""

from __future__ import annotations

from ix_operator.audit import AuditCategory, AuditEvent, AuditLogger, AuditSeverity
from ix_operator.config import OperatorConfig, OperatorMode, RuntimePaths, TransportBackend
from ix_operator.runtime import RuntimeContext
from ix_operator.session import (
    DEFAULT_SESSION_TTL_SECONDS,
    HandshakeTranscript,
    PROTOCOL_LABEL,
    PeerIdentity,
    SessionMaterial,
    SessionRecord,
    SessionRole,
    SessionState,
)

__all__ = [
    "__version__",
    "PRODUCT_NAME",
    "AuditCategory",
    "AuditEvent",
    "AuditLogger",
    "AuditSeverity",
    "DEFAULT_SESSION_TTL_SECONDS",
    "HandshakeTranscript",
    "OperatorConfig",
    "OperatorMode",
    "PROTOCOL_LABEL",
    "PeerIdentity",
    "RuntimeContext",
    "RuntimePaths",
    "SessionMaterial",
    "SessionRecord",
    "SessionRole",
    "SessionState",
    "TransportBackend",
]

PRODUCT_NAME = "IX-Operator"
__version__ = "0.1.0"
