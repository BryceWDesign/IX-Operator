"""
IX-Operator package bootstrap.
"""

from __future__ import annotations

from ix_operator.audit import AuditCategory, AuditEvent, AuditLogger, AuditSeverity
from ix_operator.config import OperatorConfig, OperatorMode, RuntimePaths, TransportBackend
from ix_operator.runtime import RuntimeContext
from ix_operator.session import (
    CHALLENGE_LEN,
    DEFAULT_SESSION_TTL_SECONDS,
    HandshakeAck,
    HandshakeCoordinator,
    HandshakeCryptoBackend,
    HandshakeHello,
    HandshakeResponse,
    HandshakeTranscript,
    LocalSecrets,
    MAX_SESSIONS_DEFAULT,
    PROTOCOL_LABEL,
    PeerIdentity,
    SIGNATURE_LEN,
    SessionManager,
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
    "CHALLENGE_LEN",
    "DEFAULT_SESSION_TTL_SECONDS",
    "HandshakeAck",
    "HandshakeCoordinator",
    "HandshakeCryptoBackend",
    "HandshakeHello",
    "HandshakeResponse",
    "HandshakeTranscript",
    "LocalSecrets",
    "MAX_SESSIONS_DEFAULT",
    "OperatorConfig",
    "OperatorMode",
    "PROTOCOL_LABEL",
    "PeerIdentity",
    "RuntimeContext",
    "RuntimePaths",
    "SIGNATURE_LEN",
    "SessionManager",
    "SessionMaterial",
    "SessionRecord",
    "SessionRole",
    "SessionState",
    "TransportBackend",
]

PRODUCT_NAME = "IX-Operator"
__version__ = "0.1.0"
