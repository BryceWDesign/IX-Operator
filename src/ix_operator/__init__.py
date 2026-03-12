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
from ix_operator.transport import (
    DEFAULT_PACKET_SIZE,
    HEADER_SIZE,
    MAX_PACKET_SIZE,
    MESSAGE_ID_SIZE,
    MIN_PACKET_SIZE,
    NONCE_SIZE,
    PROTOCOL_VERSION,
    MessageType,
    Packet,
    PacketHeader,
    build_packet,
    packet_fingerprint,
)

__all__ = [
    "__version__",
    "PRODUCT_NAME",
    "AuditCategory",
    "AuditEvent",
    "AuditLogger",
    "AuditSeverity",
    "CHALLENGE_LEN",
    "DEFAULT_PACKET_SIZE",
    "DEFAULT_SESSION_TTL_SECONDS",
    "HEADER_SIZE",
    "HandshakeAck",
    "HandshakeCoordinator",
    "HandshakeCryptoBackend",
    "HandshakeHello",
    "HandshakeResponse",
    "HandshakeTranscript",
    "LocalSecrets",
    "MAX_PACKET_SIZE",
    "MAX_SESSIONS_DEFAULT",
    "MESSAGE_ID_SIZE",
    "MIN_PACKET_SIZE",
    "NONCE_SIZE",
    "OperatorConfig",
    "OperatorMode",
    "PROTOCOL_LABEL",
    "PROTOCOL_VERSION",
    "Packet",
    "PacketHeader",
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
    "MessageType",
    "build_packet",
    "packet_fingerprint",
]

PRODUCT_NAME = "IX-Operator"
__version__ = "0.1.0"
