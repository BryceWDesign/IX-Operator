from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final
from uuid import uuid4


SESSION_ID_PREFIX: Final[str] = "sess"
DEFAULT_SESSION_TTL_SECONDS: Final[int] = 300


class SessionRole(StrEnum):
    INITIATOR = "initiator"
    RESPONDER = "responder"


class SessionState(StrEnum):
    NEW = "new"
    HANDSHAKE_STARTED = "handshake_started"
    KEYS_DERIVED = "keys_derived"
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    peer_id: str
    signing_public_key: bytes
    exchange_public_key: bytes

    def validate(self) -> None:
        if not self.peer_id.strip():
            raise ValueError("peer_id must not be empty")
        if len(self.signing_public_key) != 32:
            raise ValueError("signing_public_key must be 32 bytes")
        if len(self.exchange_public_key) != 32:
            raise ValueError("exchange_public_key must be 32 bytes")


@dataclass(slots=True)
class SessionMaterial:
    encryption_key: bytes
    authentication_key: bytes
    transcript_hash: bytes

    def validate(self) -> None:
        if len(self.encryption_key) != 32:
            raise ValueError("encryption_key must be 32 bytes")
        if len(self.authentication_key) != 32:
            raise ValueError("authentication_key must be 32 bytes")
        if len(self.transcript_hash) != 32:
            raise ValueError("transcript_hash must be 32 bytes")

    def wipe(self) -> None:
        self.encryption_key = b""
        self.authentication_key = b""
        self.transcript_hash = b""


@dataclass(slots=True)
class SessionRecord:
    session_id: str
    role: SessionRole
    state: SessionState
    local_peer: PeerIdentity
    remote_peer: PeerIdentity
    created_at_utc: datetime
    expires_at_utc: datetime
    material: SessionMaterial | None = None
    failure_reason: str | None = None
    activated_at_utc: datetime | None = None
    closed_at_utc: datetime | None = None
    last_transition_at_utc: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def create(
        cls,
        *,
        role: SessionRole,
        local_peer: PeerIdentity,
        remote_peer: PeerIdentity,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        session_id: str | None = None,
    ) -> "SessionRecord":
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than 0")

        local_peer.validate()
        remote_peer.validate()

        resolved_session_id = session_id.strip() if session_id is not None else _new_session_id()
        if not resolved_session_id:
            raise ValueError("session_id must not be empty when provided")

        now = datetime.now(UTC)
        return cls(
            session_id=resolved_session_id,
            role=role,
            state=SessionState.NEW,
            local_peer=local_peer,
            remote_peer=remote_peer,
            created_at_utc=now,
            expires_at_utc=now + timedelta(seconds=ttl_seconds),
        )

    @property
    def is_terminal(self) -> bool:
        return self.state in {SessionState.CLOSED, SessionState.FAILED}

    @property
    def is_active(self) -> bool:
        return self.state == SessionState.ACTIVE

    def mark_handshake_started(self) -> None:
        self._require_state(SessionState.NEW)
        self.state = SessionState.HANDSHAKE_STARTED
        self.last_transition_at_utc = datetime.now(UTC)

    def attach_material(self, material: SessionMaterial) -> None:
        self._require_state(SessionState.HANDSHAKE_STARTED)
        material.validate()
        self.material = material
        self.state = SessionState.KEYS_DERIVED
        self.last_transition_at_utc = datetime.now(UTC)

    def activate(self) -> None:
        self._require_state(SessionState.KEYS_DERIVED)
        self.state = SessionState.ACTIVE
        self.activated_at_utc = datetime.now(UTC)
        self.last_transition_at_utc = self.activated_at_utc

    def close(self) -> None:
        if self.state in {SessionState.CLOSED, SessionState.FAILED}:
            return

        self.state = SessionState.CLOSED
        self.closed_at_utc = datetime.now(UTC)
        self.last_transition_at_utc = self.closed_at_utc

        if self.material is not None:
            self.material.wipe()

    def fail(self, reason: str) -> None:
        if not reason.strip():
            raise ValueError("reason must not be empty")

        self.failure_reason = reason.strip()
        self.state = SessionState.FAILED
        self.closed_at_utc = datetime.now(UTC)
        self.last_transition_at_utc = self.closed_at_utc

        if self.material is not None:
            self.material.wipe()

    def is_expired(self, now: datetime | None = None) -> bool:
        current_time = now or datetime.now(UTC)
        return current_time >= self.expires_at_utc

    def _require_state(self, expected: SessionState) -> None:
        if self.state != expected:
            raise ValueError(
                f"invalid state transition: expected {expected.value}, got {self.state.value}"
            )


def _new_session_id() -> str:
    return f"{SESSION_ID_PREFIX}-{uuid4().hex}"
