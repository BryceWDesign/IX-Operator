from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from threading import RLock
from typing import Final

from ix_operator.session.models import (
    DEFAULT_SESSION_TTL_SECONDS,
    PeerIdentity,
    SessionMaterial,
    SessionRecord,
    SessionRole,
    SessionState,
)


MAX_SESSIONS_DEFAULT: Final[int] = 10_000


class SessionManager:
    def __init__(self, *, max_sessions: int = MAX_SESSIONS_DEFAULT) -> None:
        if max_sessions <= 0:
            raise ValueError("max_sessions must be greater than 0")

        self._max_sessions = max_sessions
        self._lock = RLock()
        self._sessions_by_id: dict[str, SessionRecord] = {}

    @property
    def max_sessions(self) -> int:
        return self._max_sessions

    def create_session(
        self,
        *,
        role: SessionRole,
        local_peer: PeerIdentity,
        remote_peer: PeerIdentity,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        session_id: str | None = None,
    ) -> SessionRecord:
        with self._lock:
            if len(self._sessions_by_id) >= self._max_sessions:
                raise RuntimeError("session capacity exceeded")

            session = SessionRecord.create(
                role=role,
                local_peer=local_peer,
                remote_peer=remote_peer,
                ttl_seconds=ttl_seconds,
                session_id=session_id,
            )
            self._sessions_by_id[session.session_id] = session
            return deepcopy(session)

    def get_session(self, session_id: str) -> SessionRecord | None:
        with self._lock:
            session = self._sessions_by_id.get(session_id)
            if session is None:
                return None
            return deepcopy(session)

    def list_sessions(self) -> list[SessionRecord]:
        with self._lock:
            return [deepcopy(session) for session in self._sessions_by_id.values()]

    def list_sessions_for_peer(self, peer_id: str) -> list[SessionRecord]:
        normalized_peer_id = peer_id.strip()
        if not normalized_peer_id:
            raise ValueError("peer_id must not be empty")

        with self._lock:
            matches = [
                deepcopy(session)
                for session in self._sessions_by_id.values()
                if session.remote_peer.peer_id == normalized_peer_id
            ]
            return matches

    def start_handshake(self, session_id: str) -> SessionRecord:
        with self._lock:
            session = self._require_session(session_id)
            session.mark_handshake_started()
            return deepcopy(session)

    def attach_material(self, session_id: str, material: SessionMaterial) -> SessionRecord:
        with self._lock:
            session = self._require_session(session_id)
            session.attach_material(material)
            return deepcopy(session)

    def activate_session(self, session_id: str) -> SessionRecord:
        with self._lock:
            session = self._require_session(session_id)
            session.activate()
            return deepcopy(session)

    def close_session(self, session_id: str) -> SessionRecord:
        with self._lock:
            session = self._require_session(session_id)
            session.close()
            return deepcopy(session)

    def fail_session(self, session_id: str, reason: str) -> SessionRecord:
        with self._lock:
            session = self._require_session(session_id)
            session.fail(reason)
            return deepcopy(session)

    def remove_session(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions_by_id.pop(session_id, None)
            if session is not None and session.material is not None:
                session.material.wipe()

    def get_active_session_for_peer(self, peer_id: str) -> SessionRecord | None:
        normalized_peer_id = peer_id.strip()
        if not normalized_peer_id:
            raise ValueError("peer_id must not be empty")

        with self._lock:
            candidates = [
                session
                for session in self._sessions_by_id.values()
                if session.remote_peer.peer_id == normalized_peer_id
                and session.state == SessionState.ACTIVE
                and not session.is_expired()
            ]

            if not candidates:
                return None

            candidates.sort(key=lambda item: item.last_transition_at_utc, reverse=True)
            return deepcopy(candidates[0])

    def expire_sessions(self, now: datetime | None = None) -> list[str]:
        current_time = now or datetime.now(UTC)
        expired_ids: list[str] = []

        with self._lock:
            for session_id, session in list(self._sessions_by_id.items()):
                if session.is_terminal:
                    continue

                if session.is_expired(current_time):
                    session.fail("session expired")
                    expired_ids.append(session_id)

        return expired_ids

    def _require_session(self, session_id: str) -> SessionRecord:
        session = self._sessions_by_id.get(session_id)
        if session is None:
            raise KeyError(f"unknown session_id: {session_id}")
        return session
