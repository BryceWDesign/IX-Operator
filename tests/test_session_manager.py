from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ix_operator.session import (
    SessionManager,
    SessionMaterial,
    SessionRole,
    SessionState,
)
from ix_operator.session.models import PeerIdentity


def _peer(name: str, seed: int) -> PeerIdentity:
    return PeerIdentity(
        peer_id=name,
        signing_public_key=bytes([seed]) * 32,
        exchange_public_key=bytes([seed + 1]) * 32,
    )


def _material() -> SessionMaterial:
    return SessionMaterial(
        encryption_key=b"a" * 32,
        authentication_key=b"b" * 32,
        transcript_hash=b"c" * 32,
    )


def test_create_session_registers_and_returns_copy() -> None:
    manager = SessionManager()
    session = manager.create_session(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 1),
        remote_peer=_peer("remote", 2),
    )

    fetched = manager.get_session(session.session_id)

    assert fetched is not None
    assert fetched.session_id == session.session_id
    assert fetched.state == SessionState.NEW
    assert fetched is not session


def test_session_manager_lifecycle_to_active() -> None:
    manager = SessionManager()
    session = manager.create_session(
        role=SessionRole.RESPONDER,
        local_peer=_peer("local", 3),
        remote_peer=_peer("remote", 4),
    )

    started = manager.start_handshake(session.session_id)
    assert started.state == SessionState.HANDSHAKE_STARTED

    derived = manager.attach_material(session.session_id, _material())
    assert derived.state == SessionState.KEYS_DERIVED

    active = manager.activate_session(session.session_id)
    assert active.state == SessionState.ACTIVE
    assert active.is_active is True

    latest = manager.get_active_session_for_peer("remote")
    assert latest is not None
    assert latest.session_id == session.session_id
    assert latest.state == SessionState.ACTIVE


def test_fail_session_marks_terminal() -> None:
    manager = SessionManager()
    session = manager.create_session(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 5),
        remote_peer=_peer("remote", 6),
    )

    manager.start_handshake(session.session_id)
    failed = manager.fail_session(session.session_id, "signature verification failed")

    assert failed.state == SessionState.FAILED
    assert failed.failure_reason == "signature verification failed"
    assert failed.is_terminal is True


def test_close_session_wipes_material() -> None:
    manager = SessionManager()
    session = manager.create_session(
        role=SessionRole.RESPONDER,
        local_peer=_peer("local", 7),
        remote_peer=_peer("remote", 8),
    )

    manager.start_handshake(session.session_id)
    manager.attach_material(session.session_id, _material())
    closed = manager.close_session(session.session_id)

    assert closed.state == SessionState.CLOSED
    assert closed.material is not None
    assert closed.material.encryption_key == b""
    assert closed.material.authentication_key == b""
    assert closed.material.transcript_hash == b""


def test_expire_sessions_marks_nonterminal_expired_records_failed() -> None:
    manager = SessionManager()
    session = manager.create_session(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 9),
        remote_peer=_peer("remote", 10),
        ttl_seconds=1,
    )

    future = datetime.now(UTC) + timedelta(seconds=2)
    expired_ids = manager.expire_sessions(future)
    expired = manager.get_session(session.session_id)

    assert session.session_id in expired_ids
    assert expired is not None
    assert expired.state == SessionState.FAILED
    assert expired.failure_reason == "session expired"


def test_list_sessions_for_peer_filters_remote_peer() -> None:
    manager = SessionManager()
    manager.create_session(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local-a", 11),
        remote_peer=_peer("remote-a", 12),
    )
    manager.create_session(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local-b", 13),
        remote_peer=_peer("remote-b", 14),
    )
    manager.create_session(
        role=SessionRole.RESPONDER,
        local_peer=_peer("local-c", 15),
        remote_peer=_peer("remote-a", 16),
    )

    matches = manager.list_sessions_for_peer("remote-a")

    assert len(matches) == 2
    assert all(item.remote_peer.peer_id == "remote-a" for item in matches)


def test_remove_session_deletes_it() -> None:
    manager = SessionManager()
    session = manager.create_session(
        role=SessionRole.RESPONDER,
        local_peer=_peer("local", 17),
        remote_peer=_peer("remote", 18),
    )

    manager.remove_session(session.session_id)

    assert manager.get_session(session.session_id) is None


def test_manager_rejects_unknown_session_id() -> None:
    manager = SessionManager()

    with pytest.raises(KeyError, match="unknown session_id"):
        manager.start_handshake("sess-does-not-exist")


def test_manager_enforces_capacity_limit() -> None:
    manager = SessionManager(max_sessions=1)
    manager.create_session(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local-a", 19),
        remote_peer=_peer("remote-a", 20),
    )

    with pytest.raises(RuntimeError, match="session capacity exceeded"):
        manager.create_session(
            role=SessionRole.RESPONDER,
            local_peer=_peer("local-b", 21),
            remote_peer=_peer("remote-b", 22),
        )
