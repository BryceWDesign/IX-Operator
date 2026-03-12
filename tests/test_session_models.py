from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ix_operator.session import (
    HandshakeTranscript,
    PeerIdentity,
    SessionMaterial,
    SessionRecord,
    SessionRole,
    SessionState,
)


def _peer(name: str, seed: int) -> PeerIdentity:
    return PeerIdentity(
        peer_id=name,
        signing_public_key=bytes([seed]) * 32,
        exchange_public_key=bytes([seed + 1]) * 32,
    )


def test_peer_identity_validation_accepts_32_byte_keys() -> None:
    peer = _peer("alpha", 1)
    peer.validate()

    assert peer.peer_id == "alpha"
    assert len(peer.signing_public_key) == 32
    assert len(peer.exchange_public_key) == 32


def test_peer_identity_validation_rejects_bad_signing_key() -> None:
    peer = PeerIdentity(
        peer_id="alpha",
        signing_public_key=b"short",
        exchange_public_key=b"x" * 32,
    )

    with pytest.raises(ValueError, match="signing_public_key must be 32 bytes"):
        peer.validate()


def test_session_record_lifecycle_to_active() -> None:
    record = SessionRecord.create(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 10),
        remote_peer=_peer("remote", 20),
        ttl_seconds=120,
    )

    assert record.state == SessionState.NEW
    assert record.is_active is False
    assert record.is_terminal is False

    record.mark_handshake_started()
    assert record.state == SessionState.HANDSHAKE_STARTED

    material = SessionMaterial(
        encryption_key=b"a" * 32,
        authentication_key=b"b" * 32,
        transcript_hash=b"c" * 32,
    )
    record.attach_material(material)
    assert record.state == SessionState.KEYS_DERIVED

    record.activate()
    assert record.state == SessionState.ACTIVE
    assert record.is_active is True
    assert record.activated_at_utc is not None


def test_session_record_close_wipes_material() -> None:
    record = SessionRecord.create(
        role=SessionRole.RESPONDER,
        local_peer=_peer("local", 30),
        remote_peer=_peer("remote", 40),
    )
    record.mark_handshake_started()
    record.attach_material(
        SessionMaterial(
            encryption_key=b"a" * 32,
            authentication_key=b"b" * 32,
            transcript_hash=b"c" * 32,
        )
    )

    record.close()

    assert record.state == SessionState.CLOSED
    assert record.material is not None
    assert record.material.encryption_key == b""
    assert record.material.authentication_key == b""
    assert record.material.transcript_hash == b""


def test_session_record_fail_wipes_material_and_sets_reason() -> None:
    record = SessionRecord.create(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 50),
        remote_peer=_peer("remote", 60),
    )
    record.mark_handshake_started()
    record.attach_material(
        SessionMaterial(
            encryption_key=b"a" * 32,
            authentication_key=b"b" * 32,
            transcript_hash=b"c" * 32,
        )
    )

    record.fail("signature verification failed")

    assert record.state == SessionState.FAILED
    assert record.failure_reason == "signature verification failed"
    assert record.material is not None
    assert record.material.encryption_key == b""
    assert record.is_terminal is True


def test_session_record_rejects_invalid_transition() -> None:
    record = SessionRecord.create(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 70),
        remote_peer=_peer("remote", 80),
    )

    with pytest.raises(ValueError, match="invalid state transition"):
        record.activate()


def test_session_record_expiration_check() -> None:
    record = SessionRecord.create(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 90),
        remote_peer=_peer("remote", 100),
        ttl_seconds=1,
    )

    future = datetime.now(UTC) + timedelta(seconds=2)
    assert record.is_expired(future) is True


def test_handshake_transcript_digest_is_stable() -> None:
    transcript_a = HandshakeTranscript.create(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 11),
        remote_peer=_peer("remote", 22),
    )
    transcript_b = HandshakeTranscript.create(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 11),
        remote_peer=_peer("remote", 22),
    )

    assert transcript_a.serialize() == transcript_b.serialize()
    assert transcript_a.digest() == transcript_b.digest()
    assert len(transcript_a.digest()) == 32


def test_handshake_transcript_changes_when_role_changes() -> None:
    initiator = HandshakeTranscript.create(
        role=SessionRole.INITIATOR,
        local_peer=_peer("local", 1),
        remote_peer=_peer("remote", 2),
    )
    responder = HandshakeTranscript.create(
        role=SessionRole.RESPONDER,
        local_peer=_peer("local", 1),
        remote_peer=_peer("remote", 2),
    )

    assert initiator.digest() != responder.digest()
