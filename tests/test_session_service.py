from __future__ import annotations

import hashlib

import pytest

from ix_operator.session import (
    LocalSecrets,
    PeerIdentity,
    SessionEndpoint,
    SessionManager,
    SessionRole,
    SessionService,
    SessionState,
    derive_channel_session_id,
)


class FakeHandshakeCryptoBackend:
    def __init__(self) -> None:
        self._counter = 0

    def random_bytes(self, length: int) -> bytes:
        self._counter += 1
        seed = f"rng-{self._counter}".encode("utf-8")
        output = b""
        while len(output) < length:
            seed = hashlib.sha256(seed).digest()
            output += seed
        return output[:length]

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return hashlib.sha512(private_key + message).digest()

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        expected = hashlib.sha512(public_key + message).digest()
        return expected == signature

    def shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        ordered = sorted([private_key, peer_public_key])
        return hashlib.sha256(ordered[0] + ordered[1]).digest()

    def derive_material(self, shared_secret: bytes, transcript_hash: bytes):
        encryption_key = hashlib.sha256(shared_secret + b"enc" + transcript_hash).digest()
        authentication_key = hashlib.sha256(shared_secret + b"auth" + transcript_hash).digest()
        from ix_operator.session import SessionMaterial

        return SessionMaterial(
            encryption_key=encryption_key,
            authentication_key=authentication_key,
            transcript_hash=transcript_hash,
        )


def _endpoint(name: str, seed: int) -> SessionEndpoint:
    signing_private_key = bytes([seed]) * 32
    exchange_private_key = bytes([seed + 1]) * 32

    peer = PeerIdentity(
        peer_id=name,
        signing_public_key=signing_private_key,
        exchange_public_key=exchange_private_key,
    )
    secrets = LocalSecrets(
        signing_private_key=signing_private_key,
        exchange_private_key=exchange_private_key,
    )
    return SessionEndpoint(
        local_peer=peer,
        local_secrets=secrets,
        manager=SessionManager(),
    )


def test_establish_pair_creates_active_sessions_and_matching_material() -> None:
    service = SessionService(FakeHandshakeCryptoBackend())

    initiator = _endpoint("node-alpha", 10)
    responder = _endpoint("node-beta", 30)

    established = service.establish_pair(
        initiator=initiator,
        responder=responder,
        ttl_seconds=120,
    )

    assert established.channel_session_id.startswith("chan-")
    assert established.initiator_session.state == SessionState.ACTIVE
    assert established.responder_session.state == SessionState.ACTIVE
    assert established.initiator_session.role == SessionRole.INITIATOR
    assert established.responder_session.role == SessionRole.RESPONDER

    assert (
        established.initiator_material.encryption_key
        == established.responder_material.encryption_key
    )
    assert (
        established.initiator_material.authentication_key
        == established.responder_material.authentication_key
    )
    assert (
        established.initiator_material.transcript_hash
        == established.responder_material.transcript_hash
    )

    initiator_active = initiator.manager.get_active_session_for_peer("node-beta")
    responder_active = responder.manager.get_active_session_for_peer("node-alpha")

    assert initiator_active is not None
    assert responder_active is not None
    assert initiator_active.state == SessionState.ACTIVE
    assert responder_active.state == SessionState.ACTIVE


def test_channel_session_id_is_deterministic_for_same_transcript_hash() -> None:
    transcript_hash = b"x" * 32

    first = derive_channel_session_id(transcript_hash)
    second = derive_channel_session_id(transcript_hash)

    assert first == second
    assert first == "chan-" + (b"x" * 16).hex()


def test_channel_session_id_rejects_invalid_hash_length() -> None:
    with pytest.raises(ValueError, match="transcript_hash must be 32 bytes"):
        derive_channel_session_id(b"short")


def test_established_pair_validation_rejects_mismatched_materials() -> None:
    service = SessionService(FakeHandshakeCryptoBackend())
    initiator = _endpoint("node-a", 1)
    responder = _endpoint("node-b", 2)

    established = service.establish_pair(initiator=initiator, responder=responder)

    tampered = type(established)(
        channel_session_id=established.channel_session_id,
        initiator_session=established.initiator_session,
        responder_session=established.responder_session,
        initiator_material=established.initiator_material,
        responder_material=type(established.responder_material)(
            encryption_key=b"z" * 32,
            authentication_key=established.responder_material.authentication_key,
            transcript_hash=established.responder_material.transcript_hash,
        ),
    )

    with pytest.raises(ValueError, match="initiator and responder encryption keys do not match"):
        tampered.validate()
