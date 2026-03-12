from __future__ import annotations

import hashlib

import pytest

from ix_operator.session import (
    HandshakeCoordinator,
    LocalSecrets,
    PeerIdentity,
    SessionMaterial,
    SessionRecord,
    SessionRole,
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

    def derive_material(self, shared_secret: bytes, transcript_hash: bytes) -> SessionMaterial:
        encryption_key = hashlib.sha256(shared_secret + b"enc" + transcript_hash).digest()
        authentication_key = hashlib.sha256(shared_secret + b"auth" + transcript_hash).digest()
        return SessionMaterial(
            encryption_key=encryption_key,
            authentication_key=authentication_key,
            transcript_hash=transcript_hash,
        )


def _identity(name: str, seed: int) -> tuple[PeerIdentity, LocalSecrets]:
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
    return peer, secrets


def test_full_handshake_round_trip_derives_matching_material() -> None:
    backend = FakeHandshakeCryptoBackend()
    coordinator = HandshakeCoordinator(backend)

    initiator_peer, initiator_secrets = _identity("initiator", 10)
    responder_peer, responder_secrets = _identity("responder", 30)
    shared_session_id = "sess-shared-alpha"

    initiator_session = SessionRecord.create(
        role=SessionRole.INITIATOR,
        local_peer=initiator_peer,
        remote_peer=responder_peer,
        session_id=shared_session_id,
    )
    responder_session = SessionRecord.create(
        role=SessionRole.RESPONDER,
        local_peer=responder_peer,
        remote_peer=initiator_peer,
        session_id=shared_session_id,
    )

    hello = coordinator.create_hello(initiator_session)
    response = coordinator.respond(
        session=responder_session,
        responder_secrets=responder_secrets,
        hello=hello,
    )
    initiator_material, ack = coordinator.finalize_initiator(
        session=initiator_session,
        initiator_secrets=initiator_secrets,
        hello=hello,
        response=response,
    )
    responder_material = coordinator.finalize_responder(
        session=responder_session,
        responder_secrets=responder_secrets,
        hello=hello,
        response=response,
        ack=ack,
    )

    assert initiator_material.encryption_key == responder_material.encryption_key
    assert initiator_material.authentication_key == responder_material.authentication_key
    assert initiator_material.transcript_hash == responder_material.transcript_hash
    assert len(initiator_material.encryption_key) == 32
    assert len(initiator_material.authentication_key) == 32


def test_canonical_transcript_hash_matches_across_roles() -> None:
    backend = FakeHandshakeCryptoBackend()
    coordinator = HandshakeCoordinator(backend)

    initiator_peer, _ = _identity("initiator", 50)
    responder_peer, _ = _identity("responder", 70)

    initiator_session = SessionRecord.create(
        role=SessionRole.INITIATOR,
        local_peer=initiator_peer,
        remote_peer=responder_peer,
    )
    responder_session = SessionRecord.create(
        role=SessionRole.RESPONDER,
        local_peer=responder_peer,
        remote_peer=initiator_peer,
    )

    assert (
        coordinator.canonical_transcript_hash(initiator_session)
        == coordinator.canonical_transcript_hash(responder_session)
    )


def test_responder_rejects_mismatched_hello_identity() -> None:
    backend = FakeHandshakeCryptoBackend()
    coordinator = HandshakeCoordinator(backend)

    initiator_peer, _ = _identity("initiator", 1)
    responder_peer, responder_secrets = _identity("responder", 2)
    shared_session_id = "sess-shared-beta"

    responder_session = SessionRecord.create(
        role=SessionRole.RESPONDER,
        local_peer=responder_peer,
        remote_peer=initiator_peer,
        session_id=shared_session_id,
    )

    hello = coordinator.create_hello(
        SessionRecord.create(
            role=SessionRole.INITIATOR,
            local_peer=initiator_peer,
            remote_peer=responder_peer,
            session_id=shared_session_id,
        )
    )
    tampered = type(hello)(
        session_id=hello.session_id,
        initiator_peer_id=hello.initiator_peer_id,
        signing_public_key=b"x" * 32,
        exchange_public_key=hello.exchange_public_key,
        challenge=hello.challenge,
        transcript_hash=hello.transcript_hash,
    )

    with pytest.raises(ValueError, match="signing_public_key mismatch"):
        coordinator.respond(
            session=responder_session,
            responder_secrets=responder_secrets,
            hello=tampered,
        )


def test_initiator_rejects_bad_response_signature() -> None:
    backend = FakeHandshakeCryptoBackend()
    coordinator = HandshakeCoordinator(backend)

    initiator_peer, initiator_secrets = _identity("initiator", 11)
    responder_peer, responder_secrets = _identity("responder", 22)
    shared_session_id = "sess-shared-gamma"

    initiator_session = SessionRecord.create(
        role=SessionRole.INITIATOR,
        local_peer=initiator_peer,
        remote_peer=responder_peer,
        session_id=shared_session_id,
    )
    responder_session = SessionRecord.create(
        role=SessionRole.RESPONDER,
        local_peer=responder_peer,
        remote_peer=initiator_peer,
        session_id=shared_session_id,
    )

    hello = coordinator.create_hello(initiator_session)
    response = coordinator.respond(
        session=responder_session,
        responder_secrets=responder_secrets,
        hello=hello,
    )
    tampered_response = type(response)(
        session_id=response.session_id,
        responder_peer_id=response.responder_peer_id,
        signing_public_key=response.signing_public_key,
        exchange_public_key=response.exchange_public_key,
        responder_challenge=response.responder_challenge,
        transcript_hash=response.transcript_hash,
        signature=b"z" * 64,
    )

    with pytest.raises(ValueError, match="response signature verification failed"):
        coordinator.finalize_initiator(
            session=initiator_session,
            initiator_secrets=initiator_secrets,
            hello=hello,
            response=tampered_response,
        )
