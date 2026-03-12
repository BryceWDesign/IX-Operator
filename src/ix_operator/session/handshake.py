from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ix_operator.session.models import SessionMaterial, SessionRecord, SessionRole
from ix_operator.session.transcript import HandshakeTranscript


CHALLENGE_LEN = 32
SIGNATURE_LEN = 64


class HandshakeCryptoBackend(Protocol):
    def random_bytes(self, length: int) -> bytes: ...
    def sign(self, private_key: bytes, message: bytes) -> bytes: ...
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...
    def shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes: ...
    def derive_material(self, shared_secret: bytes, transcript_hash: bytes) -> SessionMaterial: ...


@dataclass(frozen=True, slots=True)
class LocalSecrets:
    signing_private_key: bytes
    exchange_private_key: bytes

    def validate(self) -> None:
        if len(self.signing_private_key) != 32:
            raise ValueError("signing_private_key must be 32 bytes")
        if len(self.exchange_private_key) != 32:
            raise ValueError("exchange_private_key must be 32 bytes")


@dataclass(frozen=True, slots=True)
class HandshakeHello:
    session_id: str
    initiator_peer_id: str
    signing_public_key: bytes
    exchange_public_key: bytes
    challenge: bytes
    transcript_hash: bytes

    def validate(self) -> None:
        if not self.session_id.strip():
            raise ValueError("session_id must not be empty")
        if not self.initiator_peer_id.strip():
            raise ValueError("initiator_peer_id must not be empty")
        if len(self.signing_public_key) != 32:
            raise ValueError("signing_public_key must be 32 bytes")
        if len(self.exchange_public_key) != 32:
            raise ValueError("exchange_public_key must be 32 bytes")
        if len(self.challenge) != CHALLENGE_LEN:
            raise ValueError("challenge must be 32 bytes")
        if len(self.transcript_hash) != 32:
            raise ValueError("transcript_hash must be 32 bytes")


@dataclass(frozen=True, slots=True)
class HandshakeResponse:
    session_id: str
    responder_peer_id: str
    signing_public_key: bytes
    exchange_public_key: bytes
    responder_challenge: bytes
    transcript_hash: bytes
    signature: bytes

    def validate(self) -> None:
        if not self.session_id.strip():
            raise ValueError("session_id must not be empty")
        if not self.responder_peer_id.strip():
            raise ValueError("responder_peer_id must not be empty")
        if len(self.signing_public_key) != 32:
            raise ValueError("signing_public_key must be 32 bytes")
        if len(self.exchange_public_key) != 32:
            raise ValueError("exchange_public_key must be 32 bytes")
        if len(self.responder_challenge) != CHALLENGE_LEN:
            raise ValueError("responder_challenge must be 32 bytes")
        if len(self.transcript_hash) != 32:
            raise ValueError("transcript_hash must be 32 bytes")
        if len(self.signature) != SIGNATURE_LEN:
            raise ValueError("signature must be 64 bytes")


@dataclass(frozen=True, slots=True)
class HandshakeAck:
    session_id: str
    transcript_hash: bytes
    signature: bytes

    def validate(self) -> None:
        if not self.session_id.strip():
            raise ValueError("session_id must not be empty")
        if len(self.transcript_hash) != 32:
            raise ValueError("transcript_hash must be 32 bytes")
        if len(self.signature) != SIGNATURE_LEN:
            raise ValueError("signature must be 64 bytes")


class HandshakeCoordinator:
    def __init__(self, backend: HandshakeCryptoBackend) -> None:
        self._backend = backend

    def canonical_transcript_hash(self, session: SessionRecord) -> bytes:
        if session.role == SessionRole.INITIATOR:
            initiator_peer = session.local_peer
            responder_peer = session.remote_peer
        else:
            initiator_peer = session.remote_peer
            responder_peer = session.local_peer

        transcript = HandshakeTranscript.create(
            role=SessionRole.INITIATOR,
            local_peer=initiator_peer,
            remote_peer=responder_peer,
        )
        return transcript.digest()

    def create_hello(self, session: SessionRecord) -> HandshakeHello:
        if session.role != SessionRole.INITIATOR:
            raise ValueError("only initiator sessions can create hello messages")

        transcript_hash = self.canonical_transcript_hash(session)
        challenge = self._backend.random_bytes(CHALLENGE_LEN)

        hello = HandshakeHello(
            session_id=session.session_id,
            initiator_peer_id=session.local_peer.peer_id,
            signing_public_key=session.local_peer.signing_public_key,
            exchange_public_key=session.local_peer.exchange_public_key,
            challenge=challenge,
            transcript_hash=transcript_hash,
        )
        hello.validate()
        return hello

    def respond(
        self,
        *,
        session: SessionRecord,
        responder_secrets: LocalSecrets,
        hello: HandshakeHello,
    ) -> HandshakeResponse:
        if session.role != SessionRole.RESPONDER:
            raise ValueError("only responder sessions can answer hello messages")

        responder_secrets.validate()
        hello.validate()

        self._validate_common_bindings(session, hello.session_id, hello.transcript_hash)
        self._require_expected_remote_identity(
            session=session,
            peer_id=hello.initiator_peer_id,
            signing_public_key=hello.signing_public_key,
            exchange_public_key=hello.exchange_public_key,
        )

        responder_challenge = self._backend.random_bytes(CHALLENGE_LEN)
        signature = self._backend.sign(
            responder_secrets.signing_private_key,
            _response_message(
                transcript_hash=hello.transcript_hash,
                initiator_challenge=hello.challenge,
                responder_challenge=responder_challenge,
            ),
        )

        response = HandshakeResponse(
            session_id=session.session_id,
            responder_peer_id=session.local_peer.peer_id,
            signing_public_key=session.local_peer.signing_public_key,
            exchange_public_key=session.local_peer.exchange_public_key,
            responder_challenge=responder_challenge,
            transcript_hash=hello.transcript_hash,
            signature=signature,
        )
        response.validate()
        return response

    def finalize_initiator(
        self,
        *,
        session: SessionRecord,
        initiator_secrets: LocalSecrets,
        hello: HandshakeHello,
        response: HandshakeResponse,
    ) -> tuple[SessionMaterial, HandshakeAck]:
        if session.role != SessionRole.INITIATOR:
            raise ValueError("only initiator sessions can finalize initiator-side handshakes")

        initiator_secrets.validate()
        hello.validate()
        response.validate()

        self._validate_common_bindings(session, hello.session_id, hello.transcript_hash)
        self._validate_common_bindings(session, response.session_id, response.transcript_hash)

        self._require_expected_remote_identity(
            session=session,
            peer_id=response.responder_peer_id,
            signing_public_key=response.signing_public_key,
            exchange_public_key=response.exchange_public_key,
        )

        verified = self._backend.verify(
            response.signing_public_key,
            _response_message(
                transcript_hash=response.transcript_hash,
                initiator_challenge=hello.challenge,
                responder_challenge=response.responder_challenge,
            ),
            response.signature,
        )
        if not verified:
            raise ValueError("response signature verification failed")

        shared_secret = self._backend.shared_secret(
            initiator_secrets.exchange_private_key,
            response.exchange_public_key,
        )
        material = self._backend.derive_material(shared_secret, response.transcript_hash)
        material.validate()

        ack_signature = self._backend.sign(
            initiator_secrets.signing_private_key,
            _ack_message(
                transcript_hash=response.transcript_hash,
                initiator_challenge=hello.challenge,
                responder_challenge=response.responder_challenge,
            ),
        )

        ack = HandshakeAck(
            session_id=session.session_id,
            transcript_hash=response.transcript_hash,
            signature=ack_signature,
        )
        ack.validate()

        return material, ack

    def finalize_responder(
        self,
        *,
        session: SessionRecord,
        responder_secrets: LocalSecrets,
        hello: HandshakeHello,
        response: HandshakeResponse,
        ack: HandshakeAck,
    ) -> SessionMaterial:
        if session.role != SessionRole.RESPONDER:
            raise ValueError("only responder sessions can finalize responder-side handshakes")

        responder_secrets.validate()
        hello.validate()
        response.validate()
        ack.validate()

        self._validate_common_bindings(session, hello.session_id, hello.transcript_hash)
        self._validate_common_bindings(session, response.session_id, response.transcript_hash)
        self._validate_common_bindings(session, ack.session_id, ack.transcript_hash)

        self._require_expected_remote_identity(
            session=session,
            peer_id=hello.initiator_peer_id,
            signing_public_key=hello.signing_public_key,
            exchange_public_key=hello.exchange_public_key,
        )

        verified = self._backend.verify(
            hello.signing_public_key,
            _ack_message(
                transcript_hash=ack.transcript_hash,
                initiator_challenge=hello.challenge,
                responder_challenge=response.responder_challenge,
            ),
            ack.signature,
        )
        if not verified:
            raise ValueError("ack signature verification failed")

        shared_secret = self._backend.shared_secret(
            responder_secrets.exchange_private_key,
            hello.exchange_public_key,
        )
        material = self._backend.derive_material(shared_secret, ack.transcript_hash)
        material.validate()
        return material

    def _validate_common_bindings(
        self,
        session: SessionRecord,
        session_id: str,
        transcript_hash: bytes,
    ) -> None:
        if session.session_id != session_id:
            raise ValueError("session_id mismatch")
        if self.canonical_transcript_hash(session) != transcript_hash:
            raise ValueError("transcript hash mismatch")

    def _require_expected_remote_identity(
        self,
        *,
        session: SessionRecord,
        peer_id: str,
        signing_public_key: bytes,
        exchange_public_key: bytes,
    ) -> None:
        expected = session.remote_peer
        if expected.peer_id != peer_id:
            raise ValueError("peer_id mismatch")
        if expected.signing_public_key != signing_public_key:
            raise ValueError("signing_public_key mismatch")
        if expected.exchange_public_key != exchange_public_key:
            raise ValueError("exchange_public_key mismatch")


def _response_message(
    *,
    transcript_hash: bytes,
    initiator_challenge: bytes,
    responder_challenge: bytes,
) -> bytes:
    return _framed_join(
        b"ix-operator-response-v1",
        transcript_hash,
        initiator_challenge,
        responder_challenge,
    )


def _ack_message(
    *,
    transcript_hash: bytes,
    initiator_challenge: bytes,
    responder_challenge: bytes,
) -> bytes:
    return _framed_join(
        b"ix-operator-ack-v1",
        transcript_hash,
        initiator_challenge,
        responder_challenge,
    )


def _framed_join(*parts: bytes) -> bytes:
    framed: list[bytes] = []
    for part in parts:
        if len(part) > 65535:
            raise ValueError("framed part too large")
        framed.append(len(part).to_bytes(2, "big") + part)
    return b"".join(framed)
