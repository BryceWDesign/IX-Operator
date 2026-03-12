from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from uuid import uuid4

from ix_operator.session.handshake import (
    HandshakeCoordinator,
    HandshakeCryptoBackend,
    LocalSecrets,
)
from ix_operator.session.manager import SessionManager
from ix_operator.session.models import (
    DEFAULT_SESSION_TTL_SECONDS,
    PeerIdentity,
    SessionMaterial,
    SessionRecord,
    SessionRole,
)


@dataclass(frozen=True, slots=True)
class SessionEndpoint:
    local_peer: PeerIdentity
    local_secrets: LocalSecrets
    manager: SessionManager

    def validate(self) -> None:
        self.local_peer.validate()
        self.local_secrets.validate()


@dataclass(frozen=True, slots=True)
class EstablishedSessionPair:
    channel_session_id: str
    initiator_session: SessionRecord
    responder_session: SessionRecord
    initiator_material: SessionMaterial
    responder_material: SessionMaterial

    def validate(self) -> None:
        if not self.channel_session_id.strip():
            raise ValueError("channel_session_id must not be empty")

        self.initiator_material.validate()
        self.responder_material.validate()

        if self.initiator_material.encryption_key != self.responder_material.encryption_key:
            raise ValueError("initiator and responder encryption keys do not match")

        if self.initiator_material.authentication_key != self.responder_material.authentication_key:
            raise ValueError("initiator and responder authentication keys do not match")

        if self.initiator_material.transcript_hash != self.responder_material.transcript_hash:
            raise ValueError("initiator and responder transcript hashes do not match")


class SessionService:
    def __init__(self, backend: HandshakeCryptoBackend) -> None:
        self._coordinator = HandshakeCoordinator(backend)

    def establish_pair(
        self,
        *,
        initiator: SessionEndpoint,
        responder: SessionEndpoint,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    ) -> EstablishedSessionPair:
        initiator.validate()
        responder.validate()

        shared_handshake_session_id = _new_handshake_session_id()

        initiator_record = initiator.manager.create_session(
            role=SessionRole.INITIATOR,
            local_peer=initiator.local_peer,
            remote_peer=responder.local_peer,
            ttl_seconds=ttl_seconds,
            session_id=shared_handshake_session_id,
        )
        responder_record = responder.manager.create_session(
            role=SessionRole.RESPONDER,
            local_peer=responder.local_peer,
            remote_peer=initiator.local_peer,
            ttl_seconds=ttl_seconds,
            session_id=shared_handshake_session_id,
        )

        initiator_record = initiator.manager.start_handshake(initiator_record.session_id)
        responder_record = responder.manager.start_handshake(responder_record.session_id)

        hello = self._coordinator.create_hello(initiator_record)
        response = self._coordinator.respond(
            session=responder_record,
            responder_secrets=responder.local_secrets,
            hello=hello,
        )
        initiator_material, ack = self._coordinator.finalize_initiator(
            session=initiator_record,
            initiator_secrets=initiator.local_secrets,
            hello=hello,
            response=response,
        )
        responder_material = self._coordinator.finalize_responder(
            session=responder_record,
            responder_secrets=responder.local_secrets,
            hello=hello,
            response=response,
            ack=ack,
        )

        initiator_record = initiator.manager.attach_material(
            initiator_record.session_id,
            deepcopy(initiator_material),
        )
        responder_record = responder.manager.attach_material(
            responder_record.session_id,
            deepcopy(responder_material),
        )

        initiator_record = initiator.manager.activate_session(initiator_record.session_id)
        responder_record = responder.manager.activate_session(responder_record.session_id)

        established = EstablishedSessionPair(
            channel_session_id=derive_channel_session_id(initiator_material.transcript_hash),
            initiator_session=initiator_record,
            responder_session=responder_record,
            initiator_material=deepcopy(initiator_material),
            responder_material=deepcopy(responder_material),
        )
        established.validate()
        return established


def derive_channel_session_id(transcript_hash: bytes) -> str:
    if len(transcript_hash) != 32:
        raise ValueError("transcript_hash must be 32 bytes")
    return f"chan-{transcript_hash[:16].hex()}"


def _new_handshake_session_id() -> str:
    return f"sess-{uuid4().hex}"
