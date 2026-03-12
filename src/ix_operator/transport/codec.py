from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from ix_operator.session.models import SessionMaterial
from ix_operator.transport.packet import (
    DEFAULT_PACKET_SIZE,
    MESSAGE_ID_SIZE,
    NONCE_SIZE,
    MessageType,
    Packet,
    PacketHeader,
)
from ix_operator.transport.state import SessionBindingError, TransportSessionState


class TransportCryptoBackend(Protocol):
    def random_nonce(self, length: int) -> bytes: ...
    def ciphertext_length(self, plaintext_length: int) -> int: ...
    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...
    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...


@dataclass(slots=True)
class PacketCodec:
    backend: TransportCryptoBackend

    def seal(
        self,
        *,
        state: TransportSessionState,
        material: SessionMaterial,
        message_type: MessageType,
        plaintext: bytes,
        flags: int = 0,
        packet_size: int = DEFAULT_PACKET_SIZE,
    ) -> Packet:
        material.validate()

        sequence_number = state.reserve_outbound_sequence()
        nonce = self.backend.random_nonce(NONCE_SIZE)
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"crypto backend returned nonce of invalid length: {len(nonce)}")

        message_id = _new_message_id()
        expected_ciphertext_length = self.backend.ciphertext_length(len(plaintext))
        if expected_ciphertext_length < 0:
            raise ValueError("ciphertext_length must be non-negative")

        header = PacketHeader(
            version=1,
            message_type=message_type,
            flags=flags,
            sequence_number=sequence_number,
            session_id=state.session_id,
            message_id=message_id,
            nonce=nonce,
            payload_length=expected_ciphertext_length,
        )

        ciphertext = self.backend.encrypt(
            material.encryption_key,
            nonce,
            plaintext,
            header.aad(),
        )
        if len(ciphertext) != expected_ciphertext_length:
            raise ValueError(
                "crypto backend ciphertext length did not match advertised ciphertext_length"
            )

        packet = Packet(
            header=PacketHeader(
                version=header.version,
                message_type=header.message_type,
                flags=header.flags,
                sequence_number=header.sequence_number,
                session_id=header.session_id,
                message_id=header.message_id,
                nonce=header.nonce,
                payload_length=len(ciphertext),
            ),
            ciphertext=ciphertext,
            packet_size=packet_size,
        )
        packet.validate()
        return packet

    def open(
        self,
        *,
        state: TransportSessionState,
        material: SessionMaterial,
        packet: Packet,
    ) -> bytes:
        material.validate()
        self._ensure_session_binding(state, packet)

        plaintext = self.backend.decrypt(
            material.encryption_key,
            packet.header.nonce,
            packet.ciphertext,
            packet.header.aad(),
        )
        state.register_inbound_packet(packet)
        return plaintext

    def _ensure_session_binding(
        self,
        state: TransportSessionState,
        packet: Packet,
    ) -> None:
        if packet.header.session_id != state.session_id:
            raise SessionBindingError("packet session_id mismatch")


def _new_message_id() -> bytes:
    message_id = uuid4().bytes
    if len(message_id) != MESSAGE_ID_SIZE:
        raise ValueError(f"generated message_id must be {MESSAGE_ID_SIZE} bytes")
    return message_id
