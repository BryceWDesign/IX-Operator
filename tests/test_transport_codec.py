from __future__ import annotations

import hashlib

import pytest

from ix_operator.session import SessionMaterial
from ix_operator.transport import (
    NONCE_SIZE,
    MessageType,
    Packet,
    PacketCodec,
    ReplayRejectedError,
    SessionBindingError,
    TransportSessionState,
)


class FakeTransportCryptoBackend:
    TAG_LEN = 16

    def __init__(self) -> None:
        self._counter = 0

    def random_nonce(self, length: int) -> bytes:
        self._counter += 1
        seed = hashlib.sha256(f"nonce-{self._counter}".encode("utf-8")).digest()
        return seed[:length]

    def ciphertext_length(self, plaintext_length: int) -> int:
        return plaintext_length + self.TAG_LEN

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        keystream = hashlib.sha256(key + nonce).digest()
        body = bytes(
            byte ^ keystream[index % len(keystream)]
            for index, byte in enumerate(plaintext)
        )
        tag = hashlib.sha256(key + nonce + aad + plaintext).digest()[: self.TAG_LEN]
        return body + tag

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(ciphertext) < self.TAG_LEN:
            raise ValueError("ciphertext too short")

        body = ciphertext[: -self.TAG_LEN]
        tag = ciphertext[-self.TAG_LEN :]

        keystream = hashlib.sha256(key + nonce).digest()
        plaintext = bytes(
            byte ^ keystream[index % len(keystream)]
            for index, byte in enumerate(body)
        )
        expected_tag = hashlib.sha256(key + nonce + aad + plaintext).digest()[: self.TAG_LEN]
        if expected_tag != tag:
            raise ValueError("integrity check failed")

        return plaintext


def _material() -> SessionMaterial:
    return SessionMaterial(
        encryption_key=b"k" * 32,
        authentication_key=b"a" * 32,
        transcript_hash=b"t" * 32,
    )


def test_seal_and_open_round_trip() -> None:
    codec = PacketCodec(FakeTransportCryptoBackend())
    outbound_state = TransportSessionState(session_id="sess-alpha")
    inbound_state = TransportSessionState(session_id="sess-alpha")

    packet = codec.seal(
        state=outbound_state,
        material=_material(),
        message_type=MessageType.DATA,
        plaintext=b"hello operator",
    )
    plaintext = codec.open(
        state=inbound_state,
        material=_material(),
        packet=Packet.from_bytes(packet.to_bytes()),
    )

    assert plaintext == b"hello operator"
    assert packet.header.sequence_number == 0
    assert len(packet.header.nonce) == NONCE_SIZE


def test_seal_advances_outbound_sequence() -> None:
    codec = PacketCodec(FakeTransportCryptoBackend())
    state = TransportSessionState(session_id="sess-alpha")

    first = codec.seal(
        state=state,
        material=_material(),
        message_type=MessageType.DATA,
        plaintext=b"first",
    )
    second = codec.seal(
        state=state,
        material=_material(),
        message_type=MessageType.DATA,
        plaintext=b"second",
    )

    assert first.header.sequence_number == 0
    assert second.header.sequence_number == 1


def test_open_rejects_session_binding_mismatch() -> None:
    codec = PacketCodec(FakeTransportCryptoBackend())
    outbound_state = TransportSessionState(session_id="sess-alpha")
    inbound_state = TransportSessionState(session_id="sess-beta")

    packet = codec.seal(
        state=outbound_state,
        material=_material(),
        message_type=MessageType.DATA,
        plaintext=b"bound message",
    )

    with pytest.raises(SessionBindingError, match="packet session_id mismatch"):
        codec.open(
            state=inbound_state,
            material=_material(),
            packet=Packet.from_bytes(packet.to_bytes()),
        )


def test_open_rejects_tampered_ciphertext() -> None:
    codec = PacketCodec(FakeTransportCryptoBackend())
    outbound_state = TransportSessionState(session_id="sess-alpha")
    inbound_state = TransportSessionState(session_id="sess-alpha")

    packet = codec.seal(
        state=outbound_state,
        material=_material(),
        message_type=MessageType.DATA,
        plaintext=b"do not tamper",
    )
    encoded = bytearray(packet.to_bytes())
    encoded[-20] ^= 0x01
    tampered_packet = Packet.from_bytes(bytes(encoded))

    with pytest.raises(ValueError, match="integrity check failed"):
        codec.open(
            state=inbound_state,
            material=_material(),
            packet=tampered_packet,
        )


def test_open_rejects_replayed_packet() -> None:
    codec = PacketCodec(FakeTransportCryptoBackend())
    outbound_state = TransportSessionState(session_id="sess-alpha")
    inbound_state = TransportSessionState(session_id="sess-alpha")

    packet = codec.seal(
        state=outbound_state,
        material=_material(),
        message_type=MessageType.DATA,
        plaintext=b"one-shot message",
    )
    received_packet = Packet.from_bytes(packet.to_bytes())

    first_plaintext = codec.open(
        state=inbound_state,
        material=_material(),
        packet=received_packet,
    )
    assert first_plaintext == b"one-shot message"

    with pytest.raises(ReplayRejectedError):
        codec.open(
            state=inbound_state,
            material=_material(),
            packet=received_packet,
        )
