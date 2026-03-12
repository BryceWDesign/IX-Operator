from __future__ import annotations

import pytest

from ix_operator.transport import (
    DEFAULT_PACKET_SIZE,
    HEADER_SIZE,
    MESSAGE_ID_SIZE,
    NONCE_SIZE,
    MessageType,
    Packet,
    PacketHeader,
    build_packet,
    packet_fingerprint,
)


def test_packet_header_round_trip() -> None:
    header = PacketHeader(
        version=1,
        message_type=MessageType.DATA,
        flags=3,
        sequence_number=42,
        session_id="sess-123",
        message_id=b"a" * MESSAGE_ID_SIZE,
        nonce=b"b" * NONCE_SIZE,
        payload_length=99,
    )

    encoded = header.to_bytes()
    decoded = PacketHeader.from_bytes(encoded)

    assert decoded.version == 1
    assert decoded.message_type == MessageType.DATA
    assert decoded.flags == 3
    assert decoded.sequence_number == 42
    assert decoded.session_id == "sess-123"
    assert decoded.message_id == b"a" * MESSAGE_ID_SIZE
    assert decoded.nonce == b"b" * NONCE_SIZE
    assert decoded.payload_length == 99


def test_packet_round_trip_fixed_size() -> None:
    packet = build_packet(
        message_type=MessageType.DATA,
        session_id="sess-abc",
        sequence_number=7,
        nonce=b"n" * NONCE_SIZE,
        ciphertext=b"sealed-payload",
        packet_size=DEFAULT_PACKET_SIZE,
    )

    encoded = packet.to_bytes()
    decoded = Packet.from_bytes(encoded)

    assert len(encoded) == DEFAULT_PACKET_SIZE
    assert decoded.header.session_id == "sess-abc"
    assert decoded.header.sequence_number == 7
    assert decoded.ciphertext == b"sealed-payload"
    assert decoded.packet_size == DEFAULT_PACKET_SIZE


def test_packet_rejects_payload_over_capacity() -> None:
    oversized_ciphertext = b"x" * (DEFAULT_PACKET_SIZE - HEADER_SIZE + 1)

    with pytest.raises(ValueError, match="ciphertext exceeds packet payload capacity"):
        build_packet(
            message_type=MessageType.DATA,
            session_id="sess-oversized",
            sequence_number=1,
            nonce=b"n" * NONCE_SIZE,
            ciphertext=oversized_ciphertext,
            packet_size=DEFAULT_PACKET_SIZE,
        )


def test_packet_rejects_unknown_message_type() -> None:
    header = bytearray(HEADER_SIZE)
    header[0] = 1
    header[1] = 99
    header[2] = 0
    header[3:7] = (1).to_bytes(4, "big")
    header[7:47] = b"sess-x".ljust(40, b"\x00")
    header[47:63] = b"m" * 16
    header[44:56] = b"n" * 12
    header[57:59] = (0).to_bytes(2, "big")

    with pytest.raises(ValueError, match="unknown message type: 99"):
        PacketHeader.from_bytes(bytes(header))


def test_packet_fingerprint_is_stable_for_same_bytes() -> None:
    packet = build_packet(
        message_type=MessageType.ACK,
        session_id="sess-xyz",
        sequence_number=9,
        nonce=b"q" * NONCE_SIZE,
        ciphertext=b"ciphertext",
    )
    encoded = packet.to_bytes()

    assert packet_fingerprint(encoded) == packet_fingerprint(encoded)


def test_header_aad_matches_serialized_header() -> None:
    header = PacketHeader(
        version=1,
        message_type=MessageType.HANDSHAKE,
        flags=0,
        sequence_number=5,
        session_id="sess-aad",
        message_id=b"z" * MESSAGE_ID_SIZE,
        nonce=b"y" * NONCE_SIZE,
        payload_length=12,
    )

    assert header.aad() == header.to_bytes()
