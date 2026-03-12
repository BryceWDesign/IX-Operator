from __future__ import annotations

import pytest

from ix_operator.transport import (
    DEFAULT_PACKET_SIZE,
    HEADER_SIZE,
    MESSAGE_ID_SIZE,
    NONCE_SIZE,
    SESSION_ID_FIELD_SIZE,
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


def test_packet_header_preserves_distinct_fields_without_overlap() -> None:
    header = PacketHeader(
        version=1,
        message_type=MessageType.HANDSHAKE,
        flags=9,
        sequence_number=123456,
        session_id="sess-layout",
        message_id=bytes(range(16)),
        nonce=bytes(range(100, 112)),
        payload_length=321,
    )

    encoded = header.to_bytes()
    decoded = PacketHeader.from_bytes(encoded)

    assert decoded.message_id == bytes(range(16))
    assert decoded.nonce == bytes(range(100, 112))
    assert decoded.payload_length == 321


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


def test_packet_accepts_derived_channel_session_id_length() -> None:
    channel_session_id = "chan-" + ("a" * 32)

    packet = build_packet(
        message_type=MessageType.DATA,
        session_id=channel_session_id,
        sequence_number=1,
        nonce=b"n" * NONCE_SIZE,
        ciphertext=b"sealed",
    )

    decoded = Packet.from_bytes(packet.to_bytes())

    assert decoded.header.session_id == channel_session_id
    assert len(channel_session_id.encode("utf-8")) <= SESSION_ID_FIELD_SIZE


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
    header[4:8] = (1).to_bytes(4, "big")
    header[8:10] = (0).to_bytes(2, "big")
    header[10 : 10 + SESSION_ID_FIELD_SIZE] = b"sess-x".ljust(SESSION_ID_FIELD_SIZE, b"\x00")
    header[50:66] = b"m" * 16
    header[66:78] = b"n" * 12

    with pytest.raises(ValueError, match="unknown message type: 99"):
        PacketHeader.from_bytes(bytes(header))


def test_packet_rejects_session_id_too_long() -> None:
    with pytest.raises(ValueError, match=f"session_id exceeds {SESSION_ID_FIELD_SIZE} bytes"):
        PacketHeader(
            version=1,
            message_type=MessageType.DATA,
            flags=0,
            sequence_number=1,
            session_id="s" * (SESSION_ID_FIELD_SIZE + 1),
            message_id=b"a" * MESSAGE_ID_SIZE,
            nonce=b"b" * NONCE_SIZE,
            payload_length=5,
        ).to_bytes()


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
