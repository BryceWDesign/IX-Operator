from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
from uuid import uuid4


PROTOCOL_VERSION = 1
HEADER_SIZE = 64
DEFAULT_PACKET_SIZE = 1024
MAX_PACKET_SIZE = 65535
MIN_PACKET_SIZE = 256
SESSION_ID_FIELD_SIZE = 24
MESSAGE_ID_SIZE = 16
NONCE_SIZE = 12
RESERVED_SIZE = 2

_VERSION_OFFSET = 0
_MESSAGE_TYPE_OFFSET = 1
_FLAGS_OFFSET = 2
_RESERVED0_OFFSET = 3
_SEQUENCE_START = 4
_SEQUENCE_END = 8
_PAYLOAD_LENGTH_START = 8
_PAYLOAD_LENGTH_END = 10
_SESSION_ID_START = 10
_SESSION_ID_END = _SESSION_ID_START + SESSION_ID_FIELD_SIZE
_MESSAGE_ID_START = _SESSION_ID_END
_MESSAGE_ID_END = _MESSAGE_ID_START + MESSAGE_ID_SIZE
_NONCE_START = _MESSAGE_ID_END
_NONCE_END = _NONCE_START + NONCE_SIZE
_RESERVED_START = _NONCE_END
_RESERVED_END = _RESERVED_START + RESERVED_SIZE


class MessageType(IntEnum):
    HANDSHAKE = 1
    DATA = 2
    ACK = 3
    CLOSE = 4


@dataclass(frozen=True, slots=True)
class PacketHeader:
    version: int
    message_type: MessageType
    flags: int
    sequence_number: int
    session_id: str
    message_id: bytes
    nonce: bytes
    payload_length: int

    def validate(self) -> None:
        if self.version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {self.version}")
        if not (0 <= self.flags <= 255):
            raise ValueError("flags must be within 0..255")
        if not (0 <= self.sequence_number <= 0xFFFFFFFF):
            raise ValueError("sequence_number must be within 0..4294967295")
        if not self.session_id.strip():
            raise ValueError("session_id must not be empty")
        if len(self.session_id.encode("utf-8")) > SESSION_ID_FIELD_SIZE:
            raise ValueError(f"session_id exceeds {SESSION_ID_FIELD_SIZE} bytes")
        if len(self.message_id) != MESSAGE_ID_SIZE:
            raise ValueError(f"message_id must be {MESSAGE_ID_SIZE} bytes")
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
        if not (0 <= self.payload_length <= 0xFFFF):
            raise ValueError("payload_length must be within 0..65535")

    def to_bytes(self) -> bytes:
        self.validate()

        session_bytes = self.session_id.encode("utf-8")
        padded_session = session_bytes.ljust(SESSION_ID_FIELD_SIZE, b"\x00")

        output = bytearray(HEADER_SIZE)
        output[_VERSION_OFFSET] = self.version
        output[_MESSAGE_TYPE_OFFSET] = int(self.message_type)
        output[_FLAGS_OFFSET] = self.flags
        output[_RESERVED0_OFFSET] = 0
        output[_SEQUENCE_START:_SEQUENCE_END] = self.sequence_number.to_bytes(4, "big")
        output[_PAYLOAD_LENGTH_START:_PAYLOAD_LENGTH_END] = self.payload_length.to_bytes(2, "big")
        output[_SESSION_ID_START:_SESSION_ID_END] = padded_session
        output[_MESSAGE_ID_START:_MESSAGE_ID_END] = self.message_id
        output[_NONCE_START:_NONCE_END] = self.nonce
        output[_RESERVED_START:_RESERVED_END] = b"\x00" * RESERVED_SIZE

        return bytes(output)

    @classmethod
    def from_bytes(cls, data: bytes) -> "PacketHeader":
        if len(data) != HEADER_SIZE:
            raise ValueError(f"header must be exactly {HEADER_SIZE} bytes")

        version = data[_VERSION_OFFSET]
        message_type_raw = data[_MESSAGE_TYPE_OFFSET]
        flags = data[_FLAGS_OFFSET]
        sequence_number = int.from_bytes(data[_SEQUENCE_START:_SEQUENCE_END], "big")
        payload_length = int.from_bytes(data[_PAYLOAD_LENGTH_START:_PAYLOAD_LENGTH_END], "big")
        session_id = data[_SESSION_ID_START:_SESSION_ID_END].rstrip(b"\x00").decode("utf-8")
        message_id = data[_MESSAGE_ID_START:_MESSAGE_ID_END]
        nonce = data[_NONCE_START:_NONCE_END]

        try:
            message_type = MessageType(message_type_raw)
        except ValueError as exc:
            raise ValueError(f"unknown message type: {message_type_raw}") from exc

        header = cls(
            version=version,
            message_type=message_type,
            flags=flags,
            sequence_number=sequence_number,
            session_id=session_id,
            message_id=message_id,
            nonce=nonce,
            payload_length=payload_length,
        )
        header.validate()
        return header

    def aad(self) -> bytes:
        return self.to_bytes()


@dataclass(frozen=True, slots=True)
class Packet:
    header: PacketHeader
    ciphertext: bytes
    packet_size: int = DEFAULT_PACKET_SIZE

    def validate(self) -> None:
        self.header.validate()

        if not (MIN_PACKET_SIZE <= self.packet_size <= MAX_PACKET_SIZE):
            raise ValueError(
                f"packet_size must be within {MIN_PACKET_SIZE}..{MAX_PACKET_SIZE} bytes"
            )

        payload_capacity = self.packet_size - HEADER_SIZE
        if self.header.payload_length != len(self.ciphertext):
            raise ValueError("header payload_length does not match ciphertext length")
        if len(self.ciphertext) > payload_capacity:
            raise ValueError("ciphertext exceeds packet payload capacity")

    def to_bytes(self) -> bytes:
        self.validate()

        payload_capacity = self.packet_size - HEADER_SIZE
        padded_ciphertext = self.ciphertext.ljust(payload_capacity, b"\x00")
        return self.header.to_bytes() + padded_ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "Packet":
        if len(data) < HEADER_SIZE:
            raise ValueError("packet data too short")

        packet_size = len(data)
        if not (MIN_PACKET_SIZE <= packet_size <= MAX_PACKET_SIZE):
            raise ValueError(
                f"packet_size must be within {MIN_PACKET_SIZE}..{MAX_PACKET_SIZE} bytes"
            )

        header = PacketHeader.from_bytes(data[:HEADER_SIZE])
        payload_capacity = packet_size - HEADER_SIZE

        if header.payload_length > payload_capacity:
            raise ValueError("declared payload length exceeds packet capacity")

        ciphertext = data[HEADER_SIZE : HEADER_SIZE + header.payload_length]
        packet = cls(header=header, ciphertext=ciphertext, packet_size=packet_size)
        packet.validate()
        return packet


def build_packet(
    *,
    message_type: MessageType,
    session_id: str,
    sequence_number: int,
    nonce: bytes,
    ciphertext: bytes,
    flags: int = 0,
    packet_size: int = DEFAULT_PACKET_SIZE,
) -> Packet:
    header = PacketHeader(
        version=PROTOCOL_VERSION,
        message_type=message_type,
        flags=flags,
        sequence_number=sequence_number,
        session_id=session_id,
        message_id=_new_message_id(),
        nonce=nonce,
        payload_length=len(ciphertext),
    )
    packet = Packet(header=header, ciphertext=ciphertext, packet_size=packet_size)
    packet.validate()
    return packet


def packet_fingerprint(packet_bytes: bytes) -> str:
    return hashlib.sha256(packet_bytes).hexdigest()


def _new_message_id() -> bytes:
    return uuid4().bytes
