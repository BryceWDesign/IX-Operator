from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from ix_operator.transport.packet import MESSAGE_ID_SIZE, Packet


DEFAULT_REPLAY_WINDOW_SIZE = 1024
DEFAULT_MESSAGE_REGISTRY_SIZE = 4096
MAX_SEQUENCE_NUMBER = 0xFFFFFFFF


class ReplayRejectedError(ValueError):
    """Raised when an inbound packet is replayed, duplicated, or too old."""


class SessionBindingError(ValueError):
    """Raised when a packet does not belong to the expected session."""


@dataclass(slots=True)
class ReplayWindow:
    window_size: int = DEFAULT_REPLAY_WINDOW_SIZE
    highest_sequence: int = -1
    _seen_sequences: set[int] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.window_size <= 0:
            raise ValueError("window_size must be greater than 0")

    def mark(self, sequence_number: int) -> None:
        if not (0 <= sequence_number <= MAX_SEQUENCE_NUMBER):
            raise ValueError("sequence_number must be within 0..4294967295")

        if self.highest_sequence == -1:
            self.highest_sequence = sequence_number
            self._seen_sequences.add(sequence_number)
            return

        lower_bound = self.highest_sequence - self.window_size + 1
        if sequence_number < lower_bound:
            raise ReplayRejectedError("sequence number outside replay window")

        if sequence_number in self._seen_sequences:
            raise ReplayRejectedError("duplicate sequence number")

        self._seen_sequences.add(sequence_number)
        if sequence_number > self.highest_sequence:
            self.highest_sequence = sequence_number

        self._prune()

    def _prune(self) -> None:
        lower_bound = self.highest_sequence - self.window_size + 1
        self._seen_sequences = {
            sequence_number
            for sequence_number in self._seen_sequences
            if sequence_number >= lower_bound
        }


@dataclass(slots=True)
class MessageRegistry:
    max_entries: int = DEFAULT_MESSAGE_REGISTRY_SIZE
    _entries: OrderedDict[bytes, None] = field(default_factory=OrderedDict)

    def __post_init__(self) -> None:
        if self.max_entries <= 0:
            raise ValueError("max_entries must be greater than 0")

    def mark(self, message_id: bytes) -> None:
        if len(message_id) != MESSAGE_ID_SIZE:
            raise ValueError(f"message_id must be {MESSAGE_ID_SIZE} bytes")

        if message_id in self._entries:
            raise ReplayRejectedError("duplicate message_id")

        self._entries[message_id] = None
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)


@dataclass(slots=True)
class TransportSessionState:
    session_id: str
    replay_window: ReplayWindow = field(default_factory=ReplayWindow)
    message_registry: MessageRegistry = field(default_factory=MessageRegistry)
    next_outbound_sequence: int = 0
    is_closed: bool = False

    def __post_init__(self) -> None:
        if not self.session_id.strip():
            raise ValueError("session_id must not be empty")

    def reserve_outbound_sequence(self) -> int:
        self._require_open()

        if self.next_outbound_sequence > MAX_SEQUENCE_NUMBER:
            raise OverflowError("outbound sequence number exhausted")

        reserved = self.next_outbound_sequence
        self.next_outbound_sequence += 1
        return reserved

    def register_inbound_packet(self, packet: Packet) -> None:
        self._require_open()

        if packet.header.session_id != self.session_id:
            raise SessionBindingError("packet session_id mismatch")

        self.replay_window.mark(packet.header.sequence_number)
        self.message_registry.mark(packet.header.message_id)

    def close(self) -> None:
        self.is_closed = True

    def _require_open(self) -> None:
        if self.is_closed:
            raise ValueError("transport state is closed")
