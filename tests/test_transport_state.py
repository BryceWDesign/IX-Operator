from __future__ import annotations

import pytest

from ix_operator.transport import (
    MESSAGE_ID_SIZE,
    NONCE_SIZE,
    DEFAULT_REPLAY_WINDOW_SIZE,
    MessageRegistry,
    MessageType,
    ReplayRejectedError,
    ReplayWindow,
    SessionBindingError,
    TransportSessionState,
    build_packet,
)


def test_replay_window_accepts_increasing_sequences() -> None:
    window = ReplayWindow(window_size=8)

    window.mark(0)
    window.mark(1)
    window.mark(2)

    assert window.highest_sequence == 2


def test_replay_window_rejects_duplicate_sequence() -> None:
    window = ReplayWindow(window_size=8)
    window.mark(10)

    with pytest.raises(ReplayRejectedError, match="duplicate sequence number"):
        window.mark(10)


def test_replay_window_rejects_too_old_sequence() -> None:
    window = ReplayWindow(window_size=4)
    window.mark(10)
    window.mark(11)
    window.mark(12)
    window.mark(13)

    with pytest.raises(ReplayRejectedError, match="sequence number outside replay window"):
        window.mark(9)


def test_message_registry_rejects_duplicate_message_id() -> None:
    registry = MessageRegistry(max_entries=4)
    message_id = b"a" * MESSAGE_ID_SIZE

    registry.mark(message_id)

    with pytest.raises(ReplayRejectedError, match="duplicate message_id"):
        registry.mark(message_id)


def test_transport_state_reserves_outbound_sequences() -> None:
    state = TransportSessionState(session_id="sess-alpha")

    assert state.reserve_outbound_sequence() == 0
    assert state.reserve_outbound_sequence() == 1
    assert state.reserve_outbound_sequence() == 2


def test_transport_state_registers_inbound_packet() -> None:
    state = TransportSessionState(session_id="sess-alpha")
    packet = build_packet(
        message_type=MessageType.DATA,
        session_id="sess-alpha",
        sequence_number=4,
        nonce=b"n" * NONCE_SIZE,
        ciphertext=b"sealed",
    )

    state.register_inbound_packet(packet)

    assert state.replay_window.highest_sequence == 4


def test_transport_state_rejects_session_mismatch() -> None:
    state = TransportSessionState(session_id="sess-alpha")
    packet = build_packet(
        message_type=MessageType.DATA,
        session_id="sess-beta",
        sequence_number=1,
        nonce=b"n" * NONCE_SIZE,
        ciphertext=b"sealed",
    )

    with pytest.raises(SessionBindingError, match="packet session_id mismatch"):
        state.register_inbound_packet(packet)


def test_transport_state_rejects_duplicate_inbound_packet_message_id() -> None:
    state = TransportSessionState(session_id="sess-alpha")
    packet = build_packet(
        message_type=MessageType.DATA,
        session_id="sess-alpha",
        sequence_number=7,
        nonce=b"n" * NONCE_SIZE,
        ciphertext=b"sealed",
    )

    encoded = packet.to_bytes()
    same_packet = type(packet).from_bytes(encoded)

    state.register_inbound_packet(packet)

    with pytest.raises(ReplayRejectedError, match="duplicate sequence number"):
        state.register_inbound_packet(same_packet)


def test_transport_state_rejects_when_closed() -> None:
    state = TransportSessionState(session_id="sess-alpha")
    state.close()

    with pytest.raises(ValueError, match="transport state is closed"):
        state.reserve_outbound_sequence()


def test_default_replay_window_constant_is_sane() -> None:
    assert DEFAULT_REPLAY_WINDOW_SIZE >= 64
