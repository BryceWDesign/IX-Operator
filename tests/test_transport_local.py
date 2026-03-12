from __future__ import annotations

import pytest

from ix_operator.transport import (
    DEFAULT_RECEIVE_TIMEOUT_SECONDS,
    LocalTransportClosedError,
    LocalTransportHub,
    MessageType,
    Packet,
    build_packet,
)


def _packet(session_id: str, sequence_number: int, ciphertext: bytes) -> Packet:
    return build_packet(
        message_type=MessageType.DATA,
        session_id=session_id,
        sequence_number=sequence_number,
        nonce=b"n" * 12,
        ciphertext=ciphertext,
    )


def test_local_transport_delivers_packet_between_registered_peers() -> None:
    hub = LocalTransportHub()
    alice = hub.register("alice")
    bob = hub.register("bob")

    outbound = _packet("sess-alpha", 1, b"sealed-payload")
    alice.send_packet(recipient_peer_id="bob", packet=outbound)

    delivery = bob.receive_packet(timeout_seconds=DEFAULT_RECEIVE_TIMEOUT_SECONDS)

    assert delivery is not None
    assert delivery.sender_peer_id == "alice"
    assert delivery.recipient_peer_id == "bob"

    inbound = delivery.to_packet()
    assert inbound.header.session_id == "sess-alpha"
    assert inbound.header.sequence_number == 1
    assert inbound.ciphertext == b"sealed-payload"


def test_local_transport_rejects_duplicate_peer_registration() -> None:
    hub = LocalTransportHub()
    hub.register("alice")

    with pytest.raises(ValueError, match="peer_id is already registered: alice"):
        hub.register("alice")


def test_local_transport_rejects_send_to_unknown_peer() -> None:
    hub = LocalTransportHub()
    alice = hub.register("alice")

    with pytest.raises(KeyError, match="recipient peer is not registered: bob"):
        alice.send_packet(
            recipient_peer_id="bob",
            packet=_packet("sess-alpha", 1, b"sealed"),
        )


def test_local_transport_receive_timeout_returns_none() -> None:
    hub = LocalTransportHub()
    bob = hub.register("bob")

    delivery = bob.receive_packet(timeout_seconds=0.01)

    assert delivery is None


def test_local_transport_close_unregisters_endpoint() -> None:
    hub = LocalTransportHub()
    alice = hub.register("alice")
    bob = hub.register("bob")

    bob.close()

    assert hub.get_endpoint("bob") is None
    assert hub.peer_ids() == ["alice"]

    with pytest.raises(KeyError, match="recipient peer is not registered: bob"):
        alice.send_packet(
            recipient_peer_id="bob",
            packet=_packet("sess-alpha", 2, b"sealed"),
        )


def test_closed_endpoint_rejects_operations() -> None:
    hub = LocalTransportHub()
    alice = hub.register("alice")

    alice.close()

    with pytest.raises(LocalTransportClosedError, match="endpoint is closed: alice"):
        alice.send_packet(
            recipient_peer_id="bob",
            packet=_packet("sess-alpha", 3, b"sealed"),
        )

    with pytest.raises(LocalTransportClosedError, match="endpoint is closed: alice"):
        alice.receive_packet(timeout_seconds=0.01)
