from __future__ import annotations

import hashlib

import pytest

from ix_operator import (
    AgentBus,
    AgentMessage,
    LocalTransportHub,
    MessageType,
    PacketCodec,
    ReceivedAgentMessage,
    SessionMaterial,
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


def _message(body: str) -> AgentMessage:
    return AgentMessage.create(
        sender_agent_id="genesis_i",
        recipient_agent_id="genesis_ii",
        body=body,
        headers={"intent": "test"},
    )


def test_agent_bus_send_and_receive_round_trip() -> None:
    hub = LocalTransportHub()
    alice_endpoint = hub.register("node-alice")
    bob_endpoint = hub.register("node-bob")

    codec = PacketCodec(FakeTransportCryptoBackend())
    alice_bus = AgentBus(endpoint=alice_endpoint, codec=codec)
    bob_bus = AgentBus(endpoint=bob_endpoint, codec=codec)

    alice_bus.bind_channel(
        remote_peer_id="node-bob",
        session_id="sess-alpha",
        material=_material(),
    )
    bob_bus.bind_channel(
        remote_peer_id="node-alice",
        session_id="sess-alpha",
        material=_material(),
    )

    alice_bus.send_message(
        recipient_peer_id="node-bob",
        message=_message("hello from alice"),
    )

    received = bob_bus.receive_message(timeout_seconds=0.05)

    assert isinstance(received, ReceivedAgentMessage)
    assert received.sender_peer_id == "node-alice"
    assert received.recipient_peer_id == "node-bob"
    assert received.packet_session_id == "sess-alpha"
    assert received.sequence_number == 0
    assert received.message.sender_agent_id == "genesis_i"
    assert received.message.recipient_agent_id == "genesis_ii"
    assert received.message.body == "hello from alice"


def test_agent_bus_send_advances_channel_sequence() -> None:
    hub = LocalTransportHub()
    alice_endpoint = hub.register("node-alice")
    bob_endpoint = hub.register("node-bob")

    codec = PacketCodec(FakeTransportCryptoBackend())
    alice_bus = AgentBus(endpoint=alice_endpoint, codec=codec)
    bob_bus = AgentBus(endpoint=bob_endpoint, codec=codec)

    alice_bus.bind_channel(
        remote_peer_id="node-bob",
        session_id="sess-alpha",
        material=_material(),
    )
    bob_bus.bind_channel(
        remote_peer_id="node-alice",
        session_id="sess-alpha",
        material=_material(),
    )

    alice_bus.send_message(recipient_peer_id="node-bob", message=_message("one"))
    alice_bus.send_message(recipient_peer_id="node-bob", message=_message("two"))

    first = bob_bus.receive_message(timeout_seconds=0.05)
    second = bob_bus.receive_message(timeout_seconds=0.05)
    channel = alice_bus.get_channel("node-bob")

    assert first is not None
    assert second is not None
    assert first.sequence_number == 0
    assert second.sequence_number == 1
    assert channel is not None
    assert channel.outbound_state.next_outbound_sequence == 2


def test_agent_bus_receive_timeout_returns_none() -> None:
    hub = LocalTransportHub()
    endpoint = hub.register("node-alpha")

    bus = AgentBus(
        endpoint=endpoint,
        codec=PacketCodec(FakeTransportCryptoBackend()),
    )

    assert bus.receive_message(timeout_seconds=0.01) is None


def test_agent_bus_rejects_send_without_bound_channel() -> None:
    hub = LocalTransportHub()
    endpoint = hub.register("node-alpha")

    bus = AgentBus(
        endpoint=endpoint,
        codec=PacketCodec(FakeTransportCryptoBackend()),
    )

    with pytest.raises(KeyError, match="no channel bound for peer: node-beta"):
        bus.send_message(
            recipient_peer_id="node-beta",
            message=_message("missing channel"),
        )


def test_agent_bus_rejects_duplicate_channel_binding() -> None:
    hub = LocalTransportHub()
    endpoint = hub.register("node-alpha")

    bus = AgentBus(
        endpoint=endpoint,
        codec=PacketCodec(FakeTransportCryptoBackend()),
    )

    bus.bind_channel(
        remote_peer_id="node-beta",
        session_id="sess-alpha",
        material=_material(),
    )

    with pytest.raises(ValueError, match="channel is already bound: node-beta"):
        bus.bind_channel(
            remote_peer_id="node-beta",
            session_id="sess-alpha",
            material=_material(),
        )


def test_agent_bus_unbind_removes_channel() -> None:
    hub = LocalTransportHub()
    endpoint = hub.register("node-alpha")

    bus = AgentBus(
        endpoint=endpoint,
        codec=PacketCodec(FakeTransportCryptoBackend()),
    )

    bus.bind_channel(
        remote_peer_id="node-beta",
        session_id="sess-alpha",
        material=_material(),
    )
    assert bus.get_channel("node-beta") is not None

    bus.unbind_channel("node-beta")

    assert bus.get_channel("node-beta") is None
    assert bus.list_channels() == []
