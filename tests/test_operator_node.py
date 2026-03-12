from __future__ import annotations

import hashlib

import pytest

from ix_operator import LocalTransportHub, OperatorNode, PacketCodec, SessionMaterial, SessionService


class FakeHandshakeCryptoBackend:
    def __init__(self) -> None:
        self._counter = 0

    def random_bytes(self, length: int) -> bytes:
        self._counter += 1
        seed = f"rng-{self._counter}".encode("utf-8")
        output = b""
        while len(output) < length:
            seed = hashlib.sha256(seed).digest()
            output += seed
        return output[:length]

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return hashlib.sha512(private_key + message).digest()

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        expected = hashlib.sha512(public_key + message).digest()
        return expected == signature

    def shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        ordered = sorted([private_key, peer_public_key])
        return hashlib.sha256(ordered[0] + ordered[1]).digest()

    def derive_material(self, shared_secret: bytes, transcript_hash: bytes) -> SessionMaterial:
        encryption_key = hashlib.sha256(shared_secret + b"enc" + transcript_hash).digest()
        authentication_key = hashlib.sha256(shared_secret + b"auth" + transcript_hash).digest()
        return SessionMaterial(
            encryption_key=encryption_key,
            authentication_key=authentication_key,
            transcript_hash=transcript_hash,
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


def _node(
    *,
    peer_id: str,
    seed: int,
    hub: LocalTransportHub,
    service: SessionService,
) -> OperatorNode:
    signing_private_key = bytes([seed]) * 32
    exchange_private_key = bytes([seed + 1]) * 32

    return OperatorNode.create(
        peer_id=peer_id,
        signing_public_key=signing_private_key,
        exchange_public_key=exchange_private_key,
        signing_private_key=signing_private_key,
        exchange_private_key=exchange_private_key,
        hub=hub,
        session_service=service,
        codec=PacketCodec(FakeTransportCryptoBackend()),
    )


def test_operator_node_boot_program_registers_and_executes_agents() -> None:
    hub = LocalTransportHub()
    service = SessionService(FakeHandshakeCryptoBackend())
    node = _node(peer_id="node-alpha", seed=10, hub=hub, service=service)

    reports = node.boot_program(
        """
        agent genesis_i "Genesis I"
        goal "observe"
        remember mode = "passive"
        say "ready"
        """
    )

    assert len(reports) == 1
    assert reports[0].agent_id == "genesis_i"
    assert reports[0].final_goal == "observe"
    assert reports[0].memory_snapshot["mode"] == "passive"
    assert reports[0].emissions[0].text == "ready"

    state = node.registry.get_state("genesis_i")
    assert state is not None
    assert state.current_goal == "observe"


def test_operator_nodes_establish_channel_and_exchange_messages() -> None:
    hub = LocalTransportHub()
    service = SessionService(FakeHandshakeCryptoBackend())

    alice = _node(peer_id="node-alice", seed=20, hub=hub, service=service)
    bob = _node(peer_id="node-bob", seed=40, hub=hub, service=service)

    established = alice.establish_channel(bob, ttl_seconds=120)

    assert established.channel_session_id.startswith("chan-")
    assert alice.list_channels() == ["node-bob"]
    assert bob.list_channels() == ["node-alice"]

    alice.boot_program(
        """
        agent genesis_i "Genesis I"
        say "online"
        """
    )
    bob.boot_program(
        """
        agent genesis_ii "Genesis II"
        say "online"
        """
    )

    sent = alice.send_message(
        recipient_peer_id="node-bob",
        sender_agent_id="genesis_i",
        recipient_agent_id="genesis_ii",
        body="hello from alice",
        headers={"intent": "greet"},
    )
    received = bob.receive_message(timeout_seconds=0.05)

    assert sent.body == "hello from alice"
    assert received is not None
    assert received.sender_peer_id == "node-alice"
    assert received.recipient_peer_id == "node-bob"
    assert received.packet_session_id == established.channel_session_id
    assert received.message.sender_agent_id == "genesis_i"
    assert received.message.recipient_agent_id == "genesis_ii"
    assert received.message.body == "hello from alice"
    assert received.message.headers == {"intent": "greet"}

    bob_state = bob.registry.get_state("genesis_ii")
    assert bob_state is not None
    assert bob_state.last_message_at_utc is not None


def test_operator_node_rejects_self_channel_establishment() -> None:
    hub = LocalTransportHub()
    service = SessionService(FakeHandshakeCryptoBackend())
    node = _node(peer_id="node-alpha", seed=70, hub=hub, service=service)

    with pytest.raises(ValueError, match="cannot establish a channel to the same peer_id"):
        node.establish_channel(node)


def test_operator_node_shutdown_closes_endpoint_and_unbinds_channels() -> None:
    hub = LocalTransportHub()
    service = SessionService(FakeHandshakeCryptoBackend())

    alice = _node(peer_id="node-alice", seed=80, hub=hub, service=service)
    bob = _node(peer_id="node-bob", seed=100, hub=hub, service=service)

    alice.establish_channel(bob)

    assert sorted(hub.peer_ids()) == ["node-alice", "node-bob"]

    alice.shutdown()

    assert hub.get_endpoint("node-alice") is None
    assert alice.list_channels() == []
    assert hub.peer_ids() == ["node-bob"]
