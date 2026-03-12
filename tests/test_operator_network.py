from __future__ import annotations

import hashlib

import pytest

from ix_operator import NodeIdentity, OperatorNetwork, PacketCodec, SessionMaterial, SessionService


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


def _identity(peer_id: str, seed: int) -> NodeIdentity:
    return NodeIdentity(
        peer_id=peer_id,
        signing_public_key=bytes([seed]) * 32,
        exchange_public_key=bytes([seed + 1]) * 32,
        signing_private_key=bytes([seed]) * 32,
        exchange_private_key=bytes([seed + 1]) * 32,
    )


def _network() -> OperatorNetwork:
    return OperatorNetwork.local(
        session_service=SessionService(FakeHandshakeCryptoBackend()),
        codec_factory=lambda: PacketCodec(FakeTransportCryptoBackend()),
    )


def test_network_adds_and_lists_nodes() -> None:
    network = _network()

    node_a = network.add_node(_identity("node-alpha", 10))
    node_b = network.add_node(_identity("node-beta", 20))

    assert node_a.peer_id == "node-alpha"
    assert node_b.peer_id == "node-beta"
    assert network.list_nodes() == ["node-alpha", "node-beta"]
    assert network.get_node("node-alpha") is node_a
    assert network.get_node("node-beta") is node_b


def test_network_rejects_duplicate_node_registration() -> None:
    network = _network()
    network.add_node(_identity("node-alpha", 10))

    with pytest.raises(ValueError, match="node is already registered: node-alpha"):
        network.add_node(_identity("node-alpha", 11))


def test_network_connects_nodes_and_moves_agent_message() -> None:
    network = _network()
    network.add_node(_identity("node-alpha", 30))
    network.add_node(_identity("node-beta", 40))

    established = network.connect(
        initiator_peer_id="node-alpha",
        responder_peer_id="node-beta",
        ttl_seconds=120,
    )

    assert established.channel_session_id.startswith("chan-")

    network.boot_program(
        peer_id="node-alpha",
        program_or_source="""
        agent genesis_i "Genesis I"
        goal "observe"
        say "alpha online"
        """,
    )
    network.boot_program(
        peer_id="node-beta",
        program_or_source="""
        agent genesis_ii "Genesis II"
        goal "assist"
        say "beta online"
        """,
    )

    sent = network.send_message(
        sender_peer_id="node-alpha",
        recipient_peer_id="node-beta",
        sender_agent_id="genesis_i",
        recipient_agent_id="genesis_ii",
        body="hello from alpha",
        headers={"intent": "greet"},
    )
    received = network.receive_message(peer_id="node-beta", timeout_seconds=0.05)

    assert sent.body == "hello from alpha"
    assert received is not None
    assert received.sender_peer_id == "node-alpha"
    assert received.recipient_peer_id == "node-beta"
    assert received.packet_session_id == established.channel_session_id
    assert received.message.sender_agent_id == "genesis_i"
    assert received.message.recipient_agent_id == "genesis_ii"
    assert received.message.body == "hello from alpha"
    assert received.message.headers == {"intent": "greet"}


def test_network_shutdown_all_clears_registry_and_hub() -> None:
    network = _network()
    network.add_node(_identity("node-alpha", 50))
    network.add_node(_identity("node-beta", 60))

    assert network.list_nodes() == ["node-alpha", "node-beta"]
    assert sorted(network.hub.peer_ids()) == ["node-alpha", "node-beta"]

    network.shutdown_all()

    assert network.list_nodes() == []
    assert network.hub.peer_ids() == []


def test_network_requires_known_peer_id() -> None:
    network = _network()
    network.add_node(_identity("node-alpha", 70))

    with pytest.raises(KeyError, match="unknown peer_id: node-missing"):
        network.connect(
            initiator_peer_id="node-alpha",
            responder_peer_id="node-missing",
        )
