from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import ix_operator.crypto.native as native_module
from ix_operator import (
    LocalTransportHub,
    NodeIdentity,
    NodeIdentityStore,
    OperatorNode,
    PacketCodec,
    SessionMaterial,
    SessionService,
    default_identity_store,
    derive_peer_id,
    generate_node_identity,
)


class FakeNativeModule:
    def generate_ed25519_keypair_py(self) -> tuple[bytes, bytes]:
        return b"s" * 32, b"S" * 32

    def generate_x25519_keypair_py(self) -> tuple[bytes, bytes]:
        return b"x" * 32, b"X" * 32


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


def test_derive_peer_id_is_deterministic() -> None:
    peer_id_a = derive_peer_id(b"A" * 32)
    peer_id_b = derive_peer_id(b"A" * 32)

    assert peer_id_a == peer_id_b
    assert peer_id_a.startswith("node-")


def test_generate_node_identity_uses_native_keygen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())

    identity = generate_node_identity(peer_id="node-alpha")

    assert identity.peer_id == "node-alpha"
    assert identity.signing_private_key == b"s" * 32
    assert identity.signing_public_key == b"S" * 32
    assert identity.exchange_private_key == b"x" * 32
    assert identity.exchange_public_key == b"X" * 32


def test_node_identity_store_save_and_load_round_trip(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    store = NodeIdentityStore(tmp_path / "state" / "node_identity.json")

    created = store.load_or_create(peer_id="node-alpha")
    loaded = store.load()

    assert loaded is not None
    assert loaded == created
    assert store.exists() is True


def test_default_identity_store_points_to_runtime_state(tmp_path: Path) -> None:
    store = default_identity_store(tmp_path / "runtime")

    assert store.path == (tmp_path / "runtime" / "state" / "node_identity.json").resolve()


def test_operator_node_from_identity_boots_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())

    identity = NodeIdentity(
        peer_id="node-alpha",
        signing_public_key=b"S" * 32,
        exchange_public_key=b"X" * 32,
        signing_private_key=b"s" * 32,
        exchange_private_key=b"x" * 32,
    )
    hub = LocalTransportHub()
    service = SessionService(FakeHandshakeCryptoBackend())

    node = OperatorNode.from_identity(
        identity=identity,
        hub=hub,
        session_service=service,
        codec=PacketCodec(FakeTransportCryptoBackend()),
    )

    assert node.peer_id == "node-alpha"
    assert hub.get_endpoint("node-alpha") is not None
