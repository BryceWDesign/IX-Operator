from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import ix_operator.crypto.native as native_module
from ix_operator import (
    LocalTransportHub,
    OperatorApplication,
    OperatorNetwork,
    OperatorNode,
    PacketCodec,
    SessionMaterial,
    SessionService,
)


class FakeNativeModule:
    TAG_LEN = 16

    def generate_ed25519_keypair_py(self) -> tuple[bytes, bytes]:
        return b"s" * 32, b"S" * 32

    def generate_x25519_keypair_py(self) -> tuple[bytes, bytes]:
        return b"x" * 32, b"X" * 32

    def random_bytes(self, length: int) -> bytes:
        return bytes((index % 251 for index in range(length)))

    def random_nonce(self) -> bytes:
        return b"n" * 12

    def sign_ed25519_py(self, private_key: bytes, message: bytes) -> bytes:
        return hashlib.sha512(private_key + message).digest()

    def verify_ed25519_py(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        expected = hashlib.sha512(public_key + message).digest()
        return expected == signature

    def x25519_shared_secret_py(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        ordered = sorted([private_key, peer_public_key])
        return hashlib.sha256(ordered[0] + ordered[1]).digest()

    def derive_session_keys(
        self,
        shared_secret: bytes,
        salt: bytes | None,
        info: bytes,
    ) -> tuple[bytes, bytes]:
        normalized_salt = salt or b""
        encryption_key = hashlib.sha256(shared_secret + normalized_salt + info + b"enc").digest()
        authentication_key = hashlib.sha256(
            shared_secret + normalized_salt + info + b"auth"
        ).digest()
        return encryption_key, authentication_key

    def encrypt_aes256_gcm_py(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes,
    ) -> bytes:
        return self._seal(key, nonce, plaintext, aad)

    def decrypt_aes256_gcm_py(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes,
    ) -> bytes:
        return self._open(key, nonce, ciphertext, aad)

    def encrypt_chacha20_poly1305_py(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes,
    ) -> bytes:
        return self._seal(key, nonce, plaintext, aad)

    def decrypt_chacha20_poly1305_py(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes,
    ) -> bytes:
        return self._open(key, nonce, ciphertext, aad)

    def _seal(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        keystream = hashlib.sha256(key + nonce).digest()
        body = bytes(
            byte ^ keystream[index % len(keystream)]
            for index, byte in enumerate(plaintext)
        )
        tag = hashlib.sha256(key + nonce + aad + plaintext).digest()[: self.TAG_LEN]
        return body + tag

    def _open(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
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


def test_application_status_snapshot_reports_identity_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))

    app = OperatorApplication.from_env()
    before = app.status_snapshot()

    assert before.identity_exists is False
    assert before.local_peer_id is None
    assert before.transport_supported is True

    app.initialize_identity(peer_id="node-alpha")
    after = app.status_snapshot()

    assert after.identity_exists is True
    assert after.local_peer_id == "node-alpha"
    assert after.native_extension_available is True
    assert after.transport_supported is True


def test_application_status_snapshot_reports_unimplemented_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IX_OPERATOR_TRANSPORT", "tor")

    app = OperatorApplication.from_env()
    snapshot = app.status_snapshot()

    assert snapshot.transport == "tor"
    assert snapshot.transport_supported is False


def test_node_snapshot_reports_agents_and_channels() -> None:
    hub = LocalTransportHub()
    service = SessionService(FakeHandshakeCryptoBackend())

    node = OperatorNode.create(
        peer_id="node-alpha",
        signing_public_key=b"A" * 32,
        exchange_public_key=b"B" * 32,
        signing_private_key=b"A" * 32,
        exchange_private_key=b"B" * 32,
        hub=hub,
        session_service=service,
        codec=PacketCodec(FakeTransportCryptoBackend()),
    )

    node.boot_program(
        """
        agent genesis_i "Genesis I"
        goal "observe"
        say "ready"
        """
    )

    snapshot = node.snapshot()

    assert snapshot.peer_id == "node-alpha"
    assert snapshot.channel_peers == ()
    assert snapshot.registered_agents == ("genesis_i",)
    assert snapshot.active_agent_count == 0


def test_network_snapshot_reports_all_nodes() -> None:
    network = OperatorNetwork.local(
        session_service=SessionService(FakeHandshakeCryptoBackend()),
        codec_factory=lambda: PacketCodec(FakeTransportCryptoBackend()),
    )

    from ix_operator import NodeIdentity

    network.add_node(
        NodeIdentity(
            peer_id="node-alpha",
            signing_public_key=b"A" * 32,
            exchange_public_key=b"B" * 32,
            signing_private_key=b"A" * 32,
            exchange_private_key=b"B" * 32,
        )
    )
    network.add_node(
        NodeIdentity(
            peer_id="node-beta",
            signing_public_key=b"C" * 32,
            exchange_public_key=b"D" * 32,
            signing_private_key=b"C" * 32,
            exchange_private_key=b"D" * 32,
        )
    )

    snapshot = network.snapshot()

    assert snapshot.peer_ids == ("node-alpha", "node-beta")
    assert tuple(item.peer_id for item in snapshot.node_snapshots) == (
        "node-alpha",
        "node-beta",
    )
