from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import ix_operator.crypto.native as native_module
from ix_operator import OperatorApplication, UnsupportedTransportBackendError


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


def test_application_initialize_and_load_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))

    app = OperatorApplication.from_env()
    created = app.initialize_identity(peer_id="node-alpha")
    loaded = app.load_identity()

    assert created.peer_id == "node-alpha"
    assert loaded is not None
    assert loaded.peer_id == "node-alpha"
    assert app.identity_store.path.is_file()


def test_application_boot_local_node_requires_existing_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))

    app = OperatorApplication.from_env()

    with pytest.raises(FileNotFoundError, match="node identity not found"):
        app.boot_local_node()


def test_application_rejects_unimplemented_transport_backend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IX_OPERATOR_TRANSPORT", "tor")

    app = OperatorApplication.from_env()
    app.initialize_identity(peer_id="node-alpha")

    with pytest.raises(
        UnsupportedTransportBackendError,
        match="transport backend 'tor' is not implemented in v1; supported backends: local",
    ):
        app.boot_local_node()


def test_application_run_script_executes_program(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))

    app = OperatorApplication.from_env()
    app.initialize_identity(peer_id="node-alpha")

    result = app.run_script(
        """
        agent genesis_i "Genesis I"
        goal "observe"
        remember mode = "passive"
        say "ready"
        """
    )

    assert result.peer_id == "node-alpha"
    assert result.report_count == 1
    assert result.agent_ids == ("genesis_i",)
