from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest

import ix_operator.crypto.native as native_module
from ix_operator.__main__ import main


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


def test_main_info_prints_runtime_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IX_OPERATOR_MODE", "development")
    monkeypatch.setenv("IX_OPERATOR_TRANSPORT", "local")

    exit_code = main(["info"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "IX-Operator v0.1.0" in captured.out
    assert "Mode: development" in captured.out
    assert "Transport: local" in captured.out
    assert "Boot ID:" in captured.out
    assert "Native extension available: True" in captured.out


def test_main_defaults_to_info_when_no_args_are_provided(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setattr(sys, "argv", ["ix-operator"])

    exit_code = main(None)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "IX-Operator v0.1.0" in captured.out
    assert "Identity path:" in captured.out


def test_main_honors_real_sys_argv_for_identity_init(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setattr(sys, "argv", ["ix-operator", "identity", "init", "--peer-id", "node-alpha"])

    exit_code = main(None)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Identity initialized." in captured.out
    assert "Peer ID: node-alpha" in captured.out
    assert (tmp_path / "runtime" / "state" / "node_identity.json").is_file()


def test_main_identity_init_creates_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())
    monkeypatch.setenv("IX_OPERATOR_RUNTIME_DIR", str(tmp_path / "runtime"))

    exit_code = main(["identity", "init", "--peer-id", "node-alpha"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Identity initialized." in captured.out
    assert "Peer ID: node-alpha" in captured.out
    assert (tmp_path / "runtime" / "state" / "node_identity.json").is_file()
