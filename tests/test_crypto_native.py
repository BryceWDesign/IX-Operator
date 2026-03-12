from __future__ import annotations

import hashlib

import pytest

import ix_operator.crypto.native as native_module
from ix_operator.crypto import (
    NativeAeadAlgorithm,
    NativeExtensionUnavailableError,
    NativeHandshakeBackend,
    NativeTransportBackend,
    native_extension_available,
)


class FakeNativeModule:
    TAG_LEN = 16

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


def test_native_extension_available_returns_boolean() -> None:
    assert isinstance(native_extension_available(), bool)


def test_native_handshake_backend_requires_extension(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_module, "_native", None)

    backend = NativeHandshakeBackend()

    with pytest.raises(
        NativeExtensionUnavailableError,
        match="ix_operator._ix_crypto_native is not available",
    ):
        backend.random_bytes(32)


def test_native_handshake_backend_with_fake_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())

    backend = NativeHandshakeBackend()
    shared_secret = backend.shared_secret(b"a" * 32, b"b" * 32)
    material = backend.derive_material(shared_secret, b"t" * 32)

    assert len(backend.random_bytes(24)) == 24
    signature = backend.sign(b"s" * 32, b"hello")
    assert backend.verify(b"s" * 32, b"hello", signature) is True

    assert len(shared_secret) == 32
    assert material.transcript_hash == b"t" * 32
    assert len(material.encryption_key) == 32
    assert len(material.authentication_key) == 32


def test_native_transport_backend_round_trip_aes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())

    backend = NativeTransportBackend(NativeAeadAlgorithm.AES256_GCM)
    nonce = backend.random_nonce(12)
    ciphertext = backend.encrypt(b"k" * 32, nonce, b"hello", b"aad")
    plaintext = backend.decrypt(b"k" * 32, nonce, ciphertext, b"aad")

    assert len(nonce) == 12
    assert backend.ciphertext_length(5) == 21
    assert plaintext == b"hello"


def test_native_transport_backend_round_trip_chacha(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())

    backend = NativeTransportBackend(NativeAeadAlgorithm.CHACHA20_POLY1305)
    nonce = backend.random_nonce(12)
    ciphertext = backend.encrypt(b"z" * 32, nonce, b"operator", b"aad")
    plaintext = backend.decrypt(b"z" * 32, nonce, ciphertext, b"aad")

    assert plaintext == b"operator"


def test_native_transport_backend_rejects_wrong_nonce_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native_module, "_native", FakeNativeModule())

    backend = NativeTransportBackend()

    with pytest.raises(ValueError, match="native transport nonce length must be exactly 12"):
        backend.random_nonce(8)
