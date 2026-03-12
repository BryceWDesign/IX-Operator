from __future__ import annotations

from enum import StrEnum
import hashlib
import importlib
from typing import Any

from ix_operator.session import SessionMaterial
from ix_operator.transport import NONCE_SIZE


_NATIVE_MODULE_NAME = "ix_operator._ix_crypto_native"
NATIVE_SESSION_INFO = b"IX-Operator Session Keys"
AEAD_TAG_LENGTH = 16


class NativeExtensionUnavailableError(ImportError):
    """Raised when the compiled ix_crypto native extension is unavailable."""


class NativeAeadAlgorithm(StrEnum):
    AES256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


def _load_native_module() -> Any | None:
    try:
        return importlib.import_module(_NATIVE_MODULE_NAME)
    except ImportError:
        return None


_native = _load_native_module()


def native_extension_available() -> bool:
    return _native is not None


def _require_native_module() -> Any:
    if _native is None:
        raise NativeExtensionUnavailableError(
            "ix_operator._ix_crypto_native is not available; build the PyO3 extension first"
        )
    return _native


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    native = _require_native_module()
    private_key, public_key = native.generate_x25519_keypair_py()
    return bytes(private_key), bytes(public_key)


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    native = _require_native_module()
    private_key, public_key = native.generate_ed25519_keypair_py()
    return bytes(private_key), bytes(public_key)


def derive_peer_id(signing_public_key: bytes, *, prefix: str = "node") -> str:
    normalized_prefix = prefix.strip()
    if not normalized_prefix:
        raise ValueError("prefix must not be empty")
    if len(signing_public_key) != 32:
        raise ValueError("signing_public_key must be 32 bytes")

    digest = hashlib.sha256(signing_public_key).hexdigest()[:24]
    return f"{normalized_prefix}-{digest}"


class NativeHandshakeBackend:
    def random_bytes(self, length: int) -> bytes:
        if length <= 0:
            raise ValueError("length must be greater than 0")
        native = _require_native_module()
        return bytes(native.random_bytes(length))

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        native = _require_native_module()
        return bytes(native.sign_ed25519_py(private_key, message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        native = _require_native_module()
        return bool(native.verify_ed25519_py(public_key, message, signature))

    def shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        native = _require_native_module()
        return bytes(native.x25519_shared_secret_py(private_key, peer_public_key))

    def derive_material(self, shared_secret: bytes, transcript_hash: bytes) -> SessionMaterial:
        if len(transcript_hash) != 32:
            raise ValueError("transcript_hash must be 32 bytes")

        native = _require_native_module()
        encryption_key, authentication_key = native.derive_session_keys(
            shared_secret,
            transcript_hash,
            NATIVE_SESSION_INFO,
        )

        material = SessionMaterial(
            encryption_key=bytes(encryption_key),
            authentication_key=bytes(authentication_key),
            transcript_hash=transcript_hash,
        )
        material.validate()
        return material


class NativeTransportBackend:
    def __init__(self, algorithm: NativeAeadAlgorithm = NativeAeadAlgorithm.AES256_GCM) -> None:
        self._algorithm = algorithm

    @property
    def algorithm(self) -> NativeAeadAlgorithm:
        return self._algorithm

    def random_nonce(self, length: int) -> bytes:
        if length != NONCE_SIZE:
            raise ValueError(f"native transport nonce length must be exactly {NONCE_SIZE}")

        native = _require_native_module()
        nonce = bytes(native.random_nonce())
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"native extension returned invalid nonce length: {len(nonce)}")
        return nonce

    def ciphertext_length(self, plaintext_length: int) -> int:
        if plaintext_length < 0:
            raise ValueError("plaintext_length must be non-negative")
        return plaintext_length + AEAD_TAG_LENGTH

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        native = _require_native_module()

        if self._algorithm == NativeAeadAlgorithm.AES256_GCM:
            return bytes(native.encrypt_aes256_gcm_py(key, nonce, plaintext, aad))

        if self._algorithm == NativeAeadAlgorithm.CHACHA20_POLY1305:
            return bytes(native.encrypt_chacha20_poly1305_py(key, nonce, plaintext, aad))

        raise ValueError(f"unsupported native AEAD algorithm: {self._algorithm.value}")

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        native = _require_native_module()

        if self._algorithm == NativeAeadAlgorithm.AES256_GCM:
            return bytes(native.decrypt_aes256_gcm_py(key, nonce, ciphertext, aad))

        if self._algorithm == NativeAeadAlgorithm.CHACHA20_POLY1305:
            return bytes(native.decrypt_chacha20_poly1305_py(key, nonce, ciphertext, aad))

        raise ValueError(f"unsupported native AEAD algorithm: {self._algorithm.value}")
