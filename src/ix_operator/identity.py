from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from ix_operator.crypto import (
    derive_peer_id,
    generate_ed25519_keypair,
    generate_x25519_keypair,
)


@dataclass(frozen=True, slots=True)
class NodeIdentity:
    peer_id: str
    signing_public_key: bytes
    exchange_public_key: bytes
    signing_private_key: bytes
    exchange_private_key: bytes

    def validate(self) -> None:
        if not self.peer_id.strip():
            raise ValueError("peer_id must not be empty")
        if len(self.signing_public_key) != 32:
            raise ValueError("signing_public_key must be 32 bytes")
        if len(self.exchange_public_key) != 32:
            raise ValueError("exchange_public_key must be 32 bytes")
        if len(self.signing_private_key) != 32:
            raise ValueError("signing_private_key must be 32 bytes")
        if len(self.exchange_private_key) != 32:
            raise ValueError("exchange_private_key must be 32 bytes")

    def to_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "peer_id": self.peer_id,
            "signing_public_key": self.signing_public_key.hex(),
            "exchange_public_key": self.exchange_public_key.hex(),
            "signing_private_key": self.signing_private_key.hex(),
            "exchange_private_key": self.exchange_private_key.hex(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "NodeIdentity":
        identity = cls(
            peer_id=_expect_str(payload, "peer_id"),
            signing_public_key=_expect_hex_bytes(payload, "signing_public_key", 32),
            exchange_public_key=_expect_hex_bytes(payload, "exchange_public_key", 32),
            signing_private_key=_expect_hex_bytes(payload, "signing_private_key", 32),
            exchange_private_key=_expect_hex_bytes(payload, "exchange_private_key", 32),
        )
        identity.validate()
        return identity


def generate_node_identity(
    *,
    peer_id: str | None = None,
    peer_id_prefix: str = "node",
) -> NodeIdentity:
    signing_private_key, signing_public_key = generate_ed25519_keypair()
    exchange_private_key, exchange_public_key = generate_x25519_keypair()

    resolved_peer_id = peer_id.strip() if peer_id is not None else ""
    if not resolved_peer_id:
        resolved_peer_id = derive_peer_id(signing_public_key, prefix=peer_id_prefix)

    identity = NodeIdentity(
        peer_id=resolved_peer_id,
        signing_public_key=signing_public_key,
        exchange_public_key=exchange_public_key,
        signing_private_key=signing_private_key,
        exchange_private_key=exchange_private_key,
    )
    identity.validate()
    return identity


class NodeIdentityStore:
    def __init__(self, path: Path) -> None:
        self._path = path.expanduser().resolve()

    @property
    def path(self) -> Path:
        return self._path

    def exists(self) -> bool:
        return self._path.is_file()

    def load(self) -> NodeIdentity | None:
        if not self.exists():
            return None

        payload = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("node identity file must contain a JSON object")

        return NodeIdentity.from_dict(payload)

    def save(self, identity: NodeIdentity) -> None:
        identity.validate()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(identity.to_dict(), sort_keys=True, indent=2)
        self._path.write_text(serialized + "\n", encoding="utf-8")

    def load_or_create(
        self,
        *,
        peer_id: str | None = None,
        peer_id_prefix: str = "node",
    ) -> NodeIdentity:
        existing = self.load()
        if existing is not None:
            return existing

        identity = generate_node_identity(
            peer_id=peer_id,
            peer_id_prefix=peer_id_prefix,
        )
        self.save(identity)
        return identity


def default_identity_store(runtime_root: Path) -> NodeIdentityStore:
    resolved_root = runtime_root.expanduser().resolve()
    return NodeIdentityStore(resolved_root / "state" / "node_identity.json")


def _expect_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    if not value.strip():
        raise ValueError(f"{key} must not be empty")
    return value


def _expect_hex_bytes(payload: dict[str, Any], key: str, expected_len: int) -> bytes:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a hex string")

    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{key} must be valid hex") from exc

    if len(decoded) != expected_len:
        raise ValueError(f"{key} must decode to {expected_len} bytes")

    return decoded
