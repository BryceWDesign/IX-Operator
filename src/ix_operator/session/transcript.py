from __future__ import annotations

from dataclasses import dataclass
import hashlib

from ix_operator.session.models import PeerIdentity, SessionRole


PROTOCOL_LABEL = b"IX-Operator Session v1"


@dataclass(frozen=True, slots=True)
class HandshakeTranscript:
    protocol_label: bytes
    role: SessionRole
    local_peer_id: str
    remote_peer_id: str
    local_signing_public_key: bytes
    remote_signing_public_key: bytes
    local_exchange_public_key: bytes
    remote_exchange_public_key: bytes

    @classmethod
    def create(
        cls,
        *,
        role: SessionRole,
        local_peer: PeerIdentity,
        remote_peer: PeerIdentity,
    ) -> "HandshakeTranscript":
        local_peer.validate()
        remote_peer.validate()

        return cls(
            protocol_label=PROTOCOL_LABEL,
            role=role,
            local_peer_id=local_peer.peer_id,
            remote_peer_id=remote_peer.peer_id,
            local_signing_public_key=local_peer.signing_public_key,
            remote_signing_public_key=remote_peer.signing_public_key,
            local_exchange_public_key=local_peer.exchange_public_key,
            remote_exchange_public_key=remote_peer.exchange_public_key,
        )

    def serialize(self) -> bytes:
        components = [
            self.protocol_label,
            self.role.value.encode("utf-8"),
            self.local_peer_id.encode("utf-8"),
            self.remote_peer_id.encode("utf-8"),
            self.local_signing_public_key,
            self.remote_signing_public_key,
            self.local_exchange_public_key,
            self.remote_exchange_public_key,
        ]
        return b"\x1f".join(_length_prefix(component) for component in components)

    def digest(self) -> bytes:
        return hashlib.sha256(self.serialize()).digest()


def _length_prefix(value: bytes) -> bytes:
    if len(value) > 65535:
        raise ValueError("transcript component too large")
    return len(value).to_bytes(2, "big") + value
