from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NodeSnapshot:
    peer_id: str
    channel_peers: tuple[str, ...]
    registered_agents: tuple[str, ...]
    active_agent_count: int

    def validate(self) -> None:
        if not self.peer_id.strip():
            raise ValueError("peer_id must not be empty")


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    peer_ids: tuple[str, ...]
    node_snapshots: tuple[NodeSnapshot, ...]

    def validate(self) -> None:
        snapshot_peer_ids = tuple(snapshot.peer_id for snapshot in self.node_snapshots)
        if tuple(sorted(snapshot_peer_ids)) != tuple(sorted(self.peer_ids)):
            raise ValueError("peer_ids do not match node_snapshots")


@dataclass(frozen=True, slots=True)
class ApplicationSnapshot:
    product_name: str
    version: str
    mode: str
    transport: str
    transport_supported: bool
    boot_id: str
    runtime_root: str
    audit_log_path: str
    identity_path: str
    identity_exists: bool
    native_extension_available: bool
    local_peer_id: str | None

    def validate(self) -> None:
        if not self.product_name.strip():
            raise ValueError("product_name must not be empty")
        if not self.version.strip():
            raise ValueError("version must not be empty")
        if not self.mode.strip():
            raise ValueError("mode must not be empty")
        if not self.transport.strip():
            raise ValueError("transport must not be empty")
        if not self.boot_id.strip():
            raise ValueError("boot_id must not be empty")
        if not self.runtime_root.strip():
            raise ValueError("runtime_root must not be empty")
        if not self.audit_log_path.strip():
            raise ValueError("audit_log_path must not be empty")
        if not self.identity_path.strip():
            raise ValueError("identity_path must not be empty")
        if self.local_peer_id is not None and not self.local_peer_id.strip():
            raise ValueError("local_peer_id must not be empty when provided")
