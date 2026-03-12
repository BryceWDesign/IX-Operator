from __future__ import annotations

from dataclasses import dataclass

from ix_operator.config import OperatorConfig
from ix_operator.crypto import (
    NativeExtensionUnavailableError,
    NativeHandshakeBackend,
    NativeTransportBackend,
    native_extension_available,
)
from ix_operator.diagnostics import ApplicationSnapshot
from ix_operator.identity import NodeIdentity, NodeIdentityStore, default_identity_store
from ix_operator.node import OperatorNode
from ix_operator.runtime import RuntimeContext
from ix_operator.session import SessionService
from ix_operator.transport import LocalTransportHub, PacketCodec


@dataclass(frozen=True, slots=True)
class ScriptRunResult:
    peer_id: str
    report_count: int
    agent_ids: tuple[str, ...]


class OperatorApplication:
    def __init__(self, *, config: OperatorConfig, context: RuntimeContext) -> None:
        self._config = config
        self._context = context
        self._identity_store = default_identity_store(config.runtime_paths.root)

    @classmethod
    def from_env(cls) -> "OperatorApplication":
        config = OperatorConfig.from_env()
        context = RuntimeContext.bootstrap(config)
        return cls(config=config, context=context)

    @property
    def config(self) -> OperatorConfig:
        return self._config

    @property
    def context(self) -> RuntimeContext:
        return self._context

    @property
    def identity_store(self) -> NodeIdentityStore:
        return self._identity_store

    def status_snapshot(self) -> ApplicationSnapshot:
        identity = self._identity_store.load()

        snapshot = ApplicationSnapshot(
            product_name="IX-Operator",
            version="0.1.0",
            mode=self._config.mode.value,
            transport=self._config.transport_backend.value,
            boot_id=self._context.boot_id,
            runtime_root=str(self._config.runtime_paths.root),
            audit_log_path=str(self._context.audit.path),
            identity_path=str(self._identity_store.path),
            identity_exists=self._identity_store.exists(),
            native_extension_available=native_extension_available(),
            local_peer_id=identity.peer_id if identity is not None else None,
        )
        snapshot.validate()
        return snapshot

    def initialize_identity(
        self,
        *,
        peer_id: str | None = None,
        peer_id_prefix: str = "node",
    ) -> NodeIdentity:
        self._require_native_extension()

        identity = self._identity_store.load_or_create(
            peer_id=peer_id,
            peer_id_prefix=peer_id_prefix,
        )
        self._context.record_event(
            severity=self._info_severity(),
            category=self._system_category(),
            action="identity.initialize",
            outcome="success",
            details={
                "peer_id": identity.peer_id,
                "identity_path": str(self._identity_store.path),
            },
        )
        return identity

    def load_identity(self) -> NodeIdentity | None:
        identity = self._identity_store.load()
        if identity is not None:
            self._context.record_event(
                severity=self._info_severity(),
                category=self._system_category(),
                action="identity.load",
                outcome="success",
                details={
                    "peer_id": identity.peer_id,
                    "identity_path": str(self._identity_store.path),
                },
            )
        return identity

    def boot_local_node(self) -> OperatorNode:
        self._require_native_extension()

        identity = self._identity_store.load()
        if identity is None:
            raise FileNotFoundError(
                f"node identity not found at {self._identity_store.path}; run identity init first"
            )

        node = OperatorNode.from_identity(
            identity=identity,
            hub=LocalTransportHub(),
            session_service=SessionService(NativeHandshakeBackend()),
            codec=PacketCodec(NativeTransportBackend()),
        )

        self._context.record_event(
            severity=self._info_severity(),
            category=self._runtime_category(),
            action="node.boot_local",
            outcome="success",
            details={"peer_id": node.peer_id},
        )
        return node

    def run_script(self, source: str) -> ScriptRunResult:
        node = self.boot_local_node()
        reports = node.boot_program(source)

        result = ScriptRunResult(
            peer_id=node.peer_id,
            report_count=len(reports),
            agent_ids=tuple(report.agent_id for report in reports),
        )

        self._context.record_event(
            severity=self._info_severity(),
            category=self._runtime_category(),
            action="runtime.run_script",
            outcome="success",
            details={
                "peer_id": result.peer_id,
                "report_count": result.report_count,
                "agent_ids": list(result.agent_ids),
            },
        )

        node.shutdown()
        return result

    def _require_native_extension(self) -> None:
        if not native_extension_available():
            raise NativeExtensionUnavailableError(
                "native ix_crypto extension is unavailable; build the PyO3 module first"
            )

    def _info_severity(self):
        from ix_operator.audit import AuditSeverity

        return AuditSeverity.INFO

    def _system_category(self):
        from ix_operator.audit import AuditCategory

        return AuditCategory.SYSTEM

    def _runtime_category(self):
        from ix_operator.audit import AuditCategory

        return AuditCategory.RUNTIME
