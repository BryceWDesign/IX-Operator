from __future__ import annotations

from threading import RLock
from typing import Callable

from ix_operator.agents import AgentMessage
from ix_operator.bus import ReceivedAgentMessage
from ix_operator.identity import NodeIdentity
from ix_operator.ix import ExecutionReport, IxProgram
from ix_operator.node import OperatorNode
from ix_operator.session import DEFAULT_SESSION_TTL_SECONDS, EstablishedSessionPair, SessionService
from ix_operator.transport import (
    DEFAULT_RECEIVE_TIMEOUT_SECONDS,
    LocalTransportHub,
    PacketCodec,
)


CodecFactory = Callable[[], PacketCodec]


class OperatorNetwork:
    def __init__(
        self,
        *,
        hub: LocalTransportHub,
        session_service: SessionService,
        codec_factory: CodecFactory,
    ) -> None:
        self._hub = hub
        self._session_service = session_service
        self._codec_factory = codec_factory
        self._lock = RLock()
        self._nodes: dict[str, OperatorNode] = {}

    @classmethod
    def local(
        cls,
        *,
        session_service: SessionService,
        codec_factory: CodecFactory,
    ) -> "OperatorNetwork":
        return cls(
            hub=LocalTransportHub(),
            session_service=session_service,
            codec_factory=codec_factory,
        )

    @property
    def hub(self) -> LocalTransportHub:
        return self._hub

    def add_node(self, identity: NodeIdentity) -> OperatorNode:
        identity.validate()

        with self._lock:
            if identity.peer_id in self._nodes:
                raise ValueError(f"node is already registered: {identity.peer_id}")

            node = OperatorNode.from_identity(
                identity=identity,
                hub=self._hub,
                session_service=self._session_service,
                codec=self._codec_factory(),
            )
            self._nodes[identity.peer_id] = node
            return node

    def get_node(self, peer_id: str) -> OperatorNode | None:
        normalized_peer_id = self._normalize_peer_id(peer_id)

        with self._lock:
            return self._nodes.get(normalized_peer_id)

    def list_nodes(self) -> list[str]:
        with self._lock:
            return sorted(self._nodes.keys())

    def boot_program(
        self,
        *,
        peer_id: str,
        program_or_source: IxProgram | str,
    ) -> tuple[ExecutionReport, ...]:
        node = self._require_node(peer_id)
        return node.boot_program(program_or_source)

    def connect(
        self,
        *,
        initiator_peer_id: str,
        responder_peer_id: str,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    ) -> EstablishedSessionPair:
        initiator = self._require_node(initiator_peer_id)
        responder = self._require_node(responder_peer_id)
        return initiator.establish_channel(responder, ttl_seconds=ttl_seconds)

    def send_message(
        self,
        *,
        sender_peer_id: str,
        recipient_peer_id: str,
        sender_agent_id: str,
        recipient_agent_id: str,
        body: str,
        headers: dict[str, str] | None = None,
        correlation_id: str | None = None,
    ) -> AgentMessage:
        sender = self._require_node(sender_peer_id)
        return sender.send_message(
            recipient_peer_id=recipient_peer_id,
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            body=body,
            headers=headers,
            correlation_id=correlation_id,
        )

    def receive_message(
        self,
        *,
        peer_id: str,
        timeout_seconds: float | None = DEFAULT_RECEIVE_TIMEOUT_SECONDS,
    ) -> ReceivedAgentMessage | None:
        node = self._require_node(peer_id)
        return node.receive_message(timeout_seconds=timeout_seconds)

    def shutdown_all(self) -> None:
        with self._lock:
            nodes = list(self._nodes.values())
            self._nodes.clear()

        for node in nodes:
            node.shutdown()

    def _require_node(self, peer_id: str) -> OperatorNode:
        normalized_peer_id = self._normalize_peer_id(peer_id)

        with self._lock:
            node = self._nodes.get(normalized_peer_id)
            if node is None:
                raise KeyError(f"unknown peer_id: {normalized_peer_id}")
            return node

    def _normalize_peer_id(self, peer_id: str) -> str:
        normalized_peer_id = peer_id.strip()
        if not normalized_peer_id:
            raise ValueError("peer_id must not be empty")
        return normalized_peer_id
