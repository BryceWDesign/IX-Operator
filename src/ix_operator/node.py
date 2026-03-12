from __future__ import annotations

from copy import deepcopy

from ix_operator.agents import AgentMessage, AgentRegistry
from ix_operator.bus import AgentBus, ReceivedAgentMessage
from ix_operator.diagnostics import NodeSnapshot
from ix_operator.identity import NodeIdentity
from ix_operator.ix import ExecutionReport, IxInterpreter, IxProgram, parse_ix_script
from ix_operator.session import (
    DEFAULT_SESSION_TTL_SECONDS,
    EstablishedSessionPair,
    LocalSecrets,
    PeerIdentity,
    SessionEndpoint,
    SessionManager,
    SessionService,
)
from ix_operator.transport import (
    DEFAULT_RECEIVE_TIMEOUT_SECONDS,
    LocalTransportEndpoint,
    LocalTransportHub,
    PacketCodec,
)


class OperatorNode:
    def __init__(
        self,
        *,
        peer_id: str,
        endpoint: LocalTransportEndpoint,
        session_endpoint: SessionEndpoint,
        session_service: SessionService,
        bus: AgentBus,
        registry: AgentRegistry | None = None,
    ) -> None:
        normalized_peer_id = peer_id.strip()
        if not normalized_peer_id:
            raise ValueError("peer_id must not be empty")

        self._peer_id = normalized_peer_id
        self._endpoint = endpoint
        self._session_endpoint = session_endpoint
        self._session_service = session_service
        self._bus = bus
        self._registry = registry or AgentRegistry()
        self._interpreter = IxInterpreter(self._registry)

    @classmethod
    def create(
        cls,
        *,
        peer_id: str,
        signing_public_key: bytes,
        exchange_public_key: bytes,
        signing_private_key: bytes,
        exchange_private_key: bytes,
        hub: LocalTransportHub,
        session_service: SessionService,
        codec: PacketCodec,
    ) -> "OperatorNode":
        normalized_peer_id = peer_id.strip()
        if not normalized_peer_id:
            raise ValueError("peer_id must not be empty")

        local_peer = PeerIdentity(
            peer_id=normalized_peer_id,
            signing_public_key=signing_public_key,
            exchange_public_key=exchange_public_key,
        )
        local_secrets = LocalSecrets(
            signing_private_key=signing_private_key,
            exchange_private_key=exchange_private_key,
        )
        session_endpoint = SessionEndpoint(
            local_peer=local_peer,
            local_secrets=local_secrets,
            manager=SessionManager(),
        )
        endpoint = hub.register(normalized_peer_id)
        bus = AgentBus(endpoint=endpoint, codec=codec)

        return cls(
            peer_id=normalized_peer_id,
            endpoint=endpoint,
            session_endpoint=session_endpoint,
            session_service=session_service,
            bus=bus,
        )

    @classmethod
    def from_identity(
        cls,
        *,
        identity: NodeIdentity,
        hub: LocalTransportHub,
        session_service: SessionService,
        codec: PacketCodec,
    ) -> "OperatorNode":
        identity.validate()
        return cls.create(
            peer_id=identity.peer_id,
            signing_public_key=identity.signing_public_key,
            exchange_public_key=identity.exchange_public_key,
            signing_private_key=identity.signing_private_key,
            exchange_private_key=identity.exchange_private_key,
            hub=hub,
            session_service=session_service,
            codec=codec,
        )

    @property
    def peer_id(self) -> str:
        return self._peer_id

    @property
    def registry(self) -> AgentRegistry:
        return self._registry

    @property
    def bus(self) -> AgentBus:
        return self._bus

    @property
    def session_endpoint(self) -> SessionEndpoint:
        return self._session_endpoint

    def snapshot(self) -> NodeSnapshot:
        states = self._registry.list_states()
        registered_agents = tuple(sorted(state.definition.agent_id for state in states))
        active_agent_count = sum(1 for state in states if state.status.value == "running")

        snapshot = NodeSnapshot(
            peer_id=self.peer_id,
            channel_peers=tuple(self.list_channels()),
            registered_agents=registered_agents,
            active_agent_count=active_agent_count,
        )
        snapshot.validate()
        return snapshot

    def boot_program(self, program_or_source: IxProgram | str) -> tuple[ExecutionReport, ...]:
        program = self._coerce_program(program_or_source)
        return self._interpreter.boot_program(program)

    def execute_agent(
        self,
        program_or_source: IxProgram | str,
        agent_id: str,
    ) -> ExecutionReport:
        program = self._coerce_program(program_or_source)
        return self._interpreter.execute_agent(program, agent_id)

    def establish_channel(
        self,
        remote_node: "OperatorNode",
        *,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    ) -> EstablishedSessionPair:
        if self.peer_id == remote_node.peer_id:
            raise ValueError("cannot establish a channel to the same peer_id")

        established = self._session_service.establish_pair(
            initiator=self._session_endpoint,
            responder=remote_node.session_endpoint,
            ttl_seconds=ttl_seconds,
        )

        self._bus.bind_channel(
            remote_peer_id=remote_node.peer_id,
            session_id=established.channel_session_id,
            material=deepcopy(established.initiator_material),
        )
        remote_node.bus.bind_channel(
            remote_peer_id=self.peer_id,
            session_id=established.channel_session_id,
            material=deepcopy(established.responder_material),
        )

        return established

    def send_message(
        self,
        *,
        recipient_peer_id: str,
        sender_agent_id: str,
        recipient_agent_id: str,
        body: str,
        headers: dict[str, str] | None = None,
        correlation_id: str | None = None,
    ) -> AgentMessage:
        message = AgentMessage.create(
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            body=body,
            headers=headers,
            correlation_id=correlation_id,
        )
        self._bus.send_message(
            recipient_peer_id=recipient_peer_id,
            message=message,
        )

        if self._registry.contains(sender_agent_id):
            self._registry.mark_message_processed(sender_agent_id)

        return message

    def receive_message(
        self,
        *,
        timeout_seconds: float | None = DEFAULT_RECEIVE_TIMEOUT_SECONDS,
    ) -> ReceivedAgentMessage | None:
        received = self._bus.receive_message(timeout_seconds=timeout_seconds)
        if received is None:
            return None

        if self._registry.contains(received.message.recipient_agent_id):
            self._registry.mark_message_processed(received.message.recipient_agent_id)

        return received

    def list_channels(self) -> list[str]:
        return self._bus.list_channels()

    def shutdown(self) -> None:
        for remote_peer_id in self._bus.list_channels():
            self._bus.unbind_channel(remote_peer_id)
        self._endpoint.close()

    def _coerce_program(self, program_or_source: IxProgram | str) -> IxProgram:
        if isinstance(program_or_source, IxProgram):
            return program_or_source
        if isinstance(program_or_source, str):
            return parse_ix_script(program_or_source)
        raise TypeError("program_or_source must be an IxProgram or str")
