from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from threading import RLock

from ix_operator.agents import AgentMessage
from ix_operator.session import SessionMaterial
from ix_operator.transport import (
    DEFAULT_PACKET_SIZE,
    DEFAULT_RECEIVE_TIMEOUT_SECONDS,
    LocalTransportEndpoint,
    MessageType,
    PacketCodec,
    TransportSessionState,
)


@dataclass(slots=True)
class ChannelBinding:
    remote_peer_id: str
    material: SessionMaterial
    outbound_state: TransportSessionState
    inbound_state: TransportSessionState

    @classmethod
    def create(
        cls,
        *,
        remote_peer_id: str,
        session_id: str,
        material: SessionMaterial,
    ) -> "ChannelBinding":
        normalized_remote_peer_id = remote_peer_id.strip()
        normalized_session_id = session_id.strip()

        if not normalized_remote_peer_id:
            raise ValueError("remote_peer_id must not be empty")
        if not normalized_session_id:
            raise ValueError("session_id must not be empty")

        material.validate()

        return cls(
            remote_peer_id=normalized_remote_peer_id,
            material=SessionMaterial(
                encryption_key=material.encryption_key,
                authentication_key=material.authentication_key,
                transcript_hash=material.transcript_hash,
            ),
            outbound_state=TransportSessionState(session_id=normalized_session_id),
            inbound_state=TransportSessionState(session_id=normalized_session_id),
        )


@dataclass(frozen=True, slots=True)
class ReceivedAgentMessage:
    sender_peer_id: str
    recipient_peer_id: str
    packet_session_id: str
    sequence_number: int
    message: AgentMessage


class AgentBus:
    def __init__(self, *, endpoint: LocalTransportEndpoint, codec: PacketCodec) -> None:
        self._endpoint = endpoint
        self._codec = codec
        self._lock = RLock()
        self._channels: dict[str, ChannelBinding] = {}

    @property
    def local_peer_id(self) -> str:
        return self._endpoint.peer_id

    def bind_channel(
        self,
        *,
        remote_peer_id: str,
        session_id: str,
        material: SessionMaterial,
    ) -> ChannelBinding:
        normalized_remote_peer_id = self._normalize_peer_id(remote_peer_id)

        with self._lock:
            if normalized_remote_peer_id in self._channels:
                raise ValueError(f"channel is already bound: {normalized_remote_peer_id}")

            binding = ChannelBinding.create(
                remote_peer_id=normalized_remote_peer_id,
                session_id=session_id,
                material=material,
            )
            self._channels[normalized_remote_peer_id] = binding
            return deepcopy(binding)

    def get_channel(self, remote_peer_id: str) -> ChannelBinding | None:
        normalized_remote_peer_id = self._normalize_peer_id(remote_peer_id)

        with self._lock:
            binding = self._channels.get(normalized_remote_peer_id)
            if binding is None:
                return None
            return deepcopy(binding)

    def list_channels(self) -> list[str]:
        with self._lock:
            return sorted(self._channels.keys())

    def unbind_channel(self, remote_peer_id: str) -> None:
        normalized_remote_peer_id = self._normalize_peer_id(remote_peer_id)

        with self._lock:
            binding = self._channels.pop(normalized_remote_peer_id, None)
            if binding is not None:
                binding.material.wipe()
                binding.outbound_state.close()
                binding.inbound_state.close()

    def send_message(
        self,
        *,
        recipient_peer_id: str,
        message: AgentMessage,
        packet_size: int = DEFAULT_PACKET_SIZE,
    ) -> None:
        message.validate()
        normalized_recipient_peer_id = self._normalize_peer_id(recipient_peer_id)

        with self._lock:
            binding = self._require_channel_locked(normalized_recipient_peer_id)
            packet = self._codec.seal(
                state=binding.outbound_state,
                material=binding.material,
                message_type=MessageType.DATA,
                plaintext=message.to_bytes(),
                packet_size=packet_size,
            )

        self._endpoint.send_packet(
            recipient_peer_id=normalized_recipient_peer_id,
            packet=packet,
        )

    def receive_message(
        self,
        *,
        timeout_seconds: float | None = DEFAULT_RECEIVE_TIMEOUT_SECONDS,
    ) -> ReceivedAgentMessage | None:
        delivery = self._endpoint.receive_packet(timeout_seconds=timeout_seconds)
        if delivery is None:
            return None

        with self._lock:
            binding = self._require_channel_locked(delivery.sender_peer_id)
            packet = delivery.to_packet()
            plaintext = self._codec.open(
                state=binding.inbound_state,
                material=binding.material,
                packet=packet,
            )

        message = AgentMessage.from_bytes(plaintext)
        return ReceivedAgentMessage(
            sender_peer_id=delivery.sender_peer_id,
            recipient_peer_id=delivery.recipient_peer_id,
            packet_session_id=packet.header.session_id,
            sequence_number=packet.header.sequence_number,
            message=message,
        )

    def _normalize_peer_id(self, peer_id: str) -> str:
        normalized_peer_id = peer_id.strip()
        if not normalized_peer_id:
            raise ValueError("peer_id must not be empty")
        return normalized_peer_id

    def _require_channel_locked(self, remote_peer_id: str) -> ChannelBinding:
        binding = self._channels.get(remote_peer_id)
        if binding is None:
            raise KeyError(f"no channel bound for peer: {remote_peer_id}")
        return binding
