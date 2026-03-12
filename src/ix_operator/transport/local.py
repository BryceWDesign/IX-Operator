from __future__ import annotations

from dataclasses import dataclass, field
from queue import Empty, Queue
from threading import RLock
from typing import Final

from ix_operator.transport.packet import Packet


DEFAULT_RECEIVE_TIMEOUT_SECONDS: Final[float] = 0.25


class LocalTransportClosedError(RuntimeError):
    """Raised when an operation is attempted on a closed local transport endpoint."""


@dataclass(frozen=True, slots=True)
class LocalDelivery:
    sender_peer_id: str
    recipient_peer_id: str
    packet_bytes: bytes

    def to_packet(self) -> Packet:
        return Packet.from_bytes(self.packet_bytes)


@dataclass(slots=True)
class LocalTransportEndpoint:
    peer_id: str
    _hub: LocalTransportHub
    _inbox: Queue[LocalDelivery] = field(default_factory=Queue)
    _closed: bool = False

    def send_packet(self, *, recipient_peer_id: str, packet: Packet) -> None:
        self._require_open()
        self._hub._deliver(
            sender_peer_id=self.peer_id,
            recipient_peer_id=recipient_peer_id,
            packet=packet,
        )

    def receive_packet(
        self,
        *,
        timeout_seconds: float | None = DEFAULT_RECEIVE_TIMEOUT_SECONDS,
    ) -> LocalDelivery | None:
        self._require_open()

        if timeout_seconds is not None and timeout_seconds < 0:
            raise ValueError("timeout_seconds must be non-negative or None")

        try:
            if timeout_seconds is None:
                return self._inbox.get(block=True)
            return self._inbox.get(timeout=timeout_seconds)
        except Empty:
            return None

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._hub.unregister(self.peer_id)

    def _push(self, delivery: LocalDelivery) -> None:
        if self._closed:
            raise LocalTransportClosedError(f"endpoint is closed: {self.peer_id}")
        self._inbox.put(delivery)

    def _require_open(self) -> None:
        if self._closed:
            raise LocalTransportClosedError(f"endpoint is closed: {self.peer_id}")


class LocalTransportHub:
    def __init__(self) -> None:
        self._lock = RLock()
        self._endpoints: dict[str, LocalTransportEndpoint] = {}

    def register(self, peer_id: str) -> LocalTransportEndpoint:
        normalized_peer_id = peer_id.strip()
        if not normalized_peer_id:
            raise ValueError("peer_id must not be empty")

        with self._lock:
            if normalized_peer_id in self._endpoints:
                raise ValueError(f"peer_id is already registered: {normalized_peer_id}")

            endpoint = LocalTransportEndpoint(
                peer_id=normalized_peer_id,
                _hub=self,
            )
            self._endpoints[normalized_peer_id] = endpoint
            return endpoint

    def unregister(self, peer_id: str) -> None:
        normalized_peer_id = peer_id.strip()
        if not normalized_peer_id:
            raise ValueError("peer_id must not be empty")

        with self._lock:
            self._endpoints.pop(normalized_peer_id, None)

    def get_endpoint(self, peer_id: str) -> LocalTransportEndpoint | None:
        normalized_peer_id = peer_id.strip()
        if not normalized_peer_id:
            raise ValueError("peer_id must not be empty")

        with self._lock:
            return self._endpoints.get(normalized_peer_id)

    def peer_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._endpoints.keys())

    def _deliver(
        self,
        *,
        sender_peer_id: str,
        recipient_peer_id: str,
        packet: Packet,
    ) -> None:
        sender = sender_peer_id.strip()
        recipient = recipient_peer_id.strip()

        if not sender:
            raise ValueError("sender_peer_id must not be empty")
        if not recipient:
            raise ValueError("recipient_peer_id must not be empty")

        delivery = LocalDelivery(
            sender_peer_id=sender,
            recipient_peer_id=recipient,
            packet_bytes=packet.to_bytes(),
        )

        with self._lock:
            sender_endpoint = self._endpoints.get(sender)
            if sender_endpoint is None:
                raise KeyError(f"sender peer is not registered: {sender}")

            recipient_endpoint = self._endpoints.get(recipient)
            if recipient_endpoint is None:
                raise KeyError(f"recipient peer is not registered: {recipient}")

            recipient_endpoint._push(delivery)
