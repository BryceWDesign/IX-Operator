from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import json
from typing import Any
from uuid import uuid4


class AgentStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AgentDefinition:
    agent_id: str
    display_name: str
    initial_goal: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.agent_id.strip():
            raise ValueError("agent_id must not be empty")
        if not self.display_name.strip():
            raise ValueError("display_name must not be empty")

        for key, value in self.metadata.items():
            if not key.strip():
                raise ValueError("metadata keys must not be empty")
            if not value.strip():
                raise ValueError("metadata values must not be empty")


@dataclass(slots=True)
class AgentRuntimeState:
    definition: AgentDefinition
    status: AgentStatus = AgentStatus.IDLE
    current_goal: str | None = None
    last_message_at_utc: datetime | None = None
    failure_reason: str | None = None

    @classmethod
    def create(cls, definition: AgentDefinition) -> "AgentRuntimeState":
        definition.validate()
        return cls(
            definition=definition,
            status=AgentStatus.IDLE,
            current_goal=definition.initial_goal,
        )

    def start(self) -> None:
        if self.status == AgentStatus.FAILED:
            raise ValueError("cannot start failed agent")
        self.status = AgentStatus.RUNNING

    def stop(self) -> None:
        if self.status == AgentStatus.FAILED:
            return
        self.status = AgentStatus.STOPPED

    def fail(self, reason: str) -> None:
        if not reason.strip():
            raise ValueError("reason must not be empty")
        self.status = AgentStatus.FAILED
        self.failure_reason = reason.strip()

    def update_goal(self, goal: str | None) -> None:
        if goal is not None and not goal.strip():
            raise ValueError("goal must not be empty when provided")
        self.current_goal = goal

    def mark_message_processed(self) -> None:
        self.last_message_at_utc = datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AgentMessage:
    message_id: str
    sender_agent_id: str
    recipient_agent_id: str
    body: str
    created_at_utc: str
    headers: dict[str, str] = field(default_factory=dict)
    correlation_id: str | None = None

    @classmethod
    def create(
        cls,
        *,
        sender_agent_id: str,
        recipient_agent_id: str,
        body: str,
        headers: dict[str, str] | None = None,
        correlation_id: str | None = None,
    ) -> "AgentMessage":
        message = cls(
            message_id=f"msg-{uuid4().hex}",
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            body=body,
            created_at_utc=datetime.now(UTC).isoformat(),
            headers=headers or {},
            correlation_id=correlation_id,
        )
        message.validate()
        return message

    def validate(self) -> None:
        if not self.message_id.strip():
            raise ValueError("message_id must not be empty")
        if not self.sender_agent_id.strip():
            raise ValueError("sender_agent_id must not be empty")
        if not self.recipient_agent_id.strip():
            raise ValueError("recipient_agent_id must not be empty")
        if not self.body.strip():
            raise ValueError("body must not be empty")

        for key, value in self.headers.items():
            if not key.strip():
                raise ValueError("header keys must not be empty")
            if not value.strip():
                raise ValueError("header values must not be empty")

        if self.correlation_id is not None and not self.correlation_id.strip():
            raise ValueError("correlation_id must not be empty when provided")

    def to_bytes(self) -> bytes:
        self.validate()
        payload = {
            "message_id": self.message_id,
            "sender_agent_id": self.sender_agent_id,
            "recipient_agent_id": self.recipient_agent_id,
            "body": self.body,
            "created_at_utc": self.created_at_utc,
            "headers": self.headers,
            "correlation_id": self.correlation_id,
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "AgentMessage":
        try:
            payload: dict[str, Any] = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid agent message encoding") from exc

        message = cls(
            message_id=_expect_str(payload, "message_id"),
            sender_agent_id=_expect_str(payload, "sender_agent_id"),
            recipient_agent_id=_expect_str(payload, "recipient_agent_id"),
            body=_expect_str(payload, "body"),
            created_at_utc=_expect_str(payload, "created_at_utc"),
            headers=_expect_str_dict(payload.get("headers", {}), "headers"),
            correlation_id=_expect_optional_str(payload.get("correlation_id"), "correlation_id"),
        )
        message.validate()
        return message


def _expect_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _expect_optional_str(value: Any, key: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string when provided")
    return value


def _expect_str_dict(value: Any, key: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a dict")

    result: dict[str, str] = {}
    for item_key, item_value in value.items():
        if not isinstance(item_key, str):
            raise ValueError(f"{key} keys must be strings")
        if not isinstance(item_value, str):
            raise ValueError(f"{key} values must be strings")
        result[item_key] = item_value

    return result
