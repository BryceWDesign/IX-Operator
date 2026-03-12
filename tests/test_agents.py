from __future__ import annotations

import pytest

from ix_operator.agents import (
    AgentDefinition,
    AgentMemoryStore,
    AgentMessage,
    AgentRuntimeState,
    AgentStatus,
)


def test_agent_definition_validation_accepts_valid_definition() -> None:
    definition = AgentDefinition(
        agent_id="genesis-i",
        display_name="Genesis I",
        initial_goal="observe",
        metadata={"role": "primary"},
    )

    definition.validate()

    assert definition.agent_id == "genesis-i"
    assert definition.display_name == "Genesis I"
    assert definition.initial_goal == "observe"


def test_agent_definition_rejects_empty_display_name() -> None:
    definition = AgentDefinition(
        agent_id="genesis-i",
        display_name="   ",
    )

    with pytest.raises(ValueError, match="display_name must not be empty"):
        definition.validate()


def test_agent_runtime_state_lifecycle() -> None:
    definition = AgentDefinition(
        agent_id="genesis-i",
        display_name="Genesis I",
        initial_goal="assist",
    )
    state = AgentRuntimeState.create(definition)

    assert state.status == AgentStatus.IDLE
    assert state.current_goal == "assist"

    state.start()
    assert state.status == AgentStatus.RUNNING

    state.update_goal("monitor")
    assert state.current_goal == "monitor"

    state.mark_message_processed()
    assert state.last_message_at_utc is not None

    state.stop()
    assert state.status == AgentStatus.STOPPED


def test_agent_runtime_state_rejects_start_after_failure() -> None:
    definition = AgentDefinition(
        agent_id="genesis-ii",
        display_name="Genesis II",
    )
    state = AgentRuntimeState.create(definition)
    state.fail("critical runtime error")

    assert state.status == AgentStatus.FAILED
    assert state.failure_reason == "critical runtime error"

    with pytest.raises(ValueError, match="cannot start failed agent"):
        state.start()


def test_agent_message_round_trip_serialization() -> None:
    message = AgentMessage.create(
        sender_agent_id="genesis-i",
        recipient_agent_id="genesis-ii",
        body="hello there",
        headers={"intent": "ping"},
        correlation_id="corr-123",
    )

    decoded = AgentMessage.from_bytes(message.to_bytes())

    assert decoded.message_id == message.message_id
    assert decoded.sender_agent_id == "genesis-i"
    assert decoded.recipient_agent_id == "genesis-ii"
    assert decoded.body == "hello there"
    assert decoded.headers == {"intent": "ping"}
    assert decoded.correlation_id == "corr-123"


def test_agent_message_rejects_invalid_encoding() -> None:
    with pytest.raises(ValueError, match="invalid agent message encoding"):
        AgentMessage.from_bytes(b"\xff\x00\x01")


def test_memory_store_remember_recall_and_forget() -> None:
    store = AgentMemoryStore(namespace="genesis-i")

    store.remember("mode", "observe")
    store.remember("retries", 3)
    store.remember("safe", True)

    assert store.namespace == "genesis-i"
    assert store.contains("mode") is True
    assert store.recall("mode") == "observe"
    assert store.recall("retries") == 3
    assert store.recall("safe") is True
    assert store.size() == 3

    forgotten = store.forget("mode")
    assert forgotten is True
    assert store.contains("mode") is False
    assert store.recall("mode") is None


def test_memory_store_snapshot_is_isolated_copy() -> None:
    store = AgentMemoryStore(namespace="genesis-ii")
    store.remember("goal", "assist")

    snapshot = store.snapshot()
    snapshot["goal"] = "tampered"

    assert store.recall("goal") == "assist"


def test_memory_store_rejects_invalid_value_type() -> None:
    store = AgentMemoryStore(namespace="genesis-iii")

    with pytest.raises(ValueError, match="memory value must be str, int, float, bool, or None"):
        store.remember("bad", {"nested": "dict"})  # type: ignore[arg-type]
