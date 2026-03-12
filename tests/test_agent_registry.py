from __future__ import annotations

import pytest

from ix_operator.agents import AgentDefinition, AgentRegistry, AgentStatus


def _definition(agent_id: str, display_name: str, goal: str | None = None) -> AgentDefinition:
    return AgentDefinition(
        agent_id=agent_id,
        display_name=display_name,
        initial_goal=goal,
        metadata={"role": "test"},
    )


def test_register_agent_creates_state_and_memory() -> None:
    registry = AgentRegistry()

    state = registry.register(_definition("genesis-i", "Genesis I", "observe"))

    assert state.definition.agent_id == "genesis-i"
    assert state.status == AgentStatus.IDLE
    assert state.current_goal == "observe"
    assert registry.contains("genesis-i") is True
    assert registry.count() == 1
    assert registry.recall("genesis-i", "missing") is None


def test_register_duplicate_agent_rejected() -> None:
    registry = AgentRegistry()
    registry.register(_definition("genesis-i", "Genesis I"))

    with pytest.raises(ValueError, match="agent is already registered: genesis-i"):
        registry.register(_definition("genesis-i", "Genesis I Again"))


def test_agent_lifecycle_and_goal_updates() -> None:
    registry = AgentRegistry()
    registry.register(_definition("genesis-i", "Genesis I", "assist"))

    started = registry.start_agent("genesis-i")
    assert started.status == AgentStatus.RUNNING

    updated = registry.update_goal("genesis-i", "monitor")
    assert updated.current_goal == "monitor"

    processed = registry.mark_message_processed("genesis-i")
    assert processed.last_message_at_utc is not None

    stopped = registry.stop_agent("genesis-i")
    assert stopped.status == AgentStatus.STOPPED


def test_fail_agent_blocks_restart_via_state_rules() -> None:
    registry = AgentRegistry()
    registry.register(_definition("genesis-ii", "Genesis II"))

    failed = registry.fail_agent("genesis-ii", "runtime crash")
    assert failed.status == AgentStatus.FAILED
    assert failed.failure_reason == "runtime crash"

    with pytest.raises(ValueError, match="cannot start failed agent"):
        registry.start_agent("genesis-ii")


def test_memory_operations_are_scoped_per_agent() -> None:
    registry = AgentRegistry()
    registry.register(_definition("genesis-i", "Genesis I"))
    registry.register(_definition("genesis-ii", "Genesis II"))

    registry.remember("genesis-i", "mode", "observe")
    registry.remember("genesis-i", "retries", 2)
    registry.remember("genesis-ii", "mode", "assist")

    assert registry.recall("genesis-i", "mode") == "observe"
    assert registry.recall("genesis-i", "retries") == 2
    assert registry.recall("genesis-ii", "mode") == "assist"

    snapshot = registry.snapshot_memory("genesis-i")
    assert snapshot == {"mode": "observe", "retries": 2}

    forgot = registry.forget("genesis-i", "mode")
    assert forgot is True
    assert registry.recall("genesis-i", "mode") is None


def test_list_states_returns_copies() -> None:
    registry = AgentRegistry()
    registry.register(_definition("genesis-i", "Genesis I"))
    registry.register(_definition("genesis-ii", "Genesis II"))

    states = registry.list_states()
    assert len(states) == 2

    states[0].update_goal("tampered")

    original = registry.get_state("genesis-i")
    assert original is not None
    assert original.current_goal is None


def test_unregister_removes_agent_and_clears_memory() -> None:
    registry = AgentRegistry()
    registry.register(_definition("genesis-i", "Genesis I"))
    registry.remember("genesis-i", "mode", "observe")

    registry.unregister("genesis-i")

    assert registry.contains("genesis-i") is False
    assert registry.get_state("genesis-i") is None
    assert registry.count() == 0

    with pytest.raises(KeyError, match="unknown agent_id: genesis-i"):
        registry.recall("genesis-i", "mode")


def test_unknown_agent_operations_raise_key_error() -> None:
    registry = AgentRegistry()

    with pytest.raises(KeyError, match="unknown agent_id: missing-agent"):
        registry.start_agent("missing-agent")

    with pytest.raises(KeyError, match="unknown agent_id: missing-agent"):
        registry.remember("missing-agent", "mode", "observe")
