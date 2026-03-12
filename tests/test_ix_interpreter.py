from __future__ import annotations

import pytest

from ix_operator.agents import AgentRegistry, AgentStatus
from ix_operator.ix import IxInterpreter, parse_ix_script


def test_load_program_registers_agents() -> None:
    registry = AgentRegistry()
    interpreter = IxInterpreter(registry)

    program = parse_ix_script(
        """
        agent genesis_i "Genesis I"
        goal "observe"

        agent genesis_ii "Genesis II"
        say "ready"
        """
    )

    loaded = interpreter.load_program(program)

    assert loaded == ["genesis_i", "genesis_ii"]
    assert registry.contains("genesis_i") is True
    assert registry.contains("genesis_ii") is True
    assert registry.count() == 2


def test_execute_agent_applies_goal_memory_and_emissions() -> None:
    registry = AgentRegistry()
    interpreter = IxInterpreter(registry)

    program = parse_ix_script(
        """
        agent genesis_i "Genesis I"
        goal "monitor"
        remember mode = "passive"
        remember retries = "3"
        say "hello operator"
        say "standing by"
        """
    )

    report = interpreter.execute_agent(program, "genesis_i")
    state = registry.get_state("genesis_i")

    assert report.agent_id == "genesis_i"
    assert report.display_name == "Genesis I"
    assert report.final_goal == "monitor"
    assert report.memory_snapshot == {"mode": "passive", "retries": "3"}
    assert len(report.emissions) == 2
    assert report.emissions[0].text == "hello operator"
    assert report.emissions[1].text == "standing by"

    assert state is not None
    assert state.status == AgentStatus.STOPPED
    assert state.current_goal == "monitor"


def test_boot_program_executes_all_agents() -> None:
    registry = AgentRegistry()
    interpreter = IxInterpreter(registry)

    program = parse_ix_script(
        """
        agent genesis_i "Genesis I"
        goal "observe"
        remember mode = "watch"
        say "ready"

        agent genesis_ii "Genesis II"
        goal "assist"
        remember partner = "genesis_i"
        say "linked"
        """
    )

    reports = interpreter.boot_program(program)

    assert len(reports) == 2
    assert reports[0].agent_id == "genesis_i"
    assert reports[0].final_goal == "observe"
    assert reports[0].memory_snapshot["mode"] == "watch"
    assert reports[1].agent_id == "genesis_ii"
    assert reports[1].final_goal == "assist"
    assert reports[1].memory_snapshot["partner"] == "genesis_i"


def test_execute_agent_rejects_unknown_program_agent() -> None:
    registry = AgentRegistry()
    interpreter = IxInterpreter(registry)

    program = parse_ix_script(
        """
        agent genesis_i "Genesis I"
        say "hello"
        """
    )

    with pytest.raises(KeyError, match="unknown agent_id in program: missing_agent"):
        interpreter.execute_agent(program, "missing_agent")


def test_existing_agent_with_different_display_name_is_rejected() -> None:
    registry = AgentRegistry()
    interpreter = IxInterpreter(registry)

    first_program = parse_ix_script(
        """
        agent genesis_i "Genesis I"
        say "hello"
        """
    )
    second_program = parse_ix_script(
        """
        agent genesis_i "Different Name"
        say "hello"
        """
    )

    interpreter.load_program(first_program)

    with pytest.raises(
        ValueError,
        match="agent_id already registered with different display name: genesis_i",
    ):
        interpreter.load_program(second_program)
