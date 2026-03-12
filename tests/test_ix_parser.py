from __future__ import annotations

import pytest

from ix_operator.ix import (
    GoalStatement,
    IxParseError,
    RememberStatement,
    SayStatement,
    parse_ix_script,
)


def test_parse_single_agent_program() -> None:
    source = """
    agent genesis_i "Genesis I"
    goal "observe"
    remember mode = "passive"
    say "hello operator"
    """

    program = parse_ix_script(source)
    agent = program.get_agent("genesis_i")

    assert agent is not None
    assert agent.agent_id == "genesis_i"
    assert agent.display_name == "Genesis I"
    assert len(agent.statements) == 3
    assert isinstance(agent.statements[0], GoalStatement)
    assert isinstance(agent.statements[1], RememberStatement)
    assert isinstance(agent.statements[2], SayStatement)


def test_parse_multiple_agents_and_ignore_comments() -> None:
    source = """
    # primary agent
    agent genesis_i "Genesis I"
    goal "observe"

    # secondary agent
    agent genesis_ii "Genesis II"
    remember mode = "assist"
    say "ready"
    """

    program = parse_ix_script(source)

    assert len(program.agents) == 2
    assert program.get_agent("genesis_i") is not None
    assert program.get_agent("genesis_ii") is not None


def test_reject_statement_before_agent() -> None:
    source = """
    goal "observe"
    agent genesis_i "Genesis I"
    """

    with pytest.raises(
        IxParseError,
        match="statements are not allowed before the first agent block",
    ):
        parse_ix_script(source)


def test_reject_invalid_remember_syntax() -> None:
    source = """
    agent genesis_i "Genesis I"
    remember mode "passive"
    """

    with pytest.raises(
        IxParseError,
        match="remember syntax must be: remember <key> = <value>",
    ):
        parse_ix_script(source)


def test_reject_invalid_agent_identifier() -> None:
    source = """
    agent 123bad "Genesis I"
    goal "observe"
    """

    with pytest.raises(IxParseError, match="invalid agent_id '123bad'"):
        parse_ix_script(source)


def test_reject_duplicate_agent_ids() -> None:
    source = """
    agent genesis_i "Genesis I"
    say "one"
    agent genesis_i "Genesis I Again"
    say "two"
    """

    with pytest.raises(IxParseError, match="duplicate agent_id: genesis_i"):
        parse_ix_script(source)


def test_reject_unknown_statement() -> None:
    source = """
    agent genesis_i "Genesis I"
    dance "wildly"
    """

    with pytest.raises(IxParseError, match="unknown statement 'dance'"):
        parse_ix_script(source)
