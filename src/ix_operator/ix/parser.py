from __future__ import annotations

import re
import shlex

from ix_operator.ix.ast import (
    AgentBlock,
    GoalStatement,
    IxProgram,
    IxStatement,
    RememberStatement,
    SayStatement,
)


_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


class IxParseError(ValueError):
    """Raised when an IX script cannot be parsed."""


def parse_ix_script(source: str) -> IxProgram:
    if not source.strip():
        raise IxParseError("IX script must not be empty")

    agents: list[AgentBlock] = []
    current_agent_id: str | None = None
    current_display_name: str | None = None
    current_statements: list[IxStatement] = []

    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        tokens = _split_line(raw_line)
        if not tokens:
            continue

        keyword = tokens[0]

        if keyword == "agent":
            if current_agent_id is not None and current_display_name is not None:
                agents.append(
                    AgentBlock(
                        agent_id=current_agent_id,
                        display_name=current_display_name,
                        statements=tuple(current_statements),
                    )
                )
                current_statements = []

            current_agent_id, current_display_name = _parse_agent(tokens, line_number)
            continue

        if current_agent_id is None:
            raise IxParseError(
                f"line {line_number}: statements are not allowed before the first agent block"
            )

        statement = _parse_statement(tokens, line_number)
        current_statements.append(statement)

    if current_agent_id is None or current_display_name is None:
        raise IxParseError("IX script must define at least one agent")

    agents.append(
        AgentBlock(
            agent_id=current_agent_id,
            display_name=current_display_name,
            statements=tuple(current_statements),
        )
    )

    program = IxProgram(agents=tuple(agents))
    try:
        program.validate()
    except ValueError as exc:
        raise IxParseError(str(exc)) from exc

    return program


def _split_line(raw_line: str) -> list[str]:
    lexer = shlex.shlex(raw_line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)


def _parse_agent(tokens: list[str], line_number: int) -> tuple[str, str]:
    if len(tokens) != 3:
        raise IxParseError(
            f"line {line_number}: agent syntax must be: agent <agent_id> <display_name>"
        )

    _, agent_id, display_name = tokens

    if not _IDENTIFIER_RE.fullmatch(agent_id):
        raise IxParseError(
            f"line {line_number}: invalid agent_id '{agent_id}'"
        )

    if not display_name.strip():
        raise IxParseError(f"line {line_number}: display_name must not be empty")

    return agent_id, display_name


def _parse_statement(tokens: list[str], line_number: int) -> IxStatement:
    keyword = tokens[0]

    if keyword == "goal":
        if len(tokens) != 2:
            raise IxParseError(f"line {line_number}: goal syntax must be: goal <text>")
        return GoalStatement(goal=tokens[1])

    if keyword == "remember":
        if len(tokens) != 4 or tokens[2] != "=":
            raise IxParseError(
                f"line {line_number}: remember syntax must be: remember <key> = <value>"
            )

        key = tokens[1]
        if not _IDENTIFIER_RE.fullmatch(key):
            raise IxParseError(f"line {line_number}: invalid remember key '{key}'")

        return RememberStatement(key=key, value=tokens[3])

    if keyword == "say":
        if len(tokens) != 2:
            raise IxParseError(f"line {line_number}: say syntax must be: say <text>")
        return SayStatement(text=tokens[1])

    raise IxParseError(f"line {line_number}: unknown statement '{keyword}'")
