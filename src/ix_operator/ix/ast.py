from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias


@dataclass(frozen=True, slots=True)
class GoalStatement:
    goal: str

    def validate(self) -> None:
        if not self.goal.strip():
            raise ValueError("goal must not be empty")


@dataclass(frozen=True, slots=True)
class RememberStatement:
    key: str
    value: str

    def validate(self) -> None:
        if not self.key.strip():
            raise ValueError("remember key must not be empty")
        if not self.value.strip():
            raise ValueError("remember value must not be empty")


@dataclass(frozen=True, slots=True)
class SayStatement:
    text: str

    def validate(self) -> None:
        if not self.text.strip():
            raise ValueError("say text must not be empty")


IxStatement: TypeAlias = GoalStatement | RememberStatement | SayStatement


@dataclass(frozen=True, slots=True)
class AgentBlock:
    agent_id: str
    display_name: str
    statements: tuple[IxStatement, ...]

    def validate(self) -> None:
        if not self.agent_id.strip():
            raise ValueError("agent_id must not be empty")
        if not self.display_name.strip():
            raise ValueError("display_name must not be empty")

        for statement in self.statements:
            statement.validate()


@dataclass(frozen=True, slots=True)
class IxProgram:
    agents: tuple[AgentBlock, ...]

    def validate(self) -> None:
        seen_agent_ids: set[str] = set()

        for agent in self.agents:
            agent.validate()

            normalized_agent_id = agent.agent_id.strip()
            if normalized_agent_id in seen_agent_ids:
                raise ValueError(f"duplicate agent_id: {normalized_agent_id}")
            seen_agent_ids.add(normalized_agent_id)

    def get_agent(self, agent_id: str) -> AgentBlock | None:
        normalized_agent_id = agent_id.strip()
        if not normalized_agent_id:
            raise ValueError("agent_id must not be empty")

        for agent in self.agents:
            if agent.agent_id == normalized_agent_id:
                return agent
        return None
