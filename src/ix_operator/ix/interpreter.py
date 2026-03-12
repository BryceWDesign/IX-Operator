from __future__ import annotations

from dataclasses import dataclass

from ix_operator.agents import AgentDefinition, AgentRegistry
from ix_operator.ix.ast import (
    AgentBlock,
    GoalStatement,
    IxProgram,
    RememberStatement,
    SayStatement,
)


@dataclass(frozen=True, slots=True)
class SayEmission:
    agent_id: str
    display_name: str
    text: str


@dataclass(frozen=True, slots=True)
class ExecutionReport:
    agent_id: str
    display_name: str
    final_goal: str | None
    memory_snapshot: dict[str, str | int | float | bool | None]
    emissions: tuple[SayEmission, ...]


class IxInterpreter:
    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    def load_program(self, program: IxProgram) -> list[str]:
        program.validate()
        registered_agent_ids: list[str] = []

        for agent in program.agents:
            self._ensure_registered(agent)
            registered_agent_ids.append(agent.agent_id)

        return registered_agent_ids

    def execute_agent(self, program: IxProgram, agent_id: str) -> ExecutionReport:
        program.validate()

        agent = program.get_agent(agent_id)
        if agent is None:
            raise KeyError(f"unknown agent_id in program: {agent_id}")

        self._ensure_registered(agent)
        self._registry.start_agent(agent.agent_id)

        emissions: list[SayEmission] = []
        for statement in agent.statements:
            if isinstance(statement, GoalStatement):
                self._registry.update_goal(agent.agent_id, statement.goal)
                continue

            if isinstance(statement, RememberStatement):
                self._registry.remember(agent.agent_id, statement.key, statement.value)
                continue

            if isinstance(statement, SayStatement):
                emissions.append(
                    SayEmission(
                        agent_id=agent.agent_id,
                        display_name=agent.display_name,
                        text=statement.text,
                    )
                )
                continue

            raise ValueError(f"unsupported IX statement type: {type(statement).__name__}")

        self._registry.stop_agent(agent.agent_id)
        state = self._registry.get_state(agent.agent_id)
        if state is None:
            raise RuntimeError(f"agent disappeared during execution: {agent.agent_id}")

        return ExecutionReport(
            agent_id=agent.agent_id,
            display_name=agent.display_name,
            final_goal=state.current_goal,
            memory_snapshot=self._registry.snapshot_memory(agent.agent_id),
            emissions=tuple(emissions),
        )

    def boot_program(self, program: IxProgram) -> tuple[ExecutionReport, ...]:
        program.validate()
        self.load_program(program)

        reports: list[ExecutionReport] = []
        for agent in program.agents:
            reports.append(self.execute_agent(program, agent.agent_id))

        return tuple(reports)

    def _ensure_registered(self, agent: AgentBlock) -> None:
        if self._registry.contains(agent.agent_id):
            existing_definition = self._registry.get_definition(agent.agent_id)
            if existing_definition is None:
                raise RuntimeError(f"agent registry lost definition for: {agent.agent_id}")

            if existing_definition.display_name != agent.display_name:
                raise ValueError(
                    f"agent_id already registered with different display name: {agent.agent_id}"
                )
            return

        self._registry.register(
            AgentDefinition(
                agent_id=agent.agent_id,
                display_name=agent.display_name,
            )
        )
