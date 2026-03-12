from __future__ import annotations

from copy import deepcopy
from threading import RLock

from ix_operator.agents.memory import AgentMemoryStore, MemoryValue
from ix_operator.agents.models import AgentDefinition, AgentRuntimeState


class AgentRegistry:
    def __init__(self) -> None:
        self._lock = RLock()
        self._states: dict[str, AgentRuntimeState] = {}
        self._memories: dict[str, AgentMemoryStore] = {}

    def register(self, definition: AgentDefinition) -> AgentRuntimeState:
        definition.validate()
        normalized_agent_id = self._normalize_agent_id(definition.agent_id)

        with self._lock:
            if normalized_agent_id in self._states:
                raise ValueError(f"agent is already registered: {normalized_agent_id}")

            state = AgentRuntimeState.create(definition)
            memory = AgentMemoryStore(namespace=normalized_agent_id)

            self._states[normalized_agent_id] = state
            self._memories[normalized_agent_id] = memory
            return deepcopy(state)

    def unregister(self, agent_id: str) -> None:
        normalized_agent_id = self._normalize_agent_id(agent_id)

        with self._lock:
            self._require_agent_locked(normalized_agent_id)
            self._states.pop(normalized_agent_id, None)
            memory = self._memories.pop(normalized_agent_id, None)
            if memory is not None:
                memory.clear()

    def get_state(self, agent_id: str) -> AgentRuntimeState | None:
        normalized_agent_id = self._normalize_agent_id(agent_id)

        with self._lock:
            state = self._states.get(normalized_agent_id)
            if state is None:
                return None
            return deepcopy(state)

    def get_definition(self, agent_id: str) -> AgentDefinition | None:
        normalized_agent_id = self._normalize_agent_id(agent_id)

        with self._lock:
            state = self._states.get(normalized_agent_id)
            if state is None:
                return None
            return deepcopy(state.definition)

    def list_states(self) -> list[AgentRuntimeState]:
        with self._lock:
            return [deepcopy(state) for state in self._states.values()]

    def start_agent(self, agent_id: str) -> AgentRuntimeState:
        with self._lock:
            state = self._require_agent_locked(self._normalize_agent_id(agent_id))
            state.start()
            return deepcopy(state)

    def stop_agent(self, agent_id: str) -> AgentRuntimeState:
        with self._lock:
            state = self._require_agent_locked(self._normalize_agent_id(agent_id))
            state.stop()
            return deepcopy(state)

    def fail_agent(self, agent_id: str, reason: str) -> AgentRuntimeState:
        with self._lock:
            state = self._require_agent_locked(self._normalize_agent_id(agent_id))
            state.fail(reason)
            return deepcopy(state)

    def update_goal(self, agent_id: str, goal: str | None) -> AgentRuntimeState:
        with self._lock:
            state = self._require_agent_locked(self._normalize_agent_id(agent_id))
            state.update_goal(goal)
            return deepcopy(state)

    def mark_message_processed(self, agent_id: str) -> AgentRuntimeState:
        with self._lock:
            state = self._require_agent_locked(self._normalize_agent_id(agent_id))
            state.mark_message_processed()
            return deepcopy(state)

    def remember(self, agent_id: str, key: str, value: MemoryValue) -> None:
        with self._lock:
            memory = self._require_memory_locked(self._normalize_agent_id(agent_id))
            memory.remember(key, value)

    def recall(
        self,
        agent_id: str,
        key: str,
        default: MemoryValue = None,
    ) -> MemoryValue:
        with self._lock:
            memory = self._require_memory_locked(self._normalize_agent_id(agent_id))
            return memory.recall(key, default)

    def forget(self, agent_id: str, key: str) -> bool:
        with self._lock:
            memory = self._require_memory_locked(self._normalize_agent_id(agent_id))
            return memory.forget(key)

    def snapshot_memory(self, agent_id: str) -> dict[str, MemoryValue]:
        with self._lock:
            memory = self._require_memory_locked(self._normalize_agent_id(agent_id))
            return memory.snapshot()

    def clear_memory(self, agent_id: str) -> None:
        with self._lock:
            memory = self._require_memory_locked(self._normalize_agent_id(agent_id))
            memory.clear()

    def contains(self, agent_id: str) -> bool:
        normalized_agent_id = self._normalize_agent_id(agent_id)

        with self._lock:
            return normalized_agent_id in self._states

    def count(self) -> int:
        with self._lock:
            return len(self._states)

    def _normalize_agent_id(self, agent_id: str) -> str:
        normalized_agent_id = agent_id.strip()
        if not normalized_agent_id:
            raise ValueError("agent_id must not be empty")
        return normalized_agent_id

    def _require_agent_locked(self, agent_id: str) -> AgentRuntimeState:
        state = self._states.get(agent_id)
        if state is None:
            raise KeyError(f"unknown agent_id: {agent_id}")
        return state

    def _require_memory_locked(self, agent_id: str) -> AgentMemoryStore:
        memory = self._memories.get(agent_id)
        if memory is None:
            raise KeyError(f"unknown agent_id: {agent_id}")
        return memory
