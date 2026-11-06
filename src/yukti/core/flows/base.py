"""Flow tracking — the data axis.

A Flow is an end-to-end execution path through the system, from
initiation to outcome. Examples:

- The customer-onboarding flow (KYC → eligibility → account-open → notify)
- The fraud-decision flow (signal → enrichment → policy → decide → write)
- The compliance-evidence flow (trigger → collect → triangulate → store)

The :class:`FlowTracker` interface maintains the current state of all
in-flight flows and provides hooks for runtime instrumentation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FlowState(StrEnum):
    """Lifecycle states of a flow."""

    INITIATED = "initiated"
    IN_PROGRESS = "in_progress"
    GATED_BY_POLICY = "gated_by_policy"
    AWAITING_HITL = "awaiting_hitl"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass
class FlowStep:
    """One step in a flow's execution."""

    name: str
    timestamp: float
    actor: str
    """Identifier of the agent / service / human that performed the step."""

    payload: dict[str, Any] = field(default_factory=dict)
    evidence_sha256: str | None = None


@dataclass
class Flow:
    """A flow's full record.

    Tracks the sequence of steps, the current state, the pattern matches
    that have fired against this flow, and the evidence records that have
    been written for it.
    """

    flow_id: str
    flow_type: str
    state: FlowState
    steps: list[FlowStep] = field(default_factory=list)
    pattern_matches: list[str] = field(default_factory=list)
    evidence_sha256s: list[str] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class FlowTracker(ABC):
    """Maintain the runtime state of all in-flight flows.

    Implementations include:

    - **InMemoryFlowTracker** (in core) — for single-process / dev use
    - **PostgresFlowTracker** (in core) — durable, async-friendly
    - **MultiTenantFlowTracker** (in ``yukti-enterprise``) — tenant-isolated
      with quota enforcement
    """

    @abstractmethod
    async def begin(self, flow_id: str, flow_type: str) -> Flow:
        """Create and return a new flow in :data:`FlowState.INITIATED`."""

    @abstractmethod
    async def append_step(self, flow_id: str, step: FlowStep) -> None:
        """Append a step to an in-flight flow."""

    @abstractmethod
    async def transition(self, flow_id: str, new_state: FlowState) -> None:
        """Transition a flow to a new lifecycle state."""

    @abstractmethod
    async def get(self, flow_id: str) -> Flow | None:
        """Retrieve a flow by id, or None if not found."""

    @abstractmethod
    async def list_active(self, flow_type: str | None = None) -> list[Flow]:
        """List flows that have not yet reached a terminal state."""
