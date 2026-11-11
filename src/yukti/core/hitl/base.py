"""HITL — Human-in-the-loop intervention queue.

HITL gates the points in a flow where human judgment is required.
Yukti models HITL with two orthogonal dimensions:

1. **Intervention type** — what kind of human decision is needed
2. **SLA priority** — how fast the decision must be made

Each intervention type has a default priority; the runtime can escalate
or de-escalate based on context.

Lifecycle: the runtime stamps ``sla_deadline`` and a named ``assigned_to``
owner on enqueue (so "who has to act" is answerable from the queue itself);
:meth:`HITLBackend.acknowledge` records that a human has taken an item
(``acknowledged_at``); :meth:`HITLBackend.list_overdue` reports SLA breaches;
and :meth:`HITLBackend.escalate_overdue` reassigns breached, unacknowledged
items to a backup owner at CRITICAL priority. The library provides these
mechanisms; the deployment decides *when* to run the escalation sweep (its
scheduler/pager), and a durable backend plugs in through the same ABC.

This pattern is adapted from production HITL designs at multiple
regulated-industry organizations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class InterventionType(StrEnum):
    """What kind of human decision is needed."""

    APPROVAL = "approval"
    """Should this action proceed? (yes/no with reason)"""

    REVIEW = "review"
    """Confirm the agent's classification of an ambiguous case."""

    DISAMBIGUATION = "disambiguation"
    """Pick between multiple candidate decisions."""

    EXCEPTION_HANDLING = "exception_handling"
    """Handle a case the agent cannot decide."""

    DATA_QUALITY_CHECK = "data_quality_check"
    """Verify input data integrity before agent action."""

    POLICY_OVERRIDE = "policy_override"
    """Override a policy denial with documented justification."""

    ESCALATION = "escalation"
    """Escalate to higher authority (e.g., compliance officer)."""


class Priority(StrEnum):
    """SLA-defined urgency of an intervention."""

    CRITICAL = "critical"
    """0-minute target — must be acted on immediately."""

    HIGH = "high"
    """1-hour target."""

    MEDIUM = "medium"
    """4-hour target."""

    LOW = "low"
    """24-hour target."""


# Default SLAs in seconds, indexed by Priority.
SLA_SECONDS: dict[Priority, int] = {
    Priority.CRITICAL: 0,
    Priority.HIGH: 3600,
    Priority.MEDIUM: 14400,
    Priority.LOW: 86400,
}


# Default owner routing by priority. Every enqueued intervention gets a named
# accountable owner at creation, so "who has to act, right now?" is answerable
# from the queue itself, not inferred after the fact. A deployment overrides
# this with its own on-call map via ``Runtime(owners=...)``.
DEFAULT_OWNERS: dict[Priority, str] = {
    Priority.CRITICAL: "risk-officer-oncall",
    Priority.HIGH: "duty-approver",
    Priority.MEDIUM: "duty-approver",
    Priority.LOW: "queue-triage",
}

# Where an overdue, unacknowledged intervention is reassigned on escalation.
DEFAULT_ESCALATION_OWNER = "risk-authority-backup"


@dataclass
class Intervention:
    """A pending HITL intervention."""

    intervention_id: str
    flow_id: str
    intervention_type: InterventionType
    priority: Priority
    payload: dict[str, Any]
    created_at: float
    sla_deadline: float
    assigned_to: str | None = None
    acknowledged_at: float | None = None
    resolved_at: float | None = None
    resolution: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class HITLBackend(ABC):
    """Pluggable HITL queue + escalation backend.

    **InMemoryHITLBackend** (shipped, in core) is the single-process
    default. Durable and adaptive backends are roadmap, not shipped —
    see ``docs/ROADMAP.md``.
    """

    @abstractmethod
    async def enqueue(self, intervention: Intervention) -> None:
        """Add an intervention to the queue."""

    @abstractmethod
    async def dequeue(self, priority: Priority | None = None) -> Intervention | None:
        """Pull the next intervention, optionally filtered by priority."""

    @abstractmethod
    async def resolve(
        self,
        intervention_id: str,
        resolution: dict[str, Any],
        resolved_by: str,
    ) -> None:
        """Mark an intervention resolved with the given decision."""

    @abstractmethod
    async def list_pending(self, priority: Priority | None = None) -> list[Intervention]:
        """List all pending interventions, optionally filtered by priority."""

    @abstractmethod
    async def list_overdue(self) -> list[Intervention]:
        """List interventions whose SLA deadline has passed without resolution."""

    @abstractmethod
    async def acknowledge(self, intervention_id: str, by: str) -> None:
        """Record that a named human has taken ownership of a pending
        intervention: sets ``acknowledged_at`` and ``assigned_to``. Raises
        ``KeyError`` for an unknown or already-resolved intervention."""

    @abstractmethod
    async def escalate_overdue(
        self, *, backup_owner: str, now: float | None = None
    ) -> list[Intervention]:
        """Reassign every overdue, *unacknowledged* intervention to
        ``backup_owner`` at CRITICAL priority and return them. The deployment
        calls this on its own schedule; the queue provides the mechanism."""
