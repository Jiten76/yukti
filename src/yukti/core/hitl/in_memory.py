"""In-memory HITL backend — the core default :class:`HITLBackend`.

Process-local intervention queue ordered by priority then age; the
zero-config default. Durable and adaptive backends are roadmap (see
``docs/ROADMAP.md``) and would plug in through the same
:class:`HITLBackend` ABC.
"""

from __future__ import annotations

import time
from typing import Any

from yukti.core.hitl.base import HITLBackend, Intervention, Priority

# Lower number = dequeued first.
_PRIORITY_ORDER: dict[Priority, int] = {
    Priority.CRITICAL: 0,
    Priority.HIGH: 1,
    Priority.MEDIUM: 2,
    Priority.LOW: 3,
}


class InMemoryHITLBackend(HITLBackend):
    """An in-process intervention queue ordered by priority, then age."""

    def __init__(self) -> None:
        self._pending: dict[str, Intervention] = {}
        self._resolved: dict[str, Intervention] = {}

    async def enqueue(self, intervention: Intervention) -> None:
        iid = intervention.intervention_id
        if iid in self._pending or iid in self._resolved:
            raise ValueError(f"intervention {iid!r} already exists")
        self._pending[iid] = intervention

    async def dequeue(self, priority: Priority | None = None) -> Intervention | None:
        ranked = self._ranked_pending(priority)
        return ranked[0] if ranked else None

    async def resolve(
        self,
        intervention_id: str,
        resolution: dict[str, Any],
        resolved_by: str,
    ) -> None:
        intervention = self._pending.pop(intervention_id, None)
        if intervention is None:
            raise KeyError(f"unknown or already-resolved intervention {intervention_id!r}")
        intervention.resolved_at = time.time()
        # Keep ``assigned_to`` as the accountable owner; record who closed it in
        # the resolution. (Previously ``assigned_to`` was overwritten with the
        # resolver, erasing who owned the item.)
        intervention.resolution = {**resolution, "resolved_by": resolved_by}
        self._resolved[intervention_id] = intervention

    async def list_pending(self, priority: Priority | None = None) -> list[Intervention]:
        return self._ranked_pending(priority)

    async def list_overdue(self) -> list[Intervention]:
        now = time.time()
        return [i for i in self._pending.values() if i.sla_deadline < now]

    async def acknowledge(self, intervention_id: str, by: str) -> None:
        intervention = self._pending.get(intervention_id)
        if intervention is None:
            raise KeyError(f"unknown or already-resolved intervention {intervention_id!r}")
        intervention.acknowledged_at = time.time()
        intervention.assigned_to = by

    async def escalate_overdue(
        self, *, backup_owner: str, now: float | None = None
    ) -> list[Intervention]:
        ts = time.time() if now is None else now
        escalated: list[Intervention] = []
        for iv in self._pending.values():
            if iv.acknowledged_at is None and iv.sla_deadline < ts:
                iv.assigned_to = backup_owner
                iv.priority = Priority.CRITICAL
                iv.extra = {
                    **iv.extra,
                    "escalated_at": ts,
                    "escalated_from_sla": iv.sla_deadline,
                }
                escalated.append(iv)
        return escalated

    def _ranked_pending(self, priority: Priority | None) -> list[Intervention]:
        items = [i for i in self._pending.values() if priority is None or i.priority == priority]
        items.sort(key=lambda i: (_PRIORITY_ORDER[i.priority], i.created_at))
        return items

    @property
    def pending_count(self) -> int:
        """Number of unresolved interventions."""
        return len(self._pending)

    @property
    def resolved_count(self) -> int:
        """Number of resolved interventions."""
        return len(self._resolved)

    async def iter_all_pending(self) -> list[Intervention]:
        """Every pending intervention (V1 dashboard aggregator helper)."""
        return list(self._pending.values())

    async def iter_all_resolved(self) -> list[Intervention]:
        """Every resolved intervention (V1 dashboard aggregator helper)."""
        return list(self._resolved.values())

    async def get(self, intervention_id: str) -> Intervention | None:
        """Look up an intervention by id, pending or resolved.

        V1 dashboard convenience for the action-detail endpoint.
        """
        if intervention_id in self._pending:
            return self._pending[intervention_id]
        return self._resolved.get(intervention_id)
