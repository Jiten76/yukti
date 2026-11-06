"""InMemoryHITLBackend — the core default HITLBackend."""

from __future__ import annotations

import pytest

from yukti.core.hitl.base import Intervention, InterventionType, Priority
from yukti.core.hitl.in_memory import InMemoryHITLBackend


def _intervention(
    iid: str,
    priority: Priority = Priority.MEDIUM,
    created_at: float = 1700000000.0,
    sla_deadline: float = 1700099999.0,
) -> Intervention:
    return Intervention(
        intervention_id=iid,
        flow_id="flow-1",
        intervention_type=InterventionType.APPROVAL,
        priority=priority,
        payload={"reason": "test"},
        created_at=created_at,
        sla_deadline=sla_deadline,
    )


async def test_enqueue_and_pending_count() -> None:
    backend = InMemoryHITLBackend()
    await backend.enqueue(_intervention("i1"))
    assert backend.pending_count == 1
    assert backend.resolved_count == 0


async def test_enqueue_duplicate_raises() -> None:
    backend = InMemoryHITLBackend()
    await backend.enqueue(_intervention("i1"))
    with pytest.raises(ValueError, match="already exists"):
        await backend.enqueue(_intervention("i1"))


async def test_dequeue_returns_highest_priority_first() -> None:
    backend = InMemoryHITLBackend()
    await backend.enqueue(_intervention("low", priority=Priority.LOW))
    await backend.enqueue(_intervention("critical", priority=Priority.CRITICAL))
    await backend.enqueue(_intervention("medium", priority=Priority.MEDIUM))
    nxt = await backend.dequeue()
    assert nxt is not None
    assert nxt.intervention_id == "critical"


async def test_dequeue_breaks_ties_by_age() -> None:
    backend = InMemoryHITLBackend()
    await backend.enqueue(_intervention("newer", created_at=2000.0))
    await backend.enqueue(_intervention("older", created_at=1000.0))
    nxt = await backend.dequeue()
    assert nxt is not None
    assert nxt.intervention_id == "older"


async def test_dequeue_with_priority_filter() -> None:
    backend = InMemoryHITLBackend()
    await backend.enqueue(_intervention("crit", priority=Priority.CRITICAL))
    await backend.enqueue(_intervention("low", priority=Priority.LOW))
    nxt = await backend.dequeue(priority=Priority.LOW)
    assert nxt is not None
    assert nxt.intervention_id == "low"


async def test_dequeue_empty_returns_none() -> None:
    backend = InMemoryHITLBackend()
    assert await backend.dequeue() is None


async def test_resolve_moves_pending_to_resolved() -> None:
    backend = InMemoryHITLBackend()
    await backend.enqueue(_intervention("i1"))
    await backend.resolve("i1", {"decision": "approved"}, resolved_by="alice")
    assert backend.pending_count == 0
    assert backend.resolved_count == 1


async def test_resolve_unknown_raises() -> None:
    backend = InMemoryHITLBackend()
    with pytest.raises(KeyError, match="unknown or already-resolved"):
        await backend.resolve("nope", {}, resolved_by="alice")


async def test_list_overdue_filters_by_sla_deadline() -> None:
    backend = InMemoryHITLBackend()
    # deadline far in the past -> overdue
    await backend.enqueue(_intervention("overdue", sla_deadline=1.0))
    # deadline far in the future -> not overdue
    await backend.enqueue(_intervention("ontime", sla_deadline=9_999_999_999.0))
    overdue = await backend.list_overdue()
    assert {i.intervention_id for i in overdue} == {"overdue"}
