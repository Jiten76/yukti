"""InMemoryFlowTracker — the core default FlowTracker."""

from __future__ import annotations

import pytest

from yukti.core.flows.base import FlowState, FlowStep
from yukti.core.flows.in_memory import InMemoryFlowTracker


def _step(name: str, evidence: str | None = None) -> FlowStep:
    return FlowStep(name=name, timestamp=1700000000.0, actor="test", evidence_sha256=evidence)


async def test_begin_creates_initiated_flow() -> None:
    tracker = InMemoryFlowTracker()
    flow = await tracker.begin("f1", "data_leak_prevention")
    assert flow.flow_id == "f1"
    assert flow.flow_type == "data_leak_prevention"
    assert flow.state == FlowState.INITIATED
    assert flow.started_at > 0


async def test_begin_duplicate_raises() -> None:
    tracker = InMemoryFlowTracker()
    await tracker.begin("f1", "t")
    with pytest.raises(ValueError, match="already exists"):
        await tracker.begin("f1", "t")


async def test_append_step_moves_initiated_to_in_progress() -> None:
    tracker = InMemoryFlowTracker()
    await tracker.begin("f1", "t")
    await tracker.append_step("f1", _step("observation"))
    flow = await tracker.get("f1")
    assert flow is not None
    assert flow.state == FlowState.IN_PROGRESS
    assert len(flow.steps) == 1


async def test_append_step_records_evidence_hash() -> None:
    tracker = InMemoryFlowTracker()
    await tracker.begin("f1", "t")
    await tracker.append_step("f1", _step("observation", evidence="abc123"))
    flow = await tracker.get("f1")
    assert flow is not None
    assert flow.evidence_sha256s == ["abc123"]


async def test_transition_to_terminal_sets_completed_at() -> None:
    tracker = InMemoryFlowTracker()
    await tracker.begin("f1", "t")
    await tracker.transition("f1", FlowState.COMPLETED)
    flow = await tracker.get("f1")
    assert flow is not None
    assert flow.state == FlowState.COMPLETED
    assert flow.completed_at is not None


async def test_get_unknown_returns_none() -> None:
    tracker = InMemoryFlowTracker()
    assert await tracker.get("nope") is None


async def test_append_step_on_unknown_flow_raises() -> None:
    tracker = InMemoryFlowTracker()
    with pytest.raises(KeyError, match="unknown flow"):
        await tracker.append_step("nope", _step("x"))


async def test_list_active_excludes_terminal_and_filters_by_type() -> None:
    tracker = InMemoryFlowTracker()
    await tracker.begin("active1", "type_a")
    await tracker.begin("active2", "type_b")
    await tracker.begin("done", "type_a")
    await tracker.transition("done", FlowState.COMPLETED)

    all_active = await tracker.list_active()
    assert {f.flow_id for f in all_active} == {"active1", "active2"}

    type_a_active = await tracker.list_active(flow_type="type_a")
    assert {f.flow_id for f in type_a_active} == {"active1"}
