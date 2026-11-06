"""HITL lifecycle — a named owner at enqueue, acknowledge, and escalate-on-breach.

Proves the README claim "a named human on an SLA deadline": every GATE/DENY
intervention carries an accountable owner from the moment it is created, a human
can take ownership (acknowledge), and an overdue *unacknowledged* item escalates
to a backup. These are mechanisms with tests, not prose.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.base import Intervention, InterventionType, Priority
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine
from yukti.core.runtime.runtime import Runtime


def _runtime(hitl: InMemoryHITLBackend) -> Runtime:
    detector = RuleBasedPatternDetector(
        [Rule(name="egress", predicate=lambda o: o.payload.get("action") == "egress")]
    )
    policy = SimplePredicatePolicyEngine()

    def tier_policy(doc: dict[str, Any]) -> Decision:
        if not doc.get("pattern_matched"):
            return Decision.ALLOW
        tier = int(doc.get("sensitivity_tier", 0))
        if tier >= 5:
            return Decision.DENY
        if tier >= 3:
            return Decision.GATE
        return Decision.ALLOW

    policy.register("tier", tier_policy)
    return Runtime(
        detector=detector,
        policy=policy,
        evidence=InMemoryEvidenceStore(),
        hitl=hitl,
        flows=InMemoryFlowTracker(),
    )


def _obs(trace_id: str, **payload: Any) -> Observation:
    return Observation(trace_id=trace_id, payload=dict(payload), timestamp=time.time(), source="t")


def _iv(iid: str, *, sla_deadline: float, acknowledged: bool = False) -> Intervention:
    iv = Intervention(
        intervention_id=iid,
        flow_id=iid,
        intervention_type=InterventionType.ESCALATION,
        priority=Priority.HIGH,
        payload={},
        created_at=0.0,
        sla_deadline=sla_deadline,
    )
    if acknowledged:
        iv.acknowledged_at = 1.0
    return iv


async def test_deny_and_gate_get_a_named_owner_at_enqueue() -> None:
    hitl = InMemoryHITLBackend()
    rt = _runtime(hitl)
    deny = await rt.process(_obs("t-deny", action="egress", sensitivity_tier=5))
    gate = await rt.process(_obs("t-gate", action="egress", sensitivity_tier=3))
    assert deny.decision is Decision.DENY
    assert gate.decision is Decision.GATE
    pending = {i.intervention_id: i for i in await hitl.list_pending()}
    assert deny.intervention_id is not None and gate.intervention_id is not None
    assert pending[deny.intervention_id].assigned_to == "risk-officer-oncall"  # CRITICAL
    assert pending[gate.intervention_id].assigned_to == "duty-approver"  # HIGH


async def test_acknowledge_records_the_human_and_a_timestamp() -> None:
    hitl = InMemoryHITLBackend()
    await hitl.enqueue(_iv("i1", sla_deadline=time.time() + 3600))
    await hitl.acknowledge("i1", by="alice")
    iv = await hitl.get("i1")
    assert iv is not None
    assert iv.assigned_to == "alice"
    assert iv.acknowledged_at is not None
    with pytest.raises(KeyError):
        await hitl.acknowledge("nope", by="alice")


async def test_escalate_overdue_reassigns_only_unacknowledged_breaches() -> None:
    hitl = InMemoryHITLBackend()
    await hitl.enqueue(_iv("overdue", sla_deadline=1.0))
    await hitl.enqueue(_iv("ack-overdue", sla_deadline=1.0, acknowledged=True))
    await hitl.enqueue(_iv("fresh", sla_deadline=time.time() + 3600))
    escalated = await hitl.escalate_overdue(backup_owner="risk-authority-backup")
    assert {i.intervention_id for i in escalated} == {"overdue"}
    moved = await hitl.get("overdue")
    assert moved is not None
    assert moved.assigned_to == "risk-authority-backup"
    assert moved.priority is Priority.CRITICAL
    # an acknowledged breach and a fresh item are left alone
    ack = await hitl.get("ack-overdue")
    fresh = await hitl.get("fresh")
    assert ack is not None and ack.assigned_to is None
    assert fresh is not None and fresh.priority is Priority.HIGH


async def test_resolve_keeps_the_owner_and_records_the_resolver() -> None:
    hitl = InMemoryHITLBackend()
    iv = _iv("i1", sla_deadline=time.time() + 3600)
    iv.assigned_to = "duty-approver"
    await hitl.enqueue(iv)
    await hitl.resolve("i1", {"decision": "approved"}, resolved_by="bob")
    resolved = await hitl.get("i1")
    assert resolved is not None
    assert resolved.assigned_to == "duty-approver"  # owner preserved, not clobbered
    assert resolved.resolution is not None
    assert resolved.resolution["resolved_by"] == "bob"  # resolver recorded separately
