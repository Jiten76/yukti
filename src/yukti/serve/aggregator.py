"""Read-side aggregations for the V1 dashboard.

Builds the fleet/flow-type/flow/action aggregates by iterating the
Runtime's in-memory components. For V1 single-process volumes this is
fine; for scale, replace with proper aggregating storage queries —
the API contract this module backs is already scale-shaped (aggregates
at fleet, paginated lists, query-on-demand).
"""

from __future__ import annotations

from collections import Counter
from typing import Any, cast

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.base import Flow, FlowState
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.base import Intervention
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.runtime.runtime import Runtime


def _flows(runtime: Runtime) -> InMemoryFlowTracker:
    return cast(InMemoryFlowTracker, runtime.flows)


def _evidence(runtime: Runtime) -> InMemoryEvidenceStore:
    return cast(InMemoryEvidenceStore, runtime.evidence)


def _hitl(runtime: Runtime) -> InMemoryHITLBackend:
    return cast(InMemoryHITLBackend, runtime.hitl)


def _flow_to_dict(flow: Flow) -> dict[str, Any]:
    return {
        "flow_id": flow.flow_id,
        "flow_type": flow.flow_type,
        "state": flow.state.value,
        "started_at": flow.started_at,
        "completed_at": flow.completed_at,
        "step_count": len(flow.steps),
        "evidence_count": len(flow.evidence_sha256s),
        "pattern_matches": list(flow.pattern_matches),
    }


def _intervention_to_dict(iv: Intervention) -> dict[str, Any]:
    return {
        "intervention_id": iv.intervention_id,
        "flow_id": iv.flow_id,
        "type": iv.intervention_type.value,
        "priority": iv.priority.value,
        "created_at": iv.created_at,
        "sla_deadline": iv.sla_deadline,
        "resolved_at": iv.resolved_at,
        "assigned_to": iv.assigned_to,
        "payload": iv.payload,
    }


async def build_fleet_summary(runtime: Runtime) -> dict[str, Any]:
    """The aggregate posture — counts only, never lists."""
    flows = await _flows(runtime).iter_all()
    evidence = await _evidence(runtime).iter_all()
    pending = await _hitl(runtime).iter_all_pending()
    resolved = await _hitl(runtime).iter_all_resolved()

    by_state: Counter[str] = Counter(f.state.value for f in flows)
    by_flow_type: Counter[str] = Counter(f.flow_type for f in flows)
    pattern_match_counts: Counter[str] = Counter()
    decision_counts: Counter[str] = Counter()
    for ev in evidence:
        decision = ev.payload.get("decision")
        if isinstance(decision, str):
            decision_counts[decision] += 1
        patterns = ev.payload.get("patterns")
        if isinstance(patterns, list):
            for p in patterns:
                if isinstance(p, dict) and "name" in p:
                    pattern_match_counts[str(p["name"])] += 1

    pending_by_priority: Counter[str] = Counter(p.priority.value for p in pending)

    return {
        "total_flows": len(flows),
        "evidence_records": len(evidence),
        "by_state": dict(by_state),
        "by_flow_type": dict(by_flow_type),
        "pattern_matches": dict(pattern_match_counts),
        "decisions": dict(decision_counts),
        "pending_actions": len(pending),
        "resolved_actions": len(resolved),
        "pending_by_priority": dict(pending_by_priority),
    }


async def build_flow_type_aggregates(runtime: Runtime) -> list[dict[str, Any]]:
    """Aggregate per flow_type — used by the second drill level."""
    flows = await _flows(runtime).iter_all()
    by_type: dict[str, list[Flow]] = {}
    for f in flows:
        by_type.setdefault(f.flow_type, []).append(f)
    out: list[dict[str, Any]] = []
    for flow_type, items in sorted(by_type.items()):
        by_state: Counter[str] = Counter(f.state.value for f in items)
        out.append(
            {
                "flow_type": flow_type,
                "total": len(items),
                "by_state": dict(by_state),
                "pending": by_state.get(FlowState.AWAITING_HITL.value, 0)
                + by_state.get(FlowState.GATED_BY_POLICY.value, 0),
                "failed": by_state.get(FlowState.FAILED.value, 0),
                "completed": by_state.get(FlowState.COMPLETED.value, 0),
            }
        )
    return out


async def page_flows(
    runtime: Runtime,
    *,
    flow_type: str | None = None,
    state: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Paginated list of flows. Scale-shaped: caller asks for a window."""
    all_flows = await _flows(runtime).iter_all()
    filtered = [
        f
        for f in all_flows
        if (flow_type is None or f.flow_type == flow_type)
        and (state is None or f.state.value == state)
    ]
    # Most-recent first.
    filtered.sort(key=lambda f: f.started_at, reverse=True)
    window = filtered[offset : offset + max(0, limit)]
    return {
        "total": len(filtered),
        "limit": limit,
        "offset": offset,
        "items": [_flow_to_dict(f) for f in window],
    }


async def build_flow_detail(runtime: Runtime, flow_id: str) -> dict[str, Any] | None:
    """Single-flow view — steps, evidence chain, decisions."""
    flow = await runtime.flows.get(flow_id)
    if flow is None:
        return None
    chain = await runtime.evidence.list_by_trace(flow_id)
    return {
        **_flow_to_dict(flow),
        "steps": [
            {
                "name": s.name,
                "timestamp": s.timestamp,
                "actor": s.actor,
                "evidence_sha256": s.evidence_sha256,
            }
            for s in flow.steps
        ],
        "evidence_chain": [
            {
                "sha256": r.sha256,
                "tier": r.tier.value,
                "timestamp": r.timestamp,
                "payload": r.payload,
                "parent_sha256s": list(r.parent_sha256s),
            }
            for r in chain
        ],
    }


async def page_pending_actions(
    runtime: Runtime, *, limit: int = 50, offset: int = 0
) -> dict[str, Any]:
    """Paginated list of pending HITL interventions — the action leaf."""
    pending = await _hitl(runtime).list_pending()
    window = pending[offset : offset + max(0, limit)]
    return {
        "total": len(pending),
        "limit": limit,
        "offset": offset,
        "items": [_intervention_to_dict(i) for i in window],
    }


async def build_action_detail(runtime: Runtime, intervention_id: str) -> dict[str, Any] | None:
    """Single-action view — the actionable leaf, with full evidence lineage."""
    iv = await _hitl(runtime).get(intervention_id)
    if iv is None:
        return None
    evidence_sha = iv.payload.get("evidence_sha256")
    lineage: list[dict[str, Any]] = []
    if isinstance(evidence_sha, str):
        records = await runtime.evidence.lineage(evidence_sha)
        lineage = [
            {
                "sha256": r.sha256,
                "tier": r.tier.value,
                "timestamp": r.timestamp,
                "payload": r.payload,
                "parent_sha256s": list(r.parent_sha256s),
            }
            for r in records
        ]
    return {
        **_intervention_to_dict(iv),
        "evidence_lineage": lineage,
    }
