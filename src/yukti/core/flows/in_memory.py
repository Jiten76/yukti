"""In-memory flow tracker — the core default :class:`FlowTracker`.

Dict-backed, single-process, not durable across restarts. Suitable for
development and single-node deployments. The enterprise
``MultiTenantFlowTracker`` plugs in through the same :class:`FlowTracker`
ABC.

A durable ``PostgresFlowTracker`` is planned; this in-memory tracker is
the zero-config default.
"""

from __future__ import annotations

import time

from yukti.core.flows.base import Flow, FlowState, FlowStep, FlowTracker

_TERMINAL_STATES = frozenset({FlowState.COMPLETED, FlowState.FAILED, FlowState.CANCELED})


class InMemoryFlowTracker(FlowTracker):
    """Track flows in a process-local dict."""

    def __init__(self) -> None:
        self._flows: dict[str, Flow] = {}

    async def begin(self, flow_id: str, flow_type: str) -> Flow:
        if flow_id in self._flows:
            raise ValueError(f"flow {flow_id!r} already exists")
        flow = Flow(
            flow_id=flow_id,
            flow_type=flow_type,
            state=FlowState.INITIATED,
            started_at=time.time(),
        )
        self._flows[flow_id] = flow
        return flow

    async def append_step(self, flow_id: str, step: FlowStep) -> None:
        flow = self._require(flow_id)
        flow.steps.append(step)
        if step.evidence_sha256 is not None:
            flow.evidence_sha256s.append(step.evidence_sha256)
        if flow.state == FlowState.INITIATED:
            flow.state = FlowState.IN_PROGRESS

    async def transition(self, flow_id: str, new_state: FlowState) -> None:
        flow = self._require(flow_id)
        flow.state = new_state
        if new_state in _TERMINAL_STATES:
            flow.completed_at = time.time()

    async def get(self, flow_id: str) -> Flow | None:
        return self._flows.get(flow_id)

    async def list_active(self, flow_type: str | None = None) -> list[Flow]:
        return [
            f
            for f in self._flows.values()
            if f.state not in _TERMINAL_STATES and (flow_type is None or f.flow_type == flow_type)
        ]

    def _require(self, flow_id: str) -> Flow:
        flow = self._flows.get(flow_id)
        if flow is None:
            raise KeyError(f"unknown flow {flow_id!r}")
        return flow

    async def iter_all(self) -> list[Flow]:
        """Return every flow (active + terminal). In-memory convenience for the
        V1 dashboard aggregator — not part of the FlowTracker ABC because SQL
        stores will query directly instead of iterating."""
        return list(self._flows.values())
