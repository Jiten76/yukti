"""Runtime — the orchestrator that wires the core components.

These tests exercise the Runtime through the three decision paths
(ALLOW / GATE / DENY) using the real core default implementations, plus
integration notification. They are the unit-level companion to
``test_e2e_composition.py`` (which proves the pipeline by hand-wiring).
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.base import FlowState
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.base import InterventionType, Priority
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine
from yukti.core.runtime.runtime import Runtime
from yukti.integrations.webhook import WebhookConfig, WebhookIntegration


def _build_runtime(*, integrations: list[WebhookIntegration] | None = None) -> Runtime:
    detector = RuleBasedPatternDetector(
        [
            Rule(
                name="high_tier_egress",
                predicate=lambda o: (
                    o.payload.get("action") == "egress"
                    and o.payload.get("sensitivity_tier", 0) >= 3
                ),
            )
        ]
    )
    policy = SimplePredicatePolicyEngine()

    def tier_policy(doc: dict[str, Any]) -> Decision:
        tier = doc.get("sensitivity_tier", 0)
        if not doc.get("pattern_matched"):
            return Decision.ALLOW
        if tier >= 5:
            return Decision.DENY
        if tier >= 3:
            return Decision.GATE
        return Decision.ALLOW

    policy.register("tier_policy", tier_policy)
    return Runtime(
        detector=detector,
        policy=policy,
        evidence=InMemoryEvidenceStore(),
        hitl=InMemoryHITLBackend(),
        flows=InMemoryFlowTracker(),
        integrations=list(integrations) if integrations else None,
    )


def _obs(trace_id: str, **payload: Any) -> Observation:
    return Observation(
        trace_id=trace_id,
        payload=dict(payload),
        timestamp=time.time(),
        source="test.agent",
    )


async def test_allow_path_completes_flow_with_no_intervention() -> None:
    runtime = _build_runtime()
    result = await runtime.process(_obs("t-allow", action="read", sensitivity_tier=1))
    assert result.decision == Decision.ALLOW
    assert result.flow_state == FlowState.COMPLETED
    assert result.intervention_id is None
    assert result.pattern_matches == []
    # No pattern fired -> 2-record evidence chain (observation + policy decision).
    assert len(result.evidence_chain) == 2


async def test_gate_path_awaits_hitl_with_high_priority_intervention() -> None:
    runtime = _build_runtime()
    result = await runtime.process(_obs("t-gate", action="egress", sensitivity_tier=3))
    assert result.decision == Decision.GATE
    assert result.flow_state == FlowState.AWAITING_HITL
    # id = trace + "-iv-" + policy-evidence sha prefix (unique per evaluation)
    assert result.intervention_id == f"t-gate-iv-{result.evidence_chain[-1][:12]}"
    # Pattern fired -> 3-record evidence chain.
    assert len(result.evidence_chain) == 3

    pending = await runtime.hitl.list_pending()
    assert len(pending) == 1
    assert pending[0].intervention_type == InterventionType.POLICY_OVERRIDE
    assert pending[0].priority == Priority.HIGH


async def test_deny_path_fails_flow_with_critical_escalation() -> None:
    runtime = _build_runtime()
    result = await runtime.process(_obs("t-deny", action="egress", sensitivity_tier=5))
    assert result.decision == Decision.DENY
    assert result.flow_state == FlowState.FAILED
    assert result.intervention_id == f"t-deny-iv-{result.evidence_chain[-1][:12]}"

    pending = await runtime.hitl.list_pending()
    assert len(pending) == 1
    assert pending[0].intervention_type == InterventionType.ESCALATION
    assert pending[0].priority == Priority.CRITICAL


async def test_evidence_chain_is_parent_linked() -> None:
    runtime = _build_runtime()
    result = await runtime.process(_obs("t-chain", action="egress", sensitivity_tier=3))
    # The policy-decision record (last in chain) walks back to the observation.
    lineage = await runtime.evidence.lineage(result.evidence_chain[-1])
    lineage_hashes = [r.sha256 for r in lineage]
    assert lineage_hashes == list(reversed(result.evidence_chain))


async def test_runtime_notifies_integrations_that_can_notify() -> None:
    webhook = WebhookIntegration(WebhookConfig.model_validate({"url": "https://example.com/hook"}))
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    webhook._client.post = AsyncMock(return_value=mock_response)  # type: ignore[method-assign]

    runtime = _build_runtime(integrations=[webhook])
    result = await runtime.process(_obs("t-notify", action="egress", sensitivity_tier=3))
    await webhook.aclose()

    assert result.notified_integrations == ["webhook"]
    webhook._client.post.assert_called_once()
    sent = webhook._client.post.call_args.kwargs["json"]
    assert sent["trace_id"] == "t-notify"
    assert "GATE" in sent["message"]


class _ExplodingPolicyEngine(SimplePredicatePolicyEngine):
    """A policy engine whose evaluate itself raises (models a broken custom
    engine — the per-predicate catch inside the simple engine can't help)."""

    async def evaluate(
        self, input_doc: dict[str, Any], policies: list[str] | None = None
    ) -> Any:
        raise RuntimeError("engine exploded")


async def test_runtime_survives_raising_policy_engine() -> None:
    """The decision layer must not die: a raising engine fails closed to
    DENY, routes to a human, and leaves the flow in a terminal state."""
    runtime = _build_runtime()
    runtime.policy = _ExplodingPolicyEngine()
    obs = Observation(
        trace_id="t-explode",
        payload={"action": "egress", "sensitivity_tier": 5, "agent": "a1"},
        timestamp=time.time(),
        source="test",
    )
    result = await runtime.process(obs)
    assert result.decision == Decision.DENY
    assert "failing closed" in result.policy_rationale
    assert result.flow_state == FlowState.FAILED  # DENY terminal, not limbo
    assert result.intervention_id is not None  # a human sees the failure


async def test_intervention_id_unique_per_evaluation() -> None:
    """Intervention ids embed the policy-evidence sha, so a reused trace id
    can never mint a colliding id (enqueue raises on duplicates)."""
    runtime = _build_runtime()
    obs = Observation(
        trace_id="t-gate-1",
        payload={"action": "egress", "sensitivity_tier": 3, "agent": "a1"},
        timestamp=time.time(),
        source="test",
    )
    result = await runtime.process(obs)
    assert result.intervention_id is not None
    policy_sha = result.evidence_chain[-1]
    assert result.intervention_id == f"t-gate-1-iv-{policy_sha[:12]}"
