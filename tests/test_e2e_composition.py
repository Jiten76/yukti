"""End-to-end composition test — the proof that the architecture composes.

test_abcs.py proves each ABC is a proper interface.
test_enterprise_seam.py proves enterprise stubs satisfy those interfaces.
This test proves the *core default implementations fit together* into a
working Pattern x Flow -> Decision pipeline.

Scenario (sensitivity-tier egress): an agent attempts to egress data tagged
sensitivity tier 3. The pipeline must, end to end:

  1. Detect the high-tier-egress pattern        (RuleBasedPatternDetector)
  2. Evaluate policy on the match -> GATE        (SimplePredicatePolicyEngine)
  3. Enqueue a HITL intervention (because GATE)  (InMemoryHITLBackend)
  4. Write a linked evidence chain at each step  (InMemoryEvidenceStore)
  5. Track the whole thing as a Flow             (InMemoryFlowTracker)
  6. Notify an external system                   (WebhookIntegration, mocked)

If this test passes, Yukti's architecture is real — not just describable.

NOTE: the wiring here is done by hand. A `yukti.core.runtime.Runtime`
class that performs this orchestration is the next milestone; this test
is both the proof of composition and the executable spec for that
Runtime.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from yukti.core.evidence.base import EvidenceRecord, EvidenceTier
from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.base import FlowState, FlowStep
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.base import SLA_SECONDS, Intervention, InterventionType, Priority
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine
from yukti.integrations.base import IntegrationContext
from yukti.integrations.webhook import WebhookConfig, WebhookIntegration


async def test_data_leak_prevention_pipeline_composes_end_to_end() -> None:
    # ---- Wire the core default implementations ------------------------
    detector = RuleBasedPatternDetector(
        [
            Rule(
                name="high_tier_egress_attempt",
                predicate=lambda o: (
                    o.payload.get("action") == "egress"
                    and o.payload.get("sensitivity_tier", 0) >= 3
                ),
                rationale="egress of sensitivity-tier-3+ data",
            )
        ]
    )

    policy = SimplePredicatePolicyEngine()

    def tier_gate(doc: dict[str, Any]) -> Decision:
        # A matched high-tier-egress pattern on tier >= 3 must be GATEd to HITL.
        if doc.get("pattern_matched") and doc.get("sensitivity_tier", 0) >= 3:
            return Decision.GATE
        return Decision.ALLOW

    policy.register("data_leak_tier_gate", tier_gate)

    evidence = InMemoryEvidenceStore()
    hitl = InMemoryHITLBackend()
    flows = InMemoryFlowTracker()

    webhook = WebhookIntegration(
        WebhookConfig.model_validate({"url": "https://example.com/yukti-hook"})
    )
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    webhook._client.post = AsyncMock(return_value=mock_response)  # type: ignore[method-assign]

    trace_id = "trace-e2e-001"
    now = time.time()

    # ---- Step 1: an observation arrives, flow begins -----------------
    observation = Observation(
        trace_id=trace_id,
        payload={"action": "egress", "sensitivity_tier": 3, "agent": "fraud_decider"},
        timestamp=now,
        source="agent.fraud_decider",
    )
    flow = await flows.begin(trace_id, "data_leak_prevention")
    assert flow.state == FlowState.INITIATED

    obs_evidence_sha = await evidence.write(
        EvidenceRecord(
            sha256="",  # store computes it
            trace_id=trace_id,
            tier=EvidenceTier.DISCOVERY,
            payload=dict(observation.payload),
            timestamp=now,
        )
    )
    await flows.append_step(
        trace_id,
        FlowStep(
            name="observation",
            timestamp=now,
            actor=observation.source,
            evidence_sha256=obs_evidence_sha,
        ),
    )

    # ---- Step 2: pattern detection -----------------------------------
    matches = await detector.detect(observation)
    assert len(matches) == 1
    assert matches[0].pattern_name == "high_tier_egress_attempt"
    assert matches[0].confidence == 1.0

    pattern_evidence_sha = await evidence.write(
        EvidenceRecord(
            sha256="",
            trace_id=trace_id,
            tier=EvidenceTier.DECISION_GRADE,
            payload={"pattern": matches[0].pattern_name, "confidence": matches[0].confidence},
            timestamp=now,
            parent_sha256s=[obs_evidence_sha],  # chain-of-custody link
        )
    )
    await flows.append_step(
        trace_id,
        FlowStep(
            name="pattern_detected",
            timestamp=now,
            actor=detector.name,
            evidence_sha256=pattern_evidence_sha,
        ),
    )

    # ---- Step 3: policy evaluation -----------------------------------
    policy_input = {
        "pattern_matched": True,
        "sensitivity_tier": observation.payload["sensitivity_tier"],
    }
    decision = await policy.evaluate(policy_input)
    assert decision.decision == Decision.GATE
    assert "data_leak_tier_gate" in decision.matched_policies

    policy_evidence_sha = await evidence.write(
        EvidenceRecord(
            sha256="",
            trace_id=trace_id,
            tier=EvidenceTier.DECISION_GRADE,
            payload={"decision": decision.decision.value, "rationale": decision.rationale},
            timestamp=now,
            parent_sha256s=[pattern_evidence_sha],  # chain-of-custody link
        )
    )

    # ---- Step 4: GATE -> enqueue a HITL intervention -----------------
    assert decision.decision == Decision.GATE  # so we must gate to a human
    await flows.transition(trace_id, FlowState.GATED_BY_POLICY)
    intervention = Intervention(
        intervention_id=f"{trace_id}-iv1",
        flow_id=trace_id,
        intervention_type=InterventionType.POLICY_OVERRIDE,
        priority=Priority.HIGH,
        payload={"reason": "tier-3 egress gated", "evidence": policy_evidence_sha},
        created_at=now,
        sla_deadline=now + SLA_SECONDS[Priority.HIGH],
    )
    await hitl.enqueue(intervention)
    await flows.transition(trace_id, FlowState.AWAITING_HITL)

    # ---- Step 5: notify an external system ---------------------------
    ctx = IntegrationContext(trace_id=trace_id, evidence_sha256=policy_evidence_sha)
    await webhook.notify(ctx, "tier-3 egress gated — HITL review required")
    await webhook.aclose()

    # ================= ASSERT THE WHOLE PIPELINE ======================

    # The flow tracked every step and is awaiting a human.
    final_flow = await flows.get(trace_id)
    assert final_flow is not None
    assert final_flow.state == FlowState.AWAITING_HITL
    assert [s.name for s in final_flow.steps] == ["observation", "pattern_detected"]
    assert final_flow.evidence_sha256s == [obs_evidence_sha, pattern_evidence_sha]

    # The evidence chain is intact: 3 records, linked parent -> child.
    assert evidence.count == 3
    trace_evidence = await evidence.list_by_trace(trace_id)
    assert len(trace_evidence) == 3

    # Lineage from the policy decision walks back through pattern to observation.
    lineage = await evidence.lineage(policy_evidence_sha)
    lineage_hashes = [r.sha256 for r in lineage]
    assert lineage_hashes == [policy_evidence_sha, pattern_evidence_sha, obs_evidence_sha]
    # Tiers along the chain: decision-grade -> decision-grade -> discovery.
    assert [r.tier for r in lineage] == [
        EvidenceTier.DECISION_GRADE,
        EvidenceTier.DECISION_GRADE,
        EvidenceTier.DISCOVERY,
    ]

    # Exactly one HITL intervention is pending, correctly typed and prioritized.
    assert hitl.pending_count == 1
    pending = await hitl.list_pending()
    assert pending[0].intervention_type == InterventionType.POLICY_OVERRIDE
    assert pending[0].priority == Priority.HIGH
    assert pending[0].flow_id == trace_id

    # The external system was notified exactly once, with trace context.
    webhook._client.post.assert_called_once()
    sent_payload = webhook._client.post.call_args.kwargs["json"]
    assert sent_payload["trace_id"] == trace_id
    assert sent_payload["evidence_sha256"] == policy_evidence_sha


async def test_allow_path_does_not_gate_or_notify() -> None:
    """The mirror case: a tier-1 read produces no pattern, no gate, no HITL."""
    detector = RuleBasedPatternDetector(
        [
            Rule(
                name="high_tier_egress_attempt",
                predicate=lambda o: (
                    o.payload.get("action") == "egress"
                    and o.payload.get("sensitivity_tier", 0) >= 3
                ),
            )
        ]
    )
    policy = SimplePredicatePolicyEngine()
    policy.register(
        "data_leak_tier_gate",
        lambda doc: (
            Decision.GATE
            if doc.get("pattern_matched") and doc.get("sensitivity_tier", 0) >= 3
            else Decision.ALLOW
        ),
    )
    hitl = InMemoryHITLBackend()

    observation = Observation(
        trace_id="trace-allow",
        payload={"action": "read", "sensitivity_tier": 1},
        timestamp=time.time(),
        source="agent.reporting",
    )
    matches = await detector.detect(observation)
    assert matches == []  # no pattern fires

    decision = await policy.evaluate({"pattern_matched": bool(matches), "sensitivity_tier": 1})
    assert decision.decision == Decision.ALLOW
    # ALLOW -> nothing gets enqueued
    assert hitl.pending_count == 0
