"""The Yukti runtime — orchestrates patterns, flows, evidence, HITL, policy.

The :class:`Runtime` is what turns Yukti's interfaces into a working
framework. You give it the components (a ``PatternDetector``, a
``PolicyEngine``, an ``EvidenceStore``, a ``HITLBackend``, a
``FlowTracker``, and zero or more ``Integration`` s) and call
:meth:`Runtime.process`. It runs the full Pattern × Flow → Decision
pipeline and returns a :class:`ProcessResult`.

The pipeline, per observation:

  1. begin a Flow
  2. write the observation to the evidence ledger (DISCOVERY tier)
  3. run pattern detection
  4. if patterns matched, write a pattern-evidence record (DECISION_GRADE,
     child of the observation record)
  5. evaluate policy against (observation payload + pattern info)
  6. write a policy-decision evidence record (DECISION_GRADE, child of the
     pattern record — or of the observation record if no pattern fired)
  7. act on the decision:
       ALLOW   → flow COMPLETED
       MONITOR → flow COMPLETED (a monitor-only signal)
       GATE    → HITL intervention enqueued, flow AWAITING_HITL
       DENY    → CRITICAL escalation enqueued, flow FAILED
  8. notify integrations that declare the NOTIFY capability
  9. return a :class:`ProcessResult` capturing every input and output

``tests/test_e2e_composition.py`` is the executable spec for this class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yukti.core.evidence.base import EvidenceRecord, EvidenceStore, EvidenceTier
from yukti.core.flows.base import FlowState, FlowStep, FlowTracker
from yukti.core.hitl.base import (
    DEFAULT_OWNERS,
    SLA_SECONDS,
    HITLBackend,
    Intervention,
    InterventionType,
    Priority,
)
from yukti.core.patterns.base import Observation, PatternDetector, PatternMatch
from yukti.core.policy.base import Decision, PolicyEngine, PolicyResult
from yukti.integrations.base import Capability, Integration, IntegrationContext

# Default Decision → HITL priority mapping for the runtime.
_DECISION_PRIORITY: dict[Decision, Priority] = {
    Decision.GATE: Priority.HIGH,
    Decision.DENY: Priority.CRITICAL,
}

# Default Decision → InterventionType mapping for the runtime.
_DECISION_INTERVENTION: dict[Decision, InterventionType] = {
    Decision.GATE: InterventionType.POLICY_OVERRIDE,
    Decision.DENY: InterventionType.ESCALATION,
}


@dataclass
class ProcessResult:
    """The complete inputs-to-outputs record of one :meth:`Runtime.process` call."""

    trace_id: str
    observation: Observation
    pattern_matches: list[PatternMatch]
    decision: Decision
    policy_rationale: str
    matched_policies: list[str]
    evidence_chain: list[str]
    """Evidence SHA-256s in pipeline order: observation, [pattern], policy-decision."""

    flow_state: FlowState
    intervention_id: str | None
    """Set when the decision created a HITL intervention (GATE or DENY)."""

    notified_integrations: list[str] = field(default_factory=list)


class Runtime:
    """Orchestrates the core components into the governance pipeline."""

    def __init__(
        self,
        *,
        detector: PatternDetector,
        policy: PolicyEngine,
        evidence: EvidenceStore,
        hitl: HITLBackend,
        flows: FlowTracker,
        integrations: list[Integration] | None = None,
        owners: dict[Priority, str] | None = None,
        min_containment_credibility: float = 0.8,
    ) -> None:
        self.detector = detector
        self.policy = policy
        self.evidence = evidence
        self.hitl = hitl
        self.flows = flows
        self.integrations: list[Integration] = list(integrations) if integrations else []
        # Owner routing: every GATE/DENY intervention is stamped with a named
        # accountable owner at enqueue, so the queue answers "who has to act".
        self._owners: dict[Priority, str] = dict(owners) if owners else dict(DEFAULT_OWNERS)
        # Effective challenge: a containment (DENY) resting on evidence weaker
        # than this is downgraded to human review (GATE) rather than taken
        # automatically. 1.0 would challenge everything; 0.0 disables the gate.
        self._min_containment_credibility = min_containment_credibility

    async def process(
        self,
        observation: Observation,
        *,
        flow_type: str = "default",
        forced_decision: Decision | None = None,
        forced_rationale: str | None = None,
    ) -> ProcessResult:
        """Run one observation through the full pipeline. See module docstring.

        ``forced_decision`` lets a caller override the policy stage with a
        decision it reached out of band — e.g. the ingest binding gate, when a
        trace cannot be bound to any registered envelope. The forced decision is
        still rendered first-class: pattern detection runs, and the decision is
        evidenced, HITL-queued, and notified exactly like a policy verdict, with
        ``forced_rationale`` carried into the evidence record.
        """
        trace_id = observation.trace_id
        now = observation.timestamp
        evidence_chain: list[str] = []

        # 1. begin the flow
        await self.flows.begin(trace_id, flow_type)

        # 2. observation evidence (DISCOVERY tier)
        obs_sha = await self.evidence.write(
            EvidenceRecord(
                sha256="",
                trace_id=trace_id,
                tier=EvidenceTier.DISCOVERY,
                payload=dict(observation.payload),
                timestamp=now,
            )
        )
        evidence_chain.append(obs_sha)
        await self.flows.append_step(
            trace_id,
            FlowStep(
                name="observation",
                timestamp=now,
                actor=observation.source,
                evidence_sha256=obs_sha,
            ),
        )

        # 3. pattern detection
        matches = await self.detector.detect(observation)

        # 4. pattern evidence, if anything matched (DECISION_GRADE, child of obs)
        parent_for_policy = obs_sha
        if matches:
            pattern_sha = await self.evidence.write(
                EvidenceRecord(
                    sha256="",
                    trace_id=trace_id,
                    tier=EvidenceTier.DECISION_GRADE,
                    payload={
                        "patterns": [
                            {"name": m.pattern_name, "confidence": m.confidence} for m in matches
                        ]
                    },
                    timestamp=now,
                    parent_sha256s=[obs_sha],
                )
            )
            evidence_chain.append(pattern_sha)
            parent_for_policy = pattern_sha
            await self.flows.append_step(
                trace_id,
                FlowStep(
                    name="pattern_detected",
                    timestamp=now,
                    actor=self.detector.name,
                    evidence_sha256=pattern_sha,
                ),
            )

        # credibility of the signal driving this decision: the strongest
        # pattern match's confidence, overridden by an explicit per-observation
        # ``credibility`` float or a truthy ``evidence_stale`` flag. This is the
        # "× credibility" half of consequence-ranked governance, and it feeds
        # both the policy input and the containment gate below.
        confidences = [m.confidence for m in matches]
        credibility = max(confidences) if confidences else 1.0
        if observation.payload.get("evidence_stale"):
            credibility = 0.0
        explicit_cred = observation.payload.get("credibility")
        if isinstance(explicit_cred, (int, float)) and not isinstance(explicit_cred, bool):
            credibility = float(explicit_cred)

        # 5. decision: a forced decision (from the caller) overrides the policy
        # stage; otherwise evaluate the policy against the observation + patterns.
        if forced_decision is not None:
            policy_result = PolicyResult(
                decision=forced_decision,
                matched_policies=["forced"],
                rationale=forced_rationale or f"decision forced to {forced_decision.value}",
            )
        else:
            policy_input: dict[str, Any] = {
                **observation.payload,
                "pattern_matched": bool(matches),
                "patterns": [m.pattern_name for m in matches],
                "credibility": credibility,
            }
            try:
                policy_result = await self.policy.evaluate(policy_input)
            except Exception as exc:
                # The decision layer must not die mid-observation: a raising
                # policy engine fails closed to DENY (which routes to a human at
                # CRITICAL), with the failure named in the rationale — mirroring
                # the detector's raise-becomes-evidence stance one layer up.
                policy_result = PolicyResult(
                    decision=Decision.DENY,
                    matched_policies=[],
                    rationale=f"policy evaluation raised {exc!r} — failing closed",
                )
        decision = policy_result.decision

        # 5b. credibility gate (effective challenge): a containment resting on
        # weak or stale evidence is downgraded to human review (GATE) instead of
        # being taken automatically. Applies only to evidence-derived decisions —
        # a forced decision (e.g. the identity binding gate) is an identity fact,
        # not an evidence-strength question, so it is never downgraded here.
        if (
            forced_decision is None
            and decision is Decision.DENY
            and credibility < self._min_containment_credibility
        ):
            decision = Decision.GATE
            challenge = (
                f"containment downgraded to human review: weak evidence "
                f"(credibility {credibility:.2f} < "
                f"{self._min_containment_credibility:.2f})"
            )
            policy_result = PolicyResult(
                decision=Decision.GATE,
                matched_policies=policy_result.matched_policies,
                rationale=f"{policy_result.rationale}; {challenge}",
            )

        # 6. policy-decision evidence (DECISION_GRADE, child of pattern-or-obs)
        policy_sha = await self.evidence.write(
            EvidenceRecord(
                sha256="",
                trace_id=trace_id,
                tier=EvidenceTier.DECISION_GRADE,
                payload={
                    "decision": decision.value,
                    "rationale": policy_result.rationale,
                    "matched_policies": policy_result.matched_policies,
                },
                timestamp=now,
                parent_sha256s=[parent_for_policy],
            )
        )
        evidence_chain.append(policy_sha)

        # 7. act on the decision
        intervention_id: str | None = None
        if decision in (Decision.GATE, Decision.DENY):
            # Suffixed with the policy-evidence sha (unique per evaluation):
            # a bare f"{trace_id}-iv" would collide — and crash enqueue — the
            # second time one trace id gates. Same collision class as the
            # OTLP trace×span id decision.
            intervention_id = f"{trace_id}-iv-{policy_sha[:12]}"
            priority = _DECISION_PRIORITY[decision]
            await self.flows.transition(trace_id, FlowState.GATED_BY_POLICY)
            await self.hitl.enqueue(
                Intervention(
                    intervention_id=intervention_id,
                    flow_id=trace_id,
                    intervention_type=_DECISION_INTERVENTION[decision],
                    priority=priority,
                    assigned_to=self._owners.get(priority),
                    payload={
                        "decision": decision.value,
                        "rationale": policy_result.rationale,
                        "evidence_sha256": policy_sha,
                        # a human summary of the triggering action, when the
                        # observation carries one — dashboards render this instead
                        # of the raw policy name.
                        "agent": observation.payload.get("agent"),
                        "flow": observation.payload.get("flow"),
                        "consequence": observation.payload.get("consequence"),
                    },
                    created_at=now,
                    sla_deadline=now + SLA_SECONDS[priority],
                )
            )
            await self.flows.transition(
                trace_id,
                FlowState.AWAITING_HITL if decision == Decision.GATE else FlowState.FAILED,
            )
        else:
            # ALLOW and MONITOR both complete the flow.
            await self.flows.transition(trace_id, FlowState.COMPLETED)

        # 8. notify integrations that can NOTIFY. Structured kwargs let each
        # integration apply its own noise floor and formatting (e.g. Slack
        # drops ALLOWs and renders agent/consequence, not just the rationale).
        notified: list[str] = []
        ctx = IntegrationContext(trace_id=trace_id, evidence_sha256=policy_sha)
        message = f"[{decision.value.upper()}] {policy_result.rationale} (trace {trace_id})"
        for integration in self.integrations:
            if Capability.NOTIFY in integration.capabilities:
                await integration.notify(
                    ctx,
                    message,
                    decision=decision.value,
                    agent=str(observation.payload.get("agent", "")),
                    flow=flow_type,
                    consequence=str(observation.payload.get("consequence", "")),
                )
                notified.append(integration.name)

        # 9. assemble the result
        final_flow = await self.flows.get(trace_id)
        return ProcessResult(
            trace_id=trace_id,
            observation=observation,
            pattern_matches=matches,
            decision=decision,
            policy_rationale=policy_result.rationale,
            matched_policies=policy_result.matched_policies,
            evidence_chain=evidence_chain,
            flow_state=final_flow.state if final_flow else FlowState.FAILED,
            intervention_id=intervention_id,
            notified_integrations=notified,
        )
