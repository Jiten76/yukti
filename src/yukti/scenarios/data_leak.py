"""Data-leak prevention.

Governs sanctioned but tiered data access: agents that may touch data, but only
up to their clearance, only through sanctioned channels, and only toward
sanctioned destinations.

Sensitivity tiers follow the N1-N5 convention (1 = public, 5 = restricted). Each
agent run carries an :class:`AccessProfile` giving its clearance and its
sanctioned channels and destinations, declared by the operator rather than the
agent. The five patterns read the trace against that profile, and the policy
ranks by consequence: data that moved is contained, while data only read or
reshaped routes to a human.

Deterministic and synthetic; every agent, dataset, and value is invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine
from yukti.core.runtime.runtime import Runtime

#: One egress moving more records than this is mass movement regardless of tier.
BULK_RECORD_THRESHOLD = 50_000


@dataclass(frozen=True)
class AccessProfile:
    """An agent's sanctioned relationship to tiered data.

    Positive grants, operator-declared (the agent never carries its own
    clearance in its own telemetry): the highest tier it may read, the
    channels it may egress through, and the destinations it may egress to.
    """

    agent: str
    clearance_tier: int = 1
    channel_allowlist: frozenset[str] = field(default_factory=frozenset)
    destination_allowlist: frozenset[str] = field(default_factory=frozenset)


def profile_of(extra: dict[str, Any]) -> AccessProfile | None:
    prof = extra.get("access_profile")
    return prof if isinstance(prof, AccessProfile) else None


def _tier(o: Observation) -> int:
    try:
        return int(o.payload.get("sensitivity_tier", 0))
    except (TypeError, ValueError):
        return 0


def _prof(o: Observation) -> AccessProfile | None:
    return profile_of(o.extra)


# ── the five data-leak patterns ───────────────────────────────────────────────


def _tier_overreach(o: Observation) -> bool:
    """A read above clearance — data touched, not moved."""
    prof = _prof(o)
    if prof is None or o.payload.get("action") != "data_read":
        return False
    return _tier(o) > prof.clearance_tier


def _external_tier_egress(o: Observation) -> bool:
    """Tier-3+ data leaving toward a destination the operator never sanctioned."""
    prof = _prof(o)
    if prof is None or o.payload.get("action") != "egress" or _tier(o) < 3:
        return False
    return str(o.payload.get("destination", "")) not in prof.destination_allowlist


def _unsanctioned_channel(o: Observation) -> bool:
    """Egress through a channel outside the allowlist — any tier."""
    prof = _prof(o)
    if prof is None or o.payload.get("action") != "egress":
        return False
    return str(o.payload.get("channel", "")) not in prof.channel_allowlist


def _bulk_movement(o: Observation) -> bool:
    """One egress moving a mass of records — the exfiltration shape."""
    if o.payload.get("action") != "egress":
        return False
    try:
        return int(o.payload.get("record_count", 0)) > BULK_RECORD_THRESHOLD
    except (TypeError, ValueError):
        return False


def _aggregation_uplift(o: Observation) -> bool:
    """A join whose output tier exceeds the agent's clearance.

    Two individually-modest datasets can compose into something restricted —
    the effective tier of the output, not the inputs, is what clearance must
    cover.
    """
    prof = _prof(o)
    if prof is None or o.payload.get("action") != "dataset_join":
        return False
    try:
        return int(o.payload.get("output_tier", 0)) > prof.clearance_tier
    except (TypeError, ValueError):
        return False


DATA_LEAK_RULES: list[Rule] = [
    Rule(name="tier_overreach", predicate=_tier_overreach,
         rationale="read above clearance — data touched, not moved"),
    Rule(name="external_tier_egress", predicate=_external_tier_egress,
         rationale="tier-3+ data leaving toward an unsanctioned destination"),
    Rule(name="unsanctioned_channel", predicate=_unsanctioned_channel,
         rationale="egress through a channel outside the allowlist"),
    Rule(name="bulk_movement", predicate=_bulk_movement,
         rationale="one egress moving a mass of records — the exfiltration shape"),
    Rule(name="aggregation_uplift", predicate=_aggregation_uplift,
         rationale="a join whose output tier exceeds the agent's clearance"),
]

#: (id, label) for dashboard tiles, if this scenario is served.
DATA_LEAK_FAMILIES: list[tuple[str, str]] = [
    ("external_tier_egress", "Egress"),
    ("unsanctioned_channel", "Channel"),
    ("bulk_movement", "Bulk"),
    ("tier_overreach", "Overreach"),
    ("aggregation_uplift", "Uplift"),
]

# data that MOVED is contained; data merely touched/reshaped goes to a human.
_MOVED = {"external_tier_egress", "unsanctioned_channel", "bulk_movement"}
_TOUCHED = {"tier_overreach", "aggregation_uplift"}


def data_leak_policy_decision(doc: dict[str, Any]) -> Decision:
    """Consequence-ranked: movement DENYs (CRITICAL), touch GATEs (HIGH)."""
    patterns = set(doc.get("patterns") or [])
    if not patterns:
        return Decision.ALLOW
    if patterns & _MOVED:
        return Decision.DENY
    if patterns & _TOUCHED:
        return Decision.GATE
    return Decision.MONITOR


def build_data_leak_governance() -> Runtime:
    """The runtime armed with the five data-leak rules + the consequence policy."""
    policy = SimplePredicatePolicyEngine()
    policy.register("data_leak_consequence_policy", data_leak_policy_decision)
    return Runtime(
        detector=RuleBasedPatternDetector(DATA_LEAK_RULES),
        policy=policy,
        evidence=InMemoryEvidenceStore(),
        hitl=InMemoryHITLBackend(),
        flows=InMemoryFlowTracker(),
    )


# ── the agent fleet, data touch by data touch ────────────────────────────────


@dataclass(frozen=True)
class Touch:
    """One data access by an agent, with the human consequence."""

    action: str
    detail: str
    consequence: str
    tier: int = 0
    destination: str = ""
    channel: str = ""
    record_count: int = 0
    output_tier: int = 0


@dataclass(frozen=True)
class AgentDataRun:
    """One agent's data activity through a named Flow."""

    flow: str
    profile: AccessProfile
    touches: list[Touch] = field(default_factory=list)


FLEET: list[AgentDataRun] = [
    # ── clean — sanctioned access must pass untouched ──
    AgentDataRun(
        flow="support-triage",
        profile=AccessProfile("support-summarizer", clearance_tier=2,
                              channel_allowlist=frozenset({"ticket_system"}),
                              destination_allowlist=frozenset({"zendesk_workspace"})),
        touches=[
            Touch("data_read", "ticket text (N2)", "read ticket text within clearance", tier=2),
            Touch("egress", "summary to the ticket system",
                  "posted a summary through the sanctioned channel",
                  tier=2, destination="zendesk_workspace", channel="ticket_system",
                  record_count=1),
        ]),
    AgentDataRun(
        flow="fraud-decision",
        profile=AccessProfile("fraud-scorer", clearance_tier=3,
                              channel_allowlist=frozenset({"case_api"}),
                              destination_allowlist=frozenset({"case_management"})),
        touches=[
            Touch("data_read", "transaction features (N3)",
                  "read transaction features within clearance", tier=3),
        ]),
    # ── touched, not moved — a human signs off ──
    AgentDataRun(
        flow="compliance-evidence",
        profile=AccessProfile("evidence-collector", clearance_tier=3,
                              channel_allowlist=frozenset({"evidence_vault"}),
                              destination_allowlist=frozenset({"evidence_vault"})),
        touches=[
            Touch("data_read", "board-minutes excerpt (N4)",
                  "read board-minutes data one tier above its clearance", tier=4),
        ]),
    AgentDataRun(
        flow="analytics-export",
        profile=AccessProfile("analytics-bot", clearance_tier=2,
                              channel_allowlist=frozenset({"warehouse_api"}),
                              destination_allowlist=frozenset({"internal_dashboard"})),
        touches=[
            Touch("dataset_join", "orders (N2) ⨝ identities (N2) → re-identifiable (N4)",
                  "joined two modest datasets into a re-identifiable one above its clearance",
                  tier=2, output_tier=4),
        ]),
    # ── moved — contained ──
    AgentDataRun(
        flow="customer-onboarding",
        profile=AccessProfile("kyc-verifier", clearance_tier=4,
                              channel_allowlist=frozenset({"kyc_api"}),
                              destination_allowlist=frozenset({"identity_vendor_a"})),
        touches=[
            Touch("data_read", "KYC documents (N4)", "read KYC documents within clearance",
                  tier=4),
            Touch("egress", "N4 PII → data broker",
                  "sent customer PII to an external data broker",
                  tier=4, destination="external_data_broker", channel="kyc_api",
                  record_count=312),
        ]),
    AgentDataRun(
        flow="support-triage",
        profile=AccessProfile("triage-helper", clearance_tier=2,
                              channel_allowlist=frozenset({"ticket_system"}),
                              destination_allowlist=frozenset({"zendesk_workspace"})),
        touches=[
            Touch("egress", "ticket excerpts via personal email",
                  "mailed ticket excerpts through a personal email channel",
                  tier=2, destination="zendesk_workspace", channel="personal_email",
                  record_count=40),
        ]),
    AgentDataRun(
        flow="model-training",
        profile=AccessProfile("training-exporter", clearance_tier=3,
                              channel_allowlist=frozenset({"batch_export"}),
                              destination_allowlist=frozenset({"training_bucket"})),
        touches=[
            Touch("egress", "2.4M customer records in one export",
                  "exported 2.4 million customer records in a single batch",
                  tier=3, destination="training_bucket", channel="batch_export",
                  record_count=2_400_000),
        ]),
]

_T0 = 1_754_000_000.0


def data_leak_observations() -> list[Observation]:
    """Every agent's data touches as a deterministic observation list."""
    out: list[Observation] = []
    t = _T0
    for run in FLEET:
        for i, touch in enumerate(run.touches):
            payload: dict[str, Any] = {
                "agent": run.profile.agent,
                "flow": run.flow,
                "action": touch.action,
                "detail": touch.detail,
                "consequence": touch.consequence,
                "sensitivity_tier": touch.tier,
            }
            if touch.destination:
                payload["destination"] = touch.destination
            if touch.channel:
                payload["channel"] = touch.channel
            if touch.record_count:
                payload["record_count"] = touch.record_count
            if touch.output_tier:
                payload["output_tier"] = touch.output_tier
            out.append(Observation(
                trace_id=f"{run.profile.agent}-touch-{i + 1:02d}",
                payload=payload,
                timestamp=t,
                source=f"dlp.{run.profile.agent}",
                extra={"flow_type": run.flow, "access_profile": run.profile},
            ))
            t += 15.0
    return out
