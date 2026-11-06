"""Risk engineering.

A typed KRI (Key Risk Indicator) catalog governed on both consequence and
evidence quality. Every reading carries an evidence tier (discovery, proxy, or
decision-grade; see :class:`~yukti.core.evidence.base.EvidenceTier`), and the
policy requires decision-grade, fresh evidence before it will contain: an
act-line crossing carried by a proxy or discovery reading routes to a human
instead.

Readings are time-anchored, so a stale reading is itself a finding; deltas are
judged against an explicit anchor; and each KRI carries explicit "do not claim"
clauses that propagate into the evidence trail.

Deterministic and synthetic; every indicator, value, and date is invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yukti.core.evidence.base import EvidenceTier
from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine
from yukti.core.runtime.runtime import Runtime

#: A reading that worsened by more than this fraction vs its anchor is adverse.
ADVERSE_DELTA_FRACTION = 0.25


@dataclass(frozen=True)
class KRI:
    """One typed indicator in the catalog.

    ``direction`` states which way is bad; watch/act are the two lines in that
    direction. ``frameworks`` is a sparse, honest crosswalk (family-level refs
    only); ``caveat`` carries the "nearest —" note when a mapping is
    approximate rather than exact. ``do_not_claim`` states what a reading of
    this KRI can never support, and travels with every observation.
    """

    kri_id: str
    name: str
    unit: str
    direction: str  # "higher_is_worse" | "lower_is_worse"
    watch: float
    act: float
    freshness_window_s: float = 3600.0
    frameworks: list[str] = field(default_factory=list)
    caveat: str = ""
    do_not_claim: list[str] = field(default_factory=list)


def kri_of(extra: dict[str, Any]) -> KRI | None:
    kri = extra.get("kri")
    return kri if isinstance(kri, KRI) else None


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _worse_than(kri: KRI, value: float, line: float) -> bool:
    return value > line if kri.direction == "higher_is_worse" else value < line


def _tier_of(o: Observation) -> EvidenceTier:
    try:
        return EvidenceTier(str(o.payload.get("evidence_tier", "discovery")))
    except ValueError:
        return EvidenceTier.DISCOVERY


# ── the five risk-engineering patterns ────────────────────────────────────────


def _act_threshold_crossing(o: Observation) -> bool:
    kri = kri_of(o.extra)
    return kri is not None and _worse_than(kri, _num(o.payload.get("value")), kri.act)


def _watch_threshold_crossing(o: Observation) -> bool:
    """Past watch, not yet past act — the early-warning band."""
    kri = kri_of(o.extra)
    if kri is None:
        return False
    value = _num(o.payload.get("value"))
    return _worse_than(kri, value, kri.watch) and not _worse_than(kri, value, kri.act)


def _adverse_delta(o: Observation) -> bool:
    """Worsened materially against the time-anchored baseline."""
    kri = kri_of(o.extra)
    if kri is None or "anchor_value" not in o.payload:
        return False
    value = _num(o.payload.get("value"))
    anchor = _num(o.payload.get("anchor_value"))
    if anchor == 0:
        return False
    moved = (value - anchor) if kri.direction == "higher_is_worse" else (anchor - value)
    return moved / abs(anchor) > ADVERSE_DELTA_FRACTION


def _weak_evidence_actuation(o: Observation) -> bool:
    """An act-line crossing carried by sub-decision-grade evidence.

    The discipline pattern: the crossing may be real, but a proxy or discovery
    reading cannot be the basis for containment — it must route to a human.
    """
    return _act_threshold_crossing(o) and _tier_of(o) is not EvidenceTier.DECISION_GRADE


def _stale_reading(o: Observation) -> bool:
    """Older than the KRI's freshness window — deciding on old data is itself
    a finding, whatever the value says."""
    kri = kri_of(o.extra)
    if kri is None or "measured_at" not in o.payload:
        return False
    return (o.timestamp - _num(o.payload.get("measured_at"))) > kri.freshness_window_s


RISK_RULES: list[Rule] = [
    Rule(name="act_threshold_crossing", predicate=_act_threshold_crossing,
         rationale="the indicator crossed its act line"),
    Rule(name="watch_threshold_crossing", predicate=_watch_threshold_crossing,
         rationale="the indicator entered the early-warning band"),
    Rule(name="adverse_delta", predicate=_adverse_delta,
         rationale="worsened materially against the time-anchored baseline"),
    Rule(name="weak_evidence_actuation", predicate=_weak_evidence_actuation,
         rationale="an act-line crossing carried by sub-decision-grade evidence"),
    Rule(name="stale_reading", predicate=_stale_reading,
         rationale="reading older than its freshness window"),
]

#: (id, label) for dashboard tiles, if this scenario is served.
RISK_FAMILIES: list[tuple[str, str]] = [
    ("act_threshold_crossing", "Act line"),
    ("watch_threshold_crossing", "Watch"),
    ("adverse_delta", "Delta"),
    ("weak_evidence_actuation", "Weak basis"),
    ("stale_reading", "Stale"),
]


def risk_policy_decision(doc: dict[str, Any]) -> Decision:
    """Consequence × credibility.

    DENY only when the act line was crossed on decision-grade, fresh evidence.
    An act crossing on weak or stale evidence GATEs — a human decides, the
    engine doesn't contain on a basis it couldn't defend. Delta regressions
    GATE; the early-warning band MONITORs; in-tolerance ALLOWs.
    """
    patterns = set(doc.get("patterns") or [])
    if not patterns:
        return Decision.ALLOW
    if "act_threshold_crossing" in patterns:
        weak = "weak_evidence_actuation" in patterns or "stale_reading" in patterns
        return Decision.GATE if weak else Decision.DENY
    if patterns & {"adverse_delta", "stale_reading"}:
        return Decision.GATE
    return Decision.MONITOR


def build_risk_governance() -> Runtime:
    """The runtime armed with the risk rules + the consequence × credibility policy."""
    policy = SimplePredicatePolicyEngine()
    policy.register("risk_consequence_credibility_policy", risk_policy_decision)
    return Runtime(
        detector=RuleBasedPatternDetector(RISK_RULES),
        policy=policy,
        evidence=InMemoryEvidenceStore(),
        hitl=InMemoryHITLBackend(),
        flows=InMemoryFlowTracker(),
    )


# ── the catalog and its readings ─────────────────────────────────────────────

CATALOG: list[KRI] = [
    KRI("RE-01", "authorization-failure rate", "%", "higher_is_worse", watch=2.0, act=5.0,
        frameworks=["NIST CSF 2.0 PR.AA"],
        do_not_claim=["does not attribute failures to attack vs. misconfiguration"]),
    KRI("RE-02", "KYC review backlog age", "hours", "higher_is_worse", watch=24.0, act=72.0,
        do_not_claim=["does not measure review quality, only queue age"]),
    KRI("RE-03", "control-evidence coverage", "%", "lower_is_worse", watch=90.0, act=75.0,
        frameworks=["NIST CSF 2.0 ID.RA"],
        caveat="nearest — coverage of evidence collection, not control effectiveness",
        do_not_claim=["does not claim the controls themselves are effective"]),
    KRI("RE-04", "fraud-model drift index", "index", "higher_is_worse", watch=1.2, act=1.8,
        caveat="nearest — population-stability proxy, not measured fraud loss",
        do_not_claim=["a proxy: does not measure realized fraud losses"]),
    KRI("RE-05", "unreconciled item count", "items", "higher_is_worse", watch=50.0, act=200.0,
        do_not_claim=["does not distinguish timing differences from true mismatches"]),
    KRI("RE-06", "privileged-grant growth", "grants/day", "higher_is_worse", watch=5.0, act=20.0,
        freshness_window_s=1800.0,
        do_not_claim=["does not assess whether individual grants were justified"]),
    KRI("RE-07", "incident-reopen rate", "%", "higher_is_worse", watch=10.0, act=25.0,
        do_not_claim=["does not measure incident severity, only reopen frequency"]),
]


@dataclass(frozen=True)
class Reading:
    """One KRI reading with its evidence pedigree and the human consequence."""

    kri_id: str
    flow: str
    value: float
    tier: EvidenceTier
    consequence: str
    anchor_value: float | None = None
    age_s: float = 60.0
    source_query: str = ""


READINGS: list[Reading] = [
    # ── in tolerance, decision-grade — must pass ──
    Reading("RE-05", "reconciliation", 12, EvidenceTier.DECISION_GRADE,
            "unreconciled items well inside tolerance",
            source_query="SELECT count(*) FROM recon_breaks WHERE age > interval '1 day'"),
    Reading("RE-07", "support-triage", 4.1, EvidenceTier.DECISION_GRADE,
            "incident reopen rate steady"),
    # ── early-warning band → monitor ──
    Reading("RE-02", "customer-onboarding", 30, EvidenceTier.DECISION_GRADE,
            "KYC backlog aging into the early-warning band"),
    # ── adverse delta vs anchor → a human looks ──
    Reading("RE-04", "fraud-decision", 1.1, EvidenceTier.PROXY,
            "drift proxy worsened 57% against last quarter's anchor",
            anchor_value=0.7),
    # ── act crossing on weak evidence → GATE, never DENY (the discipline) ──
    Reading("RE-03", "compliance-evidence", 68, EvidenceTier.PROXY,
            "coverage proxy below the act line — needs decision-grade confirmation"),
    # ── stale reading → deciding on old data is a finding ──
    Reading("RE-06", "identity", 26, EvidenceTier.DECISION_GRADE,
            "privileged-grant reading crossed the act line but is an hour stale",
            age_s=3900.0),
    # ── act crossing, decision-grade, fresh → contain ──
    Reading("RE-01", "payment-authorization", 6.4, EvidenceTier.DECISION_GRADE,
            "authorization failures at 6.4% — past the act line on decision-grade evidence",
            source_query="sum(rate(authz_fail_total[5m])) / sum(rate(authz_total[5m]))"),
]

_T0 = 1_754_000_000.0

_CATALOG_BY_ID = {k.kri_id: k for k in CATALOG}


def risk_observations() -> list[Observation]:
    """Every catalog reading as a deterministic observation list."""
    out: list[Observation] = []
    t = _T0
    for r in READINGS:
        kri = _CATALOG_BY_ID[r.kri_id]
        payload: dict[str, Any] = {
            "agent": f"kri-monitor/{r.kri_id}",
            "flow": r.flow,
            "kri_id": r.kri_id,
            "kri_name": kri.name,
            "unit": kri.unit,
            "value": r.value,
            "evidence_tier": r.tier.value,
            "measured_at": t - r.age_s,
            "consequence": r.consequence,
            "do_not_claim": list(kri.do_not_claim),
        }
        if r.anchor_value is not None:
            payload["anchor_value"] = r.anchor_value
        if r.source_query:
            payload["source_query"] = r.source_query
        if kri.caveat:
            payload["caveat"] = kri.caveat
        out.append(Observation(
            trace_id=f"{r.kri_id.lower()}-reading-01",
            payload=payload,
            timestamp=t,
            source=f"kri.{r.kri_id.lower()}",
            extra={"flow_type": r.flow, "kri": kri},
        ))
        t += 30.0
    return out
