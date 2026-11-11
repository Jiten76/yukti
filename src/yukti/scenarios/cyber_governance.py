"""Cyber governance for a multi-agent assessment platform.

Models a platform of expert agents composed per industry vertical by
orchestrators and pointed at a customer environment under an explicit
engagement scope. It reduces such a platform to five failure modes:

1. an agent acting outside the engagement scope the customer signed,
2. an effectful action bypassing its human approval gate,
3. an orchestrator invoking an agent that is not in the engagement registry
   (the gap between the roster a platform can name and the agents actually
   registered),
4. delegation runaway, where agent-to-agent chains run deeper than sanctioned,
5. an assessment step completed without its compliance evidence attached.

The engagement scope is operator-declared and never carried in the platform's
own telemetry. It is the third declared boundary in the codebase, after the
task envelope and the access profile.

Deterministic and synthetic; every agent, network, and value is invented.
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

#: The expert-agent catalog, by capability group — the governable roster.
#: A faithful (de-branded) port of the source platform's four expert groups.
AGENT_CATALOG: dict[str, tuple[str, ...]] = {
    "enterprise-security": (
        "asset-discovery", "compliance-validation", "network-recon",
        "threat-intel", "vuln-assessment", "risk-scoring",
        "incident-response", "security-architecture",
    ),
    "ai-governance": (
        "ai-governance-lead", "bias-fairness", "explainability",
        "model-security", "ai-privacy",
    ),
    "devsecops": (
        "code-security", "container-security", "infra-security",
        "pipeline-security", "devsecops-lead",
    ),
    "third-party-risk": (
        "api-security", "saas-lateral-movement", "sbom-analysis",
        "supply-chain",
    ),
}

ALL_AGENTS: frozenset[str] = frozenset(a for group in AGENT_CATALOG.values() for a in group)

#: The three industry verticals whose orchestrators compose the fleet.
VERTICALS = ("ai-tech", "critical-infrastructure", "private-equity")


@dataclass(frozen=True)
class EngagementScope:
    """The sanctioned boundary of one customer engagement.

    Operator-declared, positive grants only — what the customer signed, not
    what the platform assumes: the network/asset prefixes agents may touch,
    the agent roster registered for this engagement, the deepest sanctioned
    delegation chain, and the actions that require an approved human
    intervention before execution.
    """

    engagement_id: str
    vertical: str
    target_scope: frozenset[str] = field(default_factory=frozenset)
    registered_agents: frozenset[str] = field(default_factory=frozenset)
    max_delegation_depth: int = 5
    approval_required_for: frozenset[str] = field(default_factory=frozenset)

    def covers_target(self, target: str | None) -> bool:
        if not target:
            return False
        return any(str(target).startswith(prefix) for prefix in self.target_scope)


def scope_of(extra: dict[str, Any]) -> EngagementScope | None:
    scope = extra.get("engagement_scope")
    return scope if isinstance(scope, EngagementScope) else None


def _scope(o: Observation) -> EngagementScope | None:
    return scope_of(o.extra)


def _int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# ── the five cyber-governance patterns ───────────────────────────────────────


def _scope_boundary_violation(o: Observation) -> bool:
    """An agent touching a target outside what the customer signed."""
    scope = _scope(o)
    if scope is None or o.payload.get("action") not in {"active_scan", "probe", "exploit_check"}:
        return False
    return not scope.covers_target(str(o.payload.get("target", "")))


def _hitl_gate_bypass(o: Observation) -> bool:
    """An approval-gated action executed without an approved intervention."""
    scope = _scope(o)
    if scope is None:
        return False
    action = str(o.payload.get("action", ""))
    if action not in scope.approval_required_for:
        return False
    return str(o.payload.get("approval_status", "")) != "approved"


def _unregistered_agent_invocation(o: Observation) -> bool:
    """An orchestrator calling an agent that isn't in the engagement registry.

    Fleet drift made operational: the roster you market, the roster you
    implement, and the roster you registered for *this* engagement are three
    different lists — governance holds the platform to the last one.
    """
    scope = _scope(o)
    if scope is None or o.payload.get("action") != "invoke_agent":
        return False
    return str(o.payload.get("invoked_agent", "")) not in scope.registered_agents


def _delegation_runaway(o: Observation) -> bool:
    """An agent-to-agent chain deeper than the engagement sanctions."""
    scope = _scope(o)
    if scope is None:
        return False
    return _int(o.payload.get("delegation_depth")) > scope.max_delegation_depth


def _evidence_gap(o: Observation) -> bool:
    """An assessment step marked complete with no evidence record attached."""
    if o.payload.get("action") != "step_complete":
        return False
    return not bool(o.payload.get("evidence_attached", False))


CYBER_RULES: list[Rule] = [
    Rule(name="scope_boundary_violation", predicate=_scope_boundary_violation,
         rationale="an agent touched a target outside the signed engagement scope"),
    Rule(name="hitl_gate_bypass", predicate=_hitl_gate_bypass,
         rationale="an approval-gated action executed without an approved intervention"),
    Rule(name="unregistered_agent_invocation", predicate=_unregistered_agent_invocation,
         rationale="an orchestrator invoked an agent outside the engagement registry"),
    Rule(name="delegation_runaway", predicate=_delegation_runaway,
         rationale="an agent-to-agent chain deeper than sanctioned"),
    Rule(name="evidence_gap", predicate=_evidence_gap,
         rationale="an assessment step completed without its compliance evidence"),
]

#: (id, label) for dashboard tiles, if this scenario is served.
CYBER_FAMILIES: list[tuple[str, str]] = [
    ("scope_boundary_violation", "Scope"),
    ("hitl_gate_bypass", "Bypass"),
    ("unregistered_agent_invocation", "Registry"),
    ("delegation_runaway", "Delegation"),
    ("evidence_gap", "Evidence"),
]

# touched the customer outside sanction, or acted past a human gate → contain;
# structural drift (registry, depth, missing evidence) → a human re-anchors it.
_CONTAIN = {"scope_boundary_violation", "hitl_gate_bypass"}


def cyber_policy_decision(doc: dict[str, Any]) -> Decision:
    """Consequence-ranked: out-of-scope or gate-bypassed actions DENY
    (CRITICAL); structural drift GATEs (HIGH); clean engagement work passes."""
    patterns = set(doc.get("patterns") or [])
    if not patterns:
        return Decision.ALLOW
    if patterns & _CONTAIN:
        return Decision.DENY
    return Decision.GATE


def build_cyber_governance() -> Runtime:
    """The runtime armed with the cyber rules + the consequence policy."""
    policy = SimplePredicatePolicyEngine()
    policy.register("cyber_consequence_policy", cyber_policy_decision)
    return Runtime(
        detector=RuleBasedPatternDetector(CYBER_RULES),
        policy=policy,
        evidence=InMemoryEvidenceStore(),
        hitl=InMemoryHITLBackend(),
        flows=InMemoryFlowTracker(),
    )


# ── one engagement, three verticals, eight platform actions ──────────────────

_AI_TECH = EngagementScope(
    engagement_id="eng-2417", vertical="ai-tech",
    target_scope=frozenset({"models.customer-a.", "10.20."}),
    registered_agents=frozenset(AGENT_CATALOG["ai-governance"])
    | frozenset(AGENT_CATALOG["enterprise-security"]),
    approval_required_for=frozenset({"active_scan", "containment_execute"}),
)
_CRIT_INFRA = EngagementScope(
    engagement_id="eng-2418", vertical="critical-infrastructure",
    target_scope=frozenset({"10.20.", "scada.customer-b."}),
    registered_agents=frozenset(AGENT_CATALOG["enterprise-security"]),
    approval_required_for=frozenset({"active_scan", "containment_execute"}),
)
_PRIV_EQ = EngagementScope(
    engagement_id="eng-2419", vertical="private-equity",
    target_scope=frozenset({"portfolio.customer-c."}),
    registered_agents=frozenset(AGENT_CATALOG["third-party-risk"]),
    max_delegation_depth=5,
)


@dataclass(frozen=True)
class PlatformAction:
    """One platform action inside an engagement, with the human consequence."""

    scope: EngagementScope
    agent: str
    payload: dict[str, Any]
    consequence: str


ACTIONS: list[PlatformAction] = [
    # ── clean engagement work — must pass ──
    PlatformAction(
        _AI_TECH, "model-security",
        {"action": "probe", "target": "models.customer-a.inference-api",
         "detail": "adversarial-robustness probe, in scope"},
        "probed the in-scope model endpoint for adversarial robustness"),
    PlatformAction(
        _AI_TECH, "compliance-validation",
        {"action": "step_complete", "framework": "SOC 2 CC7.1", "evidence_attached": True,
         "detail": "monitoring-control evidence collected and attached"},
        "completed the SOC 2 monitoring-control step with evidence attached"),
    PlatformAction(
        _CRIT_INFRA, "vuln-assessment",
        {"action": "active_scan", "target": "10.20.4.0/24", "approval_status": "approved",
         "detail": "approved scan of the in-scope segment"},
        "ran an approved vulnerability scan inside the signed scope"),
    # ── structural drift — a human re-anchors ──
    PlatformAction(
        _AI_TECH, "bias-fairness",
        {"action": "step_complete", "framework": "EU AI Act Art. 10", "evidence_attached": False,
         "detail": "fairness step closed, no evidence record"},
        "closed a fairness-assessment step without attaching its evidence"),
    PlatformAction(
        _PRIV_EQ, "portfolio-orchestrator",
        {"action": "invoke_agent", "invoked_agent": "learning-framework",
         "detail": "roster names it; the registry doesn't"},
        "invoked an agent the engagement registry doesn't contain"),
    PlatformAction(
        _PRIV_EQ, "sbom-analysis",
        {"action": "delegate", "delegation_depth": 7,
         "detail": "sbom → supply-chain → api-security → … depth 7 of 5"},
        "delegated seven levels deep — two past the sanctioned chain"),
    # ── outside sanction or past a human gate — contained ──
    PlatformAction(
        _CRIT_INFRA, "network-recon",
        {"action": "active_scan", "target": "203.0.113.0/24", "approval_status": "approved",
         "detail": "scan target outside the signed scope"},
        "scanned a network the customer never put in scope"),
    PlatformAction(
        _CRIT_INFRA, "incident-response",
        {"action": "containment_execute", "target": "10.20.7.14",
         "approval_status": "pending",
         "detail": "containment fired while approval still pending"},
        "executed containment while its human approval was still pending"),
]

_T0 = 1_754_000_000.0


def cyber_observations() -> list[Observation]:
    """Every platform action as a deterministic observation list."""
    out: list[Observation] = []
    t = _T0
    for i, act in enumerate(ACTIONS):
        payload: dict[str, Any] = {
            **act.payload,
            "agent": act.agent,
            "flow": act.scope.vertical,
            "engagement_id": act.scope.engagement_id,
            "consequence": act.consequence,
        }
        out.append(Observation(
            trace_id=f"{act.scope.engagement_id}-{act.agent}-{i + 1:02d}",
            payload=payload,
            timestamp=t,
            source=f"platform.{act.scope.vertical}",
            extra={"flow_type": act.scope.vertical, "engagement_scope": act.scope},
        ))
        t += 20.0
    return out
