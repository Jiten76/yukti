"""Default governance bundle for the V1 dashboard.

Bundles the five Pattern families and matching policies into a ready-to-run
:class:`Runtime`. The Pattern axis is intentionally bounded — five families
covers the breadth of risk we care about. Depth (the Flow axis) is where
the dashboard does its real work.

Pattern families (these are the locked V1 set):

1. **egress_data_leak** — sensitivity-tier-3+ data leaving the system
2. **change_velocity** — automation churn / release-gate bypass
3. **retry_amplification** — cascading retries deep into the call graph
4. **auth_access_anomaly** — IAM attach storms, privilege drift
5. **evidence_shape_drift** — agent output deviates from historical shape

Each family has one rule (deterministic predicate) and one policy decision.
Both are open to extension — add a rule or a predicate without touching
the framework.
"""

from __future__ import annotations

from typing import Any

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine
from yukti.core.runtime.runtime import Runtime

PATTERN_FAMILIES: list[str] = [
    "egress_data_leak",
    "change_velocity",
    "retry_amplification",
    "auth_access_anomaly",
    "evidence_shape_drift",
]


def _build_detector() -> RuleBasedPatternDetector:
    """The five default rule families."""
    return RuleBasedPatternDetector(
        [
            Rule(
                name="egress_data_leak",
                predicate=lambda o: (
                    o.payload.get("action") == "egress"
                    and o.payload.get("sensitivity_tier", 0) >= 3
                ),
                rationale="egress of sensitivity-tier-3+ data",
            ),
            Rule(
                name="change_velocity",
                predicate=lambda o: (
                    o.payload.get("action") == "change"
                    and o.payload.get("changes_per_window", 0) > 100
                ),
                rationale="release-gate change rate exceeds 100/window",
            ),
            Rule(
                name="retry_amplification",
                predicate=lambda o: (
                    o.payload.get("action") == "retry" and o.payload.get("retry_depth", 0) >= 4
                ),
                rationale="retry depth ≥ 4 across services",
            ),
            Rule(
                name="auth_access_anomaly",
                predicate=lambda o: (
                    o.payload.get("action") == "auth"
                    and (
                        bool(o.payload.get("attach_storm"))
                        or bool(o.payload.get("privilege_drift"))
                    )
                ),
                rationale="IAM attach-storm or privilege drift",
            ),
            Rule(
                name="evidence_shape_drift",
                predicate=lambda o: (
                    o.payload.get("action") == "agent_output"
                    and o.payload.get("shape_deviation", 0.0) >= 0.7
                ),
                rationale="agent output deviates from historical shape",
            ),
        ]
    )


def _egress_policy(doc: dict[str, Any]) -> Decision:
    if "egress_data_leak" not in doc.get("patterns", []):
        return Decision.ALLOW
    tier = doc.get("sensitivity_tier", 0)
    if tier >= 5:
        return Decision.DENY
    if tier >= 3:
        return Decision.GATE
    return Decision.ALLOW


def _change_velocity_policy(doc: dict[str, Any]) -> Decision:
    if "change_velocity" not in doc.get("patterns", []):
        return Decision.ALLOW
    return Decision.GATE if doc.get("changes_per_window", 0) > 300 else Decision.MONITOR


def _retry_policy(doc: dict[str, Any]) -> Decision:
    if "retry_amplification" not in doc.get("patterns", []):
        return Decision.ALLOW
    return Decision.DENY if doc.get("retry_depth", 0) >= 7 else Decision.GATE


def _auth_policy(doc: dict[str, Any]) -> Decision:
    if "auth_access_anomaly" not in doc.get("patterns", []):
        return Decision.ALLOW
    return Decision.DENY if doc.get("attach_storm") else Decision.GATE


def _drift_policy(doc: dict[str, Any]) -> Decision:
    if "evidence_shape_drift" not in doc.get("patterns", []):
        return Decision.ALLOW
    return Decision.GATE if doc.get("shape_deviation", 0.0) >= 0.9 else Decision.MONITOR


def _build_policy() -> SimplePredicatePolicyEngine:
    engine = SimplePredicatePolicyEngine()
    engine.register("egress_policy", _egress_policy)
    engine.register("change_velocity_policy", _change_velocity_policy)
    engine.register("retry_policy", _retry_policy)
    engine.register("auth_policy", _auth_policy)
    engine.register("evidence_drift_policy", _drift_policy)
    return engine


def build_runtime_with_default_governance() -> Runtime:
    """Build a Runtime wired with the five Pattern families + their policies."""
    return Runtime(
        detector=_build_detector(),
        policy=_build_policy(),
        evidence=InMemoryEvidenceStore(),
        hitl=InMemoryHITLBackend(),
        flows=InMemoryFlowTracker(),
    )
