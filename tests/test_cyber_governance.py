"""Tests for the cyber-governance scenario — scope, gates, registry, depth, evidence."""

from __future__ import annotations

import asyncio
from typing import Any

from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import RuleBasedPatternDetector
from yukti.scenarios.cyber_governance import (
    ACTIONS,
    AGENT_CATALOG,
    ALL_AGENTS,
    CYBER_RULES,
    VERTICALS,
    EngagementScope,
    build_cyber_governance,
    cyber_observations,
    cyber_policy_decision,
)

_DETECTOR = RuleBasedPatternDetector(CYBER_RULES)

_SCOPE = EngagementScope(
    engagement_id="e1",
    vertical="ai-tech",
    target_scope=frozenset({"10.20."}),
    registered_agents=frozenset({"vuln-assessment", "network-recon"}),
    max_delegation_depth=3,
    approval_required_for=frozenset({"active_scan", "containment_execute"}),
)


def _fired(payload: dict[str, Any], scope: EngagementScope | None = _SCOPE) -> set[str]:
    extra: dict[str, Any] = {}
    if scope is not None:
        extra["engagement_scope"] = scope
    obs = Observation(trace_id="t", payload=dict(payload), timestamp=0.0, source="test",
                      extra=extra)
    return {m.pattern_name for m in asyncio.run(_DETECTOR.detect(obs))}


def test_catalog_is_the_governable_roster() -> None:
    assert len(ALL_AGENTS) == 22
    assert set(AGENT_CATALOG) == {
        "enterprise-security", "ai-governance", "devsecops", "third-party-risk"
    }
    assert len(VERTICALS) == 3


def test_scope_boundary_violation_on_out_of_scope_target() -> None:
    fired = _fired(
        {"action": "active_scan", "target": "203.0.113.9", "approval_status": "approved"}
    )
    assert "scope_boundary_violation" in fired
    clean = _fired(
        {"action": "active_scan", "target": "10.20.4.1", "approval_status": "approved"}
    )
    assert "scope_boundary_violation" not in clean


def test_hitl_gate_bypass_requires_approved_status() -> None:
    assert "hitl_gate_bypass" in _fired(
        {"action": "containment_execute", "target": "10.20.1.1", "approval_status": "pending"}
    )
    assert "hitl_gate_bypass" not in _fired(
        {"action": "containment_execute", "target": "10.20.1.1", "approval_status": "approved"}
    )
    # non-gated actions don't need approval
    assert "hitl_gate_bypass" not in _fired({"action": "probe", "target": "10.20.1.1"})


def test_unregistered_agent_invocation_is_fleet_drift() -> None:
    assert "unregistered_agent_invocation" in _fired(
        {"action": "invoke_agent", "invoked_agent": "learning-framework"}
    )
    assert "unregistered_agent_invocation" not in _fired(
        {"action": "invoke_agent", "invoked_agent": "vuln-assessment"}
    )


def test_delegation_runaway_past_the_sanctioned_depth() -> None:
    assert "delegation_runaway" in _fired({"action": "delegate", "delegation_depth": 4})
    assert "delegation_runaway" not in _fired({"action": "delegate", "delegation_depth": 3})


def test_evidence_gap_on_unevidenced_completion() -> None:
    assert "evidence_gap" in _fired({"action": "step_complete", "evidence_attached": False})
    assert "evidence_gap" not in _fired({"action": "step_complete", "evidence_attached": True})


def test_no_scope_no_scope_judged_patterns() -> None:
    """Without a declared engagement scope, only structure-free checks fire."""
    fired = _fired(
        {"action": "active_scan", "target": "203.0.113.9", "approval_status": "pending"},
        scope=None,
    )
    assert fired == set()


def test_policy_contains_action_gates_structure() -> None:
    assert cyber_policy_decision({"patterns": ["scope_boundary_violation"]}).name == "DENY"
    assert cyber_policy_decision({"patterns": ["hitl_gate_bypass"]}).name == "DENY"
    assert cyber_policy_decision({"patterns": ["unregistered_agent_invocation"]}).name == "GATE"
    assert cyber_policy_decision({"patterns": ["delegation_runaway"]}).name == "GATE"
    assert cyber_policy_decision({"patterns": ["evidence_gap"]}).name == "GATE"
    assert cyber_policy_decision({"patterns": []}).name == "ALLOW"


def test_engagement_produces_the_gradient() -> None:
    runtime = build_cyber_governance()
    by_agent: dict[str, str] = {}
    for obs in cyber_observations():
        result = asyncio.run(runtime.process(obs, flow_type=str(obs.extra.get("flow_type"))))
        by_agent[str(obs.payload["agent"])] = result.decision.name
    assert by_agent["model-security"] == "ALLOW"
    assert by_agent["compliance-validation"] == "ALLOW"
    assert by_agent["vuln-assessment"] == "ALLOW"
    assert by_agent["bias-fairness"] == "GATE"            # evidence gap
    assert by_agent["portfolio-orchestrator"] == "GATE"   # unregistered agent
    assert by_agent["sbom-analysis"] == "GATE"            # delegation depth 7 of 5
    assert by_agent["network-recon"] == "DENY"            # out-of-scope scan
    assert by_agent["incident-response"] == "DENY"        # approval still pending


def test_every_action_names_its_consequence() -> None:
    assert len(cyber_observations()) == len(ACTIONS)
    for obs in cyber_observations():
        assert obs.payload.get("consequence")
        assert obs.payload.get("engagement_id")
