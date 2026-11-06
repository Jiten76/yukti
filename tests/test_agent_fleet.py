"""Tests for the diverse agent fleet — variety, consequence gradient, clean runs."""

from __future__ import annotations

import asyncio

from yukti.scenarios.agent_fleet import (
    FLEET,
    build_fleet_governance,
    fleet_observations,
    fleet_policy_decision,
)


def test_fleet_has_variety_of_named_flows() -> None:
    flows = {r.flow for r in FLEET}
    # distinct named Flows from Yukti's vocabulary, not anonymous run ids
    assert {"payment-authorization", "customer-onboarding", "fraud-decision"} <= flows
    assert len({r.agent for r in FLEET}) == len(FLEET)  # every run a distinct agent


def test_policy_ranks_by_consequence() -> None:
    # effectful reach → DENY (critical)
    assert fleet_policy_decision(
        {"patterns": ["envelope_escape"], "target": "payment_disbursement", "effectful": True}
    ).name == "DENY"
    # external egress → DENY (critical)
    assert fleet_policy_decision(
        {"patterns": ["unsanctioned_egress"], "destination": "https://x.example"}
    ).name == "DENY"
    # read-class escape → GATE (high), not critical
    assert fleet_policy_decision(
        {"patterns": ["envelope_escape"], "target": "analytics_warehouse"}
    ).name == "GATE"
    # nothing fired → ALLOW
    assert fleet_policy_decision({"patterns": []}).name == "ALLOW"


def test_fleet_run_ends_in_a_spread_not_all_critical() -> None:
    runtime = build_fleet_governance()
    decisions = [
        asyncio.run(runtime.process(o, flow_type=str(o.extra.get("flow_type")))).decision.name
        for o in fleet_observations()
    ]
    # the whole point: a spread, including clean passes and a HIGH tier —
    # not a wall of identical CRITICAL/DENY
    assert "ALLOW" in decisions
    assert "GATE" in decisions
    assert "DENY" in decisions


def test_clean_runs_stay_clean() -> None:
    runtime = build_fleet_governance()
    clean_agents = {"fraud-scorer", "recon-bot"}
    for o in fleet_observations():
        if o.payload.get("agent") in clean_agents:
            res = asyncio.run(runtime.process(o, flow_type=str(o.extra.get("flow_type"))))
            assert res.decision.name == "ALLOW", f"{o.payload.get('agent')} should be clean"


def test_every_step_carries_a_plain_language_consequence() -> None:
    for o in fleet_observations():
        assert o.payload.get("consequence"), "every step needs a human-readable consequence"
