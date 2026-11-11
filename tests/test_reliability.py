"""Tests for the SRE reliability scenario — patterns, consequence gradient, clean."""

from __future__ import annotations

import asyncio

from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import RuleBasedPatternDetector
from yukti.scenarios.reliability import (
    FLEET,
    RELIABILITY_RULES,
    build_reliability_governance,
    reliability_observations,
    reliability_policy_decision,
)

_DETECTOR = RuleBasedPatternDetector(RELIABILITY_RULES)


def _fired(payload: dict[str, object]) -> set[str]:
    obs = Observation(trace_id="t", payload=payload, timestamp=0.0, source="test", extra={})
    return {m.pattern_name for m in asyncio.run(_DETECTOR.detect(obs))}


def test_named_service_flows_are_distinct() -> None:
    assert len({r.service for r in FLEET}) == len(FLEET)
    assert {"checkout-latency", "identity", "release-governance"} <= {r.flow for r in FLEET}


def test_each_pattern_fires_on_its_signal() -> None:
    assert "retry_amplification" in _fired({"signal": "retry_ratio", "value": 5, "threshold": 3})
    assert "change_velocity_spike" in _fired({"signal": "change_velocity", "value": 300, "threshold": 120})
    assert "backpressure_accumulation" in _fired({"signal": "backpressure", "value": 2, "threshold": 1})
    assert "iam_quota_storm" in _fired({"signal": "iam_error_rate", "value": 0.2, "threshold": 0.05})
    # runway fires when it drops BELOW the floor (forward-looking)
    assert "runway_exhaustion" in _fired({"signal": "runway_days", "value": 6, "threshold": 14})
    assert "runway_exhaustion" not in _fired({"signal": "runway_days", "value": 30, "threshold": 14})


def test_in_tolerance_signal_fires_nothing() -> None:
    assert _fired({"signal": "retry_ratio", "value": 1.1, "threshold": 3}) == set()


def test_policy_ranks_by_consequence() -> None:
    assert reliability_policy_decision({"patterns": ["retry_amplification"]}).name == "DENY"
    assert reliability_policy_decision({"patterns": ["backpressure_accumulation"]}).name == "DENY"
    assert reliability_policy_decision({"patterns": ["change_velocity_spike"]}).name == "GATE"
    assert reliability_policy_decision({"patterns": ["runway_exhaustion"]}).name == "GATE"
    assert reliability_policy_decision({"patterns": []}).name == "ALLOW"


def test_fleet_run_is_a_spread_not_all_critical() -> None:
    runtime = build_reliability_governance()
    decisions = [
        asyncio.run(runtime.process(o, flow_type=str(o.extra.get("flow_type")))).decision.name
        for o in reliability_observations()
    ]
    assert "ALLOW" in decisions and "GATE" in decisions and "DENY" in decisions


def test_healthy_services_stay_clean() -> None:
    runtime = build_reliability_governance()
    for o in reliability_observations():
        if o.payload.get("service") in {"payment-api", "notify-svc"}:
            res = asyncio.run(runtime.process(o, flow_type=str(o.extra.get("flow_type"))))
            assert res.decision.name == "ALLOW", f"{o.payload.get('service')} should be healthy"


def test_every_signal_has_a_plain_language_consequence() -> None:
    for o in reliability_observations():
        assert o.payload.get("consequence")
