"""Tests for the risk-engineering scenario — thresholds, credibility, staleness."""

from __future__ import annotations

import asyncio
from typing import Any

from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import RuleBasedPatternDetector
from yukti.scenarios.risk_engineering import (
    CATALOG,
    KRI,
    READINGS,
    RISK_RULES,
    build_risk_governance,
    risk_observations,
    risk_policy_decision,
)

_DETECTOR = RuleBasedPatternDetector(RISK_RULES)

_HIGH_BAD = KRI("T-01", "test rate", "%", "higher_is_worse", watch=2.0, act=5.0)
_LOW_BAD = KRI("T-02", "coverage", "%", "lower_is_worse", watch=90.0, act=75.0)


def _fired(kri: KRI, payload: dict[str, Any], ts: float = 1000.0) -> set[str]:
    obs = Observation(trace_id="t", payload=dict(payload), timestamp=ts, source="test",
                      extra={"kri": kri})
    return {m.pattern_name for m in asyncio.run(_DETECTOR.detect(obs))}


def test_direction_aware_thresholds() -> None:
    # higher_is_worse: 6 crosses act=5; 3 sits in the watch band
    assert "act_threshold_crossing" in _fired(_HIGH_BAD, {"value": 6, "evidence_tier": "decision_grade"})
    assert _fired(_HIGH_BAD, {"value": 3, "evidence_tier": "decision_grade"}) == {
        "watch_threshold_crossing"
    }
    # lower_is_worse: 70 crosses act=75; 85 is the watch band
    assert "act_threshold_crossing" in _fired(_LOW_BAD, {"value": 70, "evidence_tier": "decision_grade"})
    assert "watch_threshold_crossing" in _fired(_LOW_BAD, {"value": 85, "evidence_tier": "decision_grade"})


def test_weak_evidence_actuation_fires_below_decision_grade() -> None:
    proxy = _fired(_HIGH_BAD, {"value": 6, "evidence_tier": "proxy"})
    assert {"act_threshold_crossing", "weak_evidence_actuation"} <= proxy
    solid = _fired(_HIGH_BAD, {"value": 6, "evidence_tier": "decision_grade"})
    assert "weak_evidence_actuation" not in solid


def test_adverse_delta_is_direction_aware_and_anchored() -> None:
    assert "adverse_delta" in _fired(
        _HIGH_BAD, {"value": 1.5, "anchor_value": 1.0, "evidence_tier": "decision_grade"}
    )
    # improvement is not adverse
    assert "adverse_delta" not in _fired(
        _HIGH_BAD, {"value": 0.7, "anchor_value": 1.0, "evidence_tier": "decision_grade"}
    )
    # lower_is_worse: falling coverage is adverse
    assert "adverse_delta" in _fired(
        _LOW_BAD, {"value": 60, "anchor_value": 95, "evidence_tier": "decision_grade"}
    )


def test_stale_reading_uses_the_freshness_window() -> None:
    fresh = _fired(_HIGH_BAD, {"value": 1, "measured_at": 900.0, "evidence_tier": "decision_grade"})
    assert "stale_reading" not in fresh
    stale = _fired(
        _HIGH_BAD, {"value": 1, "measured_at": 1000.0 - 7200.0, "evidence_tier": "decision_grade"}
    )
    assert "stale_reading" in stale


def test_policy_contains_only_on_decision_grade_fresh_evidence() -> None:
    assert risk_policy_decision({"patterns": ["act_threshold_crossing"]}).name == "DENY"
    assert risk_policy_decision(
        {"patterns": ["act_threshold_crossing", "weak_evidence_actuation"]}
    ).name == "GATE"
    assert risk_policy_decision(
        {"patterns": ["act_threshold_crossing", "stale_reading"]}
    ).name == "GATE"
    assert risk_policy_decision({"patterns": ["adverse_delta"]}).name == "GATE"
    assert risk_policy_decision({"patterns": ["watch_threshold_crossing"]}).name == "MONITOR"
    assert risk_policy_decision({"patterns": []}).name == "ALLOW"


def test_catalog_is_typed_and_honest() -> None:
    assert len({k.kri_id for k in CATALOG}) == len(CATALOG)
    for kri in CATALOG:
        assert kri.direction in {"higher_is_worse", "lower_is_worse"}
        assert kri.do_not_claim, f"{kri.kri_id} must state what it does not claim"
    # proxies carry the "nearest —" caveat idiom
    assert any(k.caveat.startswith("nearest") for k in CATALOG)


def test_fleet_exercises_all_four_decisions() -> None:
    runtime = build_risk_governance()
    decisions: dict[str, str] = {}
    for obs in risk_observations():
        result = asyncio.run(runtime.process(obs, flow_type=str(obs.extra.get("flow_type"))))
        decisions[str(obs.payload["kri_id"])] = result.decision.name
    assert decisions["RE-05"] == "ALLOW"
    assert decisions["RE-02"] == "MONITOR"   # early-warning band
    assert decisions["RE-04"] == "GATE"      # adverse delta on a proxy
    assert decisions["RE-03"] == "GATE"      # act crossing on weak evidence — never DENY
    assert decisions["RE-06"] == "GATE"      # act crossing but stale
    assert decisions["RE-01"] == "DENY"      # act + decision-grade + fresh → contain


def test_do_not_claim_travels_with_every_reading() -> None:
    for obs in risk_observations():
        assert obs.payload.get("do_not_claim"), obs.payload.get("kri_id")
        assert obs.payload.get("consequence")
    assert len(READINGS) == len(risk_observations())
