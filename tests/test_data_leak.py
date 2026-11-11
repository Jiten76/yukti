"""Tests for the data-leak-prevention scenario — tiers, movement vs touch, clean."""

from __future__ import annotations

import asyncio

from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import RuleBasedPatternDetector
from yukti.scenarios.data_leak import (
    DATA_LEAK_RULES,
    FLEET,
    AccessProfile,
    build_data_leak_governance,
    data_leak_observations,
    data_leak_policy_decision,
)

_DETECTOR = RuleBasedPatternDetector(DATA_LEAK_RULES)

_PROFILE = AccessProfile(
    "test-agent",
    clearance_tier=2,
    channel_allowlist=frozenset({"sanctioned_channel"}),
    destination_allowlist=frozenset({"sanctioned_dest"}),
)


def _fired(payload: dict[str, object], profile: AccessProfile | None = _PROFILE) -> set[str]:
    extra: dict[str, object] = {}
    if profile is not None:
        extra["access_profile"] = profile
    obs = Observation(trace_id="t", payload=dict(payload), timestamp=0.0, source="test",
                      extra=dict(extra))
    return {m.pattern_name for m in asyncio.run(_DETECTOR.detect(obs))}


def test_read_above_clearance_is_overreach_not_egress() -> None:
    fired = _fired({"action": "data_read", "sensitivity_tier": 4})
    assert fired == {"tier_overreach"}


def test_tier3_egress_to_unsanctioned_destination_fires() -> None:
    fired = _fired(
        {"action": "egress", "sensitivity_tier": 4, "destination": "external_broker",
         "channel": "sanctioned_channel", "record_count": 10}
    )
    assert "external_tier_egress" in fired


def test_sanctioned_egress_is_clean() -> None:
    fired = _fired(
        {"action": "egress", "sensitivity_tier": 2, "destination": "sanctioned_dest",
         "channel": "sanctioned_channel", "record_count": 10}
    )
    assert fired == set()


def test_unsanctioned_channel_fires_at_any_tier() -> None:
    fired = _fired(
        {"action": "egress", "sensitivity_tier": 1, "destination": "sanctioned_dest",
         "channel": "personal_email", "record_count": 2}
    )
    assert "unsanctioned_channel" in fired


def test_bulk_movement_fires_on_mass_export() -> None:
    fired = _fired(
        {"action": "egress", "sensitivity_tier": 2, "destination": "sanctioned_dest",
         "channel": "sanctioned_channel", "record_count": 2_400_000}
    )
    assert "bulk_movement" in fired


def test_aggregation_uplift_reads_the_output_tier() -> None:
    assert "aggregation_uplift" in _fired(
        {"action": "dataset_join", "sensitivity_tier": 2, "output_tier": 4}
    )
    assert _fired({"action": "dataset_join", "sensitivity_tier": 2, "output_tier": 2}) == set()


def test_no_profile_means_no_profile_judged_patterns() -> None:
    """Without a declared profile only volume (profile-free) can fire — fail-safe
    against judging an agent by a boundary nobody declared."""
    fired = _fired(
        {"action": "egress", "sensitivity_tier": 5, "destination": "x", "channel": "y",
         "record_count": 1},
        profile=None,
    )
    assert fired == set()


def test_policy_moved_vs_touched() -> None:
    assert data_leak_policy_decision({"patterns": ["external_tier_egress"]}).name == "DENY"
    assert data_leak_policy_decision({"patterns": ["bulk_movement"]}).name == "DENY"
    assert data_leak_policy_decision({"patterns": ["tier_overreach"]}).name == "GATE"
    assert data_leak_policy_decision({"patterns": ["aggregation_uplift"]}).name == "GATE"
    assert data_leak_policy_decision({"patterns": []}).name == "ALLOW"


def test_fleet_produces_a_gradient_and_clean_agents_stay_clean() -> None:
    runtime = build_data_leak_governance()
    decisions: dict[str, list[str]] = {}
    for obs in data_leak_observations():
        result = asyncio.run(runtime.process(obs, flow_type=str(obs.extra.get("flow_type"))))
        decisions.setdefault(str(obs.payload["agent"]), []).append(result.decision.name)
    flat = [d for ds in decisions.values() for d in ds]
    assert "ALLOW" in flat and "GATE" in flat and "DENY" in flat
    assert set(decisions["support-summarizer"]) == {"ALLOW"}
    assert set(decisions["fraud-scorer"]) == {"ALLOW"}
    assert "DENY" in decisions["kyc-verifier"]
    assert "DENY" in decisions["training-exporter"]
    assert "GATE" in decisions["analytics-bot"]


def test_every_touch_has_a_plain_language_consequence() -> None:
    for obs in data_leak_observations():
        assert obs.payload.get("consequence")
    assert len({r.profile.agent for r in FLEET}) == len(FLEET)
