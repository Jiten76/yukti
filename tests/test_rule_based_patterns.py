"""RuleBasedPatternDetector — the core default PatternDetector."""

from __future__ import annotations

from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector


def _obs(**payload: object) -> Observation:
    return Observation(
        trace_id="trace-1",
        payload=dict(payload),
        timestamp=1700000000.0,
        source="test",
    )


async def test_empty_detector_returns_no_matches() -> None:
    detector = RuleBasedPatternDetector()
    assert detector.rule_count == 0
    assert await detector.detect(_obs(x=1)) == []


async def test_matching_rule_produces_full_confidence_match() -> None:
    detector = RuleBasedPatternDetector(
        [Rule("high_tier", lambda o: o.payload.get("tier", 0) >= 3, "tier >= 3")]
    )
    matches = await detector.detect(_obs(tier=4))
    assert len(matches) == 1
    assert matches[0].pattern_name == "high_tier"
    assert matches[0].confidence == 1.0
    assert matches[0].rationale == "tier >= 3"
    assert matches[0].evidence == ["trace-1"]


async def test_non_matching_rule_produces_nothing() -> None:
    detector = RuleBasedPatternDetector(
        [Rule("high_tier", lambda o: o.payload.get("tier", 0) >= 3)]
    )
    assert await detector.detect(_obs(tier=1)) == []


async def test_rule_that_raises_yields_zero_confidence_not_a_crash() -> None:
    """A buggy rule must surface as a zero-confidence match, not an exception."""

    def bad_rule(o: Observation) -> bool:
        raise RuntimeError("boom")

    detector = RuleBasedPatternDetector([Rule("buggy", bad_rule)])
    matches = await detector.detect(_obs(tier=4))
    assert len(matches) == 1
    assert matches[0].confidence == 0.0
    assert "boom" in matches[0].rationale


async def test_multiple_rules_can_match_one_observation() -> None:
    detector = RuleBasedPatternDetector()
    detector.add_rule(Rule("a", lambda o: "tier" in o.payload))
    detector.add_rule(Rule("b", lambda o: o.payload.get("tier", 0) > 0))
    assert detector.rule_count == 2
    matches = await detector.detect(_obs(tier=2))
    assert {m.pattern_name for m in matches} == {"a", "b"}
