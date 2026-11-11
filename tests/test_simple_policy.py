"""SimplePredicatePolicyEngine — the core default PolicyEngine."""

from __future__ import annotations

from typing import Any

import pytest

from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine


async def test_register_and_list_policies() -> None:
    engine = SimplePredicatePolicyEngine()
    engine.register("always_allow", lambda _doc: Decision.ALLOW)
    assert await engine.list_policies() == ["always_allow"]


async def test_evaluate_with_no_policies_is_allow() -> None:
    engine = SimplePredicatePolicyEngine()
    result = await engine.evaluate({"anything": True})
    assert result.decision == Decision.ALLOW
    assert result.matched_policies == []


async def test_evaluate_single_deny() -> None:
    engine = SimplePredicatePolicyEngine()
    engine.register(
        "deny_tier_5", lambda doc: Decision.DENY if doc.get("tier") == 5 else Decision.ALLOW
    )
    result = await engine.evaluate({"tier": 5})
    assert result.decision == Decision.DENY
    assert "deny_tier_5" in result.matched_policies


async def test_most_restrictive_wins() -> None:
    """When multiple policies match, the most-restrictive decision wins."""
    engine = SimplePredicatePolicyEngine()
    engine.register("p_allow", lambda _doc: Decision.ALLOW)
    engine.register("p_monitor", lambda _doc: Decision.MONITOR)
    engine.register("p_gate", lambda _doc: Decision.GATE)
    result = await engine.evaluate({})
    # DENY > GATE > MONITOR > ALLOW; highest present here is GATE
    assert result.decision == Decision.GATE
    assert len(result.matched_policies) == 3


async def test_deny_beats_gate() -> None:
    engine = SimplePredicatePolicyEngine()
    engine.register("p_gate", lambda _doc: Decision.GATE)
    engine.register("p_deny", lambda _doc: Decision.DENY)
    result = await engine.evaluate({})
    assert result.decision == Decision.DENY


async def test_evaluate_with_explicit_policy_subset() -> None:
    engine = SimplePredicatePolicyEngine()
    engine.register("p_deny", lambda _doc: Decision.DENY)
    engine.register("p_allow", lambda _doc: Decision.ALLOW)
    # Only evaluate p_allow — p_deny is registered but not selected
    result = await engine.evaluate({}, policies=["p_allow"])
    assert result.decision == Decision.ALLOW
    assert result.matched_policies == ["p_allow"]


async def test_load_policy_raises_not_implemented() -> None:
    """The simple engine does not parse source-text policies."""
    engine = SimplePredicatePolicyEngine()
    with pytest.raises(NotImplementedError, match="register"):
        await engine.load_policy("some_policy", "fake rego source")


async def test_rationale_records_each_policy_decision() -> None:
    engine = SimplePredicatePolicyEngine()

    def tiered(doc: dict[str, Any]) -> Decision:
        return Decision.GATE if doc.get("tier", 0) >= 3 else Decision.ALLOW

    engine.register("tier_gate", tiered)
    result = await engine.evaluate({"tier": 4})
    assert "tier_gate -> gate" in result.rationale


async def test_raising_predicate_fails_closed_to_deny() -> None:
    """A buggy policy must not resolve to ALLOW or kill the pipeline."""
    engine = SimplePredicatePolicyEngine()

    def broken(_doc: dict[str, Any]) -> Decision:
        raise RuntimeError("boom")

    engine.register("broken", broken)
    engine.register("p_allow", lambda _doc: Decision.ALLOW)
    result = await engine.evaluate({})
    assert result.decision == Decision.DENY
    assert "broken" in result.matched_policies
    assert "failing closed" in result.rationale
    # the healthy policy still evaluated
    assert "p_allow" in result.matched_policies


async def test_strict_mode_raises_on_unknown_policy() -> None:
    """strict=True makes a typo'd / unregistered policy name fail loudly."""
    engine = SimplePredicatePolicyEngine(strict=True)
    engine.register("real", lambda _doc: Decision.ALLOW)
    with pytest.raises(KeyError, match="unknown policy"):
        await engine.evaluate({}, policies=["real", "typo_name"])


async def test_default_mode_skips_unknown_policy() -> None:
    """The documented default-open contract: unknown names are skipped."""
    engine = SimplePredicatePolicyEngine()
    engine.register("real", lambda _doc: Decision.DENY)
    result = await engine.evaluate({}, policies=["typo_name"])
    assert result.decision == Decision.ALLOW
    assert result.matched_policies == []
