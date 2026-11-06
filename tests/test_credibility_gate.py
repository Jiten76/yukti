"""Credibility gate — the "× credibility" half of consequence-ranked governance.

Proves the README claim that Yukti "won't take its hardest action, containment,
on weak or stale evidence; that routes to a person instead." A DENY resting on
weak or stale evidence is downgraded to GATE (human review); a DENY on strong
evidence is taken; and a forced identity decision is never second-guessed by
evidence strength. Credibility genuinely drives the decision here.
"""

from __future__ import annotations

import time
from typing import Any

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.patterns.base import Observation, PatternDetector, PatternMatch
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine
from yukti.core.runtime.runtime import Runtime


def _deny_policy() -> SimplePredicatePolicyEngine:
    policy = SimplePredicatePolicyEngine()
    policy.register(
        "contain",
        lambda doc: Decision.DENY if doc.get("pattern_matched") else Decision.ALLOW,
    )
    return policy


def _runtime(detector: PatternDetector, *, min_cred: float = 0.8) -> Runtime:
    return Runtime(
        detector=detector,
        policy=_deny_policy(),
        evidence=InMemoryEvidenceStore(),
        hitl=InMemoryHITLBackend(),
        flows=InMemoryFlowTracker(),
        min_containment_credibility=min_cred,
    )


def _obs(**payload: Any) -> Observation:
    return Observation(trace_id="t1", payload=dict(payload), timestamp=time.time(), source="t")


# a rule-based detector always fires at confidence 1.0 (strong evidence)
_STRONG = RuleBasedPatternDetector([Rule(name="hit", predicate=lambda o: True)])


class _WeakDetector(PatternDetector):
    """A detector whose single match is low-confidence (e.g. an ML signal)."""

    name = "weak"

    async def detect(self, observation: Observation) -> list[PatternMatch]:
        return [PatternMatch(pattern_name="weak_signal", confidence=0.5, rationale="low")]


async def test_strong_evidence_is_contained() -> None:
    result = await _runtime(_STRONG).process(_obs(action="x"))
    assert result.decision is Decision.DENY


async def test_low_confidence_signal_downgrades_containment_to_human() -> None:
    result = await _runtime(_WeakDetector()).process(_obs(action="x"))
    assert result.decision is Decision.GATE
    assert "weak evidence" in result.policy_rationale


async def test_explicit_low_credibility_downgrades() -> None:
    # strong detector, but the observation itself declares low credibility
    result = await _runtime(_STRONG).process(_obs(action="x", credibility=0.4))
    assert result.decision is Decision.GATE
    assert "credibility 0.40" in result.policy_rationale


async def test_stale_evidence_downgrades() -> None:
    result = await _runtime(_STRONG).process(_obs(action="x", evidence_stale=True))
    assert result.decision is Decision.GATE


async def test_forced_decision_is_not_second_guessed_by_credibility() -> None:
    # a forced identity DENY (the binding gate) is an identity fact, not an
    # evidence-strength question — it must NOT be downgraded.
    result = await _runtime(_STRONG).process(
        _obs(action="x", credibility=0.0),
        forced_decision=Decision.DENY,
        forced_rationale="unbound identity",
    )
    assert result.decision is Decision.DENY


async def test_threshold_is_configurable() -> None:
    # with the gate disabled (threshold 0.0), even a weak signal is contained
    result = await _runtime(_WeakDetector(), min_cred=0.0).process(_obs(action="x"))
    assert result.decision is Decision.DENY
