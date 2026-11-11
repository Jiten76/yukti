"""Validate the core/enterprise architectural seam.

This test defines stubs of what ``yukti-enterprise`` would provide and
proves they plug in through the core ABCs with no changes to core code.

If this test ever breaks, it means the core/enterprise contract has
diverged — fix the interfaces, not the test.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from yukti.core.patterns.base import Observation, PatternDetector, PatternMatch
from yukti.core.policy.base import Decision, PolicyEngine, PolicyResult


class StubMLPatternDetector(PatternDetector):
    """Stub of what ``yukti-enterprise`` would provide.

    A real ML detector would load a trained model in ``__init__`` and call
    it in ``detect()``. This stub returns a fixed match to prove the
    interface composes.
    """

    name = "stub_ml"

    async def detect(self, observation: Observation) -> list[PatternMatch]:
        # Pretend we ran inference and got a 0.87 confidence match.
        return [
            PatternMatch(
                pattern_name="anomalous_egress_attempt",
                confidence=0.87,
                rationale="stub-ml: would-be ML inference output",
                evidence=[observation.trace_id],
            )
        ]


class StubEnterprisePolicyEngine(PolicyEngine):
    """Stub of what ``yukti-enterprise`` would provide for policy.

    A real enterprise impl would distribute hot-reloadable policies via a
    tenant-scoped registry. This stub returns a fixed Decision to prove
    the interface composes.
    """

    name = "stub_enterprise_policy"

    def __init__(self) -> None:
        self._policies: dict[str, str] = {}

    async def evaluate(
        self,
        input_doc: dict[str, Any],
        policies: list[str] | None = None,
    ) -> PolicyResult:
        return PolicyResult(
            decision=Decision.GATE,
            matched_policies=["stub_enterprise_policy"],
            rationale="stub: would gate through HITL in real impl",
            obligations=["log_to_evidence"],
        )

    async def load_policy(self, name: str, source: str) -> None:
        self._policies[name] = source

    async def list_policies(self) -> list[str]:
        return list(self._policies.keys())


@pytest.mark.asyncio
async def test_enterprise_pattern_detector_composes_through_core_interface() -> None:
    """A stub enterprise pattern detector must plug in through the core ABC."""
    detector = StubMLPatternDetector()
    obs = Observation(
        trace_id="trace-001",
        payload={"action": "egress"},
        timestamp=time.time(),
        source="agent.fraud_decision",
    )
    matches = await detector.detect(obs)
    assert len(matches) == 1
    assert matches[0].pattern_name == "anomalous_egress_attempt"
    assert 0.0 <= matches[0].confidence <= 1.0
    assert obs.trace_id in matches[0].evidence


@pytest.mark.asyncio
async def test_enterprise_policy_engine_composes_through_core_interface() -> None:
    """A stub enterprise policy engine must plug in through the core ABC."""
    engine = StubEnterprisePolicyEngine()
    await engine.load_policy("test_policy", "fake rego source")
    assert "test_policy" in await engine.list_policies()
    result = await engine.evaluate({"action": "read", "tier": 3})
    assert result.decision == Decision.GATE
    assert "log_to_evidence" in result.obligations


@pytest.mark.asyncio
async def test_enterprise_pattern_detector_is_a_pattern_detector() -> None:
    """The stub MUST satisfy isinstance(detector, PatternDetector).

    This is the strongest possible form of the seam test: the stub is
    literally a PatternDetector at runtime, indistinguishable from core
    implementations.
    """
    detector = StubMLPatternDetector()
    assert isinstance(detector, PatternDetector)
