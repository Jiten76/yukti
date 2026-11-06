"""Synthetic fleet generator for the default dashboard mode.

Produces a realistic stream of agent observations across the five Pattern
families plus benign noise, at a configurable rate. Used by ``yukti serve`` to
give the dashboard structure to navigate without a live agent backend. A real
agent runtime can replace it through the same ``Runtime`` contract.

The output is deliberately mixed: most observations are benign (no
pattern fires), some match a pattern at low severity (MONITOR/ALLOW),
fewer match at high severity (GATE/DENY). That mix makes the dashboard
look like a real fleet — most traffic is fine, governance only acts on
the meaningful minority.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from yukti.core.patterns.base import Observation

FLOW_TYPES: list[str] = [
    "customer_onboarding",
    "fraud_decision",
    "payment_authorization",
    "compliance_evidence_collection",
    "infra_change_request",
    "data_export_request",
]

AGENT_NAMES: list[str] = [
    "fraud_decider",
    "kyc_screener",
    "egress_gatekeeper",
    "reporting_bot",
    "compliance_orchestrator",
    "change_validator",
    "rate_limiter",
    "evidence_collector",
    "iam_reconciler",
    "lineage_tracker",
    "alert_router",
]

# Weight names so benign traffic dominates (≈70%) — the dashboard should
# look mostly quiet with occasional real governance events.
_OBSERVATION_KINDS = [
    "egress_data_leak",
    "change_velocity",
    "retry_amplification",
    "auth_access_anomaly",
    "evidence_shape_drift",
    "benign_read",
    "benign_write",
]
_OBSERVATION_WEIGHTS = [6, 6, 6, 6, 6, 35, 35]


@dataclass
class FleetConfig:
    """Configuration for the fleet simulator."""

    rate_per_second: float = 4.0
    seed: int = 42


def _build_payload(rng: random.Random, kind: str) -> dict[str, Any]:
    """Build a plausible payload for the given observation kind."""
    if kind == "egress_data_leak":
        return {
            "action": "egress",
            "sensitivity_tier": rng.choices([1, 2, 3, 4, 5], weights=[40, 30, 15, 10, 5])[0],
            "agent": rng.choice(["egress_gatekeeper", "fraud_decider", "reporting_bot"]),
            "destination": rng.choice(["external_api", "partner_warehouse", "exfil_sink"]),
        }
    if kind == "change_velocity":
        return {
            "action": "change",
            "changes_per_window": rng.choices([10, 50, 120, 250, 450], weights=[40, 30, 15, 10, 5])[
                0
            ],
            "agent": rng.choice(["change_validator", "rate_limiter"]),
            "release": f"r-{rng.randint(1000, 9999)}",
        }
    if kind == "retry_amplification":
        return {
            "action": "retry",
            "retry_depth": rng.choices([1, 2, 3, 4, 6, 8], weights=[40, 25, 15, 10, 7, 3])[0],
            "agent": rng.choice(["fraud_decider", "compliance_orchestrator"]),
            "upstream": rng.choice(["payments_api", "identity_svc", "rules_engine"]),
        }
    if kind == "auth_access_anomaly":
        return {
            "action": "auth",
            "attach_storm": rng.random() < 0.15,
            "privilege_drift": rng.random() < 0.25,
            "agent": "iam_reconciler",
            "role": f"role-{rng.randint(1, 200)}",
        }
    if kind == "evidence_shape_drift":
        return {
            "action": "agent_output",
            "shape_deviation": round(rng.random(), 2),
            "agent": rng.choice(AGENT_NAMES),
            "output_kind": rng.choice(["decision", "classification", "summary"]),
        }
    if kind == "benign_read":
        return {
            "action": "read",
            "sensitivity_tier": rng.choices([1, 2], weights=[70, 30])[0],
            "agent": rng.choice(AGENT_NAMES),
        }
    # benign_write
    return {
        "action": "write",
        "agent": rng.choice(AGENT_NAMES),
        "rows": rng.randint(1, 500),
    }


class FleetSimulator:
    """Produce a stream of synthetic agent observations.

    Usage::

        sim = FleetSimulator(FleetConfig(rate_per_second=3.0))
        async for obs in sim.run():
            await runtime.process(obs, flow_type=obs.extra["flow_type"])
    """

    def __init__(self, config: FleetConfig | None = None) -> None:
        self.config = config or FleetConfig()
        self._rng = random.Random(self.config.seed)
        self._idx = 0
        self._running = False

    def next_observation(self) -> Observation:
        """Generate one observation. Synchronous; safe to call repeatedly."""
        self._idx += 1
        kind = self._rng.choices(_OBSERVATION_KINDS, weights=_OBSERVATION_WEIGHTS)[0]
        flow_type = self._rng.choice(FLOW_TYPES)
        payload = _build_payload(self._rng, kind)
        return Observation(
            trace_id=f"flow-{self._idx:06d}",
            payload=payload,
            timestamp=time.time(),
            source=f"agent.{payload['agent']}",
            extra={"flow_type": flow_type, "family_hint": kind},
        )

    async def run(self) -> AsyncIterator[Observation]:
        """Yield observations at the configured rate until :meth:`stop`."""
        period = 1.0 / max(self.config.rate_per_second, 0.001)
        self._running = True
        try:
            while self._running:
                yield self.next_observation()
                await asyncio.sleep(period)
        finally:
            self._running = False

    def stop(self) -> None:
        """Signal the run loop to exit on its next iteration."""
        self._running = False
