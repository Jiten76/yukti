"""SRE reliability governance.

Governs a fleet of services whose signals are diverging: change-velocity
spikes, retry-amplification cascades, backpressure accumulation, runway
exhaustion, and IAM-quota storms. It uses the same engine as the security
scenarios (Pattern × Flow → Decision, evidence chain, HITL) applied to a
different domain.

The patterns read trend-form signals (retry ratio, absorption versus arrival,
days-to-quota) rather than raw gauges, because a self-healing platform can keep
level metrics green while divergence grows.

Deterministic and synthetic; every service, value, and date is invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine
from yukti.core.runtime.runtime import Runtime

# ── the five reliability patterns ─────────────────────────────────────────────
# Each is a threshold over a trend-form signal on one observation. "runway_days"
# fires when it drops BELOW its floor (forward-looking); the rest fire ABOVE.


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _over(o: Observation, signal: str) -> bool:
    p = o.payload
    return p.get("signal") == signal and _num(p.get("value")) > _num(p.get("threshold"))


def _change_velocity_spike(o: Observation) -> bool:
    return _over(o, "change_velocity")


def _retry_amplification(o: Observation) -> bool:
    return _over(o, "retry_ratio")


def _backpressure_accumulation(o: Observation) -> bool:
    return _over(o, "backpressure")


def _iam_quota_storm(o: Observation) -> bool:
    return _over(o, "iam_error_rate")


def _runway_exhaustion(o: Observation) -> bool:
    p = o.payload
    return p.get("signal") == "runway_days" and _num(p.get("value")) < _num(p.get("threshold"))


RELIABILITY_RULES: list[Rule] = [
    Rule(name="change_velocity_spike", predicate=_change_velocity_spike,
         rationale="changes per window over the release-gate threshold — a gate bypass"),
    Rule(name="retry_amplification", predicate=_retry_amplification,
         rationale="retry ratio over threshold — one failure echoing across service boundaries"),
    Rule(name="backpressure_accumulation", predicate=_backpressure_accumulation,
         rationale="queue absorption below arrival — backlog growing, an outage building"),
    Rule(name="iam_quota_storm", predicate=_iam_quota_storm,
         rationale="auth/quota error rate spiking — an identity-plane storm"),
    Rule(name="runway_exhaustion", predicate=_runway_exhaustion,
         rationale="days-to-quota below the floor — capacity runway running out"),
]

#: (id, label) for the dashboard tiles, if this scenario is served.
RELIABILITY_FAMILIES: list[tuple[str, str]] = [
    ("change_velocity_spike", "Change"),
    ("retry_amplification", "Retry"),
    ("backpressure_accumulation", "Backpressure"),
    ("iam_quota_storm", "IAM storm"),
    ("runway_exhaustion", "Runway"),
]

# active degradation that spreads or hits customers → contain; governance and
# forward-looking signals → route to a human before they bite.
_CRITICAL = {"retry_amplification", "backpressure_accumulation", "iam_quota_storm"}
_HIGH = {"change_velocity_spike", "runway_exhaustion"}


def reliability_policy_decision(doc: dict[str, Any]) -> Decision:
    """Consequence-ranked: active/spreading degradation DENYs (contain), a gate
    bypass or a runway warning GATEs (human, before it bites), in-tolerance ALLOWs."""
    patterns = set(doc.get("patterns") or [])
    if not patterns:
        return Decision.ALLOW
    if patterns & _CRITICAL:
        return Decision.DENY
    if patterns & _HIGH:
        return Decision.GATE
    return Decision.MONITOR


def build_reliability_governance() -> Runtime:
    """The runtime armed with the reliability rules + the consequence policy."""
    policy = SimplePredicatePolicyEngine()
    policy.register("reliability_consequence_policy", reliability_policy_decision)
    return Runtime(
        detector=RuleBasedPatternDetector(RELIABILITY_RULES),
        policy=policy,
        evidence=InMemoryEvidenceStore(),
        hitl=InMemoryHITLBackend(),
        flows=InMemoryFlowTracker(),
    )


# ── the service fleet ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Signal:
    """One reliability reading on a service, with the human consequence."""

    signal: str
    value: float
    threshold: float
    detail: str
    customer_facing: bool = False


@dataclass(frozen=True)
class ServiceRun:
    """One service governed through a named reliability Flow."""

    flow: str
    service: str
    signals: list[Signal] = field(default_factory=list)
    headline: str = ""


FLEET: list[ServiceRun] = [
    # ── healthy — the governor must not cry wolf ──
    ServiceRun(
        flow="payment-throughput", service="payment-api",
        headline="healthy — within tolerance",
        signals=[
            Signal("retry_ratio", 1.2, 3.0, "retries steady on the payment path", True),
            Signal("change_velocity", 40, 120, "release cadence within the gate"),
        ]),
    ServiceRun(
        flow="notifications", service="notify-svc",
        headline="healthy — within tolerance",
        signals=[Signal("backpressure", 0.4, 1.0, "queue draining faster than it fills")]),
    # ── HIGH — governance / forward-looking, act before it bites ──
    ServiceRun(
        flow="release-governance", service="deploy-orchestrator",
        headline="release gate bypassed — change velocity over the line",
        signals=[Signal("change_velocity", 310, 120,
                        "310 changes this window — the release gate was bypassed")]),
    ServiceRun(
        flow="capacity-planning", service="quota-watch",
        headline="capacity runway short — 6 days to quota",
        signals=[Signal("runway_days", 6, 14,
                        "6 days of headroom left before the Kafka partition quota")]),
    # ── CRITICAL — active, spreading, or customer-facing degradation ──
    ServiceRun(
        flow="checkout-latency", service="checkout-api",
        headline="retry storm amplifying across the checkout chain",
        signals=[Signal("retry_ratio", 4.6, 3.0,
                        "retries amplifying across the checkout call chain", True)]),
    ServiceRun(
        flow="identity", service="auth-gateway",
        headline="identity-plane quota storm",
        signals=[Signal("iam_error_rate", 0.18, 0.05,
                        "auth error rate 18% — an IAM quota storm", True)]),
    ServiceRun(
        flow="ledger", service="ledger-writer",
        headline="backlog building — an outage is forming",
        signals=[Signal("backpressure", 2.3, 1.0,
                        "consumer absorbing 2.3x slower than arrival — backlog building", True)]),
]

_T0 = 1_754_000_000.0


def reliability_observations() -> list[Observation]:
    """Every service's signals as a deterministic observation list (seeded clock)."""
    out: list[Observation] = []
    t = _T0
    for run in FLEET:
        for i, sig in enumerate(run.signals):
            out.append(Observation(
                trace_id=f"{run.service}-sig-{i + 1:02d}",
                payload={
                    "service": run.service,
                    "flow": run.flow,
                    "agent": run.service,
                    "signal": sig.signal,
                    "value": sig.value,
                    "threshold": sig.threshold,
                    "customer_facing": sig.customer_facing,
                    "consequence": sig.detail,
                },
                timestamp=t,
                source=f"telemetry.{run.service}",
                extra={"flow_type": run.flow},
            ))
            t += 20.0
    return out
