"""Governing a raw gen_ai OTel span — the honest form of "governs real traces".

A span carrying only GenAI semantic-convention attributes (gen_ai.agent.name /
gen_ai.operation.name / gen_ai.tool.name), with NO hand-stamped Yukti-native
fields, is classified by the real OTLP mapper and governed against a registered
task envelope. An unsanctioned tool call is an envelope escape and is contained;
the granted tool passes; and a tool name is never mis-matched against the host
allowlist (the fixed foot-gun).
"""

from __future__ import annotations

import asyncio
from typing import Any

from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.integrations.opentelemetry import span_to_observation
from yukti.scenarios.breakout import BREAKOUT_RULES, TaskEnvelope, build_breakout_governance


def _gen_ai_span(tool: str) -> dict[str, Any]:
    """A pure gen_ai tool-call span — no Yukti-native attributes at all."""
    return {
        "traceId": "trace-gen-ai",
        "spanId": "01",
        "name": "gen_ai.execute_tool",
        "startTimeUnixNano": "1755600000000000000",
        "attributes": [
            {"key": "gen_ai.agent.name", "value": {"stringValue": "invoice-reconciler"}},
            {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
            {"key": "gen_ai.tool.name", "value": {"stringValue": tool}},
        ],
    }


# an envelope that grants exactly one tool — nothing else is sanctioned
_ENV = TaskEnvelope(
    run_id="invoice-reconciler",
    task="reconcile invoices against the ledger",
    tool_allowlist=frozenset({"ledger_read"}),
)


def _bind(tool: str) -> Observation:
    base = span_to_observation(_gen_ai_span(tool))
    return Observation(
        trace_id=base.trace_id,
        payload=base.payload,
        timestamp=base.timestamp,
        source=base.source,
        extra={**base.extra, "task_envelope": _ENV},
    )


def test_raw_gen_ai_span_maps_tool_not_target() -> None:
    obs = span_to_observation(_gen_ai_span("wire_transfer"))
    assert obs.payload["tool"] == "wire_transfer"
    assert "target" not in obs.payload  # tool name must not land in the host field


def test_unsanctioned_tool_call_is_an_envelope_escape() -> None:
    fired = {m.pattern_name for m in asyncio.run(RuleBasedPatternDetector(BREAKOUT_RULES).detect(_bind("wire_transfer")))}
    assert "envelope_escape" in fired


def test_sanctioned_tool_call_does_not_fire() -> None:
    # the granted tool passes — and its name is not a host, so it must not be
    # mis-matched against the host allowlist either (foot-gun regression guard)
    fired = {m.pattern_name for m in asyncio.run(RuleBasedPatternDetector(BREAKOUT_RULES).detect(_bind("ledger_read")))}
    assert fired == set()


def test_unsanctioned_tool_is_contained_end_to_end() -> None:
    result = asyncio.run(build_breakout_governance().process(_bind("wire_transfer"), flow_type="otel"))
    assert result.decision is Decision.DENY
