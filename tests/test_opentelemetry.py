"""Tests for the OpenTelemetry ingest integration — the flagship real tentacle."""

from __future__ import annotations

import asyncio
from typing import Any

from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import RuleBasedPatternDetector
from yukti.integrations.base import Capability, IntegrationContext
from yukti.integrations.opentelemetry import (
    OpenTelemetryConfig,
    OpenTelemetryIntegration,
    attributes_to_dict,
    observations_from_otlp,
    span_to_observation,
)
from yukti.scenarios.breakout import BREAKOUT_RULES, CTF_ENVELOPE


def _span(
    name: str = "gen_ai.execute_tool",
    attrs: list[dict[str, Any]] | None = None,
    trace_id: str = "0af7651916cd43dd8448eb211c80319c",
) -> dict[str, Any]:
    return {
        "traceId": trace_id,
        "spanId": "b7ad6b7169203331",
        "name": name,
        "startTimeUnixNano": "1723600000000000000",
        "endTimeUnixNano": "1723600001500000000",
        "attributes": attrs or [],
        "status": {"code": "STATUS_CODE_OK"},
    }


def _export(spans: list[dict[str, Any]], service: str = "payments-agent") -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service}},
                    ]
                },
                "scopeSpans": [{"scope": {"name": "test"}, "spans": spans}],
            }
        ]
    }


# ── attribute decoding ────────────────────────────────────────────────────────


def test_decodes_every_otlp_value_type() -> None:
    attrs = attributes_to_dict(
        [
            {"key": "s", "value": {"stringValue": "x"}},
            {"key": "i", "value": {"intValue": "42"}},  # int64 arrives as string
            {"key": "d", "value": {"doubleValue": 1.5}},
            {"key": "b", "value": {"boolValue": True}},
            {"key": "a", "value": {"arrayValue": {"values": [{"stringValue": "y"}]}}},
            {
                "key": "kv",
                "value": {"kvlistValue": {"values": [{"key": "n", "value": {"intValue": "7"}}]}},
            },
        ]
    )
    assert attrs == {"s": "x", "i": 42, "d": 1.5, "b": True, "a": ["y"], "kv": {"n": 7}}


def test_plain_dict_attributes_pass_through() -> None:
    assert attributes_to_dict({"already": "flat"}) == {"already": "flat"}


# ── span conversion ───────────────────────────────────────────────────────────


def test_span_becomes_observation_with_genai_mapping() -> None:
    span = _span(
        attrs=[
            {"key": "gen_ai.agent.name", "value": {"stringValue": "payout-agent"}},
            {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
            {"key": "gen_ai.tool.name", "value": {"stringValue": "wire_transfer"}},
            {"key": "yukti.flow", "value": {"stringValue": "payment-authorization"}},
        ]
    )
    obs = span_to_observation(span, {"service.name": "payments-agent"})
    assert isinstance(obs, Observation)
    assert obs.trace_id == "0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331"
    assert obs.payload["agent"] == "payout-agent"
    assert obs.payload["action"] == "execute_tool"
    assert obs.payload["tool"] == "wire_transfer"  # a tool is named, not addressed
    assert "target" not in obs.payload  # tool names never land in the host field
    assert obs.payload["service"] == "payments-agent"
    assert obs.source == "otel:payments-agent"
    assert obs.extra["flow_type"] == "payment-authorization"
    assert obs.timestamp == 1723600000.0  # nanos → seconds


def test_fallbacks_without_genai_attrs() -> None:
    obs = span_to_observation(_span(name="http.request"), {"service.name": "svc"})
    assert obs.payload["agent"] == "svc"           # falls back to service.name
    assert obs.payload["action"] == "http.request"  # falls back to span name
    assert obs.extra["flow_type"] == "otel-traces"  # default flow
    assert "target" not in obs.payload


def test_full_export_walks_all_spans_and_tolerates_empty() -> None:
    export = _export([_span(), _span(name="second")])
    assert len(observations_from_otlp(export)) == 2
    assert observations_from_otlp({}) == []
    assert observations_from_otlp({"resourceSpans": []}) == []


# ── the Integration contract ──────────────────────────────────────────────────


def test_integration_declares_ingest_and_queues() -> None:
    integ = OpenTelemetryIntegration(OpenTelemetryConfig())
    assert integ.name == "opentelemetry"
    assert Capability.INGEST_EVENT in integ.capabilities
    ctx = IntegrationContext(trace_id="t1")
    asyncio.run(integ.ingest_event(ctx, _export([_span()])))
    asyncio.run(integ.ingest_event(ctx, _export([_span(name="s2")])))
    drained = integ.drain()
    assert len(drained) == 2
    assert integ.drain() == []  # drained queue is empty


# ── end to end: an OTLP span triggers a breakout pattern ─────────────────────


def test_otel_span_with_classified_attrs_flows_into_breakout_detection() -> None:
    """An agent egressing outside its envelope, reported via OTel with
    operator-classified attributes (action/destination), is caught. (Governance
    from *raw* gen_ai semconv — agent/operation/tool only — is proven separately
    in test_gen_ai_governance.py.)"""
    span = _span(
        attrs=[
            {"key": "gen_ai.agent.name", "value": {"stringValue": "ctf-solver"}},
            {"key": "action", "value": {"stringValue": "network_egress"}},
            {"key": "destination", "value": {"stringValue": "https://api.github.com/repos/x/y"}},
        ]
    )
    obs_base = span_to_observation(span, {"service.name": "eval-harness"})
    # stamp the run's envelope the way the breakout scenario does
    obs = Observation(
        trace_id=obs_base.trace_id,
        payload=obs_base.payload,
        timestamp=obs_base.timestamp,
        source=obs_base.source,
        extra={**obs_base.extra, "task_envelope": CTF_ENVELOPE},
    )
    detector = RuleBasedPatternDetector(BREAKOUT_RULES)
    fired = {m.pattern_name for m in asyncio.run(detector.detect(obs))}
    assert "unsanctioned_egress" in fired
