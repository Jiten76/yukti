"""Serve ``dataflow`` mode over HTTP — the live ``/v1/traces`` path runs the same
provenance and delegation governance as the direct (demo/test) path.

This is the integration proof that the live API, not just the in-process runtime,
exercises the two data-flow capabilities: the ``dataflow`` mode builds
``build_dataflow_governance()`` (breakout rules plus the two data-flow rules) and
applies run-scoped read-taint propagation on ingest, so a bare egress of a data
class the run read earlier is caught over the wire — the laundering shape a
per-span label check misses.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from yukti.core.policy.base import Decision
from yukti.serve.api import create_app

_RANK = {"ALLOW": 0, "MONITOR": 1, "GATE": 2, "DENY": 3}


def _av(v: Any) -> dict[str, Any]:
    """Encode a Python value as an OTLP/JSON AnyValue (lists→arrayValue,
    dicts→kvlistValue), so a span can carry a label set or a delegated grant."""
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [_av(x) for x in v]}}
    if isinstance(v, dict):
        return {"kvlistValue": {"values": [{"key": str(k), "value": _av(x)}
                                           for k, x in v.items()]}}
    return {"stringValue": str(v)}


def _span(trace_id: str, span_id: str, attrs: dict[str, Any]) -> dict[str, Any]:
    return {
        "traceId": trace_id,
        "spanId": span_id,
        "name": "gen_ai.execute_tool",
        "startTimeUnixNano": "1755600000000000000",
        "attributes": [{"key": k, "value": _av(v)} for k, v in attrs.items()],
    }


def _export(*spans: dict[str, Any]) -> dict[str, Any]:
    return {"resourceSpans": [{"scopeSpans": [{"spans": list(spans)}]}]}


def _worst(results: list[dict[str, Any]]) -> str:
    return max((r["decision"] for r in results), key=lambda d: _RANK[d])


@pytest.fixture()
def dataflow_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("YUKTI_MODE", "dataflow")
    app = create_app(run_simulator=False, unbound_agent_decision=Decision.GATE)
    with TestClient(app) as c:
        # the analyst may report to a permitted sink, but may only egress
        # aggregates — never raw PII (data_egress_grant is the separate grant).
        c.post("/v1/envelopes", json={
            "agent": "analyst-agent",
            "task": "answer analytics questions and publish an aggregate report",
            "target_allowlist": ["warehouse"],
            "egress_allowlist": ["reports.corp.example"],
            "capability_grant": ["query", "send_report"],
            "data_egress_grant": ["aggregate.metrics"],
        })
        yield c


def test_mode_is_dataflow(dataflow_client: TestClient) -> None:
    meta = dataflow_client.get("/api/meta").json()
    assert meta["mode"] == "dataflow"
    assert "dataflow" in {m["id"] for m in meta["modes"]}


def test_taint_laundering_caught_over_http(dataflow_client: TestClient) -> None:
    # one run (shared traceId): READ raw PII, then a BARE egress to the permitted
    # sink. The egress span declares no label of its own; run-scoped taint
    # propagation on the live ingest attributes the earlier read to it.
    body = dataflow_client.post("/v1/traces", json=_export(
        _span("run-launder", "01", {
            "gen_ai.agent.name": "analyst-agent", "action": "tool_call",
            "target": "warehouse", "capability": "query",
            "data_labels": ["pii.customer_records"],
        }),
        _span("run-launder", "02", {
            "gen_ai.agent.name": "analyst-agent", "action": "network_egress",
            "destination": "reports.corp.example",  # a PERMITTED sink
        }),
    )).json()
    fired = {p for r in body["results"] for p in r["patterns"]}
    assert "provenance_violation" in fired
    # the sink is allowed, so the destination-allowlist pattern must NOT fire:
    # cross-span provenance is what catches this, not the egress allowlist.
    assert "unsanctioned_egress" not in fired
    assert _worst(body["results"]) == "DENY"


def test_aggregate_report_to_sink_is_allowed_over_http(dataflow_client: TestClient) -> None:
    # the honest other side: an aggregate (a granted class) to the permitted sink
    # is clean — the control discriminates, it does not block every egress.
    body = dataflow_client.post("/v1/traces", json=_export(
        _span("run-ok", "01", {
            "gen_ai.agent.name": "analyst-agent", "action": "tool_call",
            "target": "warehouse", "capability": "query",
            "data_labels": ["aggregate.metrics"],
        }),
        _span("run-ok", "02", {
            "gen_ai.agent.name": "analyst-agent", "action": "network_egress",
            "destination": "reports.corp.example", "data_labels": ["aggregate.metrics"],
        }),
    )).json()
    assert _worst(body["results"]) == "ALLOW"


def test_delegation_escalation_gated_over_http(dataflow_client: TestClient) -> None:
    dataflow_client.post("/v1/envelopes", json={
        "agent": "orchestrator-agent",
        "task": "coordinate a research task across subagents",
        "target_allowlist": ["warehouse"],
        "egress_allowlist": ["reports.corp.example"],
        "capability_grant": ["query", "delegate"],
    })
    body = dataflow_client.post("/v1/traces", json=_export(
        _span("run-deleg", "01", {
            "gen_ai.agent.name": "orchestrator-agent", "action": "delegate",
            "child_agent": "research-subagent-3",
            "delegated_grant": {"capability_grant": ["query", "wire_transfer"],
                                "egress_allowlist": ["exfil.evil.example"]},
        }),
    )).json()
    fired = {p for r in body["results"] for p in r["patterns"]}
    assert "delegation_escalation" in fired
    assert _worst(body["results"]) == "GATE"  # over-broad grant; nothing moved yet


def test_unbound_agent_fails_closed_over_http(dataflow_client: TestClient) -> None:
    # a spawned subagent with no registered envelope must be gated, not allowed.
    body = dataflow_client.post("/v1/traces", json=_export(
        _span("run-ghost", "01", {
            "gen_ai.agent.name": "ghost-subagent", "action": "network_egress",
            "destination": "x.example",
        }),
    )).json()
    assert body["decisions"] == {"GATE": 1}
