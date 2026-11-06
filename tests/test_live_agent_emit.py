"""The emit contract, proven end-to-end through the real ingest route.

This is the piece v1/v2 of the design got wrong: naive GenAI semconv produced
``action=execute_tool`` / ``target=http_get`` / no ``destination``, which missed
the egress and false-DENYed every sanctioned call. These tests assert the
adapter emits the Yukti-native fields the engine actually matches, verified by
posting real otel-built spans to ``/v1/traces`` against a registered envelope.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from examples.live_agent import otel
from yukti.serve.api import create_app

_BASE = {
    "trace_id": "trace-live",
    "span_id": "01",
    "agent": "docs-helper",
    "flow": "live-agent",
    "run_id": "run-1",
    "start_unixnano": "1755600000000000000",
}


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("YUKTI_MODE", "breakout")
    app = create_app(run_simulator=False)
    with TestClient(app) as c:
        c.post(
            "/v1/envelopes",
            json={
                "agent": "docs-helper",
                "task": "summarize the sandbox docs",
                "target_allowlist": [otel.SANDBOX_HOST, otel.REPORT_SINK_HOST],
                "egress_allowlist": ["api.sanctioned.internal"],
                "capability_grant": ["http_get", "file_read", "post_report"],
            },
        )
        yield c


def _decide(client: TestClient, span: dict[str, Any]) -> dict[str, Any]:
    body = client.post("/v1/traces", json=otel.export("live", [span])).json()
    return body["results"][0]


def test_http_get_unlisted_host_is_denied(client: TestClient) -> None:
    r = _decide(client, otel.http_get_span("https://raw.githubusercontent.com/x/y", **_BASE))
    assert r["envelope_bound"] is True
    assert "unsanctioned_egress" in r["patterns"]
    assert r["decision"] == "DENY"


def test_http_get_sanctioned_host_is_allowed(client: TestClient) -> None:
    r = _decide(client, otel.http_get_span("https://api.sanctioned.internal/v1/schema", **_BASE))
    assert r["decision"] == "ALLOW"
    assert r["patterns"] == []


def test_read_file_no_tool_name_leak_is_allowed(client: TestClient) -> None:
    # The v1/v2 bug: gen_ai.tool.name leaked into target and false-fired
    # envelope_escape. The adapter emits target=<sandbox host> and no tool name.
    r = _decide(client, otel.read_file_span(**_BASE))
    assert r["decision"] == "ALLOW"
    assert r["patterns"] == []


def test_post_report_is_allowed(client: TestClient) -> None:
    r = _decide(client, otel.post_report_span(**_BASE))
    assert r["decision"] == "ALLOW"


def test_adapter_omits_operation_and_tool_name(client: TestClient) -> None:
    # Emitting either would let the mapper override action / overwrite target.
    span = otel.http_get_span("https://x.example/y", **_BASE)
    keys = {a["key"] for a in span["attributes"]}
    assert "gen_ai.operation.name" not in keys
    assert "gen_ai.tool.name" not in keys


def test_validate_live_span_flags_missing_destination() -> None:
    assert (
        otel.validate_live_span({"action": "network_egress", "capability": "http_get"})
        == "network_egress without a destination"
    )
    assert otel.validate_live_span(
        {"action": "file_read", "target": "x", "capability": "file_read"}
    ) is None
