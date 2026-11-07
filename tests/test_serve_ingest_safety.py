"""Serve ingest safety — safe-by-default binding, and no silently dropped span.

Two guarantees of the shipped server:
  * the deployed app GATEs a trace it cannot bind to a registered envelope,
    rather than silently ALLOWing it (the documented entrypoint is strict); and
  * a pipeline error on ingest is recorded as evidence and routed to a human,
    not reduced to a bare error count.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from yukti.core.policy.base import Decision
from yukti.serve.api import app as shipped_app
from yukti.serve.api import create_app


def _span(trace_id: str, attrs: dict[str, str]) -> dict[str, Any]:
    return {
        "traceId": trace_id,
        "spanId": "01",
        "name": "gen_ai.execute_tool",
        "startTimeUnixNano": "1755600000000000000",
        "attributes": [{"key": k, "value": {"stringValue": v}} for k, v in attrs.items()],
    }


def _export(*spans: dict[str, Any]) -> dict[str, Any]:
    return {"resourceSpans": [{"scopeSpans": [{"spans": list(spans)}]}]}


@pytest.fixture()
def gate_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("YUKTI_MODE", "breakout")
    app = create_app(run_simulator=False, unbound_agent_decision=Decision.GATE)
    with TestClient(app) as c:
        yield c


def test_shipped_app_is_safe_by_default() -> None:
    # the module-level app that `uvicorn yukti.serve.api:app` serves GATEs
    # unbound identities; it does not use the library's pass-through default.
    assert shipped_app.state.unbound_agent_decision is Decision.GATE


def test_unbound_agent_is_gated_and_owned(gate_client: TestClient) -> None:
    body = gate_client.post(
        "/v1/traces", json=_export(_span("t-unbound", {"gen_ai.agent.name": "ghost"}))
    ).json()
    assert body["decisions"] == {"GATE": 1}
    pending = gate_client.get("/api/actions/pending").json()
    assert len(pending["items"]) == 1
    # the gated item carries a named accountable owner, not just an SLA clock
    assert pending["items"][0]["assigned_to"] == "duty-approver"


async def test_ingest_error_is_recorded_and_routed_not_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YUKTI_MODE", "breakout")
    app = create_app(run_simulator=False)
    with TestClient(app) as c:
        # force the pipeline to raise mid-observation
        app.state.runtime.process = AsyncMock(side_effect=RuntimeError("boom"))
        body = c.post(
            "/v1/traces", json=_export(_span("t-err", {"gen_ai.agent.name": "x"}))
        ).json()
        res = body["results"][0]
        assert res["decision"] == "ERROR"
        # not a bare count: the failure left first-class evidence + a queued human
        assert "evidence_sha256" in res
        assert "intervention_id" in res
        pending = await app.state.runtime.hitl.list_pending()
        assert any(
            "routed to a human" in (i.payload.get("rationale", "")) for i in pending
        )
