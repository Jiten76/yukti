"""Tests for envelope binding — breakout detection on real (OTel-ingested) traffic.

The capstone contrast: the same trace is ungoverned (ALLOW — nothing to judge
against) until the operator declares the agent's sanctioned boundary; then the
exact same actions fire breakout patterns and get contained.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from yukti.core.policy.base import Decision
from yukti.scenarios.breakout import TaskEnvelope, envelope_from_dict, envelope_to_dict
from yukti.serve.api import create_app


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("YUKTI_MODE", "breakout")
    app = create_app(run_simulator=False)
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def strict_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """App that DENYs any trace it cannot bind to a registered envelope."""
    monkeypatch.setenv("YUKTI_MODE", "breakout")
    app = create_app(run_simulator=False, unbound_agent_decision=Decision.DENY)
    with TestClient(app) as c:
        yield c


def _span(trace_id: str, attrs: dict[str, str]) -> dict[str, Any]:
    return {
        "traceId": trace_id,
        "spanId": "01",
        "name": "gen_ai.execute_tool",
        "startTimeUnixNano": "1755600000000000000",
        "attributes": [{"key": k, "value": {"stringValue": v}} for k, v in attrs.items()],
    }


def _export(*spans: dict[str, Any]) -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "prod-harness"}}
                    ]
                },
                "scopeSpans": [{"scope": {"name": "sdk"}, "spans": list(spans)}],
            }
        ]
    }


# ── envelope_from_dict: fail-safe construction ───────────────────────────────


def test_envelope_from_dict_defaults_fail_safe() -> None:
    env = envelope_from_dict({"agent": "a1"})
    assert isinstance(env, TaskEnvelope)
    assert env.target_allowlist == frozenset()
    assert env.egress_allowlist == frozenset()
    assert env.capability_grant == frozenset()
    assert env.identity_creation_allowed is False
    assert env.durable_write_scope == frozenset()


def test_envelope_dict_roundtrip() -> None:
    doc = {
        "agent": "recon",
        "task": "reconcile ledgers",
        "target_allowlist": ["ledger_read", "report_api"],
        "egress_allowlist": ["internal.corp"],
        "capability_grant": ["read"],
        "identity_creation_allowed": False,
        "durable_write_scope": [],
    }
    env = envelope_from_dict(doc)
    out = envelope_to_dict(env)
    assert out["target_allowlist"] == ["ledger_read", "report_api"]
    assert out["egress_allowlist"] == ["internal.corp"]
    assert out["run_id"] == "recon"


# ── registration API ─────────────────────────────────────────────────────────


def test_register_and_list_envelopes(client: TestClient) -> None:
    r = client.post(
        "/v1/envelopes",
        json={"agent": "invoice-reconciler", "target_allowlist": ["ledger_read"]},
    )
    assert r.status_code == 200
    assert r.json()["envelope"]["target_allowlist"] == ["ledger_read"]
    listing = client.get("/v1/envelopes").json()
    assert "invoice-reconciler" in listing


def test_register_requires_agent(client: TestClient) -> None:
    assert client.post("/v1/envelopes", json={"target_allowlist": ["x"]}).status_code == 422


# ── the capstone contrast ────────────────────────────────────────────────────


def _breakout_spans() -> dict[str, Any]:
    """One in-envelope action, one egress outside it, one unsanctioned tool."""
    return _export(
        _span(
            "trace-ok",
            {
                "gen_ai.agent.name": "invoice-reconciler",
                "action": "tool_call",
                "tool": "ledger_read",
                "yukti.flow": "reconciliation",
            },
        ),
        _span(
            "trace-egress",
            {
                "gen_ai.agent.name": "invoice-reconciler",
                "action": "network_egress",
                "destination": "https://paste.dropzone.example/upload",
                "yukti.flow": "reconciliation",
            },
        ),
        _span(
            "trace-escape",
            {
                "gen_ai.agent.name": "invoice-reconciler",
                "action": "tool_call",
                "tool": "wire_transfer",
                "yukti.flow": "payment-authorization",
            },
        ),
    )


def test_unregistered_agent_is_ungoverned(client: TestClient) -> None:
    body = client.post("/v1/traces", json=_breakout_spans()).json()
    assert body["decisions"] == {"ALLOW": 3}
    assert all(not r["envelope_bound"] for r in body["results"])


def test_registered_envelope_makes_breakout_fire_on_classified_traffic(
    client: TestClient,
) -> None:
    """These spans carry operator-classified Yukti attributes (action/tool/
    destination), not raw gen_ai semconv; governing a *raw* gen_ai span is proven
    in test_gen_ai_governance.py. Same spans that ALLOWed unbound now contain."""
    client.post(
        "/v1/envelopes",
        json={
            "agent": "invoice-reconciler",
            "task": "reconcile invoices against the ledger",
            "tool_allowlist": ["ledger_read"],
            "egress_allowlist": ["internal.corp"],
        },
    )
    body = client.post("/v1/traces", json=_breakout_spans()).json()
    by_trace = {r["trace_id"].rsplit("-", 1)[0]: r for r in body["results"]}
    assert all(r["envelope_bound"] for r in body["results"])
    # in-envelope action passes
    assert by_trace["trace-ok"]["decision"] == "ALLOW"
    # the exact same spans that ALLOWed unbound now fire and get contained
    assert "unsanctioned_egress" in by_trace["trace-egress"]["patterns"]
    assert by_trace["trace-egress"]["decision"] == "DENY"
    assert "envelope_escape" in by_trace["trace-escape"]["patterns"]
    assert by_trace["trace-escape"]["decision"] == "DENY"  # wire_transfer is effectful


def test_retried_batch_does_not_poison_ingest(client: TestClient) -> None:
    """Exporters retry whole batches; a duplicate span errors alone, the rest land."""
    export = _export(_span("trace-a", {"gen_ai.agent.name": "x", "action": "tool_call"}))
    first = client.post("/v1/traces", json=export)
    assert first.status_code == 200 and first.json()["decisions"] == {"ALLOW": 1}
    retry = client.post("/v1/traces", json=export)
    assert retry.status_code == 200
    assert retry.json()["decisions"] == {"ERROR": 1}
    assert "already exists" in retry.json()["results"][0]["error"]


# ── the binding gate: unbound identity as a first-class decision ──────────────


def test_unbound_identity_denied_when_configured(strict_client: TestClient) -> None:
    """With the binding gate on, traffic we cannot bind to a registered envelope
    is DENYed first-class — not silently ALLOWed (contrast
    test_unregistered_agent_is_ungoverned, which is the default pass-through)."""
    body = strict_client.post("/v1/traces", json=_breakout_spans()).json()
    assert body["decisions"] == {"DENY": 3}
    assert all(not r["envelope_bound"] for r in body["results"])


def test_unbound_identity_decision_is_first_class_and_queued(strict_client: TestClient) -> None:
    """The forced DENY is evidenced and opens a queryable human intervention
    carrying the reason — a real verdict, not a demo-side warning."""
    strict_client.post("/v1/traces", json=_breakout_spans())
    pending = strict_client.get("/api/actions/pending").json()
    assert len(pending["items"]) == 3
    assert all(
        "unbound identity" in item["payload"]["rationale"] for item in pending["items"]
    )


def test_spoofed_identity_is_denied_not_ungoverned(strict_client: TestClient) -> None:
    """Registering an envelope does not let a *renamed* agent slip through: the
    unbindable identity is DENYed, closing the self-identification bypass."""
    strict_client.post(
        "/v1/envelopes",
        json={"agent": "invoice-reconciler", "task": "t", "egress_allowlist": ["internal.corp"]},
    )
    spoofed = _export(
        _span(
            "trace-spoof",
            {
                "gen_ai.agent.name": "invoice-reconciler-v2",  # not the registered name
                "action": "network_egress",
                "destination": "https://paste.dropzone.example/upload",
            },
        )
    )
    body = strict_client.post("/v1/traces", json=spoofed).json()
    assert body["decisions"] == {"DENY": 1}
    assert body["results"][0]["envelope_bound"] is False
