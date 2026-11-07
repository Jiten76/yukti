"""Smoke tests for the serve layer.

We disable the background simulator (``run_simulator=False``) and feed
observations explicitly through the Runtime so tests are deterministic.
The API contract — endpoint shapes, status codes, pagination — is what
gets covered here; full UI testing is out of scope for V1.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from yukti.core.patterns.base import Observation
from yukti.core.runtime.runtime import Runtime
from yukti.serve.api import create_app
from yukti.serve.fleet import FleetSimulator
from yukti.serve.patterns import (
    PATTERN_FAMILIES,
    build_runtime_with_default_governance,
)


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(run_simulator=False)
    with TestClient(app) as c:
        yield c


def test_pattern_families_locked() -> None:
    """The five families are a stable V1 contract."""
    assert PATTERN_FAMILIES == [
        "egress_data_leak",
        "change_velocity",
        "retry_amplification",
        "auth_access_anomaly",
        "evidence_shape_drift",
    ]


async def test_default_governance_classifies_all_five_families() -> None:
    """Each family's rule + policy must produce a recognizable result."""
    runtime = build_runtime_with_default_governance()
    import time as _time

    cases = [
        # (payload, expected pattern, expected decision in)
        (
            {"action": "egress", "sensitivity_tier": 5, "agent": "x"},
            "egress_data_leak",
            {"deny"},
        ),
        (
            {"action": "change", "changes_per_window": 400, "agent": "x"},
            "change_velocity",
            {"gate"},
        ),
        (
            {"action": "retry", "retry_depth": 8, "agent": "x"},
            "retry_amplification",
            {"deny"},
        ),
        (
            {"action": "auth", "attach_storm": True, "agent": "x"},
            "auth_access_anomaly",
            {"deny"},
        ),
        (
            {"action": "agent_output", "shape_deviation": 0.95, "agent": "x"},
            "evidence_shape_drift",
            {"gate"},
        ),
    ]
    for i, (payload, expected_pattern, expected_decisions) in enumerate(cases):
        obs = Observation(trace_id=f"t-{i}", payload=payload, timestamp=_time.time(), source="test")
        result = await runtime.process(obs, flow_type=f"test-{i}")
        assert expected_pattern in [m.pattern_name for m in result.pattern_matches], (
            f"family {expected_pattern} should have matched on payload {payload}"
        )
        assert result.decision.value in expected_decisions, (
            f"{expected_pattern}: expected one of {expected_decisions} got {result.decision.value}"
        )


def test_fleet_simulator_produces_observations_in_all_families_eventually() -> None:
    sim = FleetSimulator()
    seen_kinds = set()
    for _ in range(2000):
        obs = sim.next_observation()
        seen_kinds.add(obs.extra["family_hint"])
    # All five pattern families + at least one benign kind should appear in 2000 draws.
    assert set(PATTERN_FAMILIES).issubset(seen_kinds)
    assert any(k.startswith("benign_") for k in seen_kinds)


def test_meta_endpoint(client: TestClient) -> None:
    resp = client.get("/api/meta")
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] == "0.2.1"
    # /api/meta now returns rich {id,label,accent} families + the active mode,
    # so the frontend can render tiles data-driven. Default mode's family ids
    # still match the locked PATTERN_FAMILIES contract.
    assert data["mode"] == "default"
    assert [f["id"] for f in data["pattern_families"]] == PATTERN_FAMILIES


def test_fleet_summary_endpoint_starts_empty(client: TestClient) -> None:
    resp = client.get("/api/fleet/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_flows"] == 0
    assert data["evidence_records"] == 0
    assert data["pending_actions"] == 0


def test_fleet_summary_reflects_runtime_state(client: TestClient) -> None:
    """After feeding observations through the runtime, summary updates."""
    import asyncio
    import time as _time

    runtime: Runtime = client.app.state.runtime  # type: ignore[attr-defined]

    async def feed() -> None:
        for i, payload in enumerate(
            [
                {"action": "egress", "sensitivity_tier": 5, "agent": "x"},
                {"action": "egress", "sensitivity_tier": 3, "agent": "x"},
                {"action": "read", "sensitivity_tier": 1, "agent": "x"},
            ]
        ):
            obs = Observation(
                trace_id=f"feed-{i}",
                payload=payload,
                timestamp=_time.time(),
                source="test",
                extra={"flow_type": "test_flow"},
            )
            await runtime.process(obs, flow_type="test_flow")

    asyncio.run(feed())

    summary = client.get("/api/fleet/summary").json()
    assert summary["total_flows"] == 3
    # Two egress observations produced gate-or-deny -> 2 pending actions
    assert summary["pending_actions"] == 2
    # All five families should appear in pattern_matches dict (even with 0)
    # at least the egress family should have hits
    assert summary["pattern_matches"].get("egress_data_leak", 0) >= 2


def test_flows_endpoint_paginates(client: TestClient) -> None:
    """The flows endpoint returns the paginated shape regardless of N."""
    resp = client.get("/api/flows?limit=10&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data and isinstance(data["items"], list)
    assert "total" in data
    assert data["limit"] == 10
    assert data["offset"] == 0


def test_flow_detail_404_for_unknown(client: TestClient) -> None:
    resp = client.get("/api/flows/does-not-exist")
    assert resp.status_code == 404


def test_actions_pending_endpoint_shape(client: TestClient) -> None:
    resp = client.get("/api/actions/pending")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data and "total" in data and "limit" in data


def test_index_html_served(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Yukti" in resp.text
    assert "platinum.css" in resp.text
