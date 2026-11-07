"""Tests for multi-domain serve — every governance domain on the dashboard."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from yukti.serve.api import MODES, create_app


@pytest.fixture()
def make_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    def _make(mode: str) -> TestClient:
        monkeypatch.setenv("YUKTI_MODE", mode)
        return TestClient(create_app(run_simulator=False))

    yield _make


def test_all_modes_registered() -> None:
    assert set(MODES) == {
        "default", "breakout", "reliability", "data-leak", "risk", "cyber", "dataflow"
    }


@pytest.mark.parametrize(
    ("mode", "expected_family", "expected_unit"),
    [
        ("reliability", "retry_amplification", "services"),
        ("data-leak", "aggregation_uplift", "agents"),
        ("risk", "weak_evidence_actuation", "indicators"),
        ("cyber", "scope_boundary_violation", "platform actions"),
        ("breakout", "unsanctioned_egress", "agent runs"),
    ],
)
def test_each_mode_serves_its_own_families_and_vocabulary(
    make_client: object, mode: str, expected_family: str, expected_unit: str
) -> None:
    client = make_client(mode)  # type: ignore[operator]
    with client:
        meta = client.get("/api/meta").json()
    assert meta["mode"] == mode
    assert len(meta["pattern_families"]) == 5
    assert expected_family in {f["id"] for f in meta["pattern_families"]}
    assert meta["headline"]["unit"] == expected_unit
    accents = [f["accent"] for f in meta["pattern_families"]]
    assert len(set(accents)) == 5  # every tile a distinct accent


def test_unknown_mode_falls_back_to_default(make_client: object) -> None:
    client = make_client("nonsense")  # type: ignore[operator]
    with client:
        meta = client.get("/api/meta").json()
    assert meta["mode"] == "default"


def test_scenario_simulator_restamps_live() -> None:
    import asyncio
    import time

    from yukti.scenarios.reliability import reliability_observations
    from yukti.serve.scenario_stream import ScenarioSimulator

    sim = ScenarioSimulator(reliability_observations, step_seconds=0.0, gap_seconds=0.0)

    async def take_two() -> list[object]:
        out = []
        async for obs in sim.run():
            out.append(obs)
            if len(out) == 2:
                sim.stop()
                break
        return out

    a, b = asyncio.run(take_two())
    now = time.time()
    assert abs(a.timestamp - now) < 5  # type: ignore[attr-defined]  # live, not the seeded 2025 clock
    assert a.trace_id.endswith("-l01")  # type: ignore[attr-defined]
    assert a.trace_id != b.trace_id  # type: ignore[attr-defined]


def test_switch_mode_endpoint_swaps_domain(make_client: object) -> None:
    client = make_client("breakout")  # type: ignore[operator]
    with client:
        before = client.get("/api/meta").json()
        assert before["mode"] == "breakout"
        resp = client.post("/api/mode", json={"mode": "risk"})
        assert resp.status_code == 200
        assert resp.json()["mode"] == "risk"
        after = client.get("/api/meta").json()
        assert after["mode"] == "risk"
        assert "weak_evidence_actuation" in {f["id"] for f in after["pattern_families"]}
        assert after["headline"]["unit"] == "indicators"


def test_switch_mode_rejects_unknown(make_client: object) -> None:
    client = make_client("breakout")  # type: ignore[operator]
    with client:
        assert client.post("/api/mode", json={"mode": "bogus"}).status_code == 422


def test_meta_lists_all_modes_for_the_switcher(make_client: object) -> None:
    client = make_client("default")  # type: ignore[operator]
    with client:
        modes = client.get("/api/meta").json()["modes"]
    assert [m["id"] for m in modes] == [
        "breakout", "reliability", "data-leak", "risk", "cyber", "dataflow", "default"
    ]
    assert all(m["label"] for m in modes)
