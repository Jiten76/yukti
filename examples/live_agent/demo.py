"""Run the live-agent demo: govern a run through the REAL Yukti serve route.

Replay-first: by default this replays a committed recording's spans through the
actual `/v1/envelopes` + `/v1/traces` routes of a freshly built serve app
(breakout mode, with the unbound-identity binding gate set to DENY) — no API
key, deterministic. Live capture is a separate step — see `record.py`; the
`--live` flag here only points you there.

The app is driven over httpx.ASGITransport through its genuine routes; nothing
reaches into `app.state.runtime`. What governs the run is the same code path a
production OTel exporter would hit.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Any

import httpx

from examples.live_agent import otel
from examples.live_agent.agent import RunResult, envelope_grant
from examples.live_agent.manifest import run_outcome
from yukti.core.policy.base import Decision
from yukti.serve.api import create_app

_RECORDINGS = Path(__file__).parent / "recordings"


async def _govern_async(
    spans: list[dict[str, Any]], envelope: dict[str, Any]
) -> list[dict[str, Any]]:
    app = create_app(run_simulator=False, unbound_agent_decision=Decision.DENY)
    # run the real lifespan so activate_mode builds the runtime, then drive the
    # genuine HTTP routes in-process — no app.state surgery.
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://live-agent") as client:
            await client.post("/v1/envelopes", json=envelope)
            resp = await client.post("/v1/traces", json=otel.export("live-agent", spans))
            resp.raise_for_status()
            return list(resp.json()["results"])


def govern(
    spans: list[dict[str, Any]], envelope: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Govern a run's spans through the real serve route. Requires the process
    env to select breakout mode (``main`` sets ``YUKTI_MODE=breakout``)."""
    return asyncio.run(_govern_async(spans, envelope or envelope_grant()))


def replay(recording_path: str | Path) -> dict[str, Any]:
    """Load a recording and govern its spans through the real route."""
    run = RunResult.from_dict(json.loads(Path(recording_path).read_text()))
    results = govern(run.spans)
    return {
        "run_id": run.run_id,
        "model_id": run.model_id,
        "outcome": run_outcome(results),
        "results": results,
        "report": run.report,
    }


def _print_summary(summary: dict[str, Any]) -> None:
    print(f"run {summary['run_id']}  model={summary['model_id']}")
    print(f"  run-level outcome: {summary['outcome'].upper()}")
    for r in summary["results"]:
        pats = ", ".join(r.get("patterns") or []) or "-"
        print(f"    {r['decision']:5}  {pats}")


def main() -> None:
    os.environ["YUKTI_MODE"] = "breakout"  # this demo governs the breakout domain
    ap = argparse.ArgumentParser(description="Live-agent demo (replay by default).")
    ap.add_argument(
        "--live", action="store_true",
        help="live capture is via `python -m examples.live_agent.record`; this points you there",
    )
    ap.add_argument("--recording", default=str(_RECORDINGS / "example.json"))
    args = ap.parse_args()

    if args.live:  # pragma: no cover - exercised only in the live recording session
        raise SystemExit(
            "live recording is run via the recording harness (needs ANTHROPIC_API_KEY); "
            "see recordings/README once a session has been captured."
        )
    _print_summary(replay(args.recording))


if __name__ == "__main__":  # pragma: no cover
    main()
