"""Run-level correlation — an explicit artifact, not a claim about the core.

Yukti keys one flow per observation (``trace_id`` = ``traceId-spanId``), so it
judges each tool call independently; it does not correlate a whole run. This
manifest is what ties a run together — exchange, spans, per-span decisions,
report — so "the verdict trail for the run" is a real object a reviewer can
read, honestly labeled as example-side correlation.
"""

from __future__ import annotations

import json
from typing import Any

from examples.live_agent.agent import RunResult
from examples.live_agent.ledger import sha256_text


def run_outcome(results: list[dict[str, Any]]) -> str:
    """The run-level verdict, derived from the per-span decisions."""
    decisions = {r["decision"] for r in results}
    if "DENY" in decisions:
        return "breakout"
    if "GATE" in decisions:
        return "review"
    return "clean"


def build_manifest(
    run: RunResult, results: list[dict[str, Any]], *, attempt_n: int | None = None
) -> dict[str, Any]:
    """Correlate a run's exchange, spans, decisions, and report.

    Raises if the span and result counts disagree — a mismatch must surface, not
    be silently truncated.
    """
    span_ids = [str(s["spanId"]) for s in run.spans]
    if len(span_ids) != len(results):
        raise ValueError(f"manifest: {len(span_ids)} spans but {len(results)} governed results")
    return {
        "run_id": run.run_id,
        "model_id": run.model_id,
        "requested_model": run.requested_model,
        "otel_trace_id": f"otel-{run.run_id}",
        "anthropic_exchange_sha256": sha256_text(json.dumps(run.exchange, sort_keys=True)),
        "span_ids": span_ids,
        "observation_ids": [r["trace_id"] for r in results],
        "per_span_decisions": [
            {"span_id": sid, "decision": r["decision"], "patterns": r.get("patterns", [])}
            for sid, r in zip(span_ids, results, strict=True)
        ],
        "report_sha256": sha256_text(run.report or ""),
        "outcome": run_outcome(results),
        "ledger_attempt_n": attempt_n,
    }
