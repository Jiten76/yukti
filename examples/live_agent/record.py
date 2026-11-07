"""Run a predeclared evaluation session and commit every attempt.

The protocol is written first (models, prompt hash, lure hash, planned count).
Then each attempt runs the agent, governs its spans through the real route,
writes a recording, and appends to the hash-chained ledger. Every result is
kept — clean, breakout, incomplete, or error — and the final tip is returned to
be published (README + git tag) as the anchor ``verify`` checks against.

The agent call is injected (``run_agent``) so this whole flow is proven with a
fake client; a live session passes a real Anthropic-backed ``run_agent``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from examples.live_agent import ledger
from examples.live_agent.agent import RunResult
from examples.live_agent.demo import govern
from examples.live_agent.manifest import build_manifest, run_outcome

RunAgent = Callable[[str, str], RunResult]  # (model, run_id) -> RunResult

_MAX_ERR_CHARS = 2000  # bound an error message before it enters a committed recording


def _outcome_class(run: RunResult, results: list[dict[str, Any]]) -> str:
    """A failed or unfinished run is never reported as a clean governance result."""
    if run.outcome in ("error", "incomplete"):
        return run.outcome
    return run_outcome(results)


def run_session(
    run_agent: RunAgent,
    *,
    models: list[str],
    attempts_per_model: int,
    out_dir: str | Path,
    prompt_text: str,
    lure_file: str | Path,
    timestamp_fn: Callable[[], float],
) -> dict[str, Any]:
    """Run the full session. Requires ``YUKTI_MODE=breakout`` in the environment."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    # A recording session owns its directory: start from a clean ledger. The
    # evidence store appends (replays existing + adds one), so a stale ledger
    # from a previous run would stack attempts (non-contiguous attempt_n and a
    # tip over the wrong set) and fail verify.py. Clear this session's artifacts.
    for stale in out.glob("attempt-*.json"):
        stale.unlink()
    (out / "attempts-ledger.jsonl").unlink(missing_ok=True)
    lure_sha = ledger.sha256_file(lure_file)
    ledger.write_protocol(
        out / "protocol.json",
        model_ids=models,
        prompt_sha256=ledger.sha256_text(prompt_text),
        lure_sha256=lure_sha,
        planned_attempts=len(models) * attempts_per_model,
        settings={"attempts_per_model": attempts_per_model},
    )
    ledger_path = out / "attempts-ledger.jsonl"
    tip = ledger.GENESIS
    n = 0
    summary: list[dict[str, Any]] = []
    for model in models:
        for i in range(attempts_per_model):
            n += 1
            run_id = f"{model}-{i + 1}"
            # every attempt is preserved: an API / tool / governance failure is
            # recorded as a first-class error attempt, never dropped or aborted.
            try:
                run = run_agent(model, run_id)
                results = govern(run.spans)
                recording: dict[str, Any] = {
                    "requested_model": model,
                    **run.to_dict(),
                    "manifest": build_manifest(run, results, attempt_n=n),
                }
                outcome_class = _outcome_class(run, results)
                model_id = run.model_id
            except Exception as exc:
                recording = {
                    "requested_model": model,
                    "model_id": model,
                    "run_id": run_id,
                    "outcome": "error",
                    "error": str(exc)[:_MAX_ERR_CHARS],
                }
                outcome_class = "error"
                model_id = model
            rec_path = out / f"attempt-{n}.json"
            rec_path.write_text(json.dumps(recording, indent=2, sort_keys=True))
            tip = ledger.append_attempt(
                ledger_path,
                attempt_n=n,
                model_id=model_id,
                outcome_class=outcome_class,
                recording_sha256=ledger.sha256_file(rec_path),
                lure_sha256=lure_sha,
                timestamp=timestamp_fn(),
            )
            summary.append({"attempt_n": n, "model": model, "outcome_class": outcome_class})

    (out / "PUBLISHED_TIP.txt").write_text(tip + "\n")
    return {"published_tip": tip, "attempts": n, "out_dir": str(out), "summary": summary}


def main() -> None:  # pragma: no cover - the live session; needs a key + network
    """Run a real evaluation session. Set ANTHROPIC_API_KEY first.

    Env knobs: YUKTI_LIVE_MODELS (comma-sep, default opus-5-5 + sonnet-5-5),
    YUKTI_LIVE_ATTEMPTS (per model, default 3).
    """
    import os
    import time

    import anthropic

    from examples.live_agent.agent import SYSTEM, TASK, run_live
    from examples.live_agent.tools import Tools

    os.environ["YUKTI_MODE"] = "breakout"
    here = Path(__file__).parent
    sandbox = here / "sandbox"
    lure = sandbox / "auth.md"
    models = os.environ.get("YUKTI_LIVE_MODELS", "claude-opus-5-5,claude-sonnet-5-5").split(",")
    attempts = int(os.environ.get("YUKTI_LIVE_ATTEMPTS", "3"))
    start = str(int(time.time() * 1_000_000_000))

    # Fail fast on a missing or placeholder key: otherwise a bad value (an
    # unsubstituted "…" or "PASTE_YOUR_REAL_KEY_HERE") burns every attempt on a
    # cryptic header-encode or auth error and still prints a published tip.
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key.isascii() or not key.startswith("sk-ant-") or len(key) < 40:
        raise SystemExit(
            "ANTHROPIC_API_KEY is unset or does not look like a real key "
            "(expected an ASCII 'sk-ant-...' value, ~100+ chars). No attempts "
            "were recorded. Set your real key and re-run."
        )
    client = anthropic.Anthropic()

    def run_agent(model: str, run_id: str) -> RunResult:
        return run_live(client, Tools(sandbox), model=model, run_id=run_id, start_unixnano=start)

    out = run_session(
        run_agent,
        models=models,
        attempts_per_model=attempts,
        out_dir=here / "recordings",
        prompt_text=SYSTEM + "\n" + TASK,
        lure_file=lure,
        timestamp_fn=time.time,
    )
    print(f"attempts committed: {out['attempts']}")
    for s in out["summary"]:
        print(f"  attempt {s['attempt_n']:>2}  {s['model']:20}  {s['outcome_class']}")
    print(f"\npublished tip: {out['published_tip']}")
    print("→ put this tip in examples/live_agent/README.md and a git tag, then commit recordings/.")


if __name__ == "__main__":  # pragma: no cover
    main()
