"""Cross-artifact verifier — proves the committed evaluation was not curated.

Checks that the recordings, the protocol, and the hash-chained ledger agree, and
— crucially — that the recomputed chain tip equals the tip published outside the
file (README / git tag). A pruned or edited attempt changes the tip, so this is
where curation becomes machine-visible.

    python -m examples.live_agent.verify <recordings_dir> <published_tip> [<lure_file>]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from examples.live_agent import ledger
from examples.live_agent.demo import govern
from yukti.core.evidence.chain_file import verify_chain_file


def verify(
    recordings_dir: str | Path,
    published_tip: str,
    lure_file: str | Path | None = None,
    *,
    replay: bool = True,
) -> tuple[bool, list[str]]:
    """Return ``(ok, problems)``. ``ok`` iff every check passes.

    ``published_tip`` is the tip retained *outside* this directory (README / git
    tag) — the anchor. ``replay=True`` re-governs each recording's spans through
    the real route and checks the verdicts match what was recorded (requires
    ``YUKTI_MODE=breakout`` in the environment); pass ``replay=False`` to check
    only the ledger/recording integrity offline.
    """
    d = Path(recordings_dir)
    problems: list[str] = []
    ledger_path = d / "attempts-ledger.jsonl"
    protocol_path = d / "protocol.json"

    if not ledger_path.exists():
        return False, [f"no attempts-ledger.jsonl in {d}"]

    # 1. chain integrity (per-record + per-line)
    _, chain_problems = verify_chain_file(ledger_path)
    problems.extend(chain_problems)

    # 2. THE ANCHOR: recomputed tip must equal the externally-retained tip, and
    # the convenience PUBLISHED_TIP.txt (inside the dir) must agree with it.
    tip = ledger.read_tip(ledger_path)
    if tip != published_tip:
        problems.append(
            f"ledger tip {tip[:12]}… != published tip {published_tip[:12]}… "
            "— an attempt was added, removed, or edited"
        )
    ptxt = d / "PUBLISHED_TIP.txt"
    if ptxt.exists() and ptxt.read_text().strip() != tip:
        problems.append("PUBLISHED_TIP.txt does not match the recomputed ledger tip")

    attempts = ledger.read_attempts(ledger_path)

    # 3. attempt_n contiguous from 1
    ns = [a["attempt_n"] for a in attempts]
    if ns != list(range(1, len(ns) + 1)):
        problems.append(f"attempt_n not contiguous from 1: {ns}")

    # 4. protocol: lure, planned count, declared models
    protocol = json.loads(protocol_path.read_text()) if protocol_path.exists() else {}
    protocol_lure = protocol.get("lure_sha256")
    protocol_models = set(protocol.get("model_ids") or [])
    planned = protocol.get("planned_attempts")
    if planned is not None and planned != len(attempts):
        problems.append(f"protocol planned {planned} attempts but the ledger has {len(attempts)}")
    if (
        lure_file is not None
        and protocol_lure is not None
        and ledger.sha256_file(lure_file) != protocol_lure
    ):
        problems.append("shipped lure hash != protocol lure_sha256 — lure drifted")

    # 5. per-attempt: recording present + hash + lure + model consistency + replay
    referenced: set[str] = set()
    for a in attempts:
        n = a["attempt_n"]
        rec = d / f"attempt-{n}.json"
        referenced.add(rec.name)
        if not rec.exists():
            problems.append(f"attempt {n}: recording {rec.name} missing")
            continue
        if ledger.sha256_file(rec) != a["recording_sha256"]:
            problems.append(f"attempt {n}: recording hash != ledger record")
        if protocol_lure is not None and a["lure_sha256"] != protocol_lure:
            problems.append(f"attempt {n}: lure_sha256 != protocol")
        doc = json.loads(rec.read_text())
        if doc.get("model_id") != a["model_id"]:
            problems.append(f"attempt {n}: recording model_id != ledger model_id")
        if protocol_models and doc.get("requested_model") not in protocol_models:
            problems.append(
                f"attempt {n}: requested_model {doc.get('requested_model')!r} not in protocol"
            )
        # replay equality: re-govern the recorded spans and compare verdicts to
        # what the recording claims — a doctored decision won't reproduce.
        if replay and doc.get("outcome") != "error" and "manifest" in doc:
            recorded = [
                {"span_id": e["span_id"], "decision": e["decision"]}
                for e in doc["manifest"].get("per_span_decisions", [])
            ]
            spans = doc.get("spans") or []
            results = govern(spans)
            # a span/result count mismatch is itself a problem — never let a
            # short zip silently truncate the comparison into a false match.
            if len(spans) != len(results):
                problems.append(
                    f"attempt {n}: govern returned {len(results)} results for {len(spans)} spans"
                )
                continue
            replayed = [
                {"span_id": str(s["spanId"]), "decision": r["decision"]}
                for s, r in zip(spans, results, strict=True)
            ]
            if replayed != recorded:
                problems.append(f"attempt {n}: replayed verdicts {replayed} != recorded {recorded}")

    # 6. no orphan recording files
    for rec in d.glob("attempt-*.json"):
        if rec.name not in referenced:
            problems.append(f"orphan recording {rec.name} with no ledger attempt")

    return (not problems), problems


def main(argv: list[str]) -> int:  # pragma: no cover - thin CLI wrapper
    if len(argv) < 2:
        print(__doc__)
        return 2
    lure = argv[2] if len(argv) > 2 else None
    ok, problems = verify(argv[0], argv[1], lure)
    if ok:
        print(f"VERIFIED: {argv[0]} matches published tip {argv[1][:12]}…")
        return 0
    print(f"FAILED ({len(problems)} problem(s)):")
    for p in problems:
        print(f"  - {p}")
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
