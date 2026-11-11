"""Predeclared protocol + hash-chained attempt ledger, with a published-tip anchor.

The evaluation's integrity does **not** rest on the chain alone. Yukti's chain is
unkeyed (see ``chain_file`` — it detects corruption and naive edits, but an author
could re-stitch the whole file). Integrity rests on the tip being published
*outside* the mutable file: in the committed README and a git tag. ``verify``
recomputes the chain and fails if the tip does not match the published value —
so pruning a failed attempt changes the tip and the omission is machine-visible.
That is the honest anti-curation mechanism; it claims nothing the chain can't back.

The ledger reuses ``ChainFileEvidenceStore`` — the same evidence backend Yukti
ships. The demo notarizes its own evaluation in the ledger it is selling.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from yukti.core.evidence.base import EvidenceRecord, EvidenceTier
from yukti.core.evidence.chain_file import ChainFileEvidenceStore

GENESIS = "0" * 64


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_protocol(
    path: str | Path,
    *,
    model_ids: list[str],
    prompt_sha256: str,
    lure_sha256: str,
    planned_attempts: int,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Predeclare the evaluation before running it. Written once, committed."""
    doc = {
        "model_ids": list(model_ids),
        "prompt_sha256": prompt_sha256,
        "lure_sha256": lure_sha256,
        "planned_attempts": planned_attempts,
        "settings": settings,
    }
    Path(path).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return doc


def append_attempt(
    ledger_path: str | Path,
    *,
    attempt_n: int,
    model_id: str,
    outcome_class: str,
    recording_sha256: str,
    lure_sha256: str,
    timestamp: float,
) -> str:
    """Append one attempt to the hash-chained ledger. Returns the new tip."""
    store = ChainFileEvidenceStore(ledger_path)  # replays existing, appends one
    asyncio.run(
        store.write(
            EvidenceRecord(
                sha256="",
                trace_id=f"attempt-{attempt_n}",
                tier=EvidenceTier.DECISION_GRADE,
                payload={
                    "attempt_n": attempt_n,
                    "model_id": model_id,
                    "outcome_class": outcome_class,
                    "recording_sha256": recording_sha256,
                    "lure_sha256": lure_sha256,
                },
                timestamp=timestamp,
            )
        )
    )
    return read_tip(ledger_path)


def _lines(ledger_path: str | Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in Path(ledger_path).read_text().splitlines()
        if line.strip()
    ]


def read_tip(ledger_path: str | Path) -> str:
    """The last entry hash — the chain tip that gets published for anchoring."""
    lines = _lines(ledger_path)
    return str(lines[-1]["entry_sha256"]) if lines else GENESIS


def read_attempts(ledger_path: str | Path) -> list[dict[str, Any]]:
    return [dict(line["record"]["payload"]) for line in _lines(ledger_path)]
