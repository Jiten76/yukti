"""Append-only evidence chain file — the durable ledger backend.

The storage model follows the audit-log tradition (append-only file, path via
config) rather than a database: an evidence *ledger* wants durability,
integrity, and verifiability — properties of a hash chain, not of SQL.
Queries stay on the in-memory index this class inherits; the file is the
ledger of record.

Scope: the chain is **unkeyed**, so this is an integrity checksum — it detects
corruption and naive in-place edits, and reproduces on restart. It is *not*
tamper-evident against an adversary who can rewrite the whole file (they can
re-stitch the chain end to end), and **tail truncation** — deleting lines from
the end — is invisible to the offline verifier, which has no out-of-band
knowledge of where the chain should stop. Tamper-evidence against both needs
the tip anchored out of band (keyed MAC, co-signed head, or a
periodically-published hash).

Two independent integrity properties, checkable offline:

1. **Content addressing** (per record): each record's ``sha256`` is the hash
   of its full identity — edit a record and its address no longer matches.
2. **Ledger chaining** (per line): each line carries
   ``sha256(record + previous line's entry hash)`` — delete, reorder, or
   rewrite any *interior* line and every subsequent entry hash breaks
   (tail truncation is the exception; see the scope note above).

``yukti verify-evidence <path>`` walks both. Restart-safe: on startup the
chain is replayed into the in-memory index, so the dashboard and aggregators
see the full history.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from yukti.core.evidence.base import EvidenceRecord, EvidenceStore, EvidenceTier
from yukti.core.evidence.in_memory import InMemoryEvidenceStore

_GENESIS = "0" * 64


def _record_to_dict(record: EvidenceRecord) -> dict[str, Any]:
    doc = asdict(record)
    doc["tier"] = record.tier.value
    return doc


def _record_from_dict(doc: dict[str, Any]) -> EvidenceRecord:
    return EvidenceRecord(
        sha256=str(doc.get("sha256", "")),
        trace_id=str(doc.get("trace_id", "")),
        tier=EvidenceTier(doc.get("tier", "discovery")),
        payload=dict(doc.get("payload") or {}),
        timestamp=float(doc.get("timestamp", 0.0)),
        source_query=doc.get("source_query"),
        parent_sha256s=list(doc.get("parent_sha256s") or []),
        do_not_claim=list(doc.get("do_not_claim") or []),
        extra=dict(doc.get("extra") or {}),
    )


def _entry_sha(record_doc: dict[str, Any], prev_entry: str) -> str:
    # No default= coercion: record docs are JSON-validated at write.
    canonical = json.dumps(
        {"record": record_doc, "prev_entry": prev_entry}, sort_keys=True
    ).encode()
    return EvidenceStore.compute_sha256(canonical)


class ChainFileEvidenceStore(InMemoryEvidenceStore):
    """In-memory index over an append-only, hash-chained JSONL ledger.

    Inherits the full query surface (read / list_by_trace / lineage /
    iter_all) from the in-memory store; every *new* record is additionally
    appended to the chain file. Content addresses are computed by the same
    code path as the in-memory store, so the same records produce the same
    SHAs on either backend.
    """

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self.path = Path(path)
        self._tip = _GENESIS
        if self.path.exists():
            self._replay()
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def _replay(self) -> None:
        """Load the existing chain into the in-memory index (no verification —
        use ``verify_chain_file`` for that; a corrupt line here fails loudly)."""
        with self.path.open() as fh:
            for line_no, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    record = _record_from_dict(entry["record"])
                    self._tip = str(entry["entry_sha256"])
                except (KeyError, ValueError) as exc:
                    raise ValueError(
                        f"{self.path}:{line_no}: unreadable chain entry ({exc})"
                    ) from exc
                self._records[record.sha256] = record

    async def write(self, record: EvidenceRecord) -> str:
        # canonicalize payload/extra through a JSON round-trip before
        # addressing: what we hash is exactly what a reload reproduces, so
        # verification is stable across restarts. For plain-JSON payloads
        # (every shipped scenario) this is the identity function and SHAs
        # match the in-memory backend exactly. No ``default=`` coercion:
        # non-JSON payloads are rejected (content_address enforces the same),
        # never silently str-ified into repr-dependent addresses.
        try:
            record.payload = json.loads(json.dumps(record.payload, sort_keys=True))
            record.extra = json.loads(json.dumps(record.extra, sort_keys=True))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "evidence payload/extra must be JSON-serializable "
                f"(trace {record.trace_id!r}): {exc}"
            ) from exc
        if not record.sha256:
            record.sha256 = self.content_address(record)
        is_new = record.sha256 not in self._records
        sha = await super().write(record)
        if is_new:
            doc = _record_to_dict(record)
            entry_sha = _entry_sha(doc, self._tip)
            line = json.dumps(
                {"record": doc, "prev_entry": self._tip, "entry_sha256": entry_sha},
                sort_keys=True,
            )
            with self.path.open("a") as fh:
                fh.write(line + "\n")
            self._tip = entry_sha
        return sha


def verify_chain_file(path: str | Path) -> tuple[int, list[str]]:
    """Walk a chain file and check both integrity properties.

    Returns ``(records_verified, problems)`` — an intact chain returns an
    empty problem list. Each problem names the line and what broke, so a
    corrupt or naively-edited ledger is not just detected but located. (See the
    module docstring for the unkeyed-chain threat-model scope.)
    """
    path = Path(path)
    problems: list[str] = []
    count = 0
    prev = _GENESIS
    with path.open() as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                doc = entry["record"]
                claimed_entry = str(entry["entry_sha256"])
                claimed_prev = str(entry["prev_entry"])
            except (KeyError, ValueError) as exc:
                problems.append(f"line {line_no}: unreadable ({exc})")
                prev = ""
                continue
            if claimed_prev != prev:
                problems.append(
                    f"line {line_no}: chain broken — prev_entry does not match "
                    f"the previous line's entry hash (deleted/reordered line?)"
                )
            expected_entry = _entry_sha(doc, claimed_prev)
            if claimed_entry != expected_entry:
                problems.append(f"line {line_no}: entry hash mismatch (edited line?)")
            record = _record_from_dict(doc)
            expected_address = EvidenceStore.content_address(record)
            if record.sha256 != expected_address:
                problems.append(
                    f"line {line_no}: record content-address mismatch (edited record?)"
                )
            prev = claimed_entry
            count += 1
    return count, problems
