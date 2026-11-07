"""Evidence ledger — the 5-layer chain-of-custody store.

Every decision Yukti participates in (a policy evaluation, a HITL
intervention, an agent action, a pattern match) produces an evidence
record. Evidence records are:

1. **Integrity-checked** — content-addressed by SHA-256, so an edited record
   no longer matches its address (see ``chain_file`` for the ledger's
   unkeyed-chain scope)
2. **Layered** — raw inputs, normalized canonical forms, derived rollups,
   and source/query maps that link them
3. **Cross-referenceable** — every claim links to the evidence that
   supports it (and the queries that produced that evidence)
4. **Decision-grade-classified** — discovery vs. proxy vs. decision-grade
5. **Credibility-protected** — what we explicitly *do not* claim

This pattern is adapted from the public engineering practice of layered
evidence packages in regulated industries.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class EvidenceTier(StrEnum):
    """Classification of evidence rigor."""

    DISCOVERY = "discovery"
    """Initial signals; should not be cited as conclusions."""

    PROXY = "proxy"
    """Approximate signals; explicitly labeled as proxies for the real thing."""

    DECISION_GRADE = "decision_grade"
    """Triangulated and reproducible; safe to use as basis for action."""


@dataclass
class EvidenceRecord:
    """A single evidence entry."""

    sha256: str
    trace_id: str
    tier: EvidenceTier
    payload: dict[str, Any]
    timestamp: float
    source_query: str | None = None
    """The exact query (Cypher, SQL, PromQL, Humio, etc.) that produced this evidence."""

    parent_sha256s: list[str] = field(default_factory=list)
    """SHA-256 of evidence records this one was derived from (the source/query map)."""

    do_not_claim: list[str] = field(default_factory=list)
    """Explicit statements about what this evidence does NOT support."""

    extra: dict[str, Any] = field(default_factory=dict)


class EvidenceStore(ABC):
    """Persist and retrieve evidence records.

    Shipped implementations:

    - **InMemoryEvidenceStore** — the zero-config default
    - **ChainFileEvidenceStore** — append-only, hash-chained JSONL ledger;
      durable across restarts, offline-verifiable

    SQL / object-store backends are roadmap (see ``docs/ROADMAP.md``).
    """

    @abstractmethod
    async def write(self, record: EvidenceRecord) -> str:
        """Persist the record and return its SHA-256."""

    @abstractmethod
    async def read(self, sha256: str) -> EvidenceRecord | None:
        """Retrieve a record by SHA-256, or None if not found."""

    @abstractmethod
    async def list_by_trace(self, trace_id: str) -> list[EvidenceRecord]:
        """List all evidence for a given trace, ordered by timestamp."""

    @abstractmethod
    async def lineage(self, sha256: str) -> list[EvidenceRecord]:
        """Return the full lineage of the record (all parent records, transitively)."""

    @staticmethod
    def compute_sha256(payload: bytes) -> str:
        """Convenience: compute SHA-256 of a byte payload."""
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def content_address(record: EvidenceRecord) -> str:
        """Compute the canonical content-address (SHA-256) of a record's identity.

        The address covers everything that defines the record **except** the
        ``sha256`` field itself — crucially including ``trace_id``. Two
        different traces that produce structurally identical evidence still
        get distinct, independently-auditable records: evidence belongs to a
        trace, and audit integrity demands per-trace attribution. Within a
        single trace, an identical record yields an identical address (true
        content addressing — genuine duplicates still dedup).

        ``payload`` and ``extra`` must be JSON-serializable — enforced here,
        at the canonical addressing path, so every write rejects rather than
        coerces. Coercing (``default=str``) would hash ``repr`` output, and
        for types with unstable iteration order (e.g. frozensets) the same
        record would address differently across interpreter runs, silently
        breaking address determinism.
        """
        identity = {
            "trace_id": record.trace_id,
            "tier": record.tier.value,
            "timestamp": record.timestamp,
            "payload": record.payload,
            "source_query": record.source_query,
            "parent_sha256s": sorted(record.parent_sha256s),
            "do_not_claim": record.do_not_claim,
            "extra": record.extra,
        }
        try:
            canonical = json.dumps(identity, sort_keys=True).encode()
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "evidence payload/extra must be JSON-serializable "
                f"(trace {record.trace_id!r}): {exc}"
            ) from exc
        return hashlib.sha256(canonical).hexdigest()
