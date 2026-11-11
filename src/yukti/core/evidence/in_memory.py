"""In-memory evidence store — the core default :class:`EvidenceStore`.

Dict-backed, single-process, keyed by SHA-256 content address. The
enterprise ``MultiTenantEvidenceStore`` (with retention policies and
audit-log exports) plugs in through the same :class:`EvidenceStore` ABC.

For durability, :class:`~yukti.core.evidence.chain_file.ChainFileEvidenceStore`
extends this store with an append-only hash-chained ledger file; this
in-memory store is the zero-config default.
"""

from __future__ import annotations

from yukti.core.evidence.base import EvidenceRecord, EvidenceStore


class InMemoryEvidenceStore(EvidenceStore):
    """Store evidence records in a process-local dict keyed by SHA-256."""

    def __init__(self) -> None:
        self._records: dict[str, EvidenceRecord] = {}

    async def write(self, record: EvidenceRecord) -> str:
        """Persist a record. If it has no ``sha256``, a content address is
        computed from the record's full identity — including ``trace_id`` —
        and assigned in place, so two traces never share an evidence record.
        See :meth:`EvidenceStore.content_address`."""
        if not record.sha256:
            record.sha256 = self.content_address(record)
        self._records[record.sha256] = record
        return record.sha256

    async def read(self, sha256: str) -> EvidenceRecord | None:
        return self._records.get(sha256)

    async def list_by_trace(self, trace_id: str) -> list[EvidenceRecord]:
        return sorted(
            (r for r in self._records.values() if r.trace_id == trace_id),
            key=lambda r: r.timestamp,
        )

    async def lineage(self, sha256: str) -> list[EvidenceRecord]:
        """Walk ``parent_sha256s`` transitively, breadth-first, deduplicated.

        Returns the starting record first, then its parents, then their
        parents, and so on. Unknown parent hashes are silently skipped
        (they may live in another store).
        """
        seen: set[str] = set()
        order: list[EvidenceRecord] = []
        queue: list[str] = [sha256]
        while queue:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            record = self._records.get(current)
            if record is None:
                continue
            order.append(record)
            queue.extend(record.parent_sha256s)
        return order

    @property
    def count(self) -> int:
        """Number of stored evidence records."""
        return len(self._records)

    async def iter_all(self) -> list[EvidenceRecord]:
        """Return every record. In-memory convenience for the V1 dashboard
        aggregator — not part of the EvidenceStore ABC because SQL stores
        will query directly instead of iterating."""
        return list(self._records.values())
