"""InMemoryEvidenceStore — the core default EvidenceStore."""

from __future__ import annotations

from yukti.core.evidence.base import EvidenceRecord, EvidenceTier
from yukti.core.evidence.in_memory import InMemoryEvidenceStore


def _record(
    sha256: str,
    trace_id: str = "trace-1",
    timestamp: float = 1700000000.0,
    parents: list[str] | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        sha256=sha256,
        trace_id=trace_id,
        tier=EvidenceTier.DECISION_GRADE,
        payload={"k": "v"},
        timestamp=timestamp,
        parent_sha256s=parents or [],
    )


async def test_write_returns_sha256_and_read_round_trips() -> None:
    store = InMemoryEvidenceStore()
    returned = await store.write(_record("hash-1"))
    assert returned == "hash-1"
    fetched = await store.read("hash-1")
    assert fetched is not None
    assert fetched.sha256 == "hash-1"
    assert store.count == 1


async def test_write_computes_sha256_when_missing() -> None:
    store = InMemoryEvidenceStore()
    record = EvidenceRecord(
        sha256="",  # empty — store must compute one
        trace_id="trace-1",
        tier=EvidenceTier.PROXY,
        payload={"some": "payload"},
        timestamp=1700000000.0,
    )
    returned = await store.write(record)
    assert returned != ""
    assert len(returned) == 64  # SHA-256 hex
    assert record.sha256 == returned  # assigned in place


async def test_distinct_traces_never_share_a_record_for_identical_payloads() -> None:
    """Two traces producing structurally identical evidence must NOT collide.

    Content-addressed storage dedups identical content — but an evidence
    record belongs to a trace, and audit integrity requires each trace's
    evidence be independently attributable. The content address therefore
    includes the trace_id.

    Regression test: a payload-only hash would cause cross-trace collisions —
    two traces that matched the same pattern would share one evidence record.
    """
    store = InMemoryEvidenceStore()
    rec_a = EvidenceRecord(
        sha256="",
        trace_id="trace-A",
        tier=EvidenceTier.DECISION_GRADE,
        payload={"identical": "payload"},
        timestamp=1700000000.0,
    )
    rec_b = EvidenceRecord(
        sha256="",
        trace_id="trace-B",
        tier=EvidenceTier.DECISION_GRADE,
        payload={"identical": "payload"},
        timestamp=1700000000.0,
    )
    sha_a = await store.write(rec_a)
    sha_b = await store.write(rec_b)
    assert sha_a != sha_b  # distinct traces -> distinct records
    assert store.count == 2

    # But true content-addressing still holds *within* a trace: an
    # identical record from the same trace yields the same address.
    rec_a_again = EvidenceRecord(
        sha256="",
        trace_id="trace-A",
        tier=EvidenceTier.DECISION_GRADE,
        payload={"identical": "payload"},
        timestamp=1700000000.0,
    )
    assert await store.write(rec_a_again) == sha_a
    assert store.count == 2  # no new record — genuine dedup


async def test_read_unknown_returns_none() -> None:
    store = InMemoryEvidenceStore()
    assert await store.read("nope") is None


async def test_list_by_trace_is_timestamp_sorted() -> None:
    store = InMemoryEvidenceStore()
    await store.write(_record("late", timestamp=3000.0))
    await store.write(_record("early", timestamp=1000.0))
    await store.write(_record("mid", timestamp=2000.0))
    await store.write(_record("other-trace", trace_id="trace-2", timestamp=500.0))

    records = await store.list_by_trace("trace-1")
    assert [r.sha256 for r in records] == ["early", "mid", "late"]


async def test_lineage_walks_parents_transitively() -> None:
    store = InMemoryEvidenceStore()
    # root <- mid <- leaf
    await store.write(_record("root"))
    await store.write(_record("mid", parents=["root"]))
    await store.write(_record("leaf", parents=["mid"]))

    lineage = await store.lineage("leaf")
    assert [r.sha256 for r in lineage] == ["leaf", "mid", "root"]


async def test_lineage_dedupes_diamond_dependencies() -> None:
    store = InMemoryEvidenceStore()
    # leaf depends on a and b; both depend on root (diamond)
    await store.write(_record("root"))
    await store.write(_record("a", parents=["root"]))
    await store.write(_record("b", parents=["root"]))
    await store.write(_record("leaf", parents=["a", "b"]))

    lineage = await store.lineage("leaf")
    # root must appear exactly once despite two paths to it
    assert [r.sha256 for r in lineage].count("root") == 1
    assert {r.sha256 for r in lineage} == {"leaf", "a", "b", "root"}


async def test_lineage_skips_unknown_parents() -> None:
    store = InMemoryEvidenceStore()
    await store.write(_record("leaf", parents=["missing-parent"]))
    lineage = await store.lineage("leaf")
    assert [r.sha256 for r in lineage] == ["leaf"]
