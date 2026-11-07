"""Evidence ledger primitives."""

from __future__ import annotations

import hashlib

import pytest

from yukti.core.evidence.base import EvidenceRecord, EvidenceStore, EvidenceTier


def test_compute_sha256_matches_hashlib() -> None:
    """The convenience static method must match hashlib output exactly."""
    payload = b"hello yukti"
    expected = hashlib.sha256(payload).hexdigest()
    assert EvidenceStore.compute_sha256(payload) == expected


def test_compute_sha256_is_deterministic() -> None:
    """Same input produces same SHA-256 every time."""
    payload = b"identical input"
    h1 = EvidenceStore.compute_sha256(payload)
    h2 = EvidenceStore.compute_sha256(payload)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex digest length


def test_compute_sha256_differs_for_different_inputs() -> None:
    """Different inputs must produce different SHA-256s (cryptographic).

    A trivial collision check; full collision resistance is on hashlib.
    """
    h1 = EvidenceStore.compute_sha256(b"input_a")
    h2 = EvidenceStore.compute_sha256(b"input_b")
    assert h1 != h2


def test_evidence_tier_classification() -> None:
    """The three evidence tiers are well-defined."""
    assert EvidenceTier.DISCOVERY.value == "discovery"
    assert EvidenceTier.PROXY.value == "proxy"
    assert EvidenceTier.DECISION_GRADE.value == "decision_grade"


def test_evidence_record_construction() -> None:
    """EvidenceRecord must accept all documented fields and have sensible defaults."""
    record = EvidenceRecord(
        sha256="abc123",
        trace_id="trace-1",
        tier=EvidenceTier.DECISION_GRADE,
        payload={"key": "value"},
        timestamp=1700000000.0,
    )
    assert record.parent_sha256s == []
    assert record.do_not_claim == []
    assert record.source_query is None
    assert record.extra == {}


def test_evidence_record_with_lineage_and_negative_space() -> None:
    """An EvidenceRecord must capture lineage and 'what we don't claim'."""
    record = EvidenceRecord(
        sha256="derived_hash",
        trace_id="trace-1",
        tier=EvidenceTier.PROXY,
        payload={"derived": True},
        timestamp=1700000001.0,
        source_query="SELECT * FROM signals WHERE ...",
        parent_sha256s=["parent_hash_1", "parent_hash_2"],
        do_not_claim=[
            "This proxy signal does NOT prove root cause",
            "Namespace-level attribution is not supported by this data",
        ],
    )
    assert len(record.parent_sha256s) == 2
    assert len(record.do_not_claim) == 2
    assert record.source_query is not None


def test_content_address_rejects_non_json_payload() -> None:
    """Non-JSON payloads are rejected, not coerced: repr-coercion (e.g. of a
    frozenset, whose iteration order varies across runs) would make the same
    record address differently per process."""

    record = EvidenceRecord(
        sha256="",
        trace_id="t1",
        tier=EvidenceTier.DISCOVERY,
        payload={"grant": frozenset({"read", "write"})},
        timestamp=1_755_700_000.0,
    )
    with pytest.raises(ValueError, match="JSON-serializable"):
        EvidenceStore.content_address(record)
