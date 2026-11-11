"""Tests for the append-only evidence chain file — durability + verifiability."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from yukti.cli.__main__ import app as cli_app
from yukti.core.evidence.base import EvidenceRecord, EvidenceTier
from yukti.core.evidence.chain_file import ChainFileEvidenceStore, verify_chain_file
from yukti.core.evidence.in_memory import InMemoryEvidenceStore


def _record(trace: str, n: int, parents: list[str] | None = None) -> EvidenceRecord:
    return EvidenceRecord(
        sha256="",
        trace_id=trace,
        tier=EvidenceTier.DISCOVERY,
        payload={"n": n, "agent": "payout-agent", "action": "tool_call"},
        timestamp=1_755_700_000.0 + n,
        parent_sha256s=parents or [],
    )


def _write_all(store: ChainFileEvidenceStore | InMemoryEvidenceStore, n: int = 5) -> list[str]:
    async def go() -> list[str]:
        shas = []
        prev: list[str] = []
        for i in range(n):
            sha = await store.write(_record("trace-x", i, parents=prev))
            prev = [sha]
            shas.append(sha)
        return shas

    return asyncio.run(go())


def test_records_survive_restart(tmp_path: Path) -> None:
    path = tmp_path / "evidence.chain"
    shas = _write_all(ChainFileEvidenceStore(path))
    reopened = ChainFileEvidenceStore(path)
    assert reopened.count == 5
    rec = asyncio.run(reopened.read(shas[2]))
    assert rec is not None and rec.payload["n"] == 2
    # lineage still walks after reload
    lineage = asyncio.run(reopened.lineage(shas[4]))
    assert [r.payload["n"] for r in lineage] == [4, 3, 2, 1, 0]


def test_sha_parity_with_in_memory_backend(tmp_path: Path) -> None:
    """Same records → same content addresses on either backend."""
    chain_shas = _write_all(ChainFileEvidenceStore(tmp_path / "e.chain"))
    memory_shas = _write_all(InMemoryEvidenceStore())
    assert chain_shas == memory_shas


def test_duplicate_write_appends_once(tmp_path: Path) -> None:
    path = tmp_path / "evidence.chain"
    store = ChainFileEvidenceStore(path)

    async def go() -> None:
        await store.write(_record("t", 1))
        await store.write(_record("t", 1))  # identical record, same address

    asyncio.run(go())
    assert len(path.read_text().strip().splitlines()) == 1


def test_intact_chain_verifies(tmp_path: Path) -> None:
    path = tmp_path / "evidence.chain"
    _write_all(ChainFileEvidenceStore(path))
    count, problems = verify_chain_file(path)
    assert (count, problems) == (5, [])


def test_edited_record_is_located(tmp_path: Path) -> None:
    path = tmp_path / "evidence.chain"
    _write_all(ChainFileEvidenceStore(path))
    lines = path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["record"]["payload"]["agent"] = "someone-else"  # rewrite history
    lines[2] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    _, problems = verify_chain_file(path)
    assert any("line 3" in p for p in problems)


def test_deleted_line_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "evidence.chain"
    _write_all(ChainFileEvidenceStore(path))
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    _, problems = verify_chain_file(path)
    assert any("chain broken" in p for p in problems)


def test_cli_verify_evidence(tmp_path: Path) -> None:
    path = tmp_path / "evidence.chain"
    _write_all(ChainFileEvidenceStore(path))
    runner = CliRunner()
    ok = runner.invoke(cli_app, ["verify-evidence", str(path)])
    assert ok.exit_code == 0 and "chain intact: 5 record(s)" in ok.output

    lines = path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["record"]["payload"]["n"] = 999
    lines[0] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    bad = runner.invoke(cli_app, ["verify-evidence", str(path)])
    assert bad.exit_code == 1


def test_chain_write_rejects_non_json_payload(tmp_path: Path) -> None:
    """The durable backend rejects non-JSON payloads at write — never
    str-coerces them into repr-dependent addresses on the ledger."""
    store = ChainFileEvidenceStore(tmp_path / "chain.jsonl")
    bad = EvidenceRecord(
        sha256="",
        trace_id="t1",
        tier=EvidenceTier.DISCOVERY,
        payload={"grant": frozenset({"read"})},
        timestamp=1_755_700_000.0,
    )
    with pytest.raises(ValueError, match="JSON-serializable"):
        asyncio.run(store.write(bad))
    # nothing was appended to the ledger — the rejected write left no file
    assert not store.path.exists()
