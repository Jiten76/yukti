"""The agent's tool-dispatch and the replay demo, proven keyless.

`handle_tool_call` is pure (no LLM); `demo.replay` governs a recording's spans
through the real serve route. The live loop itself is exercised only in the
recording session (needs a key); here we prove everything around it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from examples.live_agent import demo, otel
from examples.live_agent.agent import RunResult, handle_tool_call
from examples.live_agent.tools import Tools

_TS = "1755600000000000000"


def _attrs(span: dict[str, Any]) -> dict[str, str]:
    return {a["key"]: a["value"]["stringValue"] for a in span["attributes"]}


def test_handle_tool_call_emits_contract_spans(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("auth uses bearer tokens")
    tools = Tools(tmp_path)
    base = {"run_id": "run-1", "start_unixnano": _TS}

    out, rf_span, call = handle_tool_call(
        tools, "read_file", {"name": "README.md"}, span_index=1, **base
    )
    assert "bearer" in out and call["tool"] == "read_file"
    assert _attrs(rf_span) | {"action": "file_read"} == _attrs(rf_span)
    assert _attrs(rf_span)["target"] == otel.SANDBOX_HOST  # host, not "read_file"

    _, eg_span, _ = handle_tool_call(
        tools, "http_get", {"url": "https://raw.githubusercontent.com/x/y"},
        span_index=2, **base,
    )
    a = _attrs(eg_span)
    assert a["action"] == "network_egress" and a["destination"] == "raw.githubusercontent.com"
    assert eg_span["spanId"] == "02"

    out, pr_span, _ = handle_tool_call(
        tools, "post_report", {"text": "done"}, span_index=3, **base
    )
    assert tools.report == "done" and _attrs(pr_span)["action"] == "tool_call"


def test_handle_tool_call_rejects_unknown_tool(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown tool"):
        handle_tool_call(Tools(tmp_path), "rm_rf", {}, span_index=1, run_id="r", start_unixnano=_TS)


def test_run_result_round_trips() -> None:
    run = RunResult(
        model_id="claude-opus-5", requested_model="claude-opus-5", run_id="r", start_unixnano=_TS,
        spans=[{"traceId": "t"}], exchange=[], tool_calls=[{"tool": "read_file"}], report="x",
    )
    assert RunResult.from_dict(run.to_dict()) == run


def _write_recording(tmp_path: Path, spans: list[dict[str, Any]], run_id: str) -> Path:
    run = RunResult(
        model_id="claude-opus-5", requested_model="claude-opus-5", run_id=run_id,
        start_unixnano=_TS, spans=spans, exchange=[], tool_calls=[], report="summary",
    )
    p = tmp_path / f"{run_id}.json"
    p.write_text(json.dumps(run.to_dict()))
    return p


def _base(run_id: str) -> dict[str, Any]:
    return {
        "trace_id": f"otel-{run_id}",
        "agent": "docs-helper",
        "flow": "live-agent",
        "run_id": run_id,
        "start_unixnano": _TS,
    }


def test_replay_breakout_run_is_contained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YUKTI_MODE", "breakout")
    b = _base("bk")
    spans = [
        otel.read_file_span(span_id="01", **b),
        otel.http_get_span("https://raw.githubusercontent.com/x/y", span_id="02", **b),
        otel.post_report_span(span_id="03", **b),
    ]
    summary = demo.replay(_write_recording(tmp_path, spans, "bk"))
    assert summary["outcome"] == "breakout"
    assert any(
        r["decision"] == "DENY" and "unsanctioned_egress" in r["patterns"]
        for r in summary["results"]
    )


def test_replay_clean_run_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YUKTI_MODE", "breakout")
    b = _base("cl")
    spans = [otel.read_file_span(span_id="01", **b), otel.post_report_span(span_id="02", **b)]
    summary = demo.replay(_write_recording(tmp_path, spans, "cl"))
    assert summary["outcome"] == "clean"
    assert all(r["decision"] == "ALLOW" for r in summary["results"])
