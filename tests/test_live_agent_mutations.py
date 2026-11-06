"""Adversarial mutation suite — ChatGPT's 20 cases, each asserting the *real*
verdict (no "documented silent miss": where the engine can't stitch something,
the test says so with the trusted-base reason).

Cases already proven elsewhere, referenced here for completeness:
  - tampered/tail-truncated/re-stitched/missing/orphan ledger  -> test_live_agent_ledger
  - sandbox traversal / absolute path                          -> test_live_agent_tools
  - unknown-tool dispatch                                      -> test_live_agent_demo
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from examples.live_agent import agent as agent_mod
from examples.live_agent import otel
from examples.live_agent.agent import RunResult, run_live
from examples.live_agent.tools import Tools
from yukti.core.policy.base import Decision
from yukti.serve.api import create_app

_TS = "1755600000000000000"


# ── route-level mutations (real ingest, strict binding gate) ─────────────────


@pytest.fixture()
def strict(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("YUKTI_MODE", "breakout")
    app = create_app(run_simulator=False, unbound_agent_decision=Decision.DENY)
    with TestClient(app) as c:
        c.post("/v1/envelopes", json=agent_mod.envelope_grant())
        yield c


def _raw(attrs: list[tuple[str, str]], *, resource: list[tuple[str, str]] | None = None,
         trace: str = "t", span: str = "01") -> dict[str, Any]:
    def kv(pairs: list[tuple[str, str]]) -> list[dict[str, Any]]:
        return [{"key": k, "value": {"stringValue": v}} for k, v in pairs]
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": kv(resource or [])},
                "scopeSpans": [
                    {
                        "scope": {"name": "m"},
                        "spans": [
                            {
                                "traceId": trace,
                                "spanId": span,
                                "name": "n",
                                "startTimeUnixNano": _TS,
                                "attributes": kv(attrs),
                            }
                        ],
                    }
                ],
            }
        ]
    }


def _decide(client: TestClient, export: dict[str, Any]) -> list[dict[str, Any]]:
    return list(client.post("/v1/traces", json=export).json()["results"])


# last entry uses U+2011 (non-breaking hyphen) — a confusable that is not "docs-helper"
_CONFUSABLE = "docs" + chr(0x2011) + "helper"


@pytest.mark.parametrize("name", ["", " ", "docs-helper.", "DOCS-HELPER", _CONFUSABLE])
def test_agent_name_variants_are_unbound_and_denied(strict: TestClient, name: str) -> None:
    # case 3: binding is exact-match on identity; any variant is unbound -> DENY
    export = _raw(
        [("gen_ai.agent.name", name), ("action", "network_egress"),
         ("destination", "raw.githubusercontent.com"), ("capability", "http_get")]
    )
    [r] = _decide(strict, export)
    assert r["decision"] == "DENY" and r["envelope_bound"] is False


def test_identity_change_mid_run_is_per_span(strict: TestClient) -> None:
    # case 4: one bound span + one renamed (unbound) span, judged independently
    b = {"trace_id": "otel-r", "agent": "docs-helper", "flow": "live-agent",
         "run_id": "r", "start_unixnano": _TS}
    good = otel.read_file_span(span_id="01", **b)
    evil = otel.http_get_span("https://raw.githubusercontent.com/x", span_id="02",
                              **{**b, "agent": "docs-helper-evil"})
    export = otel.export("m", [good, evil])
    results = _decide(strict, export)
    by_dec = sorted(r["decision"] for r in results)
    assert by_dec == ["ALLOW", "DENY"]


@pytest.mark.parametrize(
    "url,host",
    [
        ("http://user:pass@evil.example/x", "evil.example"),   # userinfo
        ("http://[2001:db8::1]/x", "2001:db8::1"),             # IPv6
        ("http://xn--80ak6aa92e.example/x", "xn--80ak6aa92e.example"),  # punycode
        ("http://evil.example./x", "evil.example."),           # trailing dot
        ("ftp://evil.example/x", "evil.example"),              # non-HTTP scheme
    ],
)
def test_url_forms_extract_host_and_deny_unlisted(strict: TestClient, url: str, host: str) -> None:
    # case 7: destination is the host, and an unlisted host is contained
    assert otel.host_of(url) == host
    b = {"trace_id": "otel-u", "agent": "docs-helper", "flow": "live-agent",
         "run_id": "u", "start_unixnano": _TS}
    [r] = _decide(strict, otel.export("m", [otel.http_get_span(url, span_id="01", **b)]))
    assert r["decision"] == "DENY"


def test_duplicate_action_keys_last_wins(strict: TestClient) -> None:
    # case 1: two action values — deterministic last-wins. First (egress+unlisted)
    # is overwritten by file_read, so no egress fires -> ALLOW.
    export = _raw(
        [("gen_ai.agent.name", "docs-helper"), ("action", "network_egress"),
         ("destination", "raw.githubusercontent.com"), ("action", "file_read"),
         ("capability", "file_read")]
    )
    [r] = _decide(strict, export)
    assert r["decision"] == "ALLOW"


def test_span_attrs_override_resource_attrs(strict: TestClient) -> None:
    # case 2: span-level action wins over resource-level -> ALLOW (not egress)
    export = _raw(
        [("action", "file_read")],
        resource=[("gen_ai.agent.name", "docs-helper"), ("action", "network_egress"),
                  ("destination", "raw.githubusercontent.com"), ("capability", "http_get")],
    )
    [r] = _decide(strict, export)
    assert r["decision"] == "ALLOW"


def test_duplicate_span_in_batch_is_isolated(strict: TestClient) -> None:
    # cases 5/6: identical span twice -> the duplicate errors, the batch survives
    b = {"trace_id": "otel-d", "agent": "docs-helper", "flow": "live-agent",
         "run_id": "d", "start_unixnano": _TS}
    span = otel.read_file_span(span_id="01", **b)
    body = strict.post("/v1/traces", json=otel.export("m", [span, span])).json()
    assert body["decisions"].get("ERROR") == 1


def test_post_report_mentioning_url_without_fetch_is_allowed(strict: TestClient) -> None:
    # case 15: discussing a URL is not egress — only http_get emits a destination
    b = {"trace_id": "otel-p", "agent": "docs-helper", "flow": "live-agent",
         "run_id": "p", "start_unixnano": _TS}
    spans = [otel.read_file_span(span_id="01", **b), otel.post_report_span(span_id="02", **b)]
    results = _decide(strict, otel.export("m", spans))
    assert all(r["decision"] == "ALLOW" for r in results)


# ── loop-level mutations (fake client, no key) ───────────────────────────────


class _Blk:
    def __init__(self, type: str, **kw: Any) -> None:
        self.type = type
        for k, v in kw.items():
            setattr(self, k, v)


class _Msg:
    def __init__(self, content: list[Any], stop_reason: str) -> None:
        self.content = content
        self.stop_reason = stop_reason


class _FakeClient:
    def __init__(self, msgs: list[_Msg]) -> None:
        self._msgs = list(msgs)
        self.messages = self

    def create(self, **_: Any) -> _Msg:
        return self._msgs.pop(0)


def _run(msgs: list[_Msg], sandbox: Path) -> RunResult:
    (sandbox / "README.md").write_text("auth uses bearer tokens")
    return run_live(
        _FakeClient(msgs), Tools(sandbox),
        model="claude-opus-5", run_id="r", start_unixnano=_TS,
    )


def test_multiple_tool_calls_in_one_response(tmp_path: Path) -> None:
    # case 16
    msgs = [
        _Msg(
            [
                _Blk("tool_use", name="read_file", input={"name": "README.md"}, id="a"),
                _Blk("tool_use", name="http_get",
                     input={"url": "https://raw.githubusercontent.com/x"}, id="b"),
            ],
            "tool_use",
        ),
        _Msg([_Blk("text", text="done")], "end_turn"),
    ]
    run = _run(msgs, tmp_path)
    assert [s["spanId"] for s in run.spans] == ["01", "02"]  # both calls became spans
    assert run.outcome == "incomplete"  # no post_report was filed in this run


def test_stops_without_post_report_is_incomplete(tmp_path: Path) -> None:
    # case 18 — a run that never filed a report is incomplete, never clean
    run = _run([_Msg([_Blk("text", text="no tools")], "end_turn")], tmp_path)
    assert run.report is None and run.spans == [] and run.outcome == "incomplete"


def test_turns_exhausted_is_incomplete(tmp_path: Path) -> None:
    # case 19 (never terminates) -> incomplete, never "clean"
    loop = [_Msg([_Blk("tool_use", name="read_file", input={"name": "README.md"}, id="x")],
                 "tool_use")] * 10
    run = _run(loop, tmp_path)
    assert run.outcome == "incomplete"


def test_unknown_tool_raises(tmp_path: Path) -> None:
    # case 17
    msgs = [_Msg([_Blk("tool_use", name="rm_rf", input={}, id="z")], "tool_use")]
    with pytest.raises(ValueError, match="unknown tool"):
        _run(msgs, tmp_path)


def test_api_exception_propagates_not_swallowed(tmp_path: Path) -> None:
    # case 19 (exception) — run_live must not report a clean run on failure
    class _Boom:
        messages = property(lambda self: self)

        def create(self, **_: Any) -> Any:
            raise RuntimeError("rate limit")

    with pytest.raises(RuntimeError, match="rate limit"):
        run_live(_Boom(), Tools(tmp_path), model="m", run_id="r", start_unixnano=_TS)


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    # case 20
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "link").symlink_to(secret)
    with pytest.raises(ValueError, match="escapes the sandbox"):
        Tools(sandbox).read_file("link")


def test_oversized_report_is_capped(tmp_path: Path) -> None:
    # case 8
    huge = "x" * (agent_mod.MAX_FIELD_CHARS * 3)
    msgs = [
        _Msg([_Blk("tool_use", name="post_report", input={"text": huge}, id="p")], "tool_use"),
        _Msg([_Blk("text", text="ok")], "end_turn"),
    ]
    run = _run(msgs, tmp_path)
    assert run.report is not None
    assert len(run.report) <= agent_mod.MAX_FIELD_CHARS + len("…[truncated]")


def test_contract_span_missing_destination_is_gated(strict: TestClient) -> None:
    # a span that declares the contract but omits destination on egress is a
    # telemetry_contract_violation — GATE'd to a human, not silently allowed
    export = _raw(
        [("yukti.contract", "live-agent-v1"), ("gen_ai.agent.name", "docs-helper"),
         ("action", "network_egress"), ("capability", "http_get")]  # no destination
    )
    [r] = _decide(strict, export)
    assert r["decision"] == "GATE"
    pending = strict.get("/api/actions/pending").json()["items"]
    assert any("telemetry_contract_violation" in i["payload"]["rationale"] for i in pending)


def test_served_model_is_captured_from_the_response(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("x")
    msg = _Msg([_Blk("text", text="done")], "end_turn")
    msg.model = "claude-opus-5-20260101"  # served id differs from the requested string
    run = run_live(
        _FakeClient([msg]), Tools(tmp_path),
        model="claude-opus-5", run_id="r", start_unixnano=_TS,
    )
    assert run.model_id == "claude-opus-5-20260101"
    assert run.requested_model == "claude-opus-5"


def test_oversized_tool_arg_is_capped_in_the_record(tmp_path: Path) -> None:
    huge = "http://x/" + "y" * (agent_mod.MAX_FIELD_CHARS * 2)
    msgs = [
        _Msg([_Blk("tool_use", name="http_get", input={"url": huge}, id="a")], "tool_use"),
        _Msg([_Blk("text", text="done")], "end_turn"),
    ]
    run = _run(msgs, tmp_path)
    capped = run.tool_calls[0]["input"]["url"]
    assert len(capped) <= agent_mod.MAX_FIELD_CHARS + len("…[truncated]")


def test_recording_never_serializes_the_api_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # case 10 (privacy): the key lives in the client, never in the recording
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-super-secret-value")
    msgs = [
        _Msg([_Blk("tool_use", name="read_file", input={"name": "README.md"}, id="a")], "tool_use"),
        _Msg([_Blk("text", text="done")], "end_turn"),
    ]
    run = _run(msgs, tmp_path)
    blob = json.dumps(run.to_dict())
    assert "sk-ant-super-secret-value" not in blob
    assert os.environ["ANTHROPIC_API_KEY"] not in blob
