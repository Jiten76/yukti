"""Agentic data-flow governance: taint-laundering + delegation narrowing.

The claims under test:
  1. Read-taint propagates across a run: an agent that READ a sensitive class and
     later egresses it is caught EVEN WHEN the egress action declares no label of
     its own (the laundering shape a per-process taint model misses).
  2. A sanctioned-destination egress is caught by provenance, not the egress allowlist.
  3. Delegating a grant wider than the parent's envelope is caught.
  4. The data-flow runtime is a strict superset of the breakout rules.
"""

from __future__ import annotations

import asyncio

from yukti.core.patterns.base import Observation
from yukti.core.runtime.runtime import ProcessResult
from yukti.scenarios.agentic_dataflow import (
    DATAFLOW_RULES,
    build_dataflow_governance,
    dataflow_observations,
    propagate_read_taint,
)
from yukti.scenarios.breakout import BREAKOUT_RULES


def _run(obs: list[Observation]) -> list[tuple[Observation, ProcessResult]]:
    runtime = build_dataflow_governance()

    async def go() -> list[tuple[Observation, ProcessResult]]:
        return [
            (o, await runtime.process(o, flow_type=str(o.extra.get("flow_type", "default"))))
            for o in obs
        ]

    return asyncio.run(go())


def _egress(pairs, agent):
    return next(o_r for o_r in pairs
               if o_r[0].payload.get("agent") == agent
               and o_r[0].payload.get("action") == "network_egress")


def test_dataflow_rules_registered() -> None:
    assert {r.name for r in DATAFLOW_RULES} == {"provenance_violation", "delegation_escalation"}


def test_propagate_read_taint_threads_across_spans() -> None:
    # a read of a sensitive class, then a BARE egress by the same agent: the transform
    # must stamp the egress with the class the run read, even though the egress span
    # declared none of its own.
    read = Observation("t1", {"agent": "a", "action": "tool_call",
                              "data_labels": ["pii.customer_records"]}, 0.0, "s")
    egress = Observation("t2", {"agent": "a", "action": "network_egress"}, 1.0, "s")
    out = propagate_read_taint([read, egress])
    assert out[1].extra["carried_data_classes"] == ["pii.customer_records"]
    # a different agent's egress does not inherit another agent's taint
    other = Observation("t3", {"agent": "b", "action": "network_egress"}, 2.0, "s")
    assert propagate_read_taint([read, other])[1].extra["carried_data_classes"] == []


def test_clean_aggregate_report_allowed() -> None:
    pairs = _run(dataflow_observations())
    _, res = _egress(pairs, "report-agent")
    assert res.decision.name == "ALLOW"
    assert not res.pattern_matches


def test_taint_laundering_caught_via_propagation_not_egress_allowlist() -> None:
    pairs = _run(dataflow_observations())
    obs, res = _egress(pairs, "analyst-agent")
    fired = {m.pattern_name for m in res.pattern_matches}
    # the egress span itself declares NO data label — it is caught because the run
    # READ the pii class earlier and taint was propagated onto this egress.
    assert "data_labels" not in obs.payload
    assert obs.extra.get("carried_data_classes") == ["pii.customer_records"]
    # and the destination is permitted, so the egress-allowlist pattern stays silent.
    assert "provenance_violation" in fired
    assert "unsanctioned_egress" not in fired
    assert res.decision.name == "DENY"


def test_delegation_escalation_caught() -> None:
    pairs = _run(dataflow_observations())
    deleg = next(r for o, r in pairs if o.payload.get("action") == "delegate")
    assert "delegation_escalation" in {m.pattern_name for m in deleg.pattern_matches}
    assert deleg.decision.name == "GATE"  # over-broad grant; nothing moved yet


def test_dataflow_runtime_is_a_breakout_superset() -> None:
    rt = build_dataflow_governance()
    assert rt.detector.rule_count == len(BREAKOUT_RULES) + len(DATAFLOW_RULES)


def test_taint_is_scoped_per_run_not_only_per_agent() -> None:
    # The same agent name in two different runs (distinct otel_trace_id) within one
    # batch must not cross-contaminate: run A reads PII then egresses bare (caught);
    # run B only egresses bare (clean). Keying by (run, agent), not agent alone.
    def _o(trace: str, action: str, i: int, labels: list[str] | None = None) -> Observation:
        payload: dict[str, object] = {"agent": "analyst-agent", "action": action,
                                      "otel_trace_id": trace}
        if labels is not None:
            payload["data_labels"] = labels
        if action == "network_egress":
            payload["destination"] = "reports.corp.example"
        return Observation(f"{trace}-{i}", payload, float(i), "s")

    out = {
        o.payload["otel_trace_id"]: o
        for o in propagate_read_taint([
            _o("runA", "tool_call", 1, ["pii.customer_records"]),
            _o("runA", "network_egress", 2),
            _o("runB", "network_egress", 3),
        ])
        if o.payload["action"] == "network_egress"
    }
    assert out["runA"].extra["carried_data_classes"] == ["pii.customer_records"]
    assert out["runB"].extra["carried_data_classes"] == []  # no bleed from run A
