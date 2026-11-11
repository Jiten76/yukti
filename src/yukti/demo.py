"""A runnable demonstration of the Yukti runtime.

Run via ``yukti demo`` or ``python -m yukti.demo``.

This wires the core default implementations into a :class:`Runtime` and
feeds it three synthetic observations from a sensitivity-tier egress
scenario, printing every input and every output.

It is intentionally synthetic — no real LLM, no real cloud — so the
*pipeline* is visible without integration noise. For a real integration
walkthrough, see ``examples/``.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.core.flows.base import FlowState
from yukti.core.flows.in_memory import InMemoryFlowTracker
from yukti.core.hitl.in_memory import InMemoryHITLBackend
from yukti.core.patterns.base import Observation
from yukti.core.patterns.rule_based import Rule, RuleBasedPatternDetector
from yukti.core.policy.base import Decision
from yukti.core.policy.simple import SimplePredicatePolicyEngine
from yukti.core.runtime.runtime import ProcessResult, Runtime

_console = Console()

_DECISION_COLOR: dict[Decision, str] = {
    Decision.ALLOW: "green",
    Decision.MONITOR: "yellow",
    Decision.GATE: "dark_orange",
    Decision.DENY: "red",
}


def build_demo_runtime() -> Runtime:
    """Wire the core default implementations into a Runtime for the demo."""
    detector = RuleBasedPatternDetector(
        [
            Rule(
                name="high_tier_egress_attempt",
                predicate=lambda o: (
                    o.payload.get("action") == "egress"
                    and o.payload.get("sensitivity_tier", 0) >= 3
                ),
                rationale="egress of sensitivity-tier-3+ data",
            ),
        ]
    )

    policy = SimplePredicatePolicyEngine()

    def tier_policy(doc: dict[str, Any]) -> Decision:
        tier = doc.get("sensitivity_tier", 0)
        if not doc.get("pattern_matched"):
            return Decision.ALLOW
        if tier >= 5:
            return Decision.DENY  # tier-5 egress is never allowed
        if tier >= 3:
            return Decision.GATE  # tier-3/4 egress needs human sign-off
        return Decision.ALLOW

    policy.register("data_leak_tier_policy", tier_policy)

    return Runtime(
        detector=detector,
        policy=policy,
        evidence=InMemoryEvidenceStore(),
        hitl=InMemoryHITLBackend(),
        flows=InMemoryFlowTracker(),
    )


def _print_input(obs: Observation) -> None:
    body = "\n".join(f"  {k}: {v}" for k, v in obs.payload.items())
    _console.print(
        Panel(
            f"trace_id: {obs.trace_id}\nsource:   {obs.source}\npayload:\n{body}",
            title="[bold cyan]INPUT — Observation[/bold cyan]",
            border_style="cyan",
        )
    )


def _print_output(result: ProcessResult) -> None:
    color = _DECISION_COLOR[result.decision]
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("decision", f"[bold {color}]{result.decision.value.upper()}[/]")
    table.add_row("policy rationale", result.policy_rationale)
    table.add_row(
        "pattern matches",
        ", ".join(f"{m.pattern_name} ({m.confidence:.2f})" for m in result.pattern_matches)
        or "(none)",
    )
    table.add_row("flow state", result.flow_state.value)
    table.add_row(
        "evidence chain",
        " → ".join(s[:12] for s in result.evidence_chain)
        + f"   ({len(result.evidence_chain)} records)",
    )
    table.add_row(
        "HITL intervention",
        result.intervention_id or "(none — no human review needed)",
    )
    table.add_row(
        "integrations notified",
        ", ".join(result.notified_integrations) or "(none configured)",
    )
    _console.print(
        Panel(
            table,
            title="[bold]OUTPUT — ProcessResult[/bold]",
            border_style=color,
        )
    )


async def run_data_leak_demo() -> None:
    """Run the sensitivity-tier egress demo end to end."""
    _console.print()
    _console.print(
        "[bold]Yukti runtime demo — sensitivity-tier egress[/bold]\n"
        "Three synthetic observations through the Pattern × Flow → Decision "
        "pipeline.\nCore default implementations only — no real LLM, no real "
        "cloud. The point is\nto see the [italic]pipeline[/italic] clearly.\n"
    )

    runtime = build_demo_runtime()
    now = time.time()

    scenarios = [
        Observation(
            trace_id="demo-001-tier3-egress",
            payload={
                "action": "egress",
                "sensitivity_tier": 3,
                "agent": "fraud_decider",
                "dest": "external_api",
            },
            timestamp=now,
            source="agent.fraud_decider",
        ),
        Observation(
            trace_id="demo-002-tier1-read",
            payload={"action": "read", "sensitivity_tier": 1, "agent": "reporting_bot"},
            timestamp=now,
            source="agent.reporting_bot",
        ),
        Observation(
            trace_id="demo-003-tier5-egress",
            payload={
                "action": "egress",
                "sensitivity_tier": 5,
                "agent": "rogue_exporter",
                "dest": "unknown",
            },
            timestamp=now,
            source="agent.rogue_exporter",
        ),
    ]

    for i, obs in enumerate(scenarios, 1):
        _console.rule(f"[dim]Scenario {i}/{len(scenarios)}[/dim]")
        _print_input(obs)
        result = await runtime.process(obs, flow_type="data_leak_prevention")
        _print_output(result)
        _console.print()

    # Summary: real flow states + what accumulated in the ledger + HITL queue.
    pending = await runtime.hitl.list_pending()
    states: list[FlowState] = []
    total_evidence = 0
    for obs in scenarios:
        flow = await runtime.flows.get(obs.trace_id)
        if flow is not None:
            states.append(flow.state)
        total_evidence += len(await runtime.evidence.list_by_trace(obs.trace_id))

    completed = sum(1 for s in states if s == FlowState.COMPLETED)
    awaiting = sum(1 for s in states if s == FlowState.AWAITING_HITL)
    failed = sum(1 for s in states if s == FlowState.FAILED)

    _console.rule("[dim]Summary[/dim]")
    _console.print(
        Panel(
            f"evidence records written: {total_evidence} across {len(scenarios)} flows\n"
            f"flow outcomes: {completed} completed · {awaiting} awaiting-HITL · "
            f"{failed} failed\n"
            f"HITL interventions pending: {len(pending)}  "
            f"({', '.join(i.intervention_type.value for i in pending) or 'none'})",
            title="[bold]Pipeline summary[/bold]",
            border_style="white",
        )
    )
    _console.print()


def main() -> None:
    """Entry point for ``python -m yukti.demo``."""
    asyncio.run(run_data_leak_demo())


if __name__ == "__main__":
    main()
