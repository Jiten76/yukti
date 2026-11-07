"""agent-breakout demo — watch the governor catch an AI leaving its task.

Replays the seeded AISI-shaped escalation through the standard Yukti runtime and
prints each step: what the agent did, whether it was inside the envelope, which
breakout pattern fired, and the decision. The capability itself lives in
:mod:`yukti.scenarios.breakout`; this is a thin terminal demo of it.

Run:  python examples/agent-breakout/demo.py
"""

from __future__ import annotations

import asyncio
from typing import cast

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.scenarios.breakout import (
    CTF_ENVELOPE,
    build_breakout_governance,
    observations,
)

_console = Console()


async def run() -> int:
    runtime = build_breakout_governance()

    _console.print(
        Panel(
            f"[bold]run {CTF_ENVELOPE.run_id}[/bold] — {CTF_ENVELOPE.task}\n"
            f"sanctioned targets: {', '.join(sorted(CTF_ENVELOPE.target_allowlist))}\n"
            f"sanctioned egress:  {', '.join(sorted(CTF_ENVELOPE.egress_allowlist))}\n"
            f"identity creation:  {'allowed' if CTF_ENVELOPE.identity_creation_allowed else 'FORBIDDEN'}\n"
            f"durable writes:     {', '.join(sorted(CTF_ENVELOPE.durable_write_scope)) or 'NONE'}",
            title="[bold cyan]TASK ENVELOPE — what this run was sanctioned to do[/bold cyan]",
            border_style="cyan",
        )
    )

    table = Table(title="the run, step by step", show_lines=False, expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("action", style="bold")
    table.add_column("target / destination")
    table.add_column("in envelope?", justify="center")
    table.add_column("pattern fired")
    table.add_column("decision", justify="center")

    breakouts = 0
    for i, obs in enumerate(observations(), start=1):
        result = await runtime.process(obs)
        patterns = [m.pattern_name for m in result.pattern_matches]
        in_env = not patterns
        dest = obs.payload.get("destination") or obs.payload.get("target") or "—"
        decision = result.decision.name
        if not in_env:
            breakouts += 1
        table.add_row(
            str(i),
            str(obs.payload.get("action")),
            str(dest),
            "[green]✓[/green]" if in_env else "[red]✗ OUT[/red]",
            ", ".join(patterns) if patterns else "[dim]—[/dim]",
            f"[red]{decision}[/red]" if decision == "DENY" else f"[green]{decision}[/green]",
        )

    _console.print(table)

    evidence_count = cast(InMemoryEvidenceStore, runtime.evidence).count
    _console.print(
        Panel(
            f"steps replayed: [bold]{len(observations())}[/bold]\n"
            f"breakout actions caught: [bold red]{breakouts}[/bold red] "
            f"(first at the egress step — the same signal that tripped AISI's alarm)\n"
            f"decision on every breakout: [bold red]DENY[/bold red] → CRITICAL → human escalation (SLA clock)\n"
            f"evidence records written: [bold]{evidence_count}[/bold] (content-addressed chain)\n"
            f"guardrail-independent: detection derived from the trace, not the model's self-report",
            title="[bold]CONTAINMENT — caught, decided, evidenced[/bold]",
            border_style="red",
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
