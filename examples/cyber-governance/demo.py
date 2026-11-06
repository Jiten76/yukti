"""cyber-governance demo — govern a multi-agent assessment platform.

Runs one engagement (three industry verticals, agents drawn from a 22-expert
catalog) through the standard Yukti runtime and prints each platform action:
which agent, which engagement, what it did, which pattern fired, the decision.

Run:  python examples/cyber-governance/demo.py
"""

from __future__ import annotations

import asyncio
from typing import cast

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.scenarios.cyber_governance import (
    ALL_AGENTS,
    build_cyber_governance,
    cyber_observations,
)

_console = Console()


async def run() -> int:
    runtime = build_cyber_governance()

    table = Table(title="one engagement, action by action", show_lines=False, expand=True)
    table.add_column("agent", style="bold")
    table.add_column("vertical")
    table.add_column("what happened")
    table.add_column("pattern fired")
    table.add_column("decision", justify="center")

    tiers = {"ALLOW": 0, "GATE": 0, "DENY": 0}
    for obs in cyber_observations():
        result = await runtime.process(obs, flow_type=str(obs.extra.get("flow_type")))
        patterns = [m.pattern_name for m in result.pattern_matches]
        d = result.decision.name
        tiers[d] = tiers.get(d, 0) + 1
        p = obs.payload
        colour = {"DENY": "red", "GATE": "yellow", "ALLOW": "green"}.get(d, "white")
        table.add_row(
            str(p.get("agent")), str(p.get("flow")), str(p.get("detail")),
            ", ".join(patterns) if patterns else "[dim]—[/dim]",
            f"[{colour}]{d}[/{colour}]",
        )

    _console.print(table)
    evidence = cast(InMemoryEvidenceStore, runtime.evidence).count
    _console.print(
        Panel(
            f"decision spread: [green]{tiers.get('ALLOW', 0)} ALLOW[/green] · "
            f"[yellow]{tiers.get('GATE', 0)} GATE[/yellow] · [red]{tiers.get('DENY', 0)} DENY[/red]"
            f"  ·  catalog: [bold]{len(ALL_AGENTS)}[/bold] expert agents, 3 verticals\n"
            f"an out-of-scope touch or a bypassed approval gate is contained (DENY → CRITICAL); "
            f"registry drift, delegation runaway, and missing evidence route to a human "
            f"(GATE → HIGH); signed-scope work passes.\n"
            f"evidence records written: [bold]{evidence}[/bold] (content-addressed chain).",
            title="[bold]ENGAGEMENT POSTURE — ranked by consequence[/bold]",
            border_style="cyan",
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
