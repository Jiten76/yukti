"""data-leak-prevention demo — govern tiered data access across an agent fleet.

Runs the seeded fleet through the standard Yukti runtime and prints each data
touch: who, what tier, through which channel, which pattern fired, and the
decision. Same engine as agent-breakout and sre-reliability, a third
governance domain.

Run:  python examples/data-leak-prevention/demo.py
"""

from __future__ import annotations

import asyncio
from typing import cast

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.scenarios.data_leak import build_data_leak_governance, data_leak_observations

_console = Console()


async def run() -> int:
    runtime = build_data_leak_governance()

    table = Table(title="the fleet, data touch by data touch", show_lines=False, expand=True)
    table.add_column("agent", style="bold")
    table.add_column("flow")
    table.add_column("tier", justify="center")
    table.add_column("what happened")
    table.add_column("pattern fired")
    table.add_column("decision", justify="center")

    tiers = {"ALLOW": 0, "GATE": 0, "DENY": 0}
    for obs in data_leak_observations():
        result = await runtime.process(obs, flow_type=str(obs.extra.get("flow_type")))
        patterns = [m.pattern_name for m in result.pattern_matches]
        d = result.decision.name
        tiers[d] = tiers.get(d, 0) + 1
        p = obs.payload
        tier_n = int(cast(int, p.get("sensitivity_tier", 0)))
        colour = {"DENY": "red", "GATE": "yellow", "ALLOW": "green"}.get(d, "white")
        table.add_row(
            str(p.get("agent")), str(p.get("flow")), f"N{tier_n}" if tier_n else "—",
            str(p.get("detail")),
            ", ".join(patterns) if patterns else "[dim]—[/dim]",
            f"[{colour}]{d}[/{colour}]",
        )

    _console.print(table)
    evidence = cast(InMemoryEvidenceStore, runtime.evidence).count
    _console.print(
        Panel(
            f"decision spread: [green]{tiers.get('ALLOW', 0)} ALLOW[/green] · "
            f"[yellow]{tiers.get('GATE', 0)} GATE[/yellow] · [red]{tiers.get('DENY', 0)} DENY[/red]\n"
            f"data that MOVED is contained (DENY → CRITICAL); data merely touched or reshaped "
            f"routes to a human (GATE → HIGH); sanctioned access passes untouched.\n"
            f"evidence records written: [bold]{evidence}[/bold] (content-addressed chain) — "
            f"every data touch is a ledger entry.",
            title="[bold]DATA POSTURE — ranked by consequence[/bold]",
            border_style="cyan",
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
