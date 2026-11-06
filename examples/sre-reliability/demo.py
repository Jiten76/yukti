"""sre-reliability demo — govern a service fleet's reliability signals.

Runs the seeded service fleet through the standard Yukti runtime and prints each
service's signal, whether it's in tolerance, which reliability pattern fired,
and the decision. Same engine as agent-breakout, a different governance domain.

Run:  python examples/sre-reliability/demo.py
"""

from __future__ import annotations

import asyncio
from typing import cast

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.scenarios.reliability import (
    build_reliability_governance,
    reliability_observations,
)

_console = Console()


async def run() -> int:
    runtime = build_reliability_governance()

    table = Table(title="the service fleet, signal by signal", show_lines=False, expand=True)
    table.add_column("service", style="bold")
    table.add_column("flow")
    table.add_column("signal")
    table.add_column("reading", justify="right")
    table.add_column("pattern fired")
    table.add_column("decision", justify="center")

    tiers = {"ALLOW": 0, "GATE": 0, "DENY": 0}
    for obs in reliability_observations():
        result = await runtime.process(obs, flow_type=str(obs.extra.get("flow_type")))
        patterns = [m.pattern_name for m in result.pattern_matches]
        d = result.decision.name
        tiers[d] = tiers.get(d, 0) + 1
        p = obs.payload
        reading = f"{p.get('value')} / {p.get('threshold')}"
        colour = {"DENY": "red", "GATE": "yellow", "ALLOW": "green"}.get(d, "white")
        table.add_row(
            str(p.get("service")), str(p.get("flow")), str(p.get("signal")), reading,
            ", ".join(patterns) if patterns else "[dim]—[/dim]",
            f"[{colour}]{d}[/{colour}]",
        )

    _console.print(table)
    evidence = cast(InMemoryEvidenceStore, runtime.evidence).count
    _console.print(
        Panel(
            f"decision spread: [green]{tiers.get('ALLOW', 0)} ALLOW[/green] · "
            f"[yellow]{tiers.get('GATE', 0)} GATE[/yellow] · [red]{tiers.get('DENY', 0)} DENY[/red]\n"
            f"active/spreading degradation is contained (DENY → CRITICAL → escalation); a bypassed "
            f"release gate or a short runway is routed to a human (GATE → HIGH); healthy services pass.\n"
            f"evidence records written: [bold]{evidence}[/bold] (content-addressed chain) — "
            f"govern the divergence, not the level.",
            title="[bold]RELIABILITY POSTURE — ranked by consequence[/bold]",
            border_style="cyan",
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
