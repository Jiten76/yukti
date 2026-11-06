"""risk-engineering demo — govern a typed KRI catalog with evidence-grade discipline.

Runs the seeded catalog readings through the standard Yukti runtime and prints
each indicator: its value against its lines, the evidence tier carrying it,
which pattern fired, and the decision. The point to watch: the two act-line
crossings that do NOT get contained — one on proxy evidence, one stale — and
the one that does.

Run:  python examples/risk-engineering/demo.py
"""

from __future__ import annotations

import asyncio
from typing import cast

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from yukti.core.evidence.in_memory import InMemoryEvidenceStore
from yukti.scenarios.risk_engineering import build_risk_governance, risk_observations

_console = Console()

_TIER_STYLE = {"decision_grade": "bold green", "proxy": "yellow", "discovery": "dim"}


async def run() -> int:
    runtime = build_risk_governance()

    table = Table(title="the KRI catalog, reading by reading", show_lines=False, expand=True)
    table.add_column("KRI", style="bold")
    table.add_column("flow")
    table.add_column("reading", justify="right")
    table.add_column("evidence tier")
    table.add_column("pattern fired")
    table.add_column("decision", justify="center")

    tiers = {"ALLOW": 0, "MONITOR": 0, "GATE": 0, "DENY": 0}
    for obs in risk_observations():
        result = await runtime.process(obs, flow_type=str(obs.extra.get("flow_type")))
        patterns = [m.pattern_name for m in result.pattern_matches]
        d = result.decision.name
        tiers[d] = tiers.get(d, 0) + 1
        p = obs.payload
        tier = str(p.get("evidence_tier"))
        colour = {"DENY": "red", "GATE": "yellow", "MONITOR": "cyan", "ALLOW": "green"}[d]
        table.add_row(
            f"{p.get('kri_id')} {p.get('kri_name')}",
            str(p.get("flow")),
            f"{p.get('value')} {p.get('unit')}",
            f"[{_TIER_STYLE.get(tier, 'white')}]{tier}[/]",
            ", ".join(patterns) if patterns else "[dim]—[/dim]",
            f"[{colour}]{d}[/{colour}]",
        )

    _console.print(table)
    evidence = cast(InMemoryEvidenceStore, runtime.evidence).count
    _console.print(
        Panel(
            f"decision spread: [green]{tiers['ALLOW']} ALLOW[/green] · "
            f"[cyan]{tiers['MONITOR']} MONITOR[/cyan] · [yellow]{tiers['GATE']} GATE[/yellow] · "
            f"[red]{tiers['DENY']} DENY[/red]\n"
            f"containment requires decision-grade, fresh evidence: an act-line crossing on a "
            f"proxy (RE-03) or a stale reading (RE-06) routes to a human — only RE-01 is "
            f"contained.\nevidence records written: [bold]{evidence}[/bold]; every reading "
            f"carries its \"what we do not claim\" clauses.",
            title="[bold]RISK POSTURE — consequence × credibility[/bold]",
            border_style="cyan",
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
