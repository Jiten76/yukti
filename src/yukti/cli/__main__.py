"""Yukti CLI entry point.

Five commands: ``version`` (build info), ``doctor`` (environment check),
``demo`` (run a governance scenario end to end), ``serve`` (launch the live
dashboard), and ``verify-evidence`` (walk an evidence ledger and report any
broken record or chain link).
"""

from __future__ import annotations

import typer

app = typer.Typer(
    name="yukti",
    help="Yukti — patterns, flows, decisions. Agent fleet governance.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the installed Yukti version."""
    from yukti import __version__

    typer.echo(f"yukti {__version__}")


@app.command()
def doctor() -> None:
    """Sanity-check the local environment.

    Reports Python version, installed integrations, and the location of
    any Yukti runtime data on disk.
    """
    import sys

    typer.echo(f"python: {sys.version.split()[0]}")
    typer.echo("integrations: opentelemetry (trace ingest), slack (escalation), webhook (reference impl)")
    typer.echo("run `yukti demo` for the pipeline or `yukti serve` for the dashboard.")


@app.command()
def demo() -> None:
    """Run the built-in pipeline demo — see Pattern × Flow → Decision in action.

    Wires the core default implementations into a Runtime and feeds it
    three synthetic observations, printing every input and output.
    """
    import asyncio

    from yukti.demo import run_data_leak_demo

    asyncio.run(run_data_leak_demo())


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8000,
    rate: float = 4.0,
    mode: str = typer.Option(
        "default",
        help="Domain to stream: default | breakout | reliability | data-leak | risk | cyber.",
    ),
) -> None:
    """Run the live dashboard — runtime + WebSocket stream + drill-down UI.

    Starts a FastAPI server on the given host/port. Open http://localhost:<port>
    to see the dashboard, updating live over WebSocket. ``--mode breakout``
    streams the agent-breakout fleet; the default streams the synthetic
    generator at ``--rate`` observations/second. Real OTLP traces can be POSTed
    to ``/v1/traces`` in either mode.
    """
    import os

    import uvicorn

    from yukti.core.policy.base import Decision
    from yukti.serve.api import create_app
    from yukti.serve.fleet import FleetConfig

    os.environ["YUKTI_MODE"] = mode
    typer.echo(f"Yukti serve → http://{host}:{port}  (mode={mode})")
    # Safe by default: an ingested trace with no registered envelope is GATEd to
    # a human, not silently ALLOWed.
    application = create_app(
        fleet_config=FleetConfig(rate_per_second=rate),
        unbound_agent_decision=Decision.GATE,
    )
    uvicorn.run(application, host=host, port=port, log_level="info")


@app.command(name="verify-evidence")
def verify_evidence(path: str) -> None:
    """Verify an evidence chain file's integrity, offline.

    Walks the append-only ledger and checks both properties: every record's
    content address (edit a record and its address breaks) and every line's
    entry-hash chain (delete, reorder, or rewrite any line and every
    subsequent hash breaks). Exits non-zero on any problem, naming the line.
    """
    from yukti.core.evidence.chain_file import verify_chain_file

    count, problems = verify_chain_file(path)
    if problems:
        for p in problems:
            typer.echo(f"FAIL  {p}", err=True)
        typer.echo(f"chain BROKEN: {len(problems)} problem(s) across {count} record(s)")
        raise typer.Exit(code=1)
    typer.echo(f"chain intact: {count} record(s) verified (content addresses + ledger chain)")


def main() -> None:
    """Console-script entry point declared in pyproject.toml."""
    app()


if __name__ == "__main__":
    main()
