"""FastAPI app + WebSocket — the Yukti serve layer.

Exposes the Runtime as a scale-shaped query API plus a live WebSocket
stream of every :class:`ProcessResult`. Serves the single-file dashboard
at ``/``.

Threat model, stated plainly: this layer is **demo-grade and
unauthenticated** — there is no authn/authz or rate limiting on any
endpoint, including the OTLP ingest, so anyone who can reach the port can
inject observations into the evidence ledger. Run it bound to localhost
(the README's default). A network-exposed deployment needs an
authenticating reverse proxy in front; auth on the serve layer itself is
roadmap.

Architecture:

- A single Runtime is built at startup with the default governance bundle
  (see :mod:`yukti.serve.patterns`).
- A :class:`FleetSimulator` runs in a background task, generating
  synthetic observations and feeding them through ``runtime.process()``.
  Each :class:`ProcessResult` is broadcast to all connected WebSocket
  clients via a :class:`WebSocketHub`.
- REST endpoints query the Runtime's components through
  :mod:`yukti.serve.aggregator` — aggregates at the fleet level,
  paginated lists below. Never "return everything."
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, cast

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import HttpUrl
from starlette.responses import Response
from starlette.types import Scope

from yukti.core.evidence.base import EvidenceRecord, EvidenceTier
from yukti.core.evidence.chain_file import ChainFileEvidenceStore
from yukti.core.hitl.base import SLA_SECONDS, Intervention, InterventionType, Priority
from yukti.core.policy.base import Decision
from yukti.core.runtime.runtime import ProcessResult, Runtime
from yukti.integrations.opentelemetry import (
    CONTRACT_ATTR,
    observations_from_otlp,
    validate_contract_span,
)
from yukti.integrations.slack import SlackConfig, SlackIntegration
from yukti.scenarios.agent_fleet import build_fleet_governance
from yukti.scenarios.agentic_dataflow import (
    DATAFLOW_FAMILIES,
    build_dataflow_governance,
    dataflow_observations,
    propagate_read_taint,
)
from yukti.scenarios.breakout import TaskEnvelope, envelope_from_dict, envelope_to_dict
from yukti.scenarios.cyber_governance import (
    CYBER_FAMILIES,
    build_cyber_governance,
    cyber_observations,
)
from yukti.scenarios.data_leak import (
    DATA_LEAK_FAMILIES,
    build_data_leak_governance,
    data_leak_observations,
)
from yukti.scenarios.reliability import (
    RELIABILITY_FAMILIES,
    build_reliability_governance,
    reliability_observations,
)
from yukti.scenarios.risk_engineering import (
    RISK_FAMILIES,
    build_risk_governance,
    risk_observations,
)
from yukti.serve.aggregator import (
    build_action_detail,
    build_fleet_summary,
    build_flow_detail,
    build_flow_type_aggregates,
    page_flows,
    page_pending_actions,
)
from yukti.serve.breakout import BREAKOUT_PATTERN_FAMILIES, BreakoutSimulator
from yukti.serve.fleet import FleetConfig, FleetSimulator
from yukti.serve.patterns import build_runtime_with_default_governance
from yukti.serve.scenario_stream import ScenarioSimulator

# Rich {id, label, accent} families the dashboard tiles render. Default mode
# mirrors the five fleet-governance families; breakout mode swaps in the five
# breakout patterns. Served via /api/meta so the frontend is data-driven.
DEFAULT_PATTERN_FAMILIES: list[dict[str, str]] = [
    {"id": "egress_data_leak", "label": "Egress", "accent": "egress"},
    {"id": "change_velocity", "label": "Change", "accent": "change"},
    {"id": "retry_amplification", "label": "Retry", "accent": "retry"},
    {"id": "auth_access_anomaly", "label": "Auth", "accent": "auth"},
    {"id": "evidence_shape_drift", "label": "Drift", "accent": "drift"},
]


_ACCENTS = ("egress", "change", "retry", "auth", "drift")


def _rich_families(pairs: list[tuple[str, str]]) -> list[dict[str, str]]:
    """(id, label) pairs -> the {id, label, accent} dicts the tiles render."""
    return [
        {"id": pid, "label": label, "accent": _ACCENTS[i % len(_ACCENTS)]}
        for i, (pid, label) in enumerate(pairs)
    ]


# One entry per servable governance domain: runtime builder, observation
# stream, tile families, and the headline vocabulary the dashboard speaks.
_SCENARIO_MODES: dict[str, dict[str, Any]] = {
    "reliability": {
        "build": build_reliability_governance,
        "observations": reliability_observations,
        "families": _rich_families(RELIABILITY_FAMILIES),
        "headline": {"unit": "services", "breach": "are out of tolerance",
                     "clean": "the fleet is within tolerance"},
    },
    "data-leak": {
        "build": build_data_leak_governance,
        "observations": data_leak_observations,
        "families": _rich_families(DATA_LEAK_FAMILIES),
        "headline": {"unit": "agents", "breach": "mishandled tiered data",
                     "clean": "every data touch stayed sanctioned"},
    },
    "risk": {
        "build": build_risk_governance,
        "observations": risk_observations,
        "families": _rich_families(RISK_FAMILIES),
        "headline": {"unit": "indicators", "breach": "need attention",
                     "clean": "all indicators are inside their lines"},
    },
    "cyber": {
        "build": build_cyber_governance,
        "observations": cyber_observations,
        "families": _rich_families(CYBER_FAMILIES),
        "headline": {"unit": "platform actions", "breach": "left sanction",
                     "clean": "the engagement is inside its signed scope"},
    },
    "dataflow": {
        "build": build_dataflow_governance,
        "observations": dataflow_observations,
        "families": _rich_families(DATAFLOW_FAMILIES),
        "headline": {"unit": "agent runs", "breach": "leaked data or over-delegated",
                     "clean": "every run stayed inside its data and delegation grants"},
    },
}

MODES = ("breakout", "reliability", "data-leak", "risk", "cyber", "dataflow", "default")

#: Human labels for the mode switcher, in dropdown order.
MODE_LABELS: dict[str, str] = {
    "breakout": "Agent breakout",
    "reliability": "SRE reliability",
    "data-leak": "Data-leak prevention",
    "risk": "Risk engineering",
    "cyber": "Cyber governance",
    "dataflow": "Agentic data-flow",
    "default": "Default fleet",
}

_BREAKOUT_HEADLINE = {"unit": "agent runs", "breach": "broke containment",
                      "clean": "the fleet is inside its envelopes"}
_DEFAULT_HEADLINE = {"unit": "agents", "breach": "need attention",
                     "clean": "the fleet is inside policy"}


def _resolve_mode() -> str:
    mode = os.environ.get("YUKTI_MODE", "default")
    return mode if mode in MODES else "default"

_STATIC_DIR = Path(__file__).parent / "static"
_logger = logging.getLogger("yukti.serve")


class NoCacheStaticFiles(StaticFiles):
    """StaticFiles that asks browsers not to cache.

    Without this, edits to platinum.css / dashboard.js / etc. don't take
    effect until the user hard-refreshes — symptom: new HTML loads but
    the cached old JS crashes (e.g. ``cytoscape is not defined`` after we
    removed Cytoscape), which can leave the dashboard stuck on
    "connecting…". ``no-cache`` + a ``?v=`` query string in the HTML are
    belt-and-suspenders.
    """

    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response


class WebSocketHub:
    """Track connected WebSocket clients and broadcast JSON messages."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def register(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def unregister(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Send to every connected client; drop ones that have gone away."""
        async with self._lock:
            clients = list(self._clients)
        stale: list[WebSocket] = []
        for ws in clients:
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)
        if stale:
            async with self._lock:
                for ws in stale:
                    self._clients.discard(ws)

    @property
    def client_count(self) -> int:
        return len(self._clients)


def _json_safe(value: Any) -> Any:
    """Recursively coerce a value into something ``json.dumps`` accepts.

    ``asdict`` recurses nested dataclasses but leaves ``set``/``frozenset`` as-is
    — and an observation's ``extra`` can carry a governance object with frozenset
    fields (e.g. a breakout run's TaskEnvelope allowlists). Without this, every
    WebSocket broadcast would raise on ``json.dumps(frozenset)`` and the client
    would be silently dropped — the timeline would stay empty while tiles (fed by
    a REST snapshot) still moved. Sets become sorted lists; everything else is
    passed through.
    """
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_json_safe(v) for v in value)
    return value


def _result_to_dict(result: ProcessResult) -> dict[str, Any]:
    """Serialize a ProcessResult for WebSocket / JSON transport.

    ``dataclasses.asdict`` returns ``dict[str, Any]`` and recursively converts
    nested dataclasses; :func:`_json_safe` then makes the whole thing
    JSON-encodable (sets/frozensets → lists).
    """
    return cast("dict[str, Any]", _json_safe(asdict(result)))


async def _run_pipeline(
    runtime: Runtime,
    simulator: FleetSimulator | BreakoutSimulator | ScenarioSimulator,
    hub: WebSocketHub,
) -> None:
    """Background task: feed simulator observations through the runtime, broadcast."""
    try:
        async for obs in simulator.run():
            flow_type = obs.extra.get("flow_type", "default")
            if not isinstance(flow_type, str):
                flow_type = "default"
            try:
                result = await runtime.process(obs, flow_type=flow_type)
                await hub.broadcast({"event": "process_result", "data": _result_to_dict(result)})
            except Exception:
                _logger.exception("pipeline: failed to process observation %s", obs.trace_id)
    except asyncio.CancelledError:
        _logger.info("pipeline: cancelled on shutdown")
        raise


_SimAny = FleetSimulator | BreakoutSimulator | ScenarioSimulator


def _build_for_mode(
    mode: str, fleet_config: FleetConfig | None
) -> tuple[Runtime, _SimAny, list[dict[str, str]], dict[str, str]]:
    """Build the (runtime, simulator, tile families, headline vocab) for a mode.

    Shared by startup and the live mode switch, so the two never drift — and so
    the opt-in ledger/Slack arming applies whichever way a mode is entered.
    """
    runtime: Runtime
    simulator: _SimAny
    if mode == "breakout":
        runtime = build_fleet_governance()
        simulator = BreakoutSimulator()
        families = BREAKOUT_PATTERN_FAMILIES
        headline = _BREAKOUT_HEADLINE
    elif mode in _SCENARIO_MODES:
        spec = _SCENARIO_MODES[mode]
        runtime = spec["build"]()
        simulator = ScenarioSimulator(spec["observations"])
        families = spec["families"]
        headline = spec["headline"]
    else:
        runtime = build_runtime_with_default_governance()
        simulator = FleetSimulator(fleet_config)
        families = DEFAULT_PATTERN_FAMILIES
        headline = _DEFAULT_HEADLINE
    if evidence_path := os.environ.get("YUKTI_EVIDENCE_PATH"):
        runtime.evidence = ChainFileEvidenceStore(evidence_path)
    if slack_url := os.environ.get("YUKTI_SLACK_WEBHOOK"):
        runtime.integrations.append(SlackIntegration(SlackConfig(webhook_url=HttpUrl(slack_url))))
    return runtime, simulator, families, headline


def _get_runtime(request: Request) -> Runtime:
    return cast(Runtime, request.app.state.runtime)


def _get_hub(ws: WebSocket) -> WebSocketHub:
    return cast(WebSocketHub, ws.app.state.hub)


def create_app(
    *,
    fleet_config: FleetConfig | None = None,
    run_simulator: bool = True,
    unbound_agent_decision: Decision | None = None,
) -> FastAPI:
    """Build the FastAPI app.

    ``run_simulator=False`` is for tests — disables the background fleet
    so the test owns the Runtime and feeds observations explicitly.

    ``unbound_agent_decision`` closes the binding gate: when set, an ingested
    trace whose agent has no registered envelope is given this decision as a
    first-class, evidenced verdict instead of being silently ALLOWed (the
    default, ``None``, preserves that pass-through). Set it to ``Decision.DENY``
    for a strict deployment that governs only traffic it can bind.
    """

    async def activate_mode(app: FastAPI, mode: str) -> None:
        """Swap the live governance domain: tear down the current pipeline, build
        the new one, reset state, and tell connected dashboards to re-render.

        The WebSocket hub survives the swap (clients stay connected); everything
        domain-specific — runtime, simulator, evidence, families, headline,
        envelopes — is replaced. This is the engine behind both startup and the
        UI mode switcher.
        """
        old_sim = getattr(app.state, "simulator", None)
        old_task = getattr(app.state, "task", None)
        if old_sim is not None:
            old_sim.stop()
        if old_task is not None:
            old_task.cancel()
            with suppress(asyncio.CancelledError):
                await old_task
        runtime, simulator, families, headline = _build_for_mode(mode, fleet_config)
        app.state.runtime = runtime
        app.state.simulator = simulator
        app.state.mode = mode
        app.state.pattern_families = families
        app.state.headline_vocab = headline
        app.state.envelopes = {}
        app.state.task = (
            asyncio.create_task(_run_pipeline(runtime, simulator, app.state.hub))
            if run_simulator
            else None
        )
        await app.state.hub.broadcast({"event": "mode_changed", "data": {"mode": mode}})

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.hub = WebSocketHub()
        app.state.task = None
        await activate_mode(app, _resolve_mode())
        try:
            yield
        finally:
            sim = getattr(app.state, "simulator", None)
            task = getattr(app.state, "task", None)
            if sim is not None:
                sim.stop()
            if task is not None:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(
        title="Yukti",
        description="Patterns × flows × decisions. Agent fleet governance.",
        version="0.2.1",
        lifespan=lifespan,
    )
    # App-level config, persistent across mode switches (activate_mode resets
    # only the domain-specific state — runtime, envelopes, simulator).
    app.state.unbound_agent_decision = unbound_agent_decision

    @app.get("/api/meta")
    async def meta(request: Request) -> dict[str, Any]:
        return {
            "version": "0.2.1",
            "mode": getattr(request.app.state, "mode", "default"),
            "headline": getattr(request.app.state, "headline_vocab", _DEFAULT_HEADLINE),
            "modes": [{"id": m, "label": MODE_LABELS[m]} for m in MODES],
            "pattern_families": getattr(
                request.app.state, "pattern_families", DEFAULT_PATTERN_FAMILIES
            ),
        }

    @app.get("/api/fleet/summary")
    async def fleet_summary(request: Request) -> dict[str, Any]:
        return await build_fleet_summary(_get_runtime(request))

    @app.get("/api/flow-types")
    async def flow_types(request: Request) -> list[dict[str, Any]]:
        return await build_flow_type_aggregates(_get_runtime(request))

    @app.get("/api/flows")
    async def flows(
        request: Request,
        flow_type: str | None = None,
        state: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        return await page_flows(
            _get_runtime(request),
            flow_type=flow_type,
            state=state,
            limit=limit,
            offset=offset,
        )

    @app.get("/api/flows/{flow_id}")
    async def flow_detail(request: Request, flow_id: str) -> dict[str, Any]:
        detail = await build_flow_detail(_get_runtime(request), flow_id)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"unknown flow {flow_id!r}")
        return detail

    @app.get("/api/actions/pending")
    async def pending_actions(request: Request, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        return await page_pending_actions(_get_runtime(request), limit=limit, offset=offset)

    @app.get("/api/actions/{intervention_id}")
    async def action_detail(request: Request, intervention_id: str) -> dict[str, Any]:
        detail = await build_action_detail(_get_runtime(request), intervention_id)
        if detail is None:
            raise HTTPException(
                status_code=404,
                detail=f"unknown intervention {intervention_id!r}",
            )
        return detail

    @app.post("/api/mode")
    async def switch_mode(request: Request) -> dict[str, Any]:
        """Switch the live governance domain without restarting the server.

        The dashboard's mode dropdown POSTs here; the runtime + simulator are
        swapped in place and all connected clients receive a ``mode_changed``
        event that resets their view.
        """
        body = await request.json()
        mode = str(body.get("mode", "")).strip()
        if mode not in MODES:
            raise HTTPException(
                status_code=422,
                detail=f"unknown mode {mode!r}; valid: {', '.join(MODES)}",
            )
        await activate_mode(request.app, mode)
        return {
            "mode": mode,
            "pattern_families": request.app.state.pattern_families,
            "headline": request.app.state.headline_vocab,
        }

    @app.post("/v1/traces")
    async def ingest_traces(request: Request) -> dict[str, Any]:
        """OTLP/HTTP JSON trace ingest — point an OTel exporter here.

        Every span in the export is converted to an Observation (GenAI
        semantic conventions surfaced) and run through the live pipeline, so
        real agent traces appear on the dashboard exactly like simulator
        traffic. Returns per-decision counts as receipt.
        """
        export = await request.json()
        observations = observations_from_otlp(export)
        if getattr(request.app.state, "mode", "") == "dataflow":
            # Run-scoped read-taint propagation, so a bare egress of a data class
            # the run read earlier is caught over the wire exactly as in the
            # direct governance path — the laundering shape per-span labels miss.
            observations = propagate_read_taint(observations)
        runtime = _get_runtime(request)
        hub: WebSocketHub = request.app.state.hub
        envelopes: dict[str, TaskEnvelope] = request.app.state.envelopes
        counts: dict[str, int] = {}
        results: list[dict[str, Any]] = []
        for obs in observations:
            # bind the agent's registered envelope, if the operator declared
            # one — this is what lets breakout patterns judge real traffic.
            env = envelopes.get(str(obs.payload.get("agent", "")))
            forced: Decision | None = None
            forced_rationale: str | None = None
            # a span that declares the governance contract but is missing the
            # fields the engine judges cannot be trusted — route it to a human
            # instead of silently allowing it.
            if obs.payload.get(CONTRACT_ATTR):
                violation = validate_contract_span(obs.payload)
                if violation is not None:
                    forced = Decision.GATE
                    forced_rationale = f"telemetry_contract_violation: {violation}"
            if forced is not None:
                pass
            elif env is not None:
                obs = replace(obs, extra={**obs.extra, "task_envelope": env})
            elif request.app.state.unbound_agent_decision is not None:
                # binding gate: a trace we cannot bind to a registered envelope
                # gets a first-class decision, not a silent ALLOW.
                forced = request.app.state.unbound_agent_decision
                agent_name = str(obs.payload.get("agent", "")) or "(unnamed)"
                forced_rationale = (
                    f"no registered envelope for agent {agent_name!r} — unbound identity"
                )
            flow_type = obs.extra.get("flow_type", "otel-traces")
            if not isinstance(flow_type, str):
                flow_type = "otel-traces"
            # per-span isolation: real exporters retry whole batches, so one
            # duplicate or malformed span must not poison the rest.
            try:
                result = await runtime.process(
                    obs,
                    flow_type=flow_type,
                    forced_decision=forced,
                    forced_rationale=forced_rationale,
                )
            except Exception as exc:
                # Never silently drop a span: a pipeline error is recorded as
                # first-class evidence and routed to a human at CRITICAL, so an
                # ingest/governance failure is governed, not just counted. The
                # recording is itself guarded — a failure to record must not
                # poison the rest of the batch.
                err_detail: dict[str, Any] = {
                    "trace_id": obs.trace_id,
                    "decision": "ERROR",
                    "error": str(exc),
                }
                try:
                    err_sha = await runtime.evidence.write(
                        EvidenceRecord(
                            sha256="",
                            trace_id=obs.trace_id,
                            tier=EvidenceTier.DECISION_GRADE,
                            payload={
                                "ingest_error": str(exc),
                                "agent": obs.payload.get("agent"),
                            },
                            timestamp=obs.timestamp,
                        )
                    )
                    err_count = counts.get("ERROR", 0) + 1
                    await runtime.hitl.enqueue(
                        Intervention(
                            intervention_id=f"{obs.trace_id}-ingest-error-{err_count}",
                            flow_id=obs.trace_id,
                            intervention_type=InterventionType.ESCALATION,
                            priority=Priority.CRITICAL,
                            payload={
                                "decision": "ERROR",
                                "rationale": (
                                    f"ingest/pipeline error — span routed to a "
                                    f"human, not dropped: {exc}"
                                ),
                                "evidence_sha256": err_sha,
                                "agent": obs.payload.get("agent"),
                            },
                            created_at=obs.timestamp,
                            sla_deadline=obs.timestamp + SLA_SECONDS[Priority.CRITICAL],
                            assigned_to="risk-officer-oncall",
                        )
                    )
                    err_detail["evidence_sha256"] = err_sha
                    err_detail["intervention_id"] = f"{obs.trace_id}-ingest-error-{err_count}"
                except Exception:
                    # recording is best-effort: a failure to record must not
                    # poison the rest of the batch.
                    pass
                counts["ERROR"] = counts.get("ERROR", 0) + 1
                results.append(err_detail)
                continue
            counts[result.decision.name] = counts.get(result.decision.name, 0) + 1
            results.append(
                {
                    "trace_id": result.trace_id,
                    "decision": result.decision.name,
                    "patterns": [m.pattern_name for m in result.pattern_matches],
                    "envelope_bound": env is not None,
                }
            )
            await hub.broadcast({"event": "process_result", "data": _result_to_dict(result)})
        return {"spans_ingested": len(observations), "decisions": counts, "results": results}

    @app.post("/v1/envelopes")
    async def register_envelope(request: Request) -> dict[str, Any]:
        """Declare an agent's sanctioned boundary (its task envelope).

        The operator declares the envelope out-of-band — an agent never carries
        its own sanction inside its own telemetry, where it could lie. Once
        registered (keyed by agent name), every span that agent emits through
        ``/v1/traces`` is judged against it, and anything outside the envelope
        fires breakout patterns. All grants are positive: what you don't name
        isn't sanctioned.
        """
        doc = await request.json()
        agent = str(doc.get("agent", "")).strip()
        if not agent:
            raise HTTPException(status_code=422, detail="'agent' is required")
        env = envelope_from_dict(doc)
        request.app.state.envelopes[agent] = env
        return {"agent": agent, "envelope": envelope_to_dict(env)}

    @app.get("/v1/envelopes")
    async def list_envelopes(request: Request) -> dict[str, Any]:
        envelopes = cast("dict[str, TaskEnvelope]", request.app.state.envelopes)
        return {agent: envelope_to_dict(env) for agent, env in sorted(envelopes.items())}

    @app.websocket("/ws/stream")
    async def ws_stream(websocket: WebSocket) -> None:
        hub = _get_hub(websocket)
        await hub.register(websocket)
        try:
            while True:
                # We don't expect client messages; this keeps the socket alive
                # and triggers WebSocketDisconnect on close.
                await websocket.receive_text()
        except WebSocketDisconnect:
            await hub.unregister(websocket)

    # Static SPA (single-page dashboard).
    if _STATIC_DIR.exists():
        app.mount(
            "/static",
            NoCacheStaticFiles(directory=str(_STATIC_DIR)),
            name="static",
        )

        @app.get("/")
        async def index() -> FileResponse:
            # `no-store` on the entry-point HTML guarantees clients pick up
            # new ?v=… query strings on the asset links the next reload.
            return FileResponse(
                _STATIC_DIR / "index.html",
                headers={"Cache-Control": "no-store"},
            )

    else:  # pragma: no cover - static dir always present in shipped package

        @app.get("/")
        async def no_static() -> JSONResponse:
            return JSONResponse(
                {"error": "static dashboard not found", "static_dir": str(_STATIC_DIR)},
                status_code=500,
            )

    return app


# Module-level app for `uvicorn yukti.serve.api:app`. The shipped server is
# safe by default: a trace it cannot bind to a registered envelope is GATEd to a
# human, never silently ALLOWed. (The library `create_app()` default stays
# pass-through for embedding; the deployed entrypoint is the strict one.)
app = create_app(unbound_agent_decision=Decision.GATE)
