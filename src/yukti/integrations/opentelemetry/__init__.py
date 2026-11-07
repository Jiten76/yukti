"""OpenTelemetry trace ingest — the flagship working integration.

This converts OTLP JSON trace exports (the wire format every OTel SDK and
collector can emit) into Yukti :class:`Observation` objects, ready for the
Pattern × Flow → Decision pipeline. It *classifies* GenAI semantic-convention
attributes (``gen_ai.*``) into Yukti's own vocabulary: ``gen_ai.agent.name`` →
``agent``, ``gen_ai.operation.name`` → ``action``, ``gen_ai.tool.name`` →
``tool``. That is enough to govern what matters most from a raw agent trace —
which agent invoked which tool — against a registered task envelope.

Signals a ``gen_ai`` span does not itself carry (an egress ``destination``, a
``capability``, a data ``sensitivity_tier``) are supplied by operator
enrichment or a trusted classifying adapter; the engine judges whatever lands
in those fields. So this reads a *Yukti-classified view* of the traces agents
emit, not a claim that raw telemetry already speaks Yukti's vocabulary.

Deliberately dependency-free: it parses OTLP **JSON dicts** (protobuf JSON
mapping), so core needs no opentelemetry-* packages. The ``opentelemetry``
extra remains for deployments that want the SDK/exporters alongside.

Example::

    from yukti.integrations.opentelemetry import observations_from_otlp

    export = json.loads(otlp_traces_json)      # an OTLP ExportTraceServiceRequest
    for obs in observations_from_otlp(export):
        result = await runtime.process(obs, flow_type=obs.extra["flow_type"])
"""

from __future__ import annotations

from typing import Any

from yukti.core.patterns.base import Observation
from yukti.integrations.base import (
    Capability,
    Integration,
    IntegrationConfig,
    IntegrationContext,
)

_NANOS = 1_000_000_000.0


def _attr_value(value: Any) -> Any:
    """Decode one OTLP JSON AnyValue. Non-OTLP (already-plain) values pass through."""
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        return int(value["intValue"])  # protobuf JSON encodes int64 as string
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "arrayValue" in value:
        return [_attr_value(v) for v in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return attributes_to_dict(value["kvlistValue"].get("values", []))
    return value


def attributes_to_dict(attributes: Any) -> dict[str, Any]:
    """OTLP attribute list ``[{key, value}, ...]`` → flat dict (plain dicts pass through)."""
    if isinstance(attributes, dict):
        return dict(attributes)
    out: dict[str, Any] = {}
    for item in attributes or []:
        if isinstance(item, dict) and "key" in item:
            out[str(item["key"])] = _attr_value(item.get("value"))
    return out


def span_to_observation(
    span: dict[str, Any],
    resource_attrs: dict[str, Any] | None = None,
    *,
    flow_attribute: str = "yukti.flow",
    default_flow: str = "otel-traces",
) -> Observation:
    """One OTLP JSON span → one Yukti Observation.

    Span attributes win over resource attributes on key collision. GenAI
    semantic conventions map onto Yukti's native fields: ``agent`` from
    ``gen_ai.agent.name`` (falling back to ``service.name``), ``action`` from
    ``gen_ai.operation.name`` (falling back to the span name), ``tool`` from
    ``gen_ai.tool.name``. The Flow comes from the ``yukti.flow`` attribute if
    the deployment stamps one, else ``default_flow``.
    """
    resource = dict(resource_attrs or {})
    attrs = {**resource, **attributes_to_dict(span.get("attributes"))}
    service = str(attrs.get("service.name", "") or "unknown-service")
    start_nano = span.get("startTimeUnixNano") or span.get("endTimeUnixNano") or 0
    # precedence: GenAI semconv > explicit Yukti-native attrs > span fallbacks —
    # a deployment that already stamps plain `agent`/`action` keeps them.
    payload: dict[str, Any] = {
        **attrs,
        "span_name": span.get("name", ""),
        "span_id": span.get("spanId", ""),
        "service": service,
        "agent": str(
            attrs.get("gen_ai.agent.name", "") or attrs.get("agent", "") or service
        ),
        "action": str(
            attrs.get("gen_ai.operation.name", "")
            or attrs.get("action", "")
            or span.get("name", "")
        ),
    }
    if "gen_ai.tool.name" in attrs:
        # A tool is named, not addressed — it lands in ``tool`` (judged against
        # the run's tool grant), never ``target`` (a host allowlist). Routing a
        # tool name through host matching was a real foot-gun.
        payload["tool"] = attrs["gen_ai.tool.name"]
    # Model identity: the standard GenAI model NAME, plus a Yukti-native weight
    # DIGEST attribute (model governance pins the digest, not the name — a name is
    # not a reliable identity for a model whose weights can be edited in place).
    if "gen_ai.request.model" in attrs:
        payload["model_name"] = attrs["gen_ai.request.model"]
    if "gen_ai.model.digest" in attrs:
        payload["model_digest"] = attrs["gen_ai.model.digest"]
    status = span.get("status") or {}
    if status.get("code"):
        payload["status"] = status["code"]
    # observation id = trace + span: a real OTel trace carries many spans under
    # one traceId, and each span is judged individually — reusing the bare
    # traceId would collide on the second span of every multi-span trace.
    trace = str(span.get("traceId", "") or "unknown-trace")
    span_id = str(span.get("spanId", "") or "")
    # Keep the bare trace id too: spans of one agent run share it, so a trace
    # governor can group a run's spans (e.g. to propagate read-taint per run)
    # even though the per-observation id below is trace+span for uniqueness.
    payload["otel_trace_id"] = trace
    return Observation(
        trace_id=f"{trace}-{span_id}" if span_id else trace,
        payload=payload,
        timestamp=float(int(start_nano)) / _NANOS,
        source=f"otel:{service}",
        extra={"flow_type": str(attrs.get(flow_attribute, "") or default_flow)},
    )


def observations_from_otlp(
    export: dict[str, Any],
    *,
    flow_attribute: str = "yukti.flow",
    default_flow: str = "otel-traces",
) -> list[Observation]:
    """A full OTLP JSON trace export (``resourceSpans`` tree) → Observations.

    Tolerant of partial documents; a document with no spans yields ``[]``.
    """
    out: list[Observation] = []
    for rs in export.get("resourceSpans", []) or []:
        resource_attrs = attributes_to_dict((rs.get("resource") or {}).get("attributes"))
        for ss in rs.get("scopeSpans", []) or []:
            for span in ss.get("spans", []) or []:
                out.append(
                    span_to_observation(
                        span,
                        resource_attrs,
                        flow_attribute=flow_attribute,
                        default_flow=default_flow,
                    )
                )
    return out


# A span may declare the governance contract via the ``yukti.contract`` attribute.
# The runtime then requires it to carry the fields the engine judges, so a naive
# or malformed governed span is caught at ingest rather than silently allowed.
CONTRACT_ATTR = "yukti.contract"
_CONTRACT_REQUIRED = ("action", "capability")


def validate_contract_span(payload: dict[str, Any]) -> str | None:
    """Return a contract-violation reason, or ``None`` if well-formed.

    Field-level check (does not itself gate on the contract marker — the caller
    decides which spans to validate). An egress action must carry a destination.
    """
    for field in _CONTRACT_REQUIRED:
        if not payload.get(field):
            return f"missing required field {field!r}"
    if payload.get("action") == "network_egress" and not payload.get("destination"):
        return "network_egress without a destination"
    return None


class OpenTelemetryConfig(IntegrationConfig):
    """Configuration for OTel trace ingest."""

    flow_attribute: str = "yukti.flow"
    default_flow: str = "otel-traces"


class OpenTelemetryIntegration(Integration):
    """Ingest OTLP JSON trace exports and queue them as Observations.

    ``ingest_event`` accepts one OTLP export document per call and parses it;
    the host (a serve endpoint, a collector sidecar, a batch job) calls
    :meth:`drain` to collect the parsed Observations and feed the runtime.
    """

    name = "opentelemetry"
    capabilities = frozenset({Capability.INGEST_EVENT})

    def __init__(self, config: OpenTelemetryConfig | None = None) -> None:
        super().__init__(config or OpenTelemetryConfig())
        self.config: OpenTelemetryConfig = config or OpenTelemetryConfig()
        self._pending: list[Observation] = []

    async def health(self) -> bool:
        """Pure parsing, no backing system — always ready."""
        return True

    async def ingest_event(self, ctx: IntegrationContext, payload: dict[str, Any]) -> None:
        self._pending.extend(
            observations_from_otlp(
                payload,
                flow_attribute=self.config.flow_attribute,
                default_flow=self.config.default_flow,
            )
        )

    def drain(self) -> list[Observation]:
        """Return all parsed Observations accumulated so far and clear the queue."""
        pending, self._pending = self._pending, []
        return pending
