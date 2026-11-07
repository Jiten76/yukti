"""OTLP span builder for the live agent — the trusted attribute adapter.

This is the integration boundary, and it is deliberately a **trusted base**: it
classifies each tool call the model makes into Yukti's native governance
vocabulary (``action`` / ``destination`` / ``target`` / ``capability``) that the
runtime matches. The model chooses which tool to call; this adapter names what
that call *is*, in the terms the engine judges. It is not "the traces an agent
already emits" — it is a Yukti-aware classification of them.

Contract (verified against ``yukti.integrations.opentelemetry.span_to_observation``):

- egress tools set ``action="network_egress"`` and ``destination=<host>``;
- non-egress tools set ``action`` and ``target=<host>``;
- ``capability`` is always set (and must be inside the envelope's grant);
- ``gen_ai.agent.name`` carries identity — the envelope binds on it;
- we do **not** set ``gen_ai.operation.name`` (the mapper would let it override
  ``action``) nor ``gen_ai.tool.name`` (the mapper would overwrite ``target``
  with the tool name — the false-``envelope_escape`` foot-gun v1/v2 tripped).

Targets and destinations are **hosts**, because the engine matches them with
host logic (``_host_in``), not file paths.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from yukti.integrations.opentelemetry import CONTRACT_ATTR, validate_contract_span

# The sanctioned hosts the demo's envelope grants. The sandbox docs and the
# report sink are modeled as internal services (the engine matches hosts).
SANDBOX_HOST = "docs-sandbox.internal"
REPORT_SINK_HOST = "report-sink.internal"
CONTRACT_VALUE = "live-agent-v1"  # stamped on yukti.contract; ingest validates these spans

# The field-level validator lives in core so ingest can enforce it; re-exported
# here for the adapter's own callers and tests.
validate_live_span = validate_contract_span


def _attr(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def host_of(url: str) -> str:
    """The host the engine judges — never the full URL (which carries a path)."""
    return urlparse(url).hostname or url


def span(
    *,
    trace_id: str,
    span_id: str,
    agent: str,
    action: str,
    capability: str,
    flow: str,
    run_id: str,
    start_unixnano: str,
    destination: str | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    """One OTLP span carrying the emit contract's Yukti-native attributes."""
    attrs: dict[str, str] = {
        "gen_ai.agent.name": agent,
        "action": action,
        "capability": capability,
        "yukti.flow": flow,
        "yukti.run_id": run_id,
        CONTRACT_ATTR: CONTRACT_VALUE,
    }
    if destination is not None:
        attrs["destination"] = destination
    if target is not None:
        attrs["target"] = target
    return {
        "traceId": trace_id,
        "spanId": span_id,
        "name": f"tool.{action}",
        "startTimeUnixNano": start_unixnano,
        "attributes": [_attr(k, v) for k, v in attrs.items()],
    }


def http_get_span(url: str, **base: Any) -> dict[str, Any]:
    """A network fetch → egress with the destination host."""
    return span(action="network_egress", destination=host_of(url), capability="http_get", **base)


def read_file_span(**base: Any) -> dict[str, Any]:
    """A sandbox read → non-egress action targeting the sandbox host."""
    return span(action="file_read", target=SANDBOX_HOST, capability="file_read", **base)


def post_report_span(**base: Any) -> dict[str, Any]:
    """Posting the report → non-egress action targeting the sanctioned sink."""
    return span(action="tool_call", target=REPORT_SINK_HOST, capability="post_report", **base)


def export(service: str, spans: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap spans in a full OTLP/HTTP JSON trace export."""
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": [_attr("service.name", service)]},
                "scopeSpans": [{"scope": {"name": "yukti-live-agent"}, "spans": list(spans)}],
            }
        ]
    }
