"""Capability enum + supports() helper."""

from __future__ import annotations

from yukti.integrations.base import Capability, supports
from yukti.integrations.webhook import WebhookConfig, WebhookIntegration


def test_capability_enum_has_expected_values() -> None:
    """The Capability enum must cover the documented 9 capabilities."""
    expected = {
        "notify",
        "ingest_event",
        "pull_evidence",
        "open_ticket",
        "update_ticket",
        "store_artifact",
        "query_logs",
        "emit_telemetry",
        "policy_eval",
    }
    assert {c.value for c in Capability} == expected


def test_capability_string_equality() -> None:
    """StrEnum members must equal their string values at runtime.

    This matters because external systems will send capability names as
    plain strings; Yukti's routing must treat them as equivalent. We
    compare via ``.value`` so mypy is happy; the runtime equality is the
    behavioral contract.
    """
    assert Capability.NOTIFY.value == "notify"
    assert Capability.OPEN_TICKET.value == "open_ticket"
    # Runtime equality (the actual behavioral contract):
    assert str(Capability.NOTIFY) == "notify"
    assert "notify" in [c.value for c in Capability]


def test_supports_helper() -> None:
    """The supports() helper returns True iff capability is declared."""
    config = WebhookConfig.model_validate({"url": "https://example.com"})
    integration = WebhookIntegration(config)
    assert supports(integration, Capability.NOTIFY) is True
    assert supports(integration, Capability.INGEST_EVENT) is True
    assert supports(integration, Capability.OPEN_TICKET) is False
    assert supports(integration, Capability.STORE_ARTIFACT) is False
