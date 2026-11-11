"""WebhookIntegration reference implementation."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from yukti.integrations.base import Capability, IntegrationContext
from yukti.integrations.webhook import WebhookConfig, WebhookIntegration


def test_webhook_declares_correct_name_and_capabilities() -> None:
    """WebhookIntegration must declare name + exact capabilities."""
    assert WebhookIntegration.name == "webhook"
    assert WebhookIntegration.capabilities == frozenset(
        {Capability.NOTIFY, Capability.INGEST_EVENT}
    )


@pytest.mark.asyncio
async def test_webhook_health_returns_true() -> None:
    """Webhook integration health check is always True (no endpoint to probe)."""
    config = WebhookConfig.model_validate({"url": "https://example.com/hook"})
    integration = WebhookIntegration(config)
    try:
        assert await integration.health() is True
    finally:
        await integration.aclose()


@pytest.mark.asyncio
async def test_webhook_notify_posts_expected_payload() -> None:
    """WebhookIntegration.notify must POST a structured payload."""
    config = WebhookConfig.model_validate({"url": "https://example.com/hook"})
    integration = WebhookIntegration(config)

    # Stub the httpx client
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    integration._client.post = AsyncMock(return_value=mock_response)  # type: ignore[method-assign]

    ctx = IntegrationContext(
        trace_id="trace-abc",
        tenant_id="tenant-1",
        evidence_sha256="deadbeef",
    )
    try:
        await integration.notify(ctx, "pattern X matched on flow Y")
    finally:
        await integration.aclose()

    integration._client.post.assert_called_once()
    call_args = integration._client.post.call_args
    assert call_args.args[0] == "https://example.com/hook"
    payload = call_args.kwargs["json"]
    assert payload["trace_id"] == "trace-abc"
    assert payload["tenant_id"] == "tenant-1"
    assert payload["evidence_sha256"] == "deadbeef"
    assert payload["message"] == "pattern X matched on flow Y"
    mock_response.raise_for_status.assert_called_once()


@pytest.mark.asyncio
async def test_webhook_ingest_event_wraps_payload() -> None:
    """ingest_event must wrap the payload with trace context."""
    config = WebhookConfig.model_validate({"url": "https://example.com/hook"})
    integration = WebhookIntegration(config)
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    integration._client.post = AsyncMock(return_value=mock_response)  # type: ignore[method-assign]

    ctx = IntegrationContext(trace_id="trace-xyz")
    try:
        await integration.ingest_event(ctx, {"event_type": "test", "value": 42})
    finally:
        await integration.aclose()

    payload = integration._client.post.call_args.kwargs["json"]
    assert payload["trace_id"] == "trace-xyz"
    assert payload["event"]["event_type"] == "test"
    assert payload["event"]["value"] == 42


@pytest.mark.asyncio
async def test_webhook_does_not_support_open_ticket() -> None:
    """Calling a non-declared capability must raise NotImplementedError."""
    config = WebhookConfig.model_validate({"url": "https://example.com/hook"})
    integration = WebhookIntegration(config)
    ctx = IntegrationContext(trace_id="t")
    try:
        with pytest.raises(NotImplementedError, match="OPEN_TICKET"):
            await integration.open_ticket(ctx, "title", "body")
    finally:
        await integration.aclose()
