"""Generic webhook integration — the reference Integration implementation.

Webhooks are the simplest tentacle: HTTP POST to a configured URL with a
JSON payload. This implementation supports :data:`Capability.NOTIFY` and
:data:`Capability.INGEST_EVENT`.

Example::

    from yukti.integrations.webhook import WebhookConfig, WebhookIntegration
    from yukti.integrations.base import IntegrationContext

    config = WebhookConfig(url="https://example.com/yukti-webhook")
    integration = WebhookIntegration(config)

    ctx = IntegrationContext(trace_id="abc123")
    await integration.notify(ctx, "Pattern X matched on Flow Y")
"""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import Field, HttpUrl

from yukti.integrations.base import (
    Capability,
    Integration,
    IntegrationConfig,
    IntegrationContext,
)


class WebhookConfig(IntegrationConfig):
    """Configuration for the webhook integration."""

    url: HttpUrl
    timeout_s: float = 10.0
    headers: dict[str, str] = Field(default_factory=dict)


class WebhookIntegration(Integration):
    """Generic webhook — POSTs JSON to a configured URL."""

    name = "webhook"
    capabilities = frozenset({Capability.NOTIFY, Capability.INGEST_EVENT})

    def __init__(self, config: WebhookConfig) -> None:
        super().__init__(config)
        self.config: WebhookConfig = config
        self._client = httpx.AsyncClient(timeout=config.timeout_s)

    async def health(self) -> bool:
        """Webhooks have no built-in health endpoint; always returns True.

        HTTP errors surface per-call from :meth:`notify` / :meth:`ingest_event`.
        For production use, configure an integration-level health-check
        URL via the ``extra`` field if needed.
        """
        return True

    async def notify(self, ctx: IntegrationContext, message: str, **kwargs: Any) -> None:
        """POST a message + trace context to the configured webhook URL."""
        payload = {
            "trace_id": ctx.trace_id,
            "tenant_id": ctx.tenant_id,
            "evidence_sha256": ctx.evidence_sha256,
            "message": message,
            **kwargs,
        }
        resp = await self._client.post(
            str(self.config.url),
            json=payload,
            headers=self.config.headers,
        )
        resp.raise_for_status()

    async def ingest_event(self, ctx: IntegrationContext, payload: dict[str, Any]) -> None:
        """Forward an event payload to the configured webhook URL.

        Equivalent to :meth:`notify` but with the full payload rather than
        a message string. The Yukti runtime calls this when forwarding
        normalized events to external systems.
        """
        wrapped = {
            "trace_id": ctx.trace_id,
            "tenant_id": ctx.tenant_id,
            "evidence_sha256": ctx.evidence_sha256,
            "event": payload,
        }
        resp = await self._client.post(
            str(self.config.url),
            json=wrapped,
            headers=self.config.headers,
        )
        resp.raise_for_status()

    async def aclose(self) -> None:
        """Close the underlying HTTP client. Call this on shutdown."""
        await self._client.aclose()


__all__ = ["WebhookConfig", "WebhookIntegration"]
