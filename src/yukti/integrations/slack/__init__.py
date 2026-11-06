"""Slack notification integration — the escalation tentacle.

Posts governance decisions to a Slack channel via an incoming webhook
(plain HTTPS POST — no SDK, no new dependencies). This is the last mile of
the HITL story: an agent breaks containment, the policy DENYs, and a human's
channel lights up with who did what.

Slack drowns in noise fast, so the integration carries its own floor:
``min_decision`` (default ``"gate"``) drops ALLOW/MONITOR traffic and posts
only what a human may need to act on.

Example::

    from yukti.integrations.slack import SlackConfig, SlackIntegration

    slack = SlackIntegration(SlackConfig(webhook_url="https://hooks.slack.com/services/..."))
    runtime = Runtime(..., integrations=[slack])

Or for the live dashboard: set ``YUKTI_SLACK_WEBHOOK`` and every GATE/DENY
the fleet produces is posted as it happens.
"""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import HttpUrl

from yukti.integrations.base import (
    Capability,
    Integration,
    IntegrationConfig,
    IntegrationContext,
)

_DECISION_RANK = {"allow": 0, "monitor": 1, "gate": 2, "deny": 3}
_DECISION_EMOJI = {"gate": ":large_yellow_circle:", "deny": ":red_circle:"}


class SlackConfig(IntegrationConfig):
    """Configuration for the Slack incoming-webhook integration."""

    webhook_url: HttpUrl
    min_decision: str = "gate"
    timeout_s: float = 10.0


def format_blocks(
    message: str,
    *,
    decision: str = "",
    agent: str = "",
    flow: str = "",
    consequence: str = "",
    trace_id: str = "",
) -> dict[str, Any]:
    """Build the Slack payload: a plain-text fallback + Block Kit sections.

    Reads like the dashboard's language layer — who, doing what, how bad —
    rather than a policy-engine rationale dump.
    """
    emoji = _DECISION_EMOJI.get(decision, ":white_circle:")
    headline = f"{emoji} *{decision.upper() or 'DECISION'}*"
    if agent:
        headline += f" — *{agent}*" + (f" · {flow}" if flow else "")
    body = consequence or message
    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": headline}},
        {"type": "section", "text": {"type": "mrkdwn", "text": body}},
    ]
    if trace_id:
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"trace `{trace_id}` · via yukti"}],
            }
        )
    return {"text": f"{decision.upper()}: {body}", "blocks": blocks}


class SlackIntegration(Integration):
    """Post GATE/DENY decisions to Slack via an incoming webhook."""

    name = "slack"
    capabilities = frozenset({Capability.NOTIFY})

    def __init__(self, config: SlackConfig, client: httpx.AsyncClient | None = None) -> None:
        super().__init__(config)
        self.config: SlackConfig = config
        self._client = client or httpx.AsyncClient(timeout=config.timeout_s)

    async def health(self) -> bool:
        """Incoming webhooks expose no health endpoint; errors surface per-post."""
        return True

    def _passes_floor(self, decision: str) -> bool:
        floor = _DECISION_RANK.get(self.config.min_decision.lower(), 2)
        return _DECISION_RANK.get(decision.lower(), 0) >= floor

    async def notify(self, ctx: IntegrationContext, message: str, **kwargs: Any) -> None:
        decision = str(kwargs.get("decision", ""))
        if decision and not self._passes_floor(decision):
            return
        payload = format_blocks(
            message,
            decision=decision,
            agent=str(kwargs.get("agent", "")),
            flow=str(kwargs.get("flow", "")),
            consequence=str(kwargs.get("consequence", "")),
            trace_id=ctx.trace_id,
        )
        response = await self._client.post(str(self.config.webhook_url), json=payload)
        response.raise_for_status()
