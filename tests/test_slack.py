"""Tests for the Slack notification integration — floor, format, e2e escalation."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from pydantic import HttpUrl

from yukti.integrations.base import Capability, IntegrationContext
from yukti.integrations.slack import SlackConfig, SlackIntegration, format_blocks

_URL = "https://hooks.slack.com/services/T000/B000/XXXX"


def _capture() -> tuple[list[dict[str, Any]], httpx.AsyncClient]:
    """An httpx client whose transport records every posted payload."""
    posted: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        posted.append(json.loads(request.content))
        return httpx.Response(200, text="ok")

    return posted, httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _slack(min_decision: str = "gate") -> tuple[list[dict[str, Any]], SlackIntegration]:
    posted, client = _capture()
    config = SlackConfig(webhook_url=HttpUrl(_URL), min_decision=min_decision)
    return posted, SlackIntegration(config, client=client)


def test_declares_notify_only() -> None:
    _, slack = _slack()
    assert slack.capabilities == frozenset({Capability.NOTIFY})
    assert asyncio.run(slack.health())


def test_noise_floor_drops_allow_and_monitor() -> None:
    posted, slack = _slack()
    ctx = IntegrationContext(trace_id="t1")
    asyncio.run(slack.notify(ctx, "m", decision="allow"))
    asyncio.run(slack.notify(ctx, "m", decision="monitor"))
    assert posted == []
    asyncio.run(slack.notify(ctx, "m", decision="gate"))
    asyncio.run(slack.notify(ctx, "m", decision="deny"))
    assert len(posted) == 2


def test_floor_is_configurable() -> None:
    posted, slack = _slack(min_decision="deny")
    ctx = IntegrationContext(trace_id="t1")
    asyncio.run(slack.notify(ctx, "m", decision="gate"))
    assert posted == []
    asyncio.run(slack.notify(ctx, "m", decision="deny"))
    assert len(posted) == 1


def test_message_speaks_the_language_layer() -> None:
    posted, slack = _slack()
    ctx = IntegrationContext(trace_id="ctf-solver-04")
    asyncio.run(
        slack.notify(
            ctx,
            "[DENY] rationale (trace ctf-solver-04)",
            decision="deny",
            agent="ctf-solver",
            flow="cyber-eval",
            consequence="opened a PR attempting to plant a backdoor in a real repo",
        )
    )
    payload = posted[0]
    text = str(payload)
    assert "ctf-solver" in text
    assert "opened a PR attempting to plant a backdoor" in text
    assert "cyber-eval" in text
    assert "trace `ctf-solver-04`" in text
    # fallback text carries the consequence, not the rationale dump
    assert payload["text"].startswith("DENY:")


def test_format_blocks_without_context_fields_still_valid() -> None:
    payload = format_blocks("plain rationale", decision="gate")
    assert payload["blocks"][1]["text"]["text"] == "plain rationale"


def test_runtime_escalation_reaches_slack_end_to_end() -> None:
    """A DENY run through the real runtime posts exactly the DENYs to Slack."""
    from yukti.scenarios.agent_fleet import build_fleet_governance
    from yukti.scenarios.breakout import observations

    posted, slack = _slack(min_decision="deny")
    runtime = build_fleet_governance()
    runtime.integrations.append(slack)

    async def run_all() -> list[str]:
        decisions = []
        for obs in observations():
            result = await runtime.process(obs, flow_type=str(obs.extra.get("flow_type")))
            decisions.append(result.decision.name)
        return decisions

    decisions = asyncio.run(run_all())
    assert decisions.count("DENY") > 0
    assert len(posted) == decisions.count("DENY")
    assert all(p.get("blocks") for p in posted)
