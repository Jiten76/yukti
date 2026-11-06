"""Breakout serve mode — stream a diverse agent fleet to the live dashboard.

When ``YUKTI_MODE=breakout``, :func:`yukti.serve.api.create_app` swaps the random
fleet for :class:`FleetSimulator` (the named-Flow breakout fleet from
:mod:`yukti.scenarios.agent_fleet`) and the default governance for the
consequence-ranked fleet policy, so the same dashboard renders a real estate:
clean runs that pass, and break-outs ranked CRITICAL vs HIGH by consequence.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator

from yukti.core.patterns.base import Observation
from yukti.scenarios.agent_fleet import FLEET
from yukti.scenarios.breakout import BREAKOUT_FAMILIES

# The dashboard's tiles are {id, label, accent}; give each breakout family a
# distinct accent from the palette (egress/change/retry/auth/drift) so the five
# tiles read as five things, not one repeated colour.
_BREAKOUT_ACCENTS = {
    "unsanctioned_egress": "egress",
    "envelope_escape": "change",
    "identity_fabrication": "auth",
    "durable_footprint": "drift",
    "capability_escalation": "retry",
}
BREAKOUT_PATTERN_FAMILIES: list[dict[str, str]] = [
    {"id": pid, "label": label, "accent": _BREAKOUT_ACCENTS.get(pid, "auth")}
    for pid, label in BREAKOUT_FAMILIES
]


def _interleaved_steps() -> list[tuple[int, int]]:
    """(run_index, step_index) round-robin across runs, so the timeline shows the
    fleet progressing concurrently rather than one run fully before the next."""
    order: list[tuple[int, int]] = []
    depth = max((len(r.steps) for r in FLEET), default=0)
    for s in range(depth):
        for ri, run in enumerate(FLEET):
            if s < len(run.steps):
                order.append((ri, s))
    return order


class BreakoutSimulator:
    """Streams the named-Flow breakout fleet on a loop, paced for a live view.

    Mirrors the core ``FleetSimulator`` interface (``run()`` async-generator +
    ``stop()``). Live wall-clock timestamps so the dashboard's rate strip and
    "Xs ago" ages read as live; a fresh id suffix per loop so repeats are
    distinct. Observations carry the run's task envelope, flow label, agent, and
    a plain-language consequence.
    """

    def __init__(self, *, step_seconds: float = 1.4, gap_seconds: float = 3.0) -> None:
        self._step = step_seconds
        self._gap = gap_seconds
        self._running = False

    async def run(self) -> AsyncIterator[Observation]:
        self._running = True
        order = _interleaved_steps()
        loop_no = 0
        try:
            while self._running:
                loop_no += 1
                for ri, si in order:
                    if not self._running:
                        break
                    run = FLEET[ri]
                    step = run.steps[si]
                    payload: dict[str, object] = {
                        "action": step.action,
                        "agent": run.agent,
                        "flow": run.flow,
                        "consequence": step.detail,
                        "effectful": step.effectful,
                    }
                    if step.target is not None:
                        payload["target"] = step.target
                    if step.destination is not None:
                        payload["destination"] = step.destination
                    if step.capability is not None:
                        payload["capability"] = step.capability
                    yield Observation(
                        trace_id=f"{run.agent}-{si + 1:02d}-loop{loop_no:02d}",
                        payload=payload,
                        timestamp=time.time(),
                        source=f"agent.{run.agent}",
                        extra={**run.envelope.as_extra(), "flow_type": run.flow},
                    )
                    await asyncio.sleep(self._step)
                await asyncio.sleep(self._gap)
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False
