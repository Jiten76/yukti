"""Generic scenario streamer — any governance domain on the live dashboard.

Every scenario module exposes a deterministic ``observations()`` list (seeded
clock, stable trace ids) for tests and demos. This simulator adapts any of
them for the live view: it loops the list, re-stamps each observation with
live wall-clock time (so the rate strip and "Xs ago" ages read as live —
seeded 2025 clocks once produced "377d ago"), and suffixes trace ids per loop
so replays don't collide with the flow tracker.

This is what makes ``yukti serve --mode reliability|data-leak|risk|cyber``
possible with zero per-domain serve code.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import replace

from yukti.core.patterns.base import Observation


class ScenarioSimulator:
    """Stream any scenario's observation list on a loop, paced for a live view.

    Mirrors the ``FleetSimulator`` interface (``run()`` async-generator +
    ``stop()``) so the serve pipeline treats every mode identically.
    """

    def __init__(
        self,
        observations_factory: Callable[[], list[Observation]],
        *,
        step_seconds: float = 1.6,
        gap_seconds: float = 4.0,
    ) -> None:
        self._factory = observations_factory
        self._step = step_seconds
        self._gap = gap_seconds
        self._running = False

    async def run(self) -> AsyncIterator[Observation]:
        self._running = True
        loop_no = 0
        try:
            while self._running:
                loop_no += 1
                for obs in self._factory():
                    if not self._running:
                        break
                    now = time.time()
                    # Shift time-anchored payload fields by the same delta as the
                    # timestamp, so relative ages survive re-stamping. Without
                    # this a seeded ``measured_at`` (2025) against a live
                    # timestamp (now) reads as ~1yr stale and every reliability/
                    # risk reading would spuriously trip its staleness pattern.
                    delta = now - obs.timestamp
                    payload = {
                        k: (v + delta if k.endswith("_at") and isinstance(v, (int, float)) else v)
                        for k, v in obs.payload.items()
                    }
                    yield replace(
                        obs,
                        payload=payload,
                        timestamp=now,
                        trace_id=f"{obs.trace_id}-l{loop_no:02d}",
                    )
                    await asyncio.sleep(self._step)
                await asyncio.sleep(self._gap)
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False
