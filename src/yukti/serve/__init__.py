"""Yukti serve — the live runtime + dashboard API.

This package provides:

- :func:`build_runtime_with_default_governance` — a :class:`Runtime` wired
  with the five default Pattern families and their policies.
- :class:`FleetSimulator` — a synthetic stream of agent observations for the
  dashboard when no live agent backend is connected.
- :func:`create_app` — the FastAPI application that exposes the runtime
  as a scale-shaped query API plus a WebSocket live stream, and serves
  the dashboard SPA.

Run via ``yukti serve``.
"""

from yukti.serve.api import create_app
from yukti.serve.fleet import FleetConfig, FleetSimulator
from yukti.serve.patterns import (
    PATTERN_FAMILIES,
    build_runtime_with_default_governance,
)

__all__ = [
    "PATTERN_FAMILIES",
    "FleetConfig",
    "FleetSimulator",
    "build_runtime_with_default_governance",
    "create_app",
]
