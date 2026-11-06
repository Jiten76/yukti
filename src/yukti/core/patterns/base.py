"""Pattern detection — the behavioral axis.

A Pattern is a recurring behavioral signature of risk — a fingerprint
that shows up across many Flows. Pattern detectors classify, label, or
score Yukti's stream of observations.

The detector interface admits several implementations:

1. **RuleBasedPatternDetector** (shipped, in core) — predicate rules over event
   payloads. Deterministic, fast, auditable.
2. **SignaturePatternDetector** (planned) — match observation against a
   curated catalog of known-pattern fingerprints (hash + regex).
3. **MLPatternDetector** (planned, ``yukti-enterprise``) — trained classifier
   producing probability scores with explanations. Requires
   torch / transformers / sentence-transformers, not part of core
   dependencies.

The interface is intentionally narrow so the enterprise ML implementation
plugs in cleanly without touching core code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Observation:
    """One data point fed to a pattern detector.

    Observations are the unit of analysis. They originate from integrations
    (webhook events, OTLP traces, audit-log pulls, agent invocations) and
    are normalized into this shape by the runtime.
    """

    trace_id: str
    payload: dict[str, Any]
    timestamp: float
    source: str
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PatternMatch:
    """Result of a pattern detection.

    Confidence is a float in ``[0.0, 1.0]``. Rule-based detectors typically
    return ``1.0`` (exact match) or omit the match entirely. ML detectors
    return calibrated scores.
    """

    pattern_name: str
    confidence: float
    rationale: str
    evidence: list[str] = field(default_factory=list)


class PatternDetector(ABC):
    """Detect recurring behavioral signatures in a stream of observations.

    Implementations must be **side-effect-free**: no DB writes, no external
    calls, no mutation of shared state. Return matches; let the runtime
    decide what to do with them.
    """

    name: str

    @abstractmethod
    async def detect(self, observation: Observation) -> list[PatternMatch]:
        """Return zero or more matches for the given observation."""
