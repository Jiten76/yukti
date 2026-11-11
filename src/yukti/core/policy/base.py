"""Policy engine — the rule-evaluation layer.

A Policy is a declarative statement about what is allowed, denied, or
conditionally allowed within a flow. The :class:`PolicyEngine` evaluates
policies against input documents and returns decisions.

Yukti's policy interface is **engine-pluggable** through this ABC:

- **SimplePredicatePolicyEngine** (shipped, in core) — Python predicate
  evaluator
- **External engines** (planned) — the same ABC admits adapters for Open
  Policy Agent (Rego), Kyverno-style YAML, or AWS Cedar; none are shipped
- **EnterprisePolicyEngine** (planned, ``yukti-enterprise``) — multi-tenant,
  hot-reload, version-controlled policy distribution

Only the simple predicate engine ships today; the rest are interface targets.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    """Result of a policy evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    GATE = "gate"
    """Allow, but route through HITL for human approval."""

    MONITOR = "monitor"
    """Allow, but emit a high-priority telemetry signal for review."""


@dataclass
class PolicyResult:
    """Outcome of evaluating policies against an input."""

    decision: Decision
    matched_policies: list[str]
    rationale: str
    obligations: list[str] = field(default_factory=list)
    """Side-actions the runtime must take (e.g., 'log_to_evidence', 'notify_audit')."""

    extra: dict[str, Any] = field(default_factory=dict)


class PolicyEngine(ABC):
    """Evaluate one or more policies against an input document."""

    name: str

    @abstractmethod
    async def evaluate(
        self,
        input_doc: dict[str, Any],
        policies: list[str] | None = None,
    ) -> PolicyResult:
        """Evaluate the named policies (or all loaded policies) against
        the input document and return the decision."""

    @abstractmethod
    async def load_policy(self, name: str, source: str) -> None:
        """Load (or reload) a named policy from source text."""

    @abstractmethod
    async def list_policies(self) -> list[str]:
        """List the names of all currently loaded policies."""
