"""Integration plugin contract for Yukti.

An Integration is a tentacle that connects Yukti to an external system —
a notification channel, ticketing system, observability backend, queue,
storage sink, identity provider, or any other concrete operational surface.

Integrations live in ``yukti.integrations.<name>`` and ship as part of core.
Community-authored integrations live in separate PyPI packages under the
naming convention ``yukti-integration-<name>`` and register themselves
via the ``yukti.integrations`` entry-point group.

Integration design rules:

1. **Async-first.** Any I/O uses ``async def``.
2. **Capability-declared.** Class attribute ``capabilities`` enumerates
   what the integration can do; the runtime routes requests by capability.
3. **Side-effect-isolated.** Integrations never mutate core state directly;
   they receive context, perform their external action, return.
4. **Configurable.** Each integration defines its own Pydantic config
   model subclassing :class:`IntegrationConfig`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar

from pydantic import BaseModel


class Capability(StrEnum):
    """Declares what an integration can do.

    An integration may declare multiple capabilities. The runtime uses
    these to route operations only to integrations that can serve them.
    """

    NOTIFY = "notify"
    INGEST_EVENT = "ingest_event"
    PULL_EVIDENCE = "pull_evidence"
    OPEN_TICKET = "open_ticket"
    UPDATE_TICKET = "update_ticket"
    STORE_ARTIFACT = "store_artifact"
    QUERY_LOGS = "query_logs"
    EMIT_TELEMETRY = "emit_telemetry"
    POLICY_EVAL = "policy_eval"


@dataclass
class IntegrationContext:
    """Runtime context passed to every integration call.

    Carries the current ``trace_id`` (always present), ``tenant_id`` (for
    future multi-tenant enterprise builds), and the SHA-256 of the
    immediate caller's evidence record — so every integration call ties
    back into the evidence ledger.
    """

    trace_id: str
    tenant_id: str = "default"
    evidence_sha256: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class IntegrationConfig(BaseModel):
    """Base config — each integration subclasses this with its own fields."""

    enabled: bool = True


class Integration(ABC):
    """Base contract every integration implements.

    Subclasses must:

    - Declare a unique ``name`` matching the package path
      (``yukti.integrations.<name>``).
    - Declare ``capabilities`` (a frozenset of :class:`Capability` values).
    - Override the capability methods their declared capabilities require.
    - Implement ``__init__(self, config)`` taking a config subclass.
    - Implement :meth:`health` to confirm operational readiness.

    The runtime calls into integrations through the capability methods
    below. An integration that does not declare a capability MUST NOT
    override its method — the default raises :class:`NotImplementedError`,
    which is the correct behavior (it signals to the runtime that this
    integration cannot serve that capability).
    """

    name: ClassVar[str]
    capabilities: ClassVar[frozenset[Capability]]

    def __init__(self, config: IntegrationConfig) -> None:
        self.config = config

    @abstractmethod
    async def health(self) -> bool:
        """Return True if the integration's backing system is reachable."""

    # -- Capability methods --
    # Override only those that match your declared capabilities.

    async def notify(self, ctx: IntegrationContext, message: str, **kwargs: Any) -> None:
        raise NotImplementedError(f"{self.name} does not declare the NOTIFY capability")

    async def ingest_event(self, ctx: IntegrationContext, payload: dict[str, Any]) -> None:
        raise NotImplementedError(f"{self.name} does not declare the INGEST_EVENT capability")

    async def pull_evidence(
        self, ctx: IntegrationContext, query: str, **kwargs: Any
    ) -> list[dict[str, Any]]:
        raise NotImplementedError(f"{self.name} does not declare the PULL_EVIDENCE capability")

    async def open_ticket(
        self,
        ctx: IntegrationContext,
        title: str,
        body: str,
        **kwargs: Any,
    ) -> str:
        raise NotImplementedError(f"{self.name} does not declare the OPEN_TICKET capability")

    async def update_ticket(
        self,
        ctx: IntegrationContext,
        ticket_id: str,
        body: str,
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError(f"{self.name} does not declare the UPDATE_TICKET capability")

    async def store_artifact(
        self,
        ctx: IntegrationContext,
        key: str,
        data: bytes,
        **kwargs: Any,
    ) -> str:
        raise NotImplementedError(f"{self.name} does not declare the STORE_ARTIFACT capability")

    async def query_logs(
        self, ctx: IntegrationContext, query: str, **kwargs: Any
    ) -> list[dict[str, Any]]:
        raise NotImplementedError(f"{self.name} does not declare the QUERY_LOGS capability")

    async def emit_telemetry(
        self,
        ctx: IntegrationContext,
        name: str,
        value: float,
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError(f"{self.name} does not declare the EMIT_TELEMETRY capability")

    async def evaluate_policy(
        self,
        ctx: IntegrationContext,
        policy: str,
        input_doc: dict[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError(f"{self.name} does not declare the POLICY_EVAL capability")


def supports(integration: Integration, capability: Capability) -> bool:
    """Returns True if the integration declares the given capability."""
    return capability in integration.capabilities
