"""Simple predicate policy engine — the core default :class:`PolicyEngine`.

Policies are Python predicate callables: given an input document, return a
:class:`Decision`. Deterministic and auditable. The enterprise
``EnterprisePolicyEngine`` (multi-tenant, hot-reload, version-controlled
distribution) plugs in through the same :class:`PolicyEngine` ABC.

Rego / Kyverno / Cedar source-text policies would need an external policy
engine adapter, which is not shipped (see :class:`PolicyEngine` for the ABC
those adapters would implement).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from yukti.core.policy.base import Decision, PolicyEngine, PolicyResult

# A policy predicate maps an input document to a Decision.
PolicyPredicate = Callable[[dict[str, Any]], Decision]

# Most-restrictive-wins precedence when multiple policies match.
_PRECEDENCE: dict[Decision, int] = {
    Decision.DENY: 3,
    Decision.GATE: 2,
    Decision.MONITOR: 1,
    Decision.ALLOW: 0,
}


class SimplePredicatePolicyEngine(PolicyEngine):
    """Evaluate policies expressed as Python predicate callables.

    Use :meth:`register` to add a predicate directly (the ergonomic
    in-code path). :meth:`load_policy` exists for the ABC contract but
    the simple engine does not parse a policy DSL — it raises to make the
    limitation explicit. Source-text policies would require an external policy
    engine (OPA / Kyverno / Cedar), which is not shipped.

    **Default-open, and why.** Policies here express *restrictions*, not
    grants: the engine returns the most restrictive decision among the
    policies that evaluated, and with nothing to evaluate it returns ALLOW.
    That is the opposite stance from the task envelope (a positive grant that
    fails safe by denying), and it is deliberate — the two compose: the
    envelope decides what an agent *may* do; policies escalate what it *did*.
    The failure modes of that stance are handled explicitly:

    - a policy **predicate that raises** is treated as DENY for that policy
      (failing closed), with the failure named in the rationale — a buggy
      policy must not silently produce the engine's most permissive outcome;
    - an **unknown policy name** in an evaluate subset is skipped by default;
      construct with ``strict=True`` to make it raise instead, so a typo'd
      name or forgotten registration fails loudly at evaluation time.
    """

    name = "simple_predicate"

    def __init__(self, *, strict: bool = False) -> None:
        self._predicates: dict[str, PolicyPredicate] = {}
        self._strict = strict

    def register(self, name: str, predicate: PolicyPredicate) -> None:
        """Register a policy predicate directly."""
        self._predicates[name] = predicate

    async def evaluate(
        self,
        input_doc: dict[str, Any],
        policies: list[str] | None = None,
    ) -> PolicyResult:
        names = policies if policies is not None else list(self._predicates)
        matched: list[str] = []
        rationale_parts: list[str] = []
        final = Decision.ALLOW
        for policy_name in names:
            predicate = self._predicates.get(policy_name)
            if predicate is None:
                if self._strict:
                    raise KeyError(
                        f"unknown policy {policy_name!r} — not registered on "
                        f"this engine (strict mode)"
                    )
                continue
            try:
                decision = predicate(input_doc)
                rationale_parts.append(f"{policy_name} -> {decision.value}")
            except Exception as exc:
                # A buggy policy must not resolve to the engine's most
                # permissive outcome, and must not kill the pipeline: fail
                # closed for this policy and name the failure (mirrors the
                # detector's raise-becomes-evidence stance).
                decision = Decision.DENY
                rationale_parts.append(
                    f"{policy_name} raised {exc!r} -> deny (failing closed)"
                )
            matched.append(policy_name)
            if _PRECEDENCE[decision] > _PRECEDENCE[final]:
                final = decision
        return PolicyResult(
            decision=final,
            matched_policies=matched,
            rationale="; ".join(rationale_parts) or "no policies evaluated",
        )

    async def load_policy(self, name: str, source: str) -> None:
        """Not supported by the simple engine — raises to be explicit.

        The simple engine loads predicates via :meth:`register`. Source-text
        policies (Rego, Kyverno YAML, Cedar) would require an external policy
        engine, which is not shipped.
        """
        raise NotImplementedError(
            "SimplePredicatePolicyEngine loads predicates via register(); "
            "source-text policies require an external policy engine "
            "(OPA / Kyverno / Cedar), which is not shipped."
        )

    async def list_policies(self) -> list[str]:
        return list(self._predicates)
