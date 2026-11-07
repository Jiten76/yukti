"""Rule-based pattern detector — the core default :class:`PatternDetector`.

Deterministic, fast, auditable. A :class:`Rule` is a named predicate over
observations: if the predicate returns ``True``, the pattern matches with
confidence ``1.0``.

This is the implementation you get out of the box. The enterprise
``MLPatternDetector`` plugs in through the same :class:`PatternDetector`
ABC — see ``docs/ROADMAP.md``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from yukti.core.patterns.base import Observation, PatternDetector, PatternMatch


@dataclass(frozen=True)
class Rule:
    """A named predicate over observations.

    If ``predicate(observation)`` returns ``True``, the pattern matches.
    Predicates must be pure and fast — they run on every observation.
    """

    name: str
    predicate: Callable[[Observation], bool]
    rationale: str = ""


class RuleBasedPatternDetector(PatternDetector):
    """Detect patterns via a list of deterministic predicate rules."""

    name = "rule_based"

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules: list[Rule] = list(rules) if rules else []

    def add_rule(self, rule: Rule) -> None:
        """Register a new rule with the detector."""
        self._rules.append(rule)

    @property
    def rule_count(self) -> int:
        """Number of registered rules."""
        return len(self._rules)

    async def detect(self, observation: Observation) -> list[PatternMatch]:
        """Run every rule against the observation; return all matches.

        A rule whose predicate raises does not crash the pass — it yields a
        zero-confidence match recording the failure, so a buggy rule is
        visible in the evidence rather than silently swallowed.
        """
        matches: list[PatternMatch] = []
        for rule in self._rules:
            try:
                hit = rule.predicate(observation)
            except Exception as exc:
                matches.append(
                    PatternMatch(
                        pattern_name=rule.name,
                        confidence=0.0,
                        rationale=f"rule predicate raised: {exc!r}",
                    )
                )
                continue
            if hit:
                matches.append(
                    PatternMatch(
                        pattern_name=rule.name,
                        confidence=1.0,
                        rationale=rule.rationale or f"rule '{rule.name}' matched",
                        evidence=[observation.trace_id],
                    )
                )
        return matches
