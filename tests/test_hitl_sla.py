"""HITL SLA mapping + intervention types."""

from __future__ import annotations

from yukti.core.hitl.base import SLA_SECONDS, InterventionType, Priority


def test_sla_seconds_mapping_is_monotonic() -> None:
    """Higher-priority interventions must have shorter SLA windows."""
    assert SLA_SECONDS[Priority.CRITICAL] < SLA_SECONDS[Priority.HIGH]
    assert SLA_SECONDS[Priority.HIGH] < SLA_SECONDS[Priority.MEDIUM]
    assert SLA_SECONDS[Priority.MEDIUM] < SLA_SECONDS[Priority.LOW]


def test_sla_critical_is_immediate() -> None:
    """CRITICAL priority must have a zero-second deadline (act now)."""
    assert SLA_SECONDS[Priority.CRITICAL] == 0


def test_sla_documented_targets() -> None:
    """SLAs must match the documented values (0s/1h/4h/24h)."""
    assert SLA_SECONDS[Priority.CRITICAL] == 0
    assert SLA_SECONDS[Priority.HIGH] == 3600
    assert SLA_SECONDS[Priority.MEDIUM] == 14400
    assert SLA_SECONDS[Priority.LOW] == 86400


def test_sla_covers_all_priorities() -> None:
    """Every Priority enum member must have a mapping in SLA_SECONDS."""
    assert set(SLA_SECONDS.keys()) == set(Priority)


def test_intervention_type_enum_has_expected_values() -> None:
    """The documented 7 InterventionTypes must all be present."""
    expected = {
        "approval",
        "review",
        "disambiguation",
        "exception_handling",
        "data_quality_check",
        "policy_override",
        "escalation",
    }
    assert {t.value for t in InterventionType} == expected
