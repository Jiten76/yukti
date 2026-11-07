"""Verify each core ABC is properly abstract and can't be instantiated directly.

This is the most basic architectural contract: every interface declared
as an ABC must actually be abstract. If you can instantiate it directly,
something has slipped past the @abstractmethod decorator.
"""

from __future__ import annotations

import pytest

from yukti.core.evidence.base import EvidenceStore
from yukti.core.flows.base import FlowTracker
from yukti.core.hitl.base import HITLBackend
from yukti.core.patterns.base import PatternDetector
from yukti.core.policy.base import PolicyEngine
from yukti.integrations.base import Integration


@pytest.mark.parametrize(
    "abc_class",
    [
        PatternDetector,
        FlowTracker,
        EvidenceStore,
        HITLBackend,
        PolicyEngine,
        Integration,
    ],
)
def test_abc_cannot_be_instantiated(abc_class: type) -> None:
    """ABCs must not be instantiable directly."""
    with pytest.raises(TypeError):
        abc_class()


def test_pattern_detector_has_detect_method() -> None:
    """PatternDetector must declare an abstract detect() method."""
    assert hasattr(PatternDetector, "detect")
    assert getattr(PatternDetector.detect, "__isabstractmethod__", False) is True


def test_flow_tracker_has_all_methods() -> None:
    """FlowTracker must declare all five expected abstract methods."""
    for method in ("begin", "append_step", "transition", "get", "list_active"):
        assert hasattr(FlowTracker, method)
        method_obj = getattr(FlowTracker, method)
        assert getattr(method_obj, "__isabstractmethod__", False) is True


def test_evidence_store_has_all_methods() -> None:
    """EvidenceStore must declare the four async abstract methods plus the static helper."""
    for method in ("write", "read", "list_by_trace", "lineage"):
        assert hasattr(EvidenceStore, method)
        method_obj = getattr(EvidenceStore, method)
        assert getattr(method_obj, "__isabstractmethod__", False) is True
    # compute_sha256 is a non-abstract @staticmethod
    assert hasattr(EvidenceStore, "compute_sha256")


def test_hitl_backend_has_all_methods() -> None:
    """HITLBackend must declare all five expected abstract methods."""
    for method in ("enqueue", "dequeue", "resolve", "list_pending", "list_overdue"):
        assert hasattr(HITLBackend, method)
        method_obj = getattr(HITLBackend, method)
        assert getattr(method_obj, "__isabstractmethod__", False) is True


def test_policy_engine_has_all_methods() -> None:
    """PolicyEngine must declare all three expected abstract methods."""
    for method in ("evaluate", "load_policy", "list_policies"):
        assert hasattr(PolicyEngine, method)
        method_obj = getattr(PolicyEngine, method)
        assert getattr(method_obj, "__isabstractmethod__", False) is True


def test_integration_has_health_abstract() -> None:
    """Integration.health() must be abstract; capability methods must not be."""
    assert getattr(Integration.health, "__isabstractmethod__", False) is True
    # Capability methods raise NotImplementedError by default but are not abstract,
    # so subclasses don't have to override every one.
    assert getattr(Integration.notify, "__isabstractmethod__", False) is False
