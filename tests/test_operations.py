"""Tests for obtuse_hubris.operations — enums, result, and ABCs."""

from obtuse_hubris.operations import (
    DestructiveOperation,
    OperationDomain,
    OperationResult,
    SafeOperation,
    ThreatLevel,
)


def test_threat_level_ordering():
    assert ThreatLevel.SAFE.value < ThreatLevel.DESTRUCTIVE.value
    assert ThreatLevel.DESTRUCTIVE.value < ThreatLevel.CATASTROPHIC.value


def test_operation_domain_values():
    assert OperationDomain.LOCAL is not None
    assert OperationDomain.REMOTE is not None
    assert OperationDomain.SECURITY is not None


def test_operation_result_defaults():
    r = OperationResult(
        success=True,
        operation_name="test_op",
        message="ok",
    )
    assert r.blocked is False
    assert r.threat_level == ThreatLevel.SAFE


def test_operation_result_blocked():
    r = OperationResult(
        success=False,
        operation_name="force_push",
        message="blocked",
        blocked=True,
        threat_level=ThreatLevel.CATASTROPHIC,
    )
    assert r.blocked is True
    assert "BLOCKED" in str(r)


def test_operation_result_str_ok():
    r = OperationResult(success=True, operation_name="push", message="done")
    assert "[OK]" in str(r)


def test_operation_result_str_failed():
    r = OperationResult(success=False, operation_name="push", message="err")
    assert "[FAILED]" in str(r)


def test_safe_operation_is_abstract():
    """SafeOperation can't be instantiated directly."""
    try:
        SafeOperation()
        assert False, "Should have raised TypeError"
    except TypeError:
        pass


def test_destructive_operation_is_abstract():
    """DestructiveOperation can't be instantiated directly."""
    try:
        DestructiveOperation()
        assert False, "Should have raised TypeError"
    except TypeError:
        pass
