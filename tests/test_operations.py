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


import time

from obtuse_hubris.consent import (
    ConsentChallenge,
    ConsentExpired,
    ConsentInvalid,
    SafetyGate,
    UserConsent,
)
from obtuse_hubris.operations import (
    ForcePush,
    ReEnableBranchProtection,
    ThreatLevel,
    validate_consent,
)


def _make_consent(expired: bool = False, invalid: bool = False) -> UserConsent:
    """Helper to create consent objects for testing."""
    challenge = ConsentChallenge.create("test", [], ThreatLevel.DESTRUCTIVE)
    token = challenge.token
    signature = challenge.compute_signature(token)

    if invalid:
        signature = "forged_signature"

    granted_at = time.time() - 600 if expired else time.time()

    return UserConsent(
        challenge=challenge,
        response_token=token,
        signature=signature,
        granted_at=granted_at,
    )


def test_validate_consent_passes():
    consent = _make_consent()
    op = ForcePush()
    # Should not raise
    validate_consent(op, consent)


def test_validate_consent_expired():
    consent = _make_consent(expired=True)
    op = ForcePush()
    try:
        validate_consent(op, consent)
        assert False, "Should have raised ConsentExpired"
    except ConsentExpired:
        pass


def test_validate_consent_invalid():
    consent = _make_consent(invalid=True)
    op = ForcePush()
    try:
        validate_consent(op, consent)
        assert False, "Should have raised ConsentInvalid"
    except ConsentInvalid:
        pass


def test_force_push_with_valid_consent():
    consent = _make_consent()
    op = ForcePush(remote="origin", branch="main")
    result = op.execute("/tmp/repo", consent)
    assert result.success is True
    assert result.threat_level == ThreatLevel.CATASTROPHIC


def test_safe_operation_no_consent():
    op = ReEnableBranchProtection(owner="test", repo="repo")
    result = op.execute("")
    assert result.success is True
    assert result.threat_level == ThreatLevel.SAFE


def test_force_push_properties():
    op = ForcePush()
    assert op.threat_level == ThreatLevel.CATASTROPHIC
    assert op.reversible is False
