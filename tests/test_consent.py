"""Tests for obtuse_hubris.consent — the consent gate pattern."""

import time

from obtuse_hubris.consent import (
    ConsentChallenge,
    ConsentExpired,
    ConsentInvalid,
    ConsentRequired,
    SafetyGate,
    UserConsent,
)
from obtuse_hubris.operations import ThreatLevel


def test_challenge_creation():
    c = ConsentChallenge.create(
        operation_description="force push",
        affected_resources=["repo-a"],
        threat_level=ThreatLevel.CATASTROPHIC,
    )
    assert len(c.token) > 0
    assert c.operation_description == "force push"
    assert c.threat_level == ThreatLevel.CATASTROPHIC
    assert c.affected_resources == ("repo-a",)
    assert c.timestamp <= time.time()


def test_consent_grant_correct_token():
    gate = SafetyGate()
    c = ConsentChallenge.create("test op", [], ThreatLevel.DESTRUCTIVE)
    gate._pending_challenges[c.token] = c
    consent = gate.grant_consent(c, c.token)
    assert consent is not None
    assert isinstance(consent, UserConsent)


def test_consent_grant_wrong_token():
    gate = SafetyGate()
    c = ConsentChallenge.create("test op", [], ThreatLevel.DESTRUCTIVE)
    gate._pending_challenges[c.token] = c
    consent = gate.grant_consent(c, "wrong-token")
    assert consent is None


def test_consent_valid_signature():
    gate = SafetyGate()
    c = ConsentChallenge.create("test op", [], ThreatLevel.DESTRUCTIVE)
    gate._pending_challenges[c.token] = c
    consent = gate.grant_consent(c, c.token)
    assert consent is not None
    assert consent.is_valid() is True


def test_consent_expired():
    gate = SafetyGate()
    c = ConsentChallenge.create("test op", [], ThreatLevel.DESTRUCTIVE)
    gate._pending_challenges[c.token] = c
    consent = gate.grant_consent(c, c.token)
    assert consent is not None
    # Force expiry by checking with max_age=0
    assert consent.is_expired(max_age_seconds=0) is True


def test_consent_not_expired():
    gate = SafetyGate()
    c = ConsentChallenge.create("test op", [], ThreatLevel.DESTRUCTIVE)
    gate._pending_challenges[c.token] = c
    consent = gate.grant_consent(c, c.token)
    assert consent is not None
    assert consent.is_expired(max_age_seconds=300) is False


def test_challenge_single_use():
    gate = SafetyGate()
    c = ConsentChallenge.create("test op", [], ThreatLevel.DESTRUCTIVE)
    gate._pending_challenges[c.token] = c
    first = gate.grant_consent(c, c.token)
    assert first is not None
    # Second attempt with same challenge — should fail (removed from pending)
    second = gate.grant_consent(c, c.token)
    assert second is None


def test_custom_consent_provider():
    """SafetyGate accepts a callback that provides the user's response."""
    captured_challenges = []

    def fake_provider(challenge: ConsentChallenge) -> str:
        captured_challenges.append(challenge)
        return challenge.token  # auto-approve

    gate = SafetyGate(consent_provider=fake_provider)

    from obtuse_hubris.operations import (
        DestructiveOperation,
        OperationDomain,
        OperationResult,
    )

    class DummyOp(DestructiveOperation):
        name = "dummy"
        threat_level = ThreatLevel.CATASTROPHIC
        domain = OperationDomain.LOCAL
        description = "test operation"
        reversible = False

        def execute(self, target: str, consent: UserConsent) -> OperationResult:
            return OperationResult(
                success=True, operation_name=self.name, message="ok"
            )

    op = DummyOp()
    consent = gate.request_consent(op)
    assert consent is not None
    assert consent.is_valid()
    assert len(captured_challenges) == 1
    assert captured_challenges[0].operation_description == "test operation"


def test_consent_exception_hierarchy():
    assert issubclass(ConsentExpired, ConsentRequired)
    assert issubclass(ConsentInvalid, ConsentRequired)
