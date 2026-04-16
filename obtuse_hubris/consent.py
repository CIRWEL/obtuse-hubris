"""Consent gate — unforgeable proof of human approval.

The core pattern: destructive operations require a UserConsent object
that can only be created through actual user interaction. No amount of
agent reasoning can fabricate one.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from obtuse_hubris.operations import DestructiveOperation, Operation, ThreatLevel


@dataclass(frozen=True)
class ConsentChallenge:
    """A cryptographic challenge presented to the user for confirmation."""

    token: str
    operation_description: str
    affected_resources: tuple[str, ...]
    threat_level: ThreatLevel
    timestamp: float
    _hmac_key: bytes = field(repr=False)

    @classmethod
    def create(
        cls,
        operation_description: str,
        affected_resources: list[str],
        threat_level: ThreatLevel,
    ) -> ConsentChallenge:
        """Create a new challenge with a cryptographically random token."""
        return cls(
            token=secrets.token_hex(8),
            operation_description=operation_description,
            affected_resources=tuple(affected_resources),
            threat_level=threat_level,
            timestamp=time.time(),
            _hmac_key=secrets.token_bytes(32),
        )

    def compute_signature(self, response_token: str) -> str:
        """Compute HMAC signature for a response token."""
        return hmac.new(
            self._hmac_key,
            response_token.encode(),
            hashlib.sha256,
        ).hexdigest()


@dataclass(frozen=True)
class UserConsent:
    """Proof that a human approved a specific operation.

    Cannot be forged — cryptographically bound to the challenge it
    responds to. Cannot be reused — each challenge is single-use.
    Cannot be stockpiled — expires after max_age_seconds (default 5 min).
    """

    challenge: ConsentChallenge
    response_token: str
    signature: str
    granted_at: float

    @property
    def operation_description(self) -> str:
        return self.challenge.operation_description

    @property
    def threat_level(self) -> ThreatLevel:
        return self.challenge.threat_level

    def is_valid(self) -> bool:
        """Verify that the consent signature matches the challenge."""
        expected = self.challenge.compute_signature(self.response_token)
        return hmac.compare_digest(self.signature, expected)

    def is_expired(self, max_age_seconds: float = 300.0) -> bool:
        """Consent expires after max_age_seconds. No blanket approvals."""
        return (time.time() - self.granted_at) > max_age_seconds


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ConsentRequired(Exception):
    """Raised when a destructive operation is attempted without valid consent."""

    def __init__(self, operation: DestructiveOperation, reason: str):
        self.operation = operation
        self.reason = reason
        super().__init__(
            f"BLOCKED: {operation.name} requires user consent. {reason}"
        )


class ConsentExpired(ConsentRequired):
    """Consent has expired. Get fresh approval."""

    def __init__(self, operation: DestructiveOperation):
        super().__init__(operation, "Consent has expired. Request new approval.")


class ConsentInvalid(ConsentRequired):
    """Consent signature does not match. Possible forgery attempt."""

    def __init__(self, operation: DestructiveOperation):
        super().__init__(
            operation,
            "Consent signature is invalid. "
            "This may indicate an attempt to forge consent.",
        )


class ConsentMismatch(ConsentRequired):
    """Consent was granted for a different operation."""

    def __init__(self, operation: DestructiveOperation, consent: UserConsent):
        super().__init__(
            operation,
            f"Consent was granted for '{consent.operation_description}', "
            f"not for '{operation.description}'. "
            "Each destructive operation requires its own approval.",
        )


# ---------------------------------------------------------------------------
# Default consent provider
# ---------------------------------------------------------------------------


def _default_consent_provider(challenge: ConsentChallenge) -> str:
    """Interactive terminal prompt. The default consent flow."""
    print(f"\n{'=' * 60}")
    print(f"CONSENT REQUIRED — {challenge.threat_level.name}")
    print(f"{'=' * 60}")
    print(f"\n{challenge.operation_description}\n")
    if challenge.affected_resources:
        print(f"Affected: {', '.join(challenge.affected_resources)}")
    print(f"\nTo approve, type this token: {challenge.token}")
    print(f"To deny, type anything else or press Ctrl+C.\n")
    return input("Your response: ").strip()


# ---------------------------------------------------------------------------
# SafetyGate
# ---------------------------------------------------------------------------


class SafetyGate:
    """The enforcement mechanism between intent and execution.

    Args:
        consent_provider: Callable that takes a ConsentChallenge and returns
            the user's response string. Default: interactive terminal prompt.
    """

    def __init__(
        self,
        consent_provider: Callable[[ConsentChallenge], str] | None = None,
    ) -> None:
        self._consent_provider = consent_provider or _default_consent_provider
        self._pending_challenges: dict[str, ConsentChallenge] = {}
        self.audit_log: list = []

    def request_consent(self, operation: Operation) -> UserConsent:
        """Present a consent challenge and return validated consent.

        Creates a challenge, passes it to the consent_provider callback,
        validates the response, and returns a UserConsent if approved.

        Raises:
            ConsentRequired: If the user's response doesn't match the token.
        """
        from obtuse_hubris.operations import DestructiveOperation

        challenge = ConsentChallenge.create(
            operation_description=operation.description,
            affected_resources=[],
            threat_level=operation.threat_level,
        )
        self._pending_challenges[challenge.token] = challenge

        user_response = self._consent_provider(challenge)
        consent = self.grant_consent(challenge, user_response)

        if consent is None:
            if isinstance(operation, DestructiveOperation):
                raise ConsentRequired(operation, "User denied or provided wrong token.")
            raise ValueError("Consent denied.")

        return consent

    def grant_consent(
        self, challenge: ConsentChallenge, user_response: str
    ) -> Optional[UserConsent]:
        """Validate the user's response and grant consent if correct."""
        if user_response != challenge.token:
            return None

        # Single-use: challenge must still be in pending to be consumed
        if challenge.token not in self._pending_challenges:
            return None

        self._pending_challenges.pop(challenge.token)

        signature = challenge.compute_signature(user_response)
        return UserConsent(
            challenge=challenge,
            response_token=user_response,
            signature=signature,
            granted_at=time.time(),
        )

    def execute_safe(self, operation, target: str):
        """Execute a safe operation and log it."""
        from obtuse_hubris.operations import OperationResult

        result = operation.execute(target)
        self.audit_log.append(result)
        return result

    def execute_destructive(self, operation, target: str, consent: UserConsent):
        """Execute a destructive operation with validated consent."""
        from obtuse_hubris.operations import OperationResult

        if not consent.is_valid():
            result = OperationResult(
                success=False,
                operation_name=operation.name,
                message="Consent signature invalid.",
                blocked=True,
                threat_level=operation.threat_level,
            )
            self.audit_log.append(result)
            raise ConsentInvalid(operation)

        if consent.is_expired():
            result = OperationResult(
                success=False,
                operation_name=operation.name,
                message="Consent expired.",
                blocked=True,
                threat_level=operation.threat_level,
            )
            self.audit_log.append(result)
            raise ConsentExpired(operation)

        result = operation.execute(target, consent)
        self.audit_log.append(result)
        return result

    def attempt_without_consent(self, operation, target: str):
        """Record a blocked attempt in the audit log."""
        from obtuse_hubris.operations import OperationResult

        result = OperationResult(
            success=False,
            operation_name=operation.name,
            message=f"BLOCKED: {operation.name} requires user consent. "
                    f"Threat level: {operation.threat_level.name}.",
            blocked=True,
            threat_level=operation.threat_level,
        )
        self.audit_log.append(result)
        return result
