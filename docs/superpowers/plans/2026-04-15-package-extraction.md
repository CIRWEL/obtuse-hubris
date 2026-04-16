# obtuse-hubris Package Extraction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make obtuse-hubris's consent gate, operation hierarchy, and watchdog importable as a `pip install`-able Python package without disturbing the existing incident report.

**Architecture:** New `obtuse_hubris/` package directory alongside existing `src/`. Three modules extracted from `src/safe_operations.py` and `src/watchdog.py` — narrative/demo code stays in `src/`, importable library code lives in `obtuse_hubris/`. TDD throughout: tests first, then implementation extracted from the existing working code.

**Tech Stack:** Python 3.10+ stdlib only. hatchling build backend. pytest for tests.

**Spec:** `docs/superpowers/specs/2026-04-15-package-extraction-design.md`

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `obtuse_hubris/__init__.py` | Public API re-exports |
| Create | `obtuse_hubris/consent.py` | ConsentChallenge, UserConsent, SafetyGate, exceptions |
| Create | `obtuse_hubris/operations.py` | ThreatLevel, OperationDomain, operation ABCs, concrete git ops, validate_consent |
| Create | `obtuse_hubris/watchdog.py` | RiskLevel, ActionType, Verdict, Action, Assessment, RiskAssessor, CircuitBreaker, Watchdog |
| Create | `obtuse_hubris/py.typed` | PEP 561 marker (empty) |
| Create | `pyproject.toml` | Build metadata, hatchling config |
| Create | `tests/test_consent.py` | Consent gate tests |
| Create | `tests/test_operations.py` | Operation hierarchy tests |
| Create | `tests/test_watchdog.py` | Watchdog/circuit breaker tests |
| Modify | `README.md` | Add "Library" section |
| Modify | `LICENSE-CODE` | Add `obtuse_hubris/` to scope |

---

### Task 1: Project scaffolding — pyproject.toml and empty package

**Files:**
- Create: `pyproject.toml`
- Create: `obtuse_hubris/__init__.py`
- Create: `obtuse_hubris/py.typed`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "obtuse-hubris"
version = "0.1.0"
description = "Structural safety enforcement for AI agent tool access"
readme = "README.md"
license = "MIT"
license-files = ["LICENSE-CODE"]
requires-python = ">=3.10"
authors = [
    { name = "Kenny Wang", email = "hikewa@gmail.com" },
]
keywords = ["ai-safety", "agent", "governance", "consent", "tool-safety"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Topic :: Software Development :: Libraries",
    "Topic :: Security",
    "Typing :: Typed",
]

[project.urls]
Homepage = "https://github.com/CIRWEL/obtuse-hubris"
Repository = "https://github.com/CIRWEL/obtuse-hubris"
Issues = "https://github.com/CIRWEL/obtuse-hubris/issues"

[tool.hatch.build.targets.wheel]
packages = ["obtuse_hubris"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create empty `obtuse_hubris/__init__.py`**

```python
"""obtuse-hubris: Structural safety enforcement for AI agent tool access."""
```

- [ ] **Step 3: Create empty `obtuse_hubris/py.typed`**

Empty file (PEP 561 marker).

- [ ] **Step 4: Verify editable install works**

Run: `cd /tmp/obtuse-hubris && pip install -e . 2>&1 | tail -3`
Expected: "Successfully installed obtuse-hubris-0.1.0"

Run: `python3 -c "import obtuse_hubris; print(obtuse_hubris.__doc__)"`
Expected: "obtuse-hubris: Structural safety enforcement for AI agent tool access."

- [ ] **Step 5: Verify existing demos still work**

Run: `cd /tmp/obtuse-hubris && python3 src/rogue_agent.py 2>&1 | head -3`
Expected: starts with "User: *pastes GitHub message..."

- [ ] **Step 6: Commit**

```bash
cd /tmp/obtuse-hubris
git add pyproject.toml obtuse_hubris/__init__.py obtuse_hubris/py.typed
git commit -m "chore: add pyproject.toml and empty package scaffold"
```

---

### Task 2: `obtuse_hubris/operations.py` — enums, result, ABCs

The operations module has no dependencies on consent (consent imports come in Task 4 when we add the concrete ops). Build the foundation first.

**Files:**
- Create: `tests/test_operations.py` (partial — enums and ABCs only)
- Create: `obtuse_hubris/operations.py` (partial — enums, OperationResult, ABCs only)

- [ ] **Step 1: Write tests for enums, OperationResult, and ABCs**

Create `tests/test_operations.py`:

```python
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
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/test_operations.py -x -q 2>&1 | tail -5`
Expected: ImportError or ModuleNotFoundError

- [ ] **Step 3: Implement `obtuse_hubris/operations.py` — enums, result, ABCs**

Create `obtuse_hubris/operations.py`:

```python
"""Operation classification and type-safe execution hierarchy.

Extracted from the obtuse-hubris incident report. The core pattern:
SafeOperation can execute freely. DestructiveOperation requires a
UserConsent object as a positional argument — the type signature
makes "doing this without permission" a runtime exception.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from obtuse_hubris.consent import UserConsent


class ThreatLevel(Enum):
    """Classifies the reversibility and blast radius of an operation."""
    SAFE = auto()
    DESTRUCTIVE = auto()
    CATASTROPHIC = auto()


class OperationDomain(Enum):
    """Where the operation's effects are felt."""
    LOCAL = auto()
    REMOTE = auto()
    SECURITY = auto()


@dataclass
class OperationResult:
    """The outcome of an operation attempt."""
    success: bool
    operation_name: str
    message: str
    blocked: bool = False
    threat_level: ThreatLevel = ThreatLevel.SAFE

    def __str__(self) -> str:
        status = "BLOCKED" if self.blocked else ("OK" if self.success else "FAILED")
        return f"[{status}] {self.operation_name}: {self.message}"


class Operation(ABC):
    """Base class for all operations.

    Subclass SafeOperation for routine actions or DestructiveOperation
    for actions that require user consent.
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def threat_level(self) -> ThreatLevel: ...

    @property
    @abstractmethod
    def domain(self) -> OperationDomain: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def reversible(self) -> bool: ...


class SafeOperation(Operation):
    """Operations that are routine and reversible. No consent required."""

    @abstractmethod
    def execute(self, target: str) -> OperationResult: ...


class DestructiveOperation(Operation):
    """Operations that require a UserConsent object to execute.

    The consent parameter is a required positional argument.
    """

    @abstractmethod
    def execute(self, target: str, consent: UserConsent) -> OperationResult: ...
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/test_operations.py -x -q`
Expected: 8 passed

- [ ] **Step 5: Commit**

```bash
cd /tmp/obtuse-hubris
git add obtuse_hubris/operations.py tests/test_operations.py
git commit -m "feat: add operation enums, result dataclass, and ABCs"
```

---

### Task 3: `obtuse_hubris/consent.py` — consent gate

**Files:**
- Create: `tests/test_consent.py`
- Create: `obtuse_hubris/consent.py`

- [ ] **Step 1: Write consent tests**

Create `tests/test_consent.py`:

```python
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
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/test_consent.py -x -q 2>&1 | tail -5`
Expected: ImportError

- [ ] **Step 3: Implement `obtuse_hubris/consent.py`**

Create `obtuse_hubris/consent.py`:

```python
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

        self._pending_challenges.pop(challenge.token, None)

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
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/test_consent.py -x -q`
Expected: 9 passed

- [ ] **Step 5: Commit**

```bash
cd /tmp/obtuse-hubris
git add obtuse_hubris/consent.py tests/test_consent.py
git commit -m "feat: add consent gate — challenge, consent, safety gate"
```

---

### Task 4: Concrete git operations + `validate_consent`

Now that consent.py exists, add the concrete operations that depend on UserConsent at runtime.

**Files:**
- Modify: `obtuse_hubris/operations.py` — add `validate_consent` and 6 concrete ops
- Modify: `tests/test_operations.py` — add tests for concrete ops

- [ ] **Step 1: Write tests for validate_consent and concrete operations**

Append to `tests/test_operations.py`:

```python
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
```

- [ ] **Step 2: Run new tests — verify they fail**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/test_operations.py::test_validate_consent_passes -x -q 2>&1 | tail -5`
Expected: ImportError (validate_consent not defined yet)

- [ ] **Step 3: Add `validate_consent` and concrete ops to `obtuse_hubris/operations.py`**

Append to the end of `obtuse_hubris/operations.py`:

```python
# ---------------------------------------------------------------------------
# Consent validation — public so subclasses can use it
# ---------------------------------------------------------------------------


def validate_consent(operation: DestructiveOperation, consent: UserConsent) -> None:
    """Validate consent before executing a destructive operation.

    Raises:
        ConsentInvalid: If the HMAC signature doesn't verify.
        ConsentExpired: If the consent has expired.
    """
    from obtuse_hubris.consent import ConsentExpired, ConsentInvalid, UserConsent as UC

    if not consent.is_valid():
        raise ConsentInvalid(operation)
    if consent.is_expired():
        raise ConsentExpired(operation)


# ---------------------------------------------------------------------------
# Concrete git operations — reference implementations
# ---------------------------------------------------------------------------


class InstallHistoryRewritingTool(DestructiveOperation):
    """Installing a history-rewriting tool like git-filter-repo."""

    name = "install_history_rewriting_tool"
    threat_level = ThreatLevel.CATASTROPHIC
    domain = OperationDomain.LOCAL
    description = (
        "Install a tool that rewrites entire repository history, "
        "modifying every commit object and changing all SHA hashes."
    )
    reversible = False

    def __init__(self, tool_name: str = "git-filter-repo"):
        self.tool_name = tool_name

    def execute(self, target: str, consent: UserConsent) -> OperationResult:
        validate_consent(self, consent)
        return OperationResult(
            success=True,
            operation_name=self.name,
            message=f"Installed {self.tool_name} with user consent.",
            threat_level=self.threat_level,
        )


class FilterRepo(DestructiveOperation):
    """Rewriting repository history with git-filter-repo."""

    name = "filter_repo"
    threat_level = ThreatLevel.CATASTROPHIC
    domain = OperationDomain.LOCAL
    description = (
        "Rewrite every commit in the repository using git-filter-repo. "
        "Creates entirely new commit objects with new SHA hashes."
    )
    reversible = False

    def __init__(self, callback: str = "", force: bool = False):
        self.callback = callback
        self.force = force

    def execute(self, target: str, consent: UserConsent) -> OperationResult:
        validate_consent(self, consent)
        return OperationResult(
            success=True,
            operation_name=self.name,
            message=f"Rewrote history in {target} with user consent.",
            threat_level=self.threat_level,
        )


class RemoveBranchProtection(DestructiveOperation):
    """Removing branch protection from a repository."""

    name = "remove_branch_protection"
    threat_level = ThreatLevel.DESTRUCTIVE
    domain = OperationDomain.SECURITY
    description = (
        "Remove branch protection rules, disabling force-push prevention "
        "and required reviews."
    )
    reversible = True

    def __init__(self, owner: str = "", repo: str = "", branch: str = "main"):
        self.owner = owner
        self.repo = repo
        self.branch = branch

    def execute(self, target: str, consent: UserConsent) -> OperationResult:
        validate_consent(self, consent)
        return OperationResult(
            success=True,
            operation_name=self.name,
            message=f"Removed branch protection on {self.owner}/{self.repo}:{self.branch}.",
            threat_level=self.threat_level,
        )


class ForcePush(DestructiveOperation):
    """Force-pushing to a remote repository."""

    name = "force_push"
    threat_level = ThreatLevel.CATASTROPHIC
    domain = OperationDomain.REMOTE
    description = (
        "Force-push to a remote repository, replacing its entire history "
        "with the local version."
    )
    reversible = False

    def __init__(self, remote: str = "origin", branch: str = "main"):
        self.remote = remote
        self.branch = branch

    def execute(self, target: str, consent: UserConsent) -> OperationResult:
        validate_consent(self, consent)
        return OperationResult(
            success=True,
            operation_name=self.name,
            message=f"Force-pushed {target} to {self.remote}/{self.branch}.",
            threat_level=self.threat_level,
        )


class ResetHard(DestructiveOperation):
    """Hard reset, discarding all uncommitted changes."""

    name = "reset_hard"
    threat_level = ThreatLevel.DESTRUCTIVE
    domain = OperationDomain.LOCAL
    description = (
        "Discard ALL uncommitted changes. Not recoverable."
    )
    reversible = False

    def __init__(self, ref: str = "HEAD"):
        self.ref = ref

    def execute(self, target: str, consent: UserConsent) -> OperationResult:
        validate_consent(self, consent)
        return OperationResult(
            success=True,
            operation_name=self.name,
            message=f"Reset {target} to {self.ref}.",
            threat_level=self.threat_level,
        )


class ReEnableBranchProtection(SafeOperation):
    """Re-enabling branch protection. Always safe — no consent required."""

    name = "re_enable_branch_protection"
    threat_level = ThreatLevel.SAFE
    domain = OperationDomain.SECURITY
    description = "Re-enable branch protection rules."
    reversible = True

    def __init__(self, owner: str = "", repo: str = "", branch: str = "main"):
        self.owner = owner
        self.repo = repo
        self.branch = branch

    def execute(self, target: str) -> OperationResult:
        return OperationResult(
            success=True,
            operation_name=self.name,
            message=f"Re-enabled branch protection on {self.owner}/{self.repo}:{self.branch}.",
            threat_level=self.threat_level,
        )
```

- [ ] **Step 4: Run all operations tests**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/test_operations.py -x -q`
Expected: 14 passed

- [ ] **Step 5: Commit**

```bash
cd /tmp/obtuse-hubris
git add obtuse_hubris/operations.py tests/test_operations.py
git commit -m "feat: add validate_consent and concrete git operations"
```

---

### Task 5: `obtuse_hubris/watchdog.py` — trajectory detection

**Files:**
- Create: `tests/test_watchdog.py`
- Create: `obtuse_hubris/watchdog.py`

- [ ] **Step 1: Write watchdog tests**

Create `tests/test_watchdog.py`:

```python
"""Tests for obtuse_hubris.watchdog — trajectory-based circuit breaking."""

from obtuse_hubris.watchdog import (
    Action,
    ActionType,
    Assessment,
    CircuitBreaker,
    RiskAssessor,
    RiskLevel,
    Verdict,
    Watchdog,
)


def _action(action_type: ActionType, target: str = "repo") -> Action:
    return Action(
        agent_id="test-agent",
        action_type=action_type,
        target=target,
        description=f"test {action_type.name}",
    )


def test_safe_action_allows():
    w = Watchdog()
    a = w.evaluate(_action(ActionType.NORMAL_OPERATION))
    assert a.verdict == Verdict.ALLOW
    assert a.risk_level == RiskLevel.SAFE


def test_elevated_warns():
    w = Watchdog()
    a = w.evaluate(_action(ActionType.INSTALL_TOOL))
    assert a.verdict == Verdict.WARN
    assert a.risk_level == RiskLevel.ELEVATED


def test_dangerous_pauses():
    w = Watchdog()
    a = w.evaluate(_action(ActionType.REWRITE_HISTORY))
    assert a.verdict == Verdict.PAUSE
    assert a.risk_level == RiskLevel.DANGEROUS


def test_consecutive_dangerous_escalates():
    w = Watchdog()
    a1 = w.evaluate(_action(ActionType.REWRITE_HISTORY))
    assert a1.verdict == Verdict.PAUSE

    a2 = w.evaluate(_action(ActionType.MODIFY_PERMISSIONS))
    assert a2.verdict == Verdict.KILL
    assert a2.escalated is True
    assert a2.risk_level == RiskLevel.CATASTROPHIC


def test_catastrophic_kills_immediately():
    w = Watchdog()
    a = w.evaluate(_action(ActionType.FORCE_PUSH))
    assert a.verdict == Verdict.KILL
    assert a.risk_level == RiskLevel.CATASTROPHIC


def test_killed_session_stays_killed():
    w = Watchdog()
    w.evaluate(_action(ActionType.FORCE_PUSH))  # kills session
    a = w.evaluate(_action(ActionType.NORMAL_OPERATION))
    assert a.verdict == Verdict.KILL


def test_user_confirmed_resets_counter():
    w = Watchdog()
    a1 = w.evaluate(_action(ActionType.REWRITE_HISTORY))
    assert a1.verdict == Verdict.PAUSE

    w.user_confirmed()

    a2 = w.evaluate(_action(ActionType.MODIFY_PERMISSIONS))
    assert a2.verdict == Verdict.PAUSE  # PAUSE, not KILL — counter was reset


def test_safe_resets_consecutive():
    w = Watchdog()
    w.evaluate(_action(ActionType.REWRITE_HISTORY))  # PAUSE
    w.user_confirmed()  # reset counter
    w.evaluate(_action(ActionType.NORMAL_OPERATION))  # SAFE resets counter too
    a = w.evaluate(_action(ActionType.REWRITE_HISTORY))
    assert a.verdict == Verdict.PAUSE  # not KILL


def test_full_incident_timeline():
    """Replay the Feb 25 incident — watchdog should stop at step 2."""
    w = Watchdog()
    steps = [
        ActionType.INSTALL_TOOL,       # step 1: WARN
        ActionType.REWRITE_HISTORY,    # step 2: PAUSE (first DANGEROUS)
        ActionType.REWRITE_HISTORY,    # step 3: would be KILL (consecutive)
        ActionType.MODIFY_PERMISSIONS, # step 4: already dead
        ActionType.FORCE_PUSH,         # step 5: already dead
        ActionType.DESTRUCTIVE_RESET,  # step 6: already dead
    ]

    results = []
    for step_type in steps:
        a = w.evaluate(_action(step_type))
        results.append(a)

    # Step 1: WARN (elevated, not dangerous)
    assert results[0].verdict == Verdict.WARN
    # Step 2: PAUSE (first dangerous)
    assert results[1].verdict == Verdict.PAUSE
    # Step 3: KILL (second consecutive dangerous — user never confirmed)
    assert results[2].verdict == Verdict.KILL
    assert results[2].escalated is True
    # Steps 4-6: all KILL (session is dead)
    for r in results[3:]:
        assert r.verdict == Verdict.KILL


def test_watchdog_logs_all_assessments():
    w = Watchdog()
    w.evaluate(_action(ActionType.NORMAL_OPERATION))
    w.evaluate(_action(ActionType.INSTALL_TOOL))
    assert len(w.log) == 2


def test_risk_assessor_maps_correctly():
    assessor = RiskAssessor()
    assert assessor.assess(_action(ActionType.NORMAL_OPERATION)) == RiskLevel.SAFE
    assert assessor.assess(_action(ActionType.INSTALL_TOOL)) == RiskLevel.ELEVATED
    assert assessor.assess(_action(ActionType.REWRITE_HISTORY)) == RiskLevel.DANGEROUS
    assert assessor.assess(_action(ActionType.FORCE_PUSH)) == RiskLevel.CATASTROPHIC
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/test_watchdog.py -x -q 2>&1 | tail -5`
Expected: ImportError

- [ ] **Step 3: Implement `obtuse_hubris/watchdog.py`**

Create `obtuse_hubris/watchdog.py`:

```python
"""Watchdog — trajectory-based circuit breaking for agent actions.

Detects dangerous behavioral trajectories, not just individual actions.
An agent that chains DANGEROUS operations without user confirmation is
on a trajectory. The circuit breaker recognizes trajectories and
escalates accordingly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Optional


class RiskLevel(Enum):
    """How dangerous an action is."""
    SAFE = 0
    ELEVATED = 1
    DANGEROUS = 2
    CATASTROPHIC = 3


class ActionType(Enum):
    """Categories of agent operations, ranked by destructive potential."""
    NORMAL_OPERATION = auto()
    INSTALL_TOOL = auto()
    REWRITE_HISTORY = auto()
    MODIFY_PERMISSIONS = auto()
    FORCE_PUSH = auto()
    DESTRUCTIVE_RESET = auto()


class Verdict(Enum):
    """What the watchdog decides to do."""
    ALLOW = auto()
    WARN = auto()
    PAUSE = auto()
    KILL = auto()


@dataclass
class Action:
    """A single operation attempted by an agent."""
    agent_id: str
    action_type: ActionType
    target: str
    description: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_level: Optional[RiskLevel] = None
    command: Optional[str] = None


@dataclass
class Assessment:
    """The watchdog's evaluation of an action."""
    action: Action
    risk_level: RiskLevel
    verdict: Verdict
    reasoning: str
    escalated: bool = False


class RiskAssessor:
    """Maps action types to risk levels."""

    RISK_MAP: dict[ActionType, RiskLevel] = {
        ActionType.NORMAL_OPERATION: RiskLevel.SAFE,
        ActionType.INSTALL_TOOL: RiskLevel.ELEVATED,
        ActionType.REWRITE_HISTORY: RiskLevel.DANGEROUS,
        ActionType.MODIFY_PERMISSIONS: RiskLevel.DANGEROUS,
        ActionType.FORCE_PUSH: RiskLevel.CATASTROPHIC,
        ActionType.DESTRUCTIVE_RESET: RiskLevel.DANGEROUS,
    }

    def assess(self, action: Action) -> RiskLevel:
        """Determine the risk level of an action."""
        risk = self.RISK_MAP.get(action.action_type, RiskLevel.SAFE)
        action.risk_level = risk
        return risk


class CircuitBreaker:
    """Enforces escalating responses to dangerous agent behavior.

    Key design: consecutive DANGEROUS operations without user confirmation
    escalate to CATASTROPHIC. The circuit breaker recognizes trajectories,
    not just individual actions.
    """

    def __init__(self) -> None:
        self.consecutive_dangerous: int = 0
        self.total_dangerous: int = 0
        self.total_catastrophic: int = 0
        self.session_killed: bool = False
        self.history: list[Assessment] = []

    def evaluate(self, action: Action, risk_level: RiskLevel) -> Assessment:
        """Decide what to do about this action."""
        if self.session_killed:
            return self._record(Assessment(
                action=action,
                risk_level=risk_level,
                verdict=Verdict.KILL,
                reasoning="Session already terminated.",
            ))

        if risk_level == RiskLevel.SAFE:
            self.consecutive_dangerous = 0
            return self._record(Assessment(
                action=action,
                risk_level=risk_level,
                verdict=Verdict.ALLOW,
                reasoning="Routine operation.",
            ))

        if risk_level == RiskLevel.ELEVATED:
            return self._record(Assessment(
                action=action,
                risk_level=risk_level,
                verdict=Verdict.WARN,
                reasoning="Elevated risk detected. Monitoring.",
            ))

        if risk_level == RiskLevel.DANGEROUS:
            self.consecutive_dangerous += 1
            self.total_dangerous += 1

            if self.consecutive_dangerous >= 2:
                self.session_killed = True
                self.total_catastrophic += 1
                return self._record(Assessment(
                    action=action,
                    risk_level=RiskLevel.CATASTROPHIC,
                    verdict=Verdict.KILL,
                    reasoning=(
                        f"{self.consecutive_dangerous} consecutive DANGEROUS "
                        f"operations without user confirmation. "
                        f"Session terminated."
                    ),
                    escalated=True,
                ))

            return self._record(Assessment(
                action=action,
                risk_level=risk_level,
                verdict=Verdict.PAUSE,
                reasoning="DANGEROUS operation detected. User must confirm.",
            ))

        if risk_level == RiskLevel.CATASTROPHIC:
            self.session_killed = True
            self.total_catastrophic += 1
            return self._record(Assessment(
                action=action,
                risk_level=risk_level,
                verdict=Verdict.KILL,
                reasoning="CATASTROPHIC operation detected. Session terminated.",
            ))

        return self._record(Assessment(
            action=action,
            risk_level=risk_level,
            verdict=Verdict.PAUSE,
            reasoning="Unknown risk level. Pausing.",
        ))

    def user_confirmed(self) -> None:
        """Record that the user explicitly confirmed the paused action."""
        self.consecutive_dangerous = 0

    def _record(self, assessment: Assessment) -> Assessment:
        self.history.append(assessment)
        return assessment


class Watchdog:
    """Governance layer that sits between agent and tools.

    Every action passes through evaluate(). The agent cannot bypass it.
    """

    def __init__(self) -> None:
        self.assessor = RiskAssessor()
        self.breaker = CircuitBreaker()
        self.log: list[Assessment] = []

    def evaluate(self, action: Action) -> Assessment:
        """Evaluate an action and return the verdict."""
        risk_level = self.assessor.assess(action)
        assessment = self.breaker.evaluate(action, risk_level)
        self.log.append(assessment)
        return assessment

    def user_confirmed(self) -> None:
        """User explicitly authorized the paused action."""
        self.breaker.user_confirmed()
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/test_watchdog.py -x -q`
Expected: 12 passed

- [ ] **Step 5: Commit**

```bash
cd /tmp/obtuse-hubris
git add obtuse_hubris/watchdog.py tests/test_watchdog.py
git commit -m "feat: add watchdog with trajectory-based circuit breaking"
```

---

### Task 6: `__init__.py` re-exports and full integration test

**Files:**
- Modify: `obtuse_hubris/__init__.py` — add all re-exports
- Modify: `tests/test_operations.py` — add import-from-root test

- [ ] **Step 1: Write integration import test**

Append to `tests/test_operations.py`:

```python
def test_public_api_importable_from_root():
    """All public names should be importable from obtuse_hubris directly."""
    from obtuse_hubris import (
        # consent
        ConsentChallenge,
        ConsentRequired,
        ConsentExpired,
        ConsentInvalid,
        ConsentMismatch,
        SafetyGate,
        UserConsent,
        # operations
        DestructiveOperation,
        FilterRepo,
        ForcePush,
        InstallHistoryRewritingTool,
        Operation,
        OperationDomain,
        OperationResult,
        ReEnableBranchProtection,
        RemoveBranchProtection,
        ResetHard,
        SafeOperation,
        ThreatLevel,
        validate_consent,
        # watchdog
        Action,
        ActionType,
        Assessment,
        CircuitBreaker,
        RiskAssessor,
        RiskLevel,
        Verdict,
        Watchdog,
    )
    # If we get here, all imports succeeded
    assert SafetyGate is not None
    assert Watchdog is not None
```

- [ ] **Step 2: Run test — verify it fails**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/test_operations.py::test_public_api_importable_from_root -x -q 2>&1 | tail -5`
Expected: ImportError (empty __init__.py)

- [ ] **Step 3: Update `obtuse_hubris/__init__.py`**

```python
"""obtuse-hubris: Structural safety enforcement for AI agent tool access."""

from obtuse_hubris.consent import (
    ConsentChallenge,
    ConsentExpired,
    ConsentInvalid,
    ConsentMismatch,
    ConsentRequired,
    SafetyGate,
    UserConsent,
)
from obtuse_hubris.operations import (
    DestructiveOperation,
    FilterRepo,
    ForcePush,
    InstallHistoryRewritingTool,
    Operation,
    OperationDomain,
    OperationResult,
    ReEnableBranchProtection,
    RemoveBranchProtection,
    ResetHard,
    SafeOperation,
    ThreatLevel,
    validate_consent,
)
from obtuse_hubris.watchdog import (
    Action,
    ActionType,
    Assessment,
    CircuitBreaker,
    RiskAssessor,
    RiskLevel,
    Verdict,
    Watchdog,
)

__all__ = [
    # consent
    "ConsentChallenge",
    "ConsentExpired",
    "ConsentInvalid",
    "ConsentMismatch",
    "ConsentRequired",
    "SafetyGate",
    "UserConsent",
    # operations
    "DestructiveOperation",
    "FilterRepo",
    "ForcePush",
    "InstallHistoryRewritingTool",
    "Operation",
    "OperationDomain",
    "OperationResult",
    "ReEnableBranchProtection",
    "RemoveBranchProtection",
    "ResetHard",
    "SafeOperation",
    "ThreatLevel",
    "validate_consent",
    # watchdog
    "Action",
    "ActionType",
    "Assessment",
    "CircuitBreaker",
    "RiskAssessor",
    "RiskLevel",
    "Verdict",
    "Watchdog",
]
```

- [ ] **Step 4: Run full test suite**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/ -x -q`
Expected: all tests pass (consent: 9, operations: 15, watchdog: 12 = 36 total)

- [ ] **Step 5: Commit**

```bash
cd /tmp/obtuse-hubris
git add obtuse_hubris/__init__.py tests/test_operations.py
git commit -m "feat: wire up __init__.py re-exports for public API"
```

---

### Task 7: README and LICENSE-CODE updates

**Files:**
- Modify: `README.md` — add "Library" section
- Modify: `LICENSE-CODE` — add `obtuse_hubris/` to scope

- [ ] **Step 1: Update LICENSE-CODE scope**

Add `obtuse_hubris/` to the scope list at the bottom of `LICENSE-CODE`. Change:

```
This license applies to:
- src/ (all source code: Python, Rust, Go, Prolog)
- hooks/ (all git hook scripts and install.sh)
```

To:

```
This license applies to:
- obtuse_hubris/ (installable Python package)
- src/ (all source code: Python, Rust, Go, Prolog)
- hooks/ (all git hook scripts and install.sh)
- tests/ (test suite)
```

- [ ] **Step 2: Add "Library" section to README.md**

Insert after the "Tools" section (line ~183, before "Contributing"), this block:

```markdown
## Library

The safety patterns in this report are also an installable Python package.

### Install

```bash
pip install obtuse-hubris
```

### Usage

```python
from obtuse_hubris import SafetyGate, ForcePush

gate = SafetyGate()
op = ForcePush(remote="origin", branch="main")

# This flow requires actual human input — the agent can't skip it
consent = gate.request_consent(op)
result = gate.execute_destructive(op, "/path/to/repo", consent)
```

### Custom operations

Subclass `DestructiveOperation` for your own domain:

```python
from obtuse_hubris import DestructiveOperation, ThreatLevel, OperationDomain, UserConsent, OperationResult

class DropTable(DestructiveOperation):
    name = "drop_table"
    threat_level = ThreatLevel.CATASTROPHIC
    domain = OperationDomain.REMOTE
    description = "Drop a database table and all its data."
    reversible = False

    def execute(self, table_name: str, consent: UserConsent) -> OperationResult:
        # consent is validated by the gate before this is called
        ...
```

### Watchdog

Monitor agent behavior trajectories:

```python
from obtuse_hubris import Watchdog, Action, ActionType, Verdict

watchdog = Watchdog()

action = Action(
    agent_id="my-agent",
    action_type=ActionType.REWRITE_HISTORY,
    target="main-repo",
    description="Rewriting commit history",
)

assessment = watchdog.evaluate(action)
if assessment.verdict == Verdict.KILL:
    # terminate the agent session
    ...
```

See [`src/`](src/) for full demonstrations.
```

- [ ] **Step 3: Commit**

```bash
cd /tmp/obtuse-hubris
git add LICENSE-CODE README.md
git commit -m "docs: add Library section to README, update LICENSE-CODE scope"
```

---

### Task 8: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cd /tmp/obtuse-hubris && python3 -m pytest tests/ -v`
Expected: 36 tests pass, 0 fail

- [ ] **Step 2: Verify editable install**

Run: `cd /tmp/obtuse-hubris && pip install -e . 2>&1 | tail -3`

Run: `python3 -c "from obtuse_hubris import SafetyGate, Watchdog, ForcePush; print('OK')" `
Expected: "OK"

- [ ] **Step 3: Verify existing demos unchanged**

Run: `cd /tmp/obtuse-hubris && python3 src/rogue_agent.py 2>&1 | head -3`
Expected: starts with "User: *pastes GitHub message..."

Run: `cd /tmp/obtuse-hubris && python3 -m src.safe_operations 2>&1 | head -3`
Expected: starts with "=" * 72

Run: `cd /tmp/obtuse-hubris && python3 src/watchdog.py 2>&1 | head -3`
Expected: ANSI-colored output starting with "="

- [ ] **Step 4: Verify wheel builds**

Run: `cd /tmp/obtuse-hubris && pip install build && python3 -m build --wheel 2>&1 | tail -3`
Expected: wheel created in `dist/`

Run: `unzip -l dist/obtuse_hubris-0.1.0-py3-none-any.whl | head -15`
Expected: contains `obtuse_hubris/` files only, no `src/`, `hooks/`, `docs/`

- [ ] **Step 5: Final commit if any fixups needed**

```bash
cd /tmp/obtuse-hubris
git status
# Only commit if there are changes from fixups
```
