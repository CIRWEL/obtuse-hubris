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
