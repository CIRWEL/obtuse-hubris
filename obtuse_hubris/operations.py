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
