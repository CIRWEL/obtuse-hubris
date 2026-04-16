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
