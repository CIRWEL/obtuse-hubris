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
