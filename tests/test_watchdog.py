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
