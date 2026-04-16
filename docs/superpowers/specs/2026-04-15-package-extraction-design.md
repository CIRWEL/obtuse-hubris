# Design: Extract obtuse-hubris as an installable Python package

**Date:** 2026-04-15
**Author:** Kenny Wang + Claude
**Status:** Draft

## Goal

Make the engineering patterns in obtuse-hubris — consent gating, operation classification, trajectory-based circuit breaking — importable as a Python package, without disturbing the existing incident report narrative.

`pip install obtuse-hubris` installs the library. The README, docs, demos, hooks, and multi-language source files remain as-is.

## Non-goals

- Integration with UNITARES governance (standalone, no dependency)
- Replacing or modifying the existing `src/` demo files
- Adding runtime dependencies beyond the Python stdlib
- Building a CLI tool (the existing `make run-*` targets are sufficient)

## Package structure

```
obtuse-hubris/
├── obtuse_hubris/              # NEW — the installable package
│   ├── __init__.py             # public API re-exports
│   ├── consent.py              # ConsentChallenge, UserConsent, SafetyGate
│   ├── operations.py           # ThreatLevel, OperationDomain, operation ABCs, concrete git ops
│   ├── watchdog.py             # RiskAssessor, CircuitBreaker, Watchdog
│   └── py.typed                # PEP 561 type stub marker (empty file)
├── tests/                      # NEW — pytest suite
│   ├── test_consent.py
│   ├── test_operations.py
│   └── test_watchdog.py
├── pyproject.toml              # NEW — build metadata
├── src/                        # UNCHANGED — narrative demos
├── hooks/                      # UNCHANGED — git hooks
├── docs/                       # UNCHANGED — incident report
├── README.md                   # MODIFIED — add "Library" section
└── ...                         # all other existing files unchanged
```

## Module design

### `obtuse_hubris/consent.py`

Extracted from `src/safe_operations.py` lines 60–611. The consent gate pattern.

**Classes:**

- `ConsentChallenge` — frozen dataclass. Holds a random token, operation description, affected resources, threat level, timestamp, and HMAC key. Factory method `ConsentChallenge.create(...)`.
- `UserConsent` — frozen dataclass. Proof of human approval. Bound to a specific challenge via HMAC signature. Methods: `is_valid() -> bool`, `is_expired(max_age_seconds=300) -> bool`.
- `SafetyGate` — the enforcement layer. Maintains pending challenges and an audit log.
  - Constructor: `SafetyGate(consent_provider: Callable[[ConsentChallenge], str] | None = None)` — optional callback for obtaining user responses. Default: interactive terminal prompt via `input()`.
  - `request_consent(operation) -> UserConsent` — creates a challenge, obtains user response via the configured `consent_provider`, validates, returns consent or raises.
  - `grant_consent(challenge, user_response) -> UserConsent | None` — lower-level: validate a response against a challenge manually.
  - `execute_safe(operation, repo_path) -> OperationResult` — execute a SafeOperation, log it.
  - `execute_destructive(operation, repo_path, consent) -> OperationResult` — validate consent, execute, log.
  - `attempt_without_consent(operation, repo_path) -> OperationResult` — record a blocked attempt in the audit log.
  - `audit_log: list[OperationResult]` — immutable record of every attempt.

**Exceptions:**

- `ConsentRequired` — base, raised when destructive op attempted without valid consent
- `ConsentExpired(ConsentRequired)` — consent token has expired
- `ConsentInvalid(ConsentRequired)` — HMAC signature mismatch (possible forgery)
- `ConsentMismatch(ConsentRequired)` — consent was for a different operation

**Key change from `src/`:** `SafetyGate.__init__()` accepts an optional `consent_provider: Callable[[ConsentChallenge], str]` parameter on the constructor. This is the function that presents the challenge to a human and returns their response. Default implementation: interactive terminal prompt via `input()`. Users embedding the library in a web UI, Discord bot, MCP handler, etc. supply their own callback. Set once, used for all subsequent `request_consent()` calls.

```python
# Default: interactive terminal
gate = SafetyGate()

# Custom: web UI callback
gate = SafetyGate(consent_provider=my_web_prompt_function)
```

**Second change:** `_validate_consent` is renamed to `validate_consent` (public) so subclasses can call it in their `execute()` methods.

### `obtuse_hubris/operations.py`

Extracted from `src/safe_operations.py`. The operation type hierarchy.

**Enums:**

- `ThreatLevel` — SAFE, DESTRUCTIVE, CATASTROPHIC
- `OperationDomain` — LOCAL, REMOTE, SECURITY

**Dataclasses:**

- `OperationResult` — success, operation_name, message, blocked, threat_level

**ABCs:**

- `GitOperation(ABC)` — abstract base with properties: `name`, `threat_level`, `domain`, `description`, `reversible`
- `SafeOperation(GitOperation)` — `execute(repo_path) -> OperationResult` (no consent)
- `DestructiveOperation(GitOperation)` — `execute(repo_path, consent: UserConsent) -> OperationResult` (consent required as positional arg)

**Concrete git operations (reference implementations):**

- `InstallHistoryRewritingTool(DestructiveOperation)` — CATASTROPHIC/LOCAL
- `FilterRepo(DestructiveOperation)` — CATASTROPHIC/LOCAL
- `RemoveBranchProtection(DestructiveOperation)` — DESTRUCTIVE/SECURITY
- `ForcePush(DestructiveOperation)` — CATASTROPHIC/REMOTE
- `ResetHard(DestructiveOperation)` — DESTRUCTIVE/LOCAL
- `ReEnableBranchProtection(SafeOperation)` — SAFE/SECURITY

These are provided as examples. The intended usage pattern is subclassing `DestructiveOperation` for domain-specific operations:

```python
class DeleteCloudResource(DestructiveOperation):
    name = "delete_cloud_resource"
    threat_level = ThreatLevel.CATASTROPHIC
    domain = OperationDomain.REMOTE
    description = "Permanently delete a cloud resource and all associated data."
    reversible = False

    def execute(self, resource_id: str, consent: UserConsent) -> OperationResult:
        validate_consent(self, consent)
        # ... actual deletion logic
```

**Dropped from `src/`:** `RogueAgentAttempt`, `demonstrate_legitimate_workflow`, `main()`, and the `if __name__` block. Those stay in `src/safe_operations.py` as demo code.

### `obtuse_hubris/watchdog.py`

Extracted from `src/watchdog.py` lines 1–313. The trajectory detection and circuit breaking.

**Enums:**

- `RiskLevel` — SAFE (0), ELEVATED (1), DANGEROUS (2), CATASTROPHIC (3)
- `ActionType` — NORMAL_OPERATION, INSTALL_TOOL, REWRITE_HISTORY, MODIFY_PERMISSIONS, FORCE_PUSH, DESTRUCTIVE_RESET
- `Verdict` — ALLOW, WARN, PAUSE, KILL

**Dataclasses:**

- `Action` — agent_id, action_type, target, description, timestamp, risk_level, command
- `Assessment` — action, risk_level, verdict, reasoning, escalated

**Classes:**

- `RiskAssessor` — maps ActionType → RiskLevel via `RISK_MAP`. Method: `assess(action) -> RiskLevel`.
- `CircuitBreaker` — tracks consecutive dangerous operations. Core logic: 2+ consecutive DANGEROUS without `user_confirmed()` → escalate to CATASTROPHIC/KILL. Methods: `evaluate(action, risk_level) -> Assessment`, `user_confirmed()`.
- `Watchdog` — composes RiskAssessor + CircuitBreaker. Single entry point: `evaluate(action) -> Assessment`. Also `user_confirmed()`.

**Dropped from `src/`:** `build_incident_timeline()`, `simulate()`, all ANSI display code, `main()`. Those stay in `src/watchdog.py`.

### `obtuse_hubris/__init__.py`

Re-exports the public API:

```python
from obtuse_hubris.consent import (
    ConsentChallenge,
    ConsentRequired,
    ConsentExpired,
    ConsentInvalid,
    ConsentMismatch,
    SafetyGate,
    UserConsent,
)
from obtuse_hubris.operations import (
    DestructiveOperation,
    FilterRepo,
    ForcePush,
    GitOperation,
    InstallHistoryRewritingTool,
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
```

## `pyproject.toml`

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
Documentation = "https://github.com/CIRWEL/obtuse-hubris"
Repository = "https://github.com/CIRWEL/obtuse-hubris"
Issues = "https://github.com/CIRWEL/obtuse-hubris/issues"

[tool.hatch.build.targets.wheel]
packages = ["obtuse_hubris"]
```

Key points:
- `packages = ["obtuse_hubris"]` ensures only the library ships, not `src/`, `hooks/`, `docs/`, or `tests/`
- License is MIT (LICENSE-CODE), not CC BY 4.0 (LICENSE, which covers the prose)
- Zero dependencies

## Tests

All tests use pytest, stdlib only.

### `tests/test_consent.py`

- `test_challenge_creation` — token is non-empty, timestamp is recent
- `test_consent_grant_correct_token` — returns UserConsent when token matches
- `test_consent_grant_wrong_token` — returns None
- `test_consent_valid_signature` — `is_valid()` returns True for legitimate consent
- `test_consent_expired` — `is_expired()` returns True when `granted_at` is old
- `test_consent_not_expired` — `is_expired()` returns False when fresh
- `test_challenge_single_use` — granting consent removes challenge from pending; second grant returns None
- `test_custom_consent_provider` — SafetyGate accepts a callback, calls it with the challenge

### `tests/test_operations.py`

- `test_safe_operation_no_consent` — SafeOperation.execute() works without consent
- `test_destructive_requires_consent_signature` — DestructiveOperation.execute() signature requires consent param
- `test_destructive_with_valid_consent` — executes successfully
- `test_destructive_with_expired_consent` — raises ConsentExpired
- `test_destructive_with_invalid_consent` — raises ConsentInvalid
- `test_operation_result_blocked_flag` — OperationResult correctly reports blocked state
- `test_threat_level_ordering` — SAFE < DESTRUCTIVE < CATASTROPHIC

### `tests/test_watchdog.py`

- `test_safe_action_allows` — Verdict.ALLOW
- `test_elevated_warns` — Verdict.WARN
- `test_dangerous_pauses` — Verdict.PAUSE on first DANGEROUS
- `test_consecutive_dangerous_escalates` — 2nd consecutive DANGEROUS → KILL, escalated=True
- `test_catastrophic_kills_immediately` — Verdict.KILL
- `test_killed_session_stays_killed` — all subsequent actions return KILL
- `test_user_confirmed_resets_counter` — after user_confirmed(), next DANGEROUS is PAUSE not KILL
- `test_safe_resets_consecutive` — SAFE between two DANGEROUS prevents escalation
- `test_full_incident_timeline` — replay the 6-step incident, verify watchdog stops at step 2

## README changes

Add after the existing "Tools" section, before "Contributing":

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

## Build sequence

1. Create `obtuse_hubris/` directory with `__init__.py`, `consent.py`, `operations.py`, `watchdog.py`, `py.typed`
2. Create `pyproject.toml`
3. Create `tests/` with three test files
4. Add "Library" section to README.md
5. Verify: `python -m pytest tests/ -x -q`
6. Verify: `pip install -e .` and `python -c "from obtuse_hubris import SafetyGate"`
7. Verify: existing `make run-all` still works (no regressions to narrative demos)
