"""Deployment lifecycle state machine (single source of truth for API, worker and agent)."""

from __future__ import annotations

from enum import StrEnum


class DeploymentState(StrEnum):
    RECEIVED = "received"
    VALIDATED = "validated"
    AWAITING_APPROVAL = "awaiting_approval"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    QUEUED = "queued"
    PREPARING = "preparing"
    PULLING = "pulling"
    VERIFYING = "verifying"
    STARTING = "starting"
    HEALTHCHECKING = "healthchecking"
    SWITCHING = "switching"
    SUCCEEDED = "succeeded"
    ROLLBACK_PENDING = "rollback_pending"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    CANCELLED = "cancelled"


S = DeploymentState

TERMINAL: frozenset[DeploymentState] = frozenset(
    {S.SUCCEEDED, S.ROLLED_BACK, S.FAILED, S.CANCELLED, S.BLOCKED_BY_POLICY}
)

# States in which a deployment owns the (project, environment) runtime.
# A partial unique index in PostgreSQL enforces at most one of these per environment.
ACTIVE: frozenset[DeploymentState] = frozenset(
    {S.PREPARING, S.PULLING, S.VERIFYING, S.STARTING, S.HEALTHCHECKING, S.SWITCHING, S.ROLLBACK_PENDING}
)

# States reported by the agent while executing a plan.
AGENT_REPORTABLE: frozenset[DeploymentState] = ACTIVE | {S.SUCCEEDED, S.ROLLED_BACK, S.FAILED}

_EXECUTION_ORDER = [S.PREPARING, S.PULLING, S.VERIFYING, S.STARTING, S.HEALTHCHECKING, S.SWITCHING]

TRANSITIONS: dict[DeploymentState, frozenset[DeploymentState]] = {
    S.RECEIVED: frozenset({S.VALIDATED, S.BLOCKED_BY_POLICY, S.FAILED, S.CANCELLED}),
    S.VALIDATED: frozenset({S.AWAITING_APPROVAL, S.QUEUED, S.BLOCKED_BY_POLICY, S.CANCELLED}),
    S.AWAITING_APPROVAL: frozenset({S.QUEUED, S.CANCELLED, S.BLOCKED_BY_POLICY}),
    S.QUEUED: frozenset({S.PREPARING, S.CANCELLED, S.BLOCKED_BY_POLICY, S.FAILED}),
    S.ROLLBACK_PENDING: frozenset({S.ROLLED_BACK, S.FAILED}),
}
for _i, _state in enumerate(_EXECUTION_ORDER):
    _forward = set(_EXECUTION_ORDER[_i + 1 :]) | {S.SUCCEEDED}
    TRANSITIONS[_state] = frozenset(_forward | {S.ROLLBACK_PENDING, S.ROLLED_BACK, S.FAILED, S.CANCELLED})
for _t in TERMINAL:
    TRANSITIONS[_t] = frozenset()


class InvalidTransition(ValueError):
    pass


def can_transition(current: DeploymentState, target: DeploymentState) -> bool:
    return target in TRANSITIONS[current]


def check_transition(current: DeploymentState, target: DeploymentState) -> None:
    if current == target:
        return
    if not can_transition(current, target):
        raise InvalidTransition(f"illegal deployment transition {current} -> {target}")


class ReleaseStatus(StrEnum):
    PENDING_VERIFICATION = "pending_verification"
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"


class TaskStatus(StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    DONE = "done"
    FAILED = "failed"
