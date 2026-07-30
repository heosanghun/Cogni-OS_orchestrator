"""Task schemas and state transition rules for Cogni-OS."""

from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from typing import Any

from .errors import ConfigurationError, TransitionError
from .util import parse_utc, utc_now, validate_agent_id, validate_task_id

TASK_STATES = {
    "pending",
    "claimed",
    "running",
    "blocked",
    "submitted",
    "verified",
    "rejected",
    "archived",
}

TRANSITIONS = {
    "pending": {"claimed", "submitted"},
    "claimed": {"running", "blocked"},
    "running": {"blocked", "submitted"},
    "blocked": {"pending"},
    "submitted": {"verified", "rejected"},
    "rejected": {"pending"},
    "verified": {"archived"},
    "archived": set(),
}


def new_task(
    *,
    task_id: str,
    title: str,
    description: str,
    owner: str,
    created_by: str,
    prerequisites: list[str] | None = None,
    allowed_write_roots: list[str] | None = None,
    permissions: dict[str, bool] | None = None,
    gates: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    """Create a validated task record in the pending state."""

    now = utc_now()
    record = {
        "schema_version": 1,
        "id": validate_task_id(task_id),
        "title": title.strip(),
        "description": description.strip(),
        "owner": validate_agent_id(owner),
        "created_by": validate_agent_id(created_by),
        "state": "pending",
        "revision": 1,
        "attempt": 0,
        "created_at": now,
        "updated_at": now,
        "prerequisites": prerequisites or [],
        "allowed_write_roots": allowed_write_roots or [],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
            **(permissions or {}),
        },
        "gates": {
            "require_validation": True,
            "allow_skips": False,
            "require_known_answer_check": True,
            "require_independent_verification": True,
            **(gates or {}),
        },
        "idempotency_key": idempotency_key or task_id,
        "lease": None,
        "result": None,
        "verification": None,
        "blocked_reason": None,
    }
    validate_task(record)
    return record


def validate_task(task: dict[str, Any]) -> None:
    """Validate the fields needed by Cogni-OS."""

    validate_task_id(str(task.get("id", "")))
    validate_agent_id(str(task.get("owner", "")))
    state = task.get("state")
    if state not in TASK_STATES:
        raise ConfigurationError(f"Unknown task state: {state!r}")
    if not str(task.get("title", "")).strip():
        raise ConfigurationError("Task title cannot be empty")
    if not isinstance(task.get("revision"), int) or task["revision"] < 1:
        raise ConfigurationError("Task revision must be a positive integer")
    if not isinstance(task.get("prerequisites"), list):
        raise ConfigurationError("Task prerequisites must be a list")
    if not isinstance(task.get("permissions"), dict):
        raise ConfigurationError("Task permissions must be an object")
    if not isinstance(task.get("gates"), dict):
        raise ConfigurationError("Task gates must be an object")


def transition(task: dict[str, Any], target: str, **updates: Any) -> dict[str, Any]:
    """Return a copy of a task after a legal state transition."""

    source = task["state"]
    if target not in TRANSITIONS.get(source, set()):
        raise TransitionError(f"Task {task['id']} cannot transition {source} -> {target}")
    result = deepcopy(task)
    result["state"] = target
    result["revision"] += 1
    result["updated_at"] = utc_now()
    result.update(updates)
    validate_task(result)
    return result


def lease_expired(task: dict[str, Any], now: str | None = None) -> bool:
    """Return whether an active task lease has expired."""

    lease = task.get("lease")
    if not lease:
        return False
    current = parse_utc(now or utc_now())
    return current >= parse_utc(lease["expires_at"])


def lease_expiry(seconds: int, now: str | None = None) -> str:
    """Build a UTC lease expiration timestamp."""

    if seconds < 10:
        raise ConfigurationError("Lease duration must be at least 10 seconds")
    current = parse_utc(now or utc_now())
    return (current + timedelta(seconds=seconds)).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
