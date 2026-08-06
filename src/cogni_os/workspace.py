"""Transactional workspace broker and task state machine for Cogni-OS."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from pathlib import Path
from typing import Any

from .actor_capability import authority_for_workspace
from .archive import archive_evidence_bundle
from .errors import (
    AuthorizationError,
    ConfigurationError,
    EvidenceError,
    IntegrityError,
    LeaseError,
    TransitionError,
)
from .evidence import validate_manifest, validate_submission
from .independence import (
    build_identity,
    evaluate_independence,
    identity_snapshot,
)
from .ledger import Ledger
from .lock import FileLock
from .model import lease_expired, lease_expiry, new_task, transition
from .trusted_runner import TRUSTED_RECEIPT_RESULT_KEYS, run_trusted_validations
from .util import (
    atomic_write_json,
    canonical_json,
    read_json,
    utc_now,
    validate_agent_id,
    validate_task_id,
)
from .verification_lifecycle import (
    VERIFICATION_TERMINAL_ACTIONS,
    find_verification_run,
    validate_verification_run_id,
)
from .verifier_attestation_protocol import (
    VerifierAttestationError,
    request_executor_attestation,
    verify_executor_attestation,
)

VERIFICATION_FAILURE_STAGES = frozenset(
    {
        "trusted_runner",
        "executor_attestation",
        "archive",
        "state_transition",
        "recovery",
    }
)
VERIFICATION_FAILURE_ERROR_TYPES = frozenset(
    {
        "authorization_error",
        "configuration_error",
        "evidence_error",
        "integrity_error",
        "io_error",
        "state_error",
        "timeout_error",
        "unexpected_error",
        "interrupted_error",
    }
)


def _verification_error_type(error: Exception) -> str:
    """Map an exception to a stable, non-sensitive verification category."""

    if isinstance(error, TimeoutError):
        return "timeout_error"
    if isinstance(error, EvidenceError):
        return "evidence_error"
    if isinstance(error, IntegrityError):
        return "integrity_error"
    if isinstance(error, AuthorizationError):
        return "authorization_error"
    if isinstance(error, ConfigurationError):
        return "configuration_error"
    if isinstance(error, (LeaseError, TransitionError)):
        return "state_error"
    if isinstance(error, OSError):
        return "io_error"
    return "unexpected_error"


class Workspace:
    """Coordinate multi-agents through a local evidence-gated Cogni-OS workspace."""

    CONFIG_VERSION = 1

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.control_dir = self.root / ".cogni"
        if not self.control_dir.exists() and (self.root / ".efo").exists():
            self.control_dir = self.root / ".efo"
        self.config_path = self.control_dir / "workspace.json"
        self.agents_dir = self.root / "agents"
        self.tasks_dir = self.root / "tasks"
        self.reports_dir = self.root / "reports"
        self.runs_dir = self.root / "runs"
        self.shared_dir = self.root / "shared"
        self.archive_dir = self.root / "archive"
        self.submissions_dir = self.root / "submissions"
        self.ledger = Ledger(
            self.root / "ledger" / "events.jsonl",
            self.control_dir / "locks" / "ledger.lock",
            self.control_dir / "ledger.key",
        )
        if not self.config_path.is_file():
            raise ConfigurationError(f"Not a valid Cogni-OS workspace: {self.root}")
        self.config = read_json(self.config_path)
        if self.config.get("schema_version") != self.CONFIG_VERSION:
            raise ConfigurationError("Unsupported workspace schema version")
        if self.ledger.path.exists() and self.ledger.key_path.exists():
            events = self.ledger.read()
            if events:
                self.ledger.verify()
                initialization = next(
                    (
                        event
                        for event in events
                        if event.get("action") == "workspace.initialized"
                    ),
                    None,
                )
                expected_config = (
                    initialization.get("payload", {}).get("config")
                    if initialization
                    else None
                )
                if expected_config != self.config:
                    raise IntegrityError(
                        "Workspace configuration differs from the signed ledger"
                    )

    @classmethod
    def initialize(
        cls,
        root: str | Path,
        *,
        name: str,
        orchestrator: str = "codex",
        orchestrator_control_principal: str | None = "codex-conductor",
        orchestrator_model_family: str | None = "openai-codex",
        preset: str | None = "cogni-codex-antigravity",
    ) -> Workspace:
        """Create a Cogni-OS workspace and initial agent topology."""

        root_path = Path(root).resolve()
        control_dir = root_path / ".cogni"
        config_path = control_dir / "workspace.json"
        if config_path.exists():
            raise ConfigurationError(f"Workspace already initialized: {root_path}")
        orchestrator = validate_agent_id(orchestrator)
        for directory in (
            control_dir / "locks" / "tasks",
            root_path / "agents",
            root_path / "tasks",
            root_path / "reports",
            root_path / "runs",
            root_path / "shared",
            root_path / "archive",
            root_path / "submissions",
            root_path / "ledger",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        (control_dir / ".gitignore").write_text(
            "ledger.key\nlocks/\n",
            encoding="utf-8",
        )
        (root_path / "runs" / ".gitignore").write_text(
            "*\n!.gitignore\n",
            encoding="utf-8",
        )
        config = {
            "schema_version": cls.CONFIG_VERSION,
            "workspace_id": secrets.token_hex(16),
            "name": name.strip() or root_path.name,
            "orchestrator": orchestrator,
            "created_at": utc_now(),
            "defaults": {
                "lease_seconds": 1800,
                "permissions": {
                    "gpu": False,
                    "performance_metrics": False,
                    "network": False,
                },
                "gates": {
                    "require_validation": True,
                    "allow_skips": False,
                    "require_known_answer_check": True,
                    "require_independent_verification": True,
                },
                "max_evidence_bytes": 50 * 1024 * 1024,
            },
        }
        atomic_write_json(config_path, config)
        workspace = cls(root_path)
        workspace.ledger.initialize()
        workspace.ledger.append(
            actor=orchestrator,
            action="workspace.initialized",
            task_id=None,
            payload={"config": config},
        )
        orchestrator_identity = None
        if orchestrator_control_principal or orchestrator_model_family:
            if not orchestrator_control_principal or not orchestrator_model_family:
                raise ConfigurationError(
                    "Both orchestrator_control_principal and "
                    "orchestrator_model_family are required together"
                )
            orchestrator_identity = build_identity(
                control_principal=orchestrator_control_principal,
                model_family=orchestrator_model_family,
            )
        workspace._commit_agent(
            actor=orchestrator,
            record={
                "schema_version": 2,
                "id": orchestrator,
                "role": "orchestrator",
                "mode": "manual",
                "command": None,
                "created_at": utc_now(),
                "write_roots": ["tasks", "shared", "archive"],
                "identity": orchestrator_identity,
            },
        )
        if preset == "cogni-codex-antigravity":
            # Register Antigravity primary executant worker
            workspace._commit_agent(
                actor=orchestrator,
                record={
                    "schema_version": 2,
                    "id": "antigravity",
                    "role": "worker",
                    "mode": "manual",
                    "command": None,
                    "created_at": utc_now(),
                    "write_roots": [],
                    "identity": build_identity(
                        control_principal="antigravity-executant",
                        model_family="google-antigravity",
                    ),
                },
            )
            # Register a same-family verifier candidate.  The independence
            # gate deliberately rejects it for Antigravity submissions;
            # Codex remains the accountable cross-family verifier.
            workspace._commit_agent(
                actor=orchestrator,
                record={
                    "schema_version": 2,
                    "id": "antigravity-verifier",
                    "role": "verifier",
                    "mode": "manual",
                    "command": None,
                    "created_at": utc_now(),
                    "write_roots": [],
                    "identity": build_identity(
                        control_principal="antigravity-verifier-control",
                        model_family="google-antigravity-verifier",
                    ),
                },
            )
        elif preset is not None:
            raise ConfigurationError(f"Unknown workspace preset: {preset}")
        return workspace

    @property
    def orchestrator(self) -> str:
        return str(self.config["orchestrator"])

    def authorize_actor_capability(
        self,
        *,
        actor: str,
        operation: str,
        capability_secret: str | bytes | None,
        require_actor_os_isolation: bool = False,
        task_id: str | None = None,
        run_id: str | None = None,
        task_attempt: int | None = None,
    ) -> dict[str, Any]:
        """Authenticate one privileged action outside the shared ledger trust root.

        ``actor`` is still recorded for accountability, but it is not accepted
        as authorization.  The high-entropy credential is used only in memory
        to mint and immediately consume an operation-scoped, one-time proof.
        Missing capability provisioning or credentials fail before callers
        acquire workspace locks or append ledger events.
        """

        actor = validate_agent_id(actor)
        if capability_secret is None:
            raise AuthorizationError("Actor capability credential is required")
        authority = authority_for_workspace(self)
        posture = authority.status(actor=actor)
        if posture["state"] != "provisioned":
            raise AuthorizationError(
                "CAPABILITY_UNPROVISIONED: privileged operation denied"
            )
        if require_actor_os_isolation and not posture["actor_os_isolation_proven"]:
            raise AuthorizationError(
                "CAPABILITY_UNATTESTED: release-critical operation requires an "
                "OS-separated actor principal or external secret broker"
            )
        token = authority.mint(
            actor=actor,
            operation=operation,
            credential_secret=capability_secret,
            task_id=task_id,
            run_id=run_id,
            task_attempt=task_attempt,
        )
        return authority.verify_and_consume(
            expected_actor=actor,
            expected_operation=operation,
            token=token,
            expected_task_id=task_id,
            expected_run_id=run_id,
            expected_task_attempt=task_attempt,
        )

    def _agent_path(self, agent_id: str) -> Path:
        return self.agents_dir / f"{validate_agent_id(agent_id)}.json"

    def _task_path(self, task_id: str) -> Path:
        return self.tasks_dir / f"{validate_task_id(task_id)}.json"

    def _task_lock(self, task_id: str) -> FileLock:
        target_id = validate_task_id(task_id)
        return FileLock(self.control_dir / "locks" / "tasks" / f"{target_id}.lock")

    def _creation_lock(self) -> FileLock:
        return FileLock(self.control_dir / "locks" / "task-create.lock")

    def _agent_lock(self) -> FileLock:
        return FileLock(self.control_dir / "locks" / "agent-create.lock")

    def _write_agent(self, record: dict[str, Any]) -> None:
        path = self._agent_path(record["id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        (self.reports_dir / record["id"]).mkdir(parents=True, exist_ok=True)
        (self.runs_dir / record["id"]).mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, record)

    def _commit_agent(
        self,
        *,
        actor: str,
        record: dict[str, Any],
        action: str = "agent.added",
    ) -> dict[str, Any]:
        self.ledger.append(
            actor=actor,
            action=action,
            task_id=None,
            payload={"agent": record},
        )
        self._write_agent(record)
        return record

    def add_agent(
        self,
        *,
        actor: str,
        capability_secret: str | bytes | None = None,
        agent_id: str,
        role: str = "worker",
        mode: str = "manual",
        command: list[str] | None = None,
        write_roots: list[str] | None = None,
        control_principal: str | None = None,
        model_family: str | None = None,
        alias_of: str | None = None,
    ) -> dict[str, Any]:
        """Register a new agent in the workspace."""
        if actor != self.orchestrator:
            raise AuthorizationError("Only the orchestrator can register agents")
        self.authorize_actor_capability(
            actor=actor,
            operation="agent.add",
            capability_secret=capability_secret,
        )
        with self._agent_lock():
            target_id = validate_agent_id(agent_id)
            if self._agent_path(target_id).exists():
                raise ConfigurationError(f"Agent already exists: {target_id}")
            if role not in {"orchestrator", "worker", "verifier", "advisor"}:
                raise ConfigurationError(f"Invalid agent role: {role}")
            if mode not in {"manual", "command"}:
                raise ConfigurationError(f"Invalid agent mode: {mode}")

            identity = None
            if alias_of:
                target_agent = self.get_agent(alias_of)
                if not target_agent.get("identity"):
                    raise ConfigurationError(
                        f"Alias target agent {alias_of} has no identity"
                    )
                identity = build_identity(
                    control_principal=target_agent["identity"]["control_principal"],
                    model_family=target_agent["identity"]["model_family"],
                    alias_of=validate_agent_id(alias_of),
                    alias_chain=[
                        validate_agent_id(alias_of),
                        *target_agent["identity"].get("alias_chain", []),
                    ],
                )
            elif control_principal or model_family:
                if not control_principal or not model_family:
                    raise ConfigurationError(
                        "control_principal and model_family must be provided together"
                    )
                identity = build_identity(
                    control_principal=control_principal,
                    model_family=model_family,
                )

            record = {
                "schema_version": 2,
                "id": target_id,
                "role": role,
                "mode": mode,
                "command": command,
                "created_at": utc_now(),
                "write_roots": write_roots or [],
                "identity": identity,
            }
            return self._commit_agent(actor=actor, record=record)

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        """Get an agent configuration record by ID."""
        path = self._agent_path(agent_id)
        if not path.is_file():
            raise ConfigurationError(f"Agent not found: {agent_id}")
        return read_json(path)

    def list_agents(self) -> list[dict[str, Any]]:
        """List all registered agents."""
        agents = []
        for path in sorted(self.agents_dir.glob("*.json")):
            try:
                agents.append(read_json(path))
            except ConfigurationError:
                continue
        return agents

    def add_task(
        self,
        *,
        actor: str,
        capability_secret: str | bytes | None = None,
        task_id: str,
        title: str,
        description: str,
        owner: str,
        prerequisites: list[str] | None = None,
        allowed_write_roots: list[str] | None = None,
        permissions: dict[str, bool] | None = None,
        gates: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Create a new pending task in the workspace."""
        if actor != self.orchestrator:
            raise AuthorizationError("Only the orchestrator can create tasks")
        self.authorize_actor_capability(
            actor=actor,
            operation="task.add",
            capability_secret=capability_secret,
        )
        with self._creation_lock():
            target_id = validate_task_id(task_id)
            if self._task_path(target_id).exists():
                raise ConfigurationError(f"Task already exists: {target_id}")
            self.get_agent(owner)
            normalized_prerequisites = [
                validate_task_id(str(item)) for item in (prerequisites or [])
            ]
            if target_id in normalized_prerequisites:
                raise ConfigurationError("A task cannot depend on itself")
            if len(normalized_prerequisites) != len(set(normalized_prerequisites)):
                raise ConfigurationError("Task prerequisites cannot contain duplicates")
            missing_prerequisites = [
                item
                for item in normalized_prerequisites
                if not self._task_path(item).is_file()
            ]
            if missing_prerequisites:
                raise ConfigurationError(
                    "Task prerequisites do not exist: "
                    + ", ".join(missing_prerequisites)
                )
            record = new_task(
                task_id=target_id,
                title=title,
                description=description,
                owner=owner,
                created_by=actor,
                prerequisites=normalized_prerequisites,
                allowed_write_roots=allowed_write_roots,
                permissions=permissions,
                gates=gates,
                idempotency_key=idempotency_key,
            )
            self.ledger.append(
                actor=actor,
                action="task.created",
                task_id=target_id,
                payload={"task": record},
            )
            atomic_write_json(self._task_path(target_id), record)
            return record

    def get_task(self, task_id: str) -> dict[str, Any]:
        """Get a task record by ID."""
        path = self._task_path(task_id)
        if not path.is_file():
            raise ConfigurationError(f"Task not found: {task_id}")
        return read_json(path)

    def list_tasks(self) -> list[dict[str, Any]]:
        """List all tasks in the workspace."""
        tasks = []
        for path in sorted(self.tasks_dir.glob("*.json")):
            try:
                tasks.append(read_json(path))
            except ConfigurationError:
                continue
        return tasks

    def _unsatisfied_prerequisites(self, task: dict[str, Any]) -> list[str]:
        """Return prerequisite IDs that are not independently verified."""
        unsatisfied: list[str] = []
        for prerequisite_id in task.get("prerequisites", []):
            try:
                prerequisite = self.get_task(str(prerequisite_id))
            except ConfigurationError:
                unsatisfied.append(f"{prerequisite_id}:missing")
                continue
            if prerequisite.get("state") not in {"verified", "archived"}:
                unsatisfied.append(
                    f"{prerequisite_id}:{prerequisite.get('state', 'unknown')}"
                )
        return unsatisfied

    def claim(
        self,
        *,
        actor: str,
        task_id: str | None = None,
        lease_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Atomically claim a pending task or a specific task."""
        actor = validate_agent_id(actor)
        self.get_agent(actor)
        duration = lease_seconds or self.config["defaults"]["lease_seconds"]

        candidates = [self.get_task(task_id)] if task_id else self.list_tasks()
        for task in candidates:
            if task["owner"] != actor:
                continue
            if task["state"] != "pending":
                continue
            with self._task_lock(task["id"]):
                current = self.get_task(task["id"])
                if current["state"] != "pending":
                    continue
                unsatisfied = self._unsatisfied_prerequisites(current)
                if unsatisfied:
                    if task_id:
                        raise LeaseError(
                            "Task prerequisites are not verified: "
                            + ", ".join(unsatisfied)
                        )
                    continue
                lease_token = secrets.token_hex(16)
                issued_at = utc_now()
                lease = {
                    "holder": actor,
                    "session_id": secrets.token_hex(16),
                    "issued_at": issued_at,
                    "token_hash": hashlib.sha256(
                        lease_token.encode("ascii")
                    ).hexdigest(),
                    "expires_at": lease_expiry(duration, now=issued_at),
                    "duration_seconds": duration,
                }
                updated = transition(
                    current, "claimed", attempt=current["attempt"] + 1, lease=lease
                )
                self.ledger.append(
                    actor=actor,
                    action="task.claimed",
                    task_id=task["id"],
                    payload={"task": updated},
                )
                atomic_write_json(self._task_path(task["id"]), updated)
                return {"task": updated, "lease_token": lease_token}
        raise LeaseError("No matching claimable task available")

    def recover_lease(
        self,
        *,
        actor: str,
        task_id: str,
        reason: str,
        force: bool = False,
        capability_secret: str | bytes | None = None,
    ) -> dict[str, Any]:
        """Requeue an expired task lease using signed session evidence.

        Normal recovery cannot preempt a healthy lease.  Exceptional forced
        recovery is fail-closed until an actor-capability authority validates
        ``capability_secret``; it uses a distinct signed event when enabled.
        Neither path reads, replaces, or records the bearer token, and the
        original attempt is preserved.
        """

        target_id = validate_task_id(task_id)
        actor = validate_agent_id(actor)
        if actor != self.orchestrator:
            raise AuthorizationError(
                "Only the accountable orchestrator can recover a task lease"
            )
        normalized_reason = reason.strip() if isinstance(reason, str) else ""
        if not normalized_reason:
            raise EvidenceError("Lease recovery reason must be non-empty")
        capability_receipt = None

        with self._task_lock(target_id):
            task = self.get_task(target_id)
            events = self.ledger.read_verified()
            source_event = next(
                (
                    event
                    for event in reversed(events)
                    if event.get("task_id") == target_id
                    and isinstance(event.get("payload", {}).get("task"), dict)
                ),
                None,
            )
            signed_task = (
                source_event.get("payload", {}).get("task")
                if isinstance(source_event, dict)
                else None
            )
            if signed_task != task:
                raise IntegrityError(
                    "Task projection differs from the signed ledger before recovery"
                )
            if task["state"] not in {"claimed", "running"}:
                raise TransitionError(
                    f"Task {target_id} lease cannot be recovered from "
                    f"state {task['state']}"
                )
            lease = task.get("lease")
            if not isinstance(lease, dict):
                raise LeaseError("Active task has no recoverable lease metadata")
            holder = lease.get("holder")
            expires_at = lease.get("expires_at")
            session_id = lease.get("session_id")
            issued_at = lease.get("issued_at")
            if not isinstance(holder, str) or not holder:
                raise LeaseError("Active task lease holder is invalid")
            if not isinstance(expires_at, str) or not expires_at:
                raise LeaseError("Active task lease expiration is invalid")
            session_is_valid = (
                isinstance(session_id, str)
                and len(session_id) == 32
                and all(character in "0123456789abcdef" for character in session_id)
            )
            if not force and not session_is_valid:
                raise LeaseError("Active task has no signed recovery session identity")
            if not force and (not isinstance(issued_at, str) or not issued_at):
                raise LeaseError("Active task has no signed lease issue time")
            if source_event is None or source_event.get("action") not in {
                "task.claimed",
                "task.started",
                "task.heartbeat",
            }:
                raise IntegrityError(
                    "Latest signed active task event is not liveness evidence"
                )
            if source_event.get("actor") != holder:
                raise IntegrityError(
                    "Signed liveness event actor differs from the lease holder"
                )
            try:
                expired = lease_expired(task)
            except (KeyError, TypeError, ValueError) as error:
                raise LeaseError("Active task lease expiration is invalid") from error
            if not force and not expired:
                raise LeaseError("A healthy task lease cannot be recovered")

            previous_state = task["state"]
            previous_attempt = task["attempt"]
            if (
                not isinstance(previous_attempt, int)
                or isinstance(previous_attempt, bool)
                or previous_attempt < 1
            ):
                raise IntegrityError("Active task attempt is invalid")
            if force:
                capability_receipt = self.authorize_actor_capability(
                    actor=actor,
                    operation="task.recover_lease.force",
                    capability_secret=capability_secret,
                    require_actor_os_isolation=True,
                    task_id=target_id,
                    run_id=session_id if session_is_valid else None,
                    task_attempt=previous_attempt,
                )
            blocked = transition(
                task,
                "blocked",
                lease=None,
                blocked_reason=normalized_reason,
            )
            requeued = transition(
                blocked,
                "pending",
                lease=None,
                blocked_reason=None,
            )
            if requeued["attempt"] != previous_attempt:
                raise IntegrityError("Lease recovery changed the task attempt")

            self.ledger.append(
                actor=actor,
                action=(
                    "task.lease_force_recovered" if force else "task.lease_recovered"
                ),
                task_id=target_id,
                payload={
                    "schema_version": 2,
                    "recovery_mode": "forced" if force else "expired_lease",
                    "reason": normalized_reason,
                    "previous_state": previous_state,
                    "previous_holder": holder,
                    "previous_expires_at": expires_at,
                    "previous_attempt": previous_attempt,
                    "liveness_evidence": {
                        "kind": (
                            "forced_capability_override"
                            if force
                            else "signed_activity_plus_expired_lease"
                        ),
                        "session_id": session_id if session_is_valid else None,
                        "issued_at": issued_at,
                        "lease_expired": expired,
                        "source_action": source_event["action"],
                        "source_sequence": source_event["sequence"],
                        "source_event_hash": source_event["event_hash"],
                        "observed_at": utc_now(),
                    },
                    "capability_receipt": capability_receipt,
                    "transition": {
                        "from": previous_state,
                        "via": "blocked",
                        "to": "pending",
                    },
                    "task": requeued,
                },
            )
            atomic_write_json(self._task_path(target_id), requeued)
            return requeued

    def _check_lease(self, task: dict[str, Any], actor: str, lease_token: str) -> None:
        lease = task.get("lease")
        if not lease or lease["holder"] != actor:
            raise LeaseError("Actor does not hold the lease for this task")
        token_hash = hashlib.sha256(lease_token.encode("ascii")).hexdigest()
        if not hmac.compare_digest(lease["token_hash"], token_hash):
            raise LeaseError("Invalid lease token")
        if lease_expired(task):
            raise LeaseError("Task lease has expired")

    def start(self, *, actor: str, task_id: str, lease_token: str) -> dict[str, Any]:
        """Transition task from claimed to running."""
        with self._task_lock(task_id):
            task = self.get_task(task_id)
            self._check_lease(task, actor, lease_token)
            updated = transition(task, "running")
            self.ledger.append(
                actor=actor,
                action="task.started",
                task_id=task_id,
                payload={"task": updated},
            )
            atomic_write_json(self._task_path(task_id), updated)
            return updated

    def heartbeat(
        self, *, actor: str, task_id: str, lease_token: str
    ) -> dict[str, Any]:
        """Extend the lease expiration for a running task."""
        with self._task_lock(task_id):
            task = self.get_task(task_id)
            self._check_lease(task, actor, lease_token)
            if task["state"] not in {"claimed", "running"}:
                raise TransitionError(f"Cannot heartbeat task in state {task['state']}")
            duration = task["lease"]["duration_seconds"]
            task["lease"]["expires_at"] = lease_expiry(duration)
            task["updated_at"] = utc_now()
            self.ledger.append(
                actor=actor,
                action="task.heartbeat",
                task_id=task_id,
                payload={"task": task},
            )
            atomic_write_json(self._task_path(task_id), task)
            return task

    def block(
        self,
        *,
        actor: str,
        task_id: str,
        lease_token: str,
        reason: str,
    ) -> dict[str, Any]:
        """Block a task and release its lease."""
        with self._task_lock(task_id):
            task = self.get_task(task_id)
            self._check_lease(task, actor, lease_token)
            updated = transition(
                task,
                "blocked",
                lease=None,
                blocked_reason=reason.strip(),
            )
            self.ledger.append(
                actor=actor,
                action="task.blocked",
                task_id=task_id,
                payload={"task": updated, "reason": reason.strip()},
            )
            atomic_write_json(self._task_path(task_id), updated)
            return updated

    def submit(
        self,
        *,
        actor: str,
        task_id: str,
        lease_token: str,
        report_path: str | Path,
        evidence_path: str | Path,
    ) -> dict[str, Any]:
        """Submit report and evidence manifest for verification."""
        with self._task_lock(task_id):
            task = self.get_task(task_id)
            self._check_lease(task, actor, lease_token)
            r_path = Path(report_path).resolve()
            e_path = Path(evidence_path).resolve()
            validated = validate_submission(
                r_path,
                e_path,
                permissions=task["permissions"],
                gates=task["gates"],
                allowed_root=self.reports_dir / actor,
            )
            worker_agent = self.get_agent(actor)
            worker_identity = identity_snapshot(actor, worker_agent.get("identity"))
            result = {
                "submitted_at": utc_now(),
                "submitted_by": actor,
                "report": validated["report"],
                "manifest": validated["manifest"],
            }
            updated = transition(task, "submitted", lease=None, result=result)
            bundle = archive_evidence_bundle(
                submissions_root=self.submissions_dir,
                task_id=task_id,
                attempt=updated["attempt"],
                label="worker",
                report=validated["report"],
                manifest=validated["manifest"],
                max_artifact_bytes=self.config["defaults"]["max_evidence_bytes"],
            )
            self.ledger.append(
                actor=actor,
                action="task.submitted",
                task_id=task_id,
                payload={
                    "task": updated,
                    "worker_identity": worker_identity,
                    "bundle": bundle,
                },
            )
            atomic_write_json(self._task_path(task_id), updated)
            return updated

    def verify(
        self,
        *,
        actor: str,
        capability_secret: str | bytes | None = None,
        task_id: str,
        decision: str,
        note: str,
        evidence_path: str | Path | None = None,
        timeout_seconds: int = 300,
    ) -> dict[str, Any]:
        """Independently verify or reject a submitted task."""
        if decision not in {"accept", "reject"}:
            raise ConfigurationError(
                "Verification decision must be 'accept' or 'reject'"
            )
        if not note.strip():
            raise EvidenceError("Verification note must be non-empty")
        if evidence_path is None:
            raise EvidenceError("Verifier evidence manifest is required")
        verifier_agent = self.get_agent(actor)
        if verifier_agent["role"] not in {"verifier", "orchestrator"}:
            raise AuthorizationError("Actor role is not authorized for verification")

        with self._task_lock(task_id):
            task = self.get_task(task_id)
            if task["state"] != "submitted":
                raise TransitionError(
                    f"Task {task_id} is not submitted for verification"
                )

            target_state = "verified" if decision == "accept" else "rejected"
            verifier_identity = identity_snapshot(actor, verifier_agent.get("identity"))

            # Fetch worker identity and reserve a run ID from one verified
            # ledger snapshot before recording the new lifecycle event.
            events = self.ledger.read_verified()
            submitted_event = next(
                (
                    e
                    for e in reversed(events)
                    if e.get("action") == "task.submitted"
                    and e.get("task_id") == task_id
                ),
                None,
            )
            worker_identity = (
                submitted_event.get("payload", {}).get("worker_identity")
                if submitted_event
                else None
            )
            independence = evaluate_independence(worker_identity, verifier_identity)

            if not independence["independent"]:
                raise AuthorizationError(
                    f"Independent verification failed: {', '.join(independence['reasons'])}"
                )

            verifier_evidence = validate_manifest(
                Path(evidence_path).resolve(),
                permissions=task["permissions"],
                gates=task["gates"],
                require_command_argv=True,
                allowed_root=self.reports_dir / actor,
            )
            worker_manifest_sha = (
                task.get("result", {}).get("manifest", {}).get("manifest_sha256")
            )
            if isinstance(worker_manifest_sha, str) and hmac.compare_digest(
                worker_manifest_sha.lower(),
                verifier_evidence["manifest_sha256"].lower(),
            ):
                raise EvidenceError(
                    "Verifier evidence must be independently produced, not the "
                    "worker submission manifest"
                )
            used_run_ids = {
                event.get("payload", {}).get("run_id")
                for event in events
                if event.get("action", "").startswith("verification.")
            }
            run_id = ""
            for _ in range(8):
                candidate = secrets.token_hex(16)
                if candidate not in used_run_ids:
                    run_id = candidate
                    break
            if not run_id:
                raise IntegrityError("Could not allocate a unique verification run ID")
            capability_receipt = self.authorize_actor_capability(
                actor=actor,
                operation="task.verify",
                capability_secret=capability_secret,
                require_actor_os_isolation=True,
                task_id=task_id,
                run_id=run_id,
                task_attempt=task["attempt"],
            )
            verification_contract_inputs_sha256 = hashlib.sha256(
                canonical_json(
                    {
                        "task_id": task_id,
                        "task_attempt": task["attempt"],
                        "run_id": run_id,
                        "actor": actor,
                        "verifier_identity": verifier_identity,
                        "verifier_manifest_sha256": verifier_evidence[
                            "manifest_sha256"
                        ],
                        "worker_manifest_sha256": worker_manifest_sha,
                        "permissions": task["permissions"],
                        "gates": task["gates"],
                    }
                )
            ).hexdigest()
            self.ledger.append(
                actor=actor,
                action="verification.started",
                task_id=task_id,
                payload={
                    "schema_version": 1,
                    "run_id": run_id,
                    "task_attempt": task["attempt"],
                    "verifier_manifest_sha256": verifier_evidence["manifest_sha256"],
                    "worker_manifest_sha256": worker_manifest_sha,
                    "verifier_identity": verifier_identity,
                    "verification_contract_inputs_sha256": (
                        verification_contract_inputs_sha256
                    ),
                    "capability_receipt": capability_receipt,
                },
            )
            try:
                trusted_validation = run_trusted_validations(
                    workspace_root=self.root,
                    runs_root=self.runs_dir,
                    task_id=task_id,
                    attempt=task["attempt"],
                    actor=actor,
                    run_id=run_id,
                    manifest=verifier_evidence,
                    gpu_allowed=bool(task["permissions"].get("gpu", False)),
                    network_allowed=bool(task["permissions"].get("network", False)),
                    timeout_seconds=timeout_seconds,
                )
            except Exception as error:
                self._record_verification_failure(
                    actor=actor,
                    task_id=task_id,
                    run_id=run_id,
                    task_attempt=task["attempt"],
                    stage="trusted_runner",
                    error=error,
                    capability_receipt=capability_receipt,
                    verification_contract_inputs_sha256=(
                        verification_contract_inputs_sha256
                    ),
                )
                raise
            try:
                if not isinstance(trusted_validation, dict):
                    raise VerifierAttestationError(
                        "Trusted runner result is not an object"
                    )
                if set(trusted_validation) != TRUSTED_RECEIPT_RESULT_KEYS:
                    raise VerifierAttestationError(
                        "Trusted runner result schema is invalid"
                    )
                trusted_validations = trusted_validation["validations"]
                if not isinstance(trusted_validations, list):
                    raise VerifierAttestationError(
                        "Trusted runner validations must be a list"
                    )
                executor_attestation = request_executor_attestation(
                    receipt=trusted_validation,
                    verifier_identity=verifier_identity,
                )
                verify_executor_attestation(
                    executor_attestation,
                    receipt=trusted_validation,
                    verifier_identity=verifier_identity,
                )
            except Exception as error:
                self._record_verification_failure(
                    actor=actor,
                    task_id=task_id,
                    run_id=run_id,
                    task_attempt=task["attempt"],
                    stage="executor_attestation",
                    error=error,
                    capability_receipt=capability_receipt,
                    verification_contract_inputs_sha256=(
                        verification_contract_inputs_sha256
                    ),
                )
                raise
            try:
                trusted_files = [
                    {
                        "path": trusted_validation["receipt_path"],
                        "sha256": trusted_validation["receipt_sha256"],
                        "kind": "trusted_runner_receipt",
                        "force": True,
                    },
                    *[
                        {
                            "path": validation["output_path"],
                            "sha256": validation["output_sha256"],
                            "kind": "trusted_runner_output",
                            "force": True,
                        }
                        for validation in trusted_validations
                    ],
                ]
                verifier_bundle = archive_evidence_bundle(
                    submissions_root=self.submissions_dir,
                    task_id=task_id,
                    attempt=task["attempt"],
                    label="verifier",
                    report=None,
                    manifest=verifier_evidence,
                    max_artifact_bytes=self.config["defaults"]["max_evidence_bytes"],
                    extra_files=trusted_files,
                )
            except Exception as error:
                self._record_verification_failure(
                    actor=actor,
                    task_id=task_id,
                    run_id=run_id,
                    task_attempt=task["attempt"],
                    stage="archive",
                    error=error,
                    capability_receipt=capability_receipt,
                    verification_contract_inputs_sha256=(
                        verification_contract_inputs_sha256
                    ),
                )
                raise

            verification_record = {
                "run_id": run_id,
                "verified_at": utc_now(),
                "verified_by": actor,
                "decision": decision,
                "note": note.strip(),
                "independence": independence,
                "verifier_evidence": {
                    "manifest_sha256": verifier_evidence["manifest_sha256"],
                    "bundle": verifier_bundle,
                    "executor_attestation": executor_attestation,
                },
                "trusted_validation": trusted_validation,
                "verifier_identity": verifier_identity,
                "worker_manifest_sha256": worker_manifest_sha,
                "verification_contract_inputs_sha256": (
                    verification_contract_inputs_sha256
                ),
                "capability_receipt": capability_receipt,
            }
            try:
                updated = transition(
                    task,
                    target_state,
                    verification=verification_record,
                )
            except Exception as error:
                self._record_verification_failure(
                    actor=actor,
                    task_id=task_id,
                    run_id=run_id,
                    task_attempt=task["attempt"],
                    stage="state_transition",
                    error=error,
                    capability_receipt=capability_receipt,
                    verification_contract_inputs_sha256=(
                        verification_contract_inputs_sha256
                    ),
                )
                raise
            self.ledger.append(
                actor=actor,
                action=f"task.{target_state}",
                task_id=task_id,
                payload={
                    "run_id": run_id,
                    "task": updated,
                    "verifier_identity": verifier_identity,
                    "independence": independence,
                    "verifier_evidence": verification_record["verifier_evidence"],
                    "trusted_validation": trusted_validation,
                    "worker_manifest_sha256": worker_manifest_sha,
                    "verification_contract_inputs_sha256": (
                        verification_contract_inputs_sha256
                    ),
                    "capability_receipt": capability_receipt,
                },
            )
            atomic_write_json(self._task_path(task_id), updated)
            return updated

    def _record_verification_failure(
        self,
        *,
        actor: str,
        task_id: str,
        run_id: str,
        task_attempt: int,
        stage: str,
        error: Exception,
        capability_receipt: dict[str, Any],
        verification_contract_inputs_sha256: str,
    ) -> None:
        """Append a redacted terminal event for a started verification run."""

        if stage not in VERIFICATION_FAILURE_STAGES:
            raise IntegrityError("Verification failure stage is not allowlisted")
        error_type = _verification_error_type(error)
        if error_type not in VERIFICATION_FAILURE_ERROR_TYPES:
            raise IntegrityError("Verification failure type is not allowlisted")
        events = self.ledger.read_verified()
        try:
            started, terminals = find_verification_run(
                events,
                task_id=task_id,
                run_id=run_id,
            )
        except ValueError as failure:
            raise IntegrityError(str(failure)) from failure
        if started is None:
            raise IntegrityError("Verification failure has no signed started event")
        if started.get("payload", {}).get("task_attempt") != task_attempt:
            raise IntegrityError(
                "Verification failure attempt differs from started run"
            )
        if len(terminals) > 1:
            raise IntegrityError(
                "Verification run already has multiple terminal events"
            )
        if terminals:
            if terminals[0].get("action") == "verification.failed":
                return
            raise IntegrityError("Verification run already has a task terminal event")
        self.ledger.append(
            actor=actor,
            action="verification.failed",
            task_id=task_id,
            payload={
                "schema_version": 1,
                "run_id": run_id,
                "task_attempt": task_attempt,
                "stage": stage,
                "error_type": error_type,
                "verifier_identity": started.get("payload", {}).get(
                    "verifier_identity"
                ),
                "verifier_manifest_sha256": started.get("payload", {}).get(
                    "verifier_manifest_sha256"
                ),
                "worker_manifest_sha256": started.get("payload", {}).get(
                    "worker_manifest_sha256"
                ),
                "verification_contract_inputs_sha256": (
                    verification_contract_inputs_sha256
                ),
                "capability_receipt": capability_receipt,
            },
        )

    @staticmethod
    def _signed_task_projection(
        events: list[dict[str, Any]], task_id: str
    ) -> dict[str, Any]:
        """Return the latest task snapshot from one verified ledger read."""

        snapshot = next(
            (
                event.get("payload", {}).get("task")
                for event in reversed(events)
                if event.get("task_id") == task_id
                and isinstance(event.get("payload", {}).get("task"), dict)
            ),
            None,
        )
        if not isinstance(snapshot, dict) or snapshot.get("id") != task_id:
            raise IntegrityError("Signed task projection is missing or malformed")
        return snapshot

    def reconcile_verification(
        self,
        *,
        actor: str,
        capability_secret: str | bytes | None = None,
        task_id: str,
        run_id: str,
    ) -> dict[str, Any]:
        """Idempotently close an orphan run or rebuild its task projection.

        Reconciliation never executes validation commands.  A run with no
        terminal event is closed as an interrupted failure.  A run that already
        has one terminal event only replays the latest signed task snapshot to
        the mutable projection file.
        """

        actor = validate_agent_id(actor)
        if actor != self.orchestrator:
            raise AuthorizationError(
                "Only the accountable orchestrator can reconcile verification"
            )
        target_id = validate_task_id(task_id)
        try:
            target_run_id = validate_verification_run_id(run_id)
        except ValueError as error:
            raise ConfigurationError(str(error)) from error
        with self._task_lock(target_id):
            events = self.ledger.read_verified()
            try:
                started, terminals = find_verification_run(
                    events,
                    task_id=target_id,
                    run_id=target_run_id,
                )
            except ValueError as error:
                raise IntegrityError(str(error)) from error
            if started is None:
                raise EvidenceError("Verification run has no signed started event")
            if len(terminals) > 1:
                raise IntegrityError(
                    "Verification run has more than one terminal event"
                )

            task_attempt = started.get("payload", {}).get("task_attempt")
            if (
                not isinstance(task_attempt, int)
                or isinstance(task_attempt, bool)
                or task_attempt < 1
            ):
                raise IntegrityError("Verification started event has invalid attempt")
            capability_receipt = self.authorize_actor_capability(
                actor=actor,
                operation="task.reconcile_verification",
                capability_secret=capability_secret,
                require_actor_os_isolation=True,
                task_id=target_id,
                run_id=target_run_id,
                task_attempt=task_attempt,
            )

            appended_terminal = False
            terminal = terminals[0] if terminals else None
            if terminal is None:
                terminal = self.ledger.append(
                    actor=actor,
                    action="verification.failed",
                    task_id=target_id,
                    payload={
                        "schema_version": 1,
                        "run_id": target_run_id,
                        "task_attempt": task_attempt,
                        "stage": "recovery",
                        "error_type": "interrupted_error",
                        "started_sequence": started["sequence"],
                        "started_event_hash": started["event_hash"],
                        "started_actor": started.get("actor"),
                        "verifier_identity": started.get("payload", {}).get(
                            "verifier_identity"
                        ),
                        "verifier_manifest_sha256": started.get("payload", {}).get(
                            "verifier_manifest_sha256"
                        ),
                        "worker_manifest_sha256": started.get("payload", {}).get(
                            "worker_manifest_sha256"
                        ),
                        "verification_contract_inputs_sha256": started.get(
                            "payload", {}
                        ).get("verification_contract_inputs_sha256"),
                        "started_capability_receipt": started.get("payload", {}).get(
                            "capability_receipt"
                        ),
                        "recovered_by": actor,
                        "capability_receipt": capability_receipt,
                    },
                )
                appended_terminal = True
                events = [*events, terminal]
            else:
                terminal_attempt = terminal.get("payload", {}).get("task_attempt")
                if terminal_attempt is None:
                    terminal_task = terminal.get("payload", {}).get("task")
                    if isinstance(terminal_task, dict):
                        terminal_attempt = terminal_task.get("attempt")
                if terminal_attempt != task_attempt:
                    raise IntegrityError(
                        "Verification terminal attempt differs from started run"
                    )
                if terminal.get("action") not in VERIFICATION_TERMINAL_ACTIONS:
                    raise IntegrityError("Verification terminal action is unsupported")

            authoritative_task = self._signed_task_projection(events, target_id)
            projection_path = self._task_path(target_id)
            projection_changed = True
            try:
                projection_changed = read_json(projection_path) != authoritative_task
            except (FileNotFoundError, ConfigurationError):
                projection_changed = True
            if projection_changed:
                atomic_write_json(projection_path, authoritative_task)

            return {
                "schema_version": 1,
                "task_id": target_id,
                "run_id": target_run_id,
                "terminal_action": terminal["action"],
                "terminal_sequence": terminal["sequence"],
                "terminal_appended": appended_terminal,
                "projection_rebuilt": projection_changed,
                "task": authoritative_task,
            }

    def restate_verification(
        self,
        *,
        actor: str,
        capability_secret: str | bytes | None = None,
        task_id: str,
        effective_status: str,
        reason: str,
        target_sequence: int | None = None,
    ) -> dict[str, Any]:
        """Append a signed correction without rewriting historical task evidence.

        A restatement never mutates the task snapshot or the verification event it
        references.  Consumers must treat the later signed event as the effective
        trust status while retaining the original claim for audit and replay.
        """

        if actor != self.orchestrator:
            raise AuthorizationError(
                "Only the accountable orchestrator can restate verification trust"
            )
        if effective_status not in {
            "verification_disputed",
            "verification_revoked",
        }:
            raise ConfigurationError(
                "Effective verification status must be verification_disputed or "
                "verification_revoked"
            )
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise EvidenceError("Verification restatement reason must be non-empty")
        if target_sequence is not None and (
            not isinstance(target_sequence, int)
            or isinstance(target_sequence, bool)
            or target_sequence < 1
        ):
            raise ConfigurationError(
                "Target verification sequence must be a positive integer"
            )

        with self._task_lock(task_id):
            self.get_task(task_id)
            events = self.ledger.read_verified()
            candidates = [
                event
                for event in events
                if event.get("action") == "task.verified"
                and event.get("task_id") == task_id
            ]
            if target_sequence is None:
                target = candidates[-1] if candidates else None
            else:
                target = next(
                    (
                        event
                        for event in candidates
                        if event.get("sequence") == target_sequence
                    ),
                    None,
                )
            if target is None:
                raise EvidenceError(
                    f"No task.verified event found for {task_id}"
                    + (
                        ""
                        if target_sequence is None
                        else f" at sequence {target_sequence}"
                    )
                )

            target_task = target.get("payload", {}).get("task")
            target_verification = (
                target_task.get("verification")
                if isinstance(target_task, dict)
                else None
            )
            target_run_id = (
                target_verification.get("run_id")
                if isinstance(target_verification, dict)
                else None
            )
            target_attempt = (
                target_task.get("attempt") if isinstance(target_task, dict) else None
            )
            if target_run_id is not None:
                try:
                    validate_verification_run_id(target_run_id)
                except (TypeError, ValueError) as error:
                    raise IntegrityError(
                        "Target verification has an invalid run binding"
                    ) from error
            if (
                not isinstance(target_attempt, int)
                or isinstance(target_attempt, bool)
                or target_attempt < 1
            ):
                raise IntegrityError(
                    "Target verification lacks a valid attempt binding"
                )
            capability_receipt = self.authorize_actor_capability(
                actor=actor,
                operation="task.restate_verification",
                capability_secret=capability_secret,
                require_actor_os_isolation=True,
                task_id=task_id,
                run_id=target_run_id,
                task_attempt=target_attempt,
            )

            target_hash = str(target.get("event_hash", ""))
            for event in reversed(events):
                if event.get("action") != "verification.restatement":
                    continue
                payload = event.get("payload", {})
                if (
                    payload.get("target_verification_sequence")
                    != target.get("sequence")
                    or payload.get("target_verification_hash") != target_hash
                ):
                    continue
                previous_status = payload.get("effective_status")
                if (
                    previous_status == effective_status
                    and payload.get("reason") == normalized_reason
                ):
                    return event
                if previous_status == "verification_revoked":
                    raise TransitionError(
                        "A revoked verification cannot be restored or weakened"
                    )
                break

            return self.ledger.append(
                actor=actor,
                action="verification.restatement",
                task_id=task_id,
                payload={
                    "schema_version": 1,
                    "target_verification_sequence": target["sequence"],
                    "target_verification_hash": target_hash,
                    "original_verifier": target.get("actor"),
                    "effective_status": effective_status,
                    "reason": normalized_reason,
                    "capability_receipt": capability_receipt,
                },
            )

    def status(self) -> dict[str, Any]:
        """Return operational status summary for Cogni-OS."""
        tasks = self.list_tasks()
        counts = {
            state: 0
            for state in (
                "pending",
                "claimed",
                "running",
                "blocked",
                "submitted",
                "verified",
                "rejected",
                "archived",
            )
        }
        for t in tasks:
            state = t.get("state")
            if state in counts:
                counts[state] += 1
        ledger_info = self.ledger.verify()
        return {
            "workspace": str(self.root),
            "name": self.config["name"],
            "orchestrator": self.orchestrator,
            "total_tasks": len(tasks),
            "states": counts,
            "ledger": ledger_info,
        }

    def audit_projections(self) -> dict[str, Any]:
        """Check consistency between event stream and projected task files."""
        events = self.ledger.read()
        self.ledger.verify()
        projected = self.ledger.projected_tasks()
        actual = {t["id"]: t for t in self.list_tasks()}
        mismatches = []
        for tid, ptask in projected.items():
            atask = actual.get(tid)
            if atask != ptask:
                mismatches.append(tid)
        return {
            "valid": len(mismatches) == 0,
            "events_count": len(events),
            "projected_count": len(projected),
            "actual_count": len(actual),
            "mismatches": mismatches,
        }
