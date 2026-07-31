"""Transactional workspace broker and task state machine for Cogni-OS."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from copy import deepcopy
from pathlib import Path
from typing import Any

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
    audit_verification_events,
    build_identity,
    evaluate_independence,
    identity_snapshot,
)
from .ledger import Ledger
from .lock import FileLock
from .model import lease_expired, lease_expiry, new_task, transition, validate_task
from .provenance import (
    validate_git_commit,
    validate_git_provenance,
    validate_git_source_claim,
)
from .trusted_runner import run_trusted_validations
from .util import (
    atomic_write_json,
    is_relative_to,
    parse_utc,
    read_json,
    utc_now,
    validate_agent_id,
    validate_task_id,
)


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
            raise ConfigurationError(
                f"Not a valid Cogni-OS workspace: {self.root}"
            )
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
            workspace.add_agent(
                actor=orchestrator,
                agent_id="antigravity",
                role="worker",
                mode="manual",
                control_principal="antigravity-executant",
                model_family="google-antigravity",
            )
            # Register a same-family verifier candidate.  The independence
            # gate deliberately rejects it for Antigravity submissions;
            # Codex remains the accountable cross-family verifier.
            workspace.add_agent(
                actor=orchestrator,
                agent_id="antigravity-verifier",
                role="verifier",
                mode="manual",
                control_principal="antigravity-verifier-control",
                model_family="google-antigravity-verifier",
            )
        elif preset is not None:
            raise ConfigurationError(f"Unknown workspace preset: {preset}")
        return workspace

    @property
    def orchestrator(self) -> str:
        return str(self.config["orchestrator"])

    def _agent_path(self, agent_id: str) -> Path:
        return self.agents_dir / f"{validate_agent_id(agent_id)}.json"

    def _task_path(self, task_id: str) -> Path:
        return self.tasks_dir / f"{validate_task_id(task_id)}.json"

    def _task_lock(self, task_id: str) -> FileLock:
        return FileLock(self.control_dir / "locks" / "tasks" / f"{task_id}.lock")

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
                    raise ConfigurationError(f"Alias target agent {alias_of} has no identity")
                identity = build_identity(
                    control_principal=target_agent["identity"]["control_principal"],
                    model_family=target_agent["identity"]["model_family"],
                    alias_of=validate_agent_id(alias_of),
                    alias_chain=[validate_agent_id(alias_of), *target_agent["identity"].get("alias_chain", [])],
                )
            elif control_principal or model_family:
                if not control_principal or not model_family:
                    raise ConfigurationError("control_principal and model_family must be provided together")
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
                lease = {
                    "holder": actor,
                    "token_hash": hashlib.sha256(lease_token.encode("ascii")).hexdigest(),
                    "expires_at": lease_expiry(duration),
                    "duration_seconds": duration,
                }
                updated = transition(current, "claimed", attempt=current["attempt"] + 1, lease=lease)
                self.ledger.append(
                    actor=actor,
                    action="task.claimed",
                    task_id=task["id"],
                    payload={"task": updated},
                )
                atomic_write_json(self._task_path(task["id"]), updated)
                return {"task": updated, "lease_token": lease_token}
        raise LeaseError("No matching claimable task available")

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

    def heartbeat(self, *, actor: str, task_id: str, lease_token: str) -> dict[str, Any]:
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
        task_id: str,
        decision: str,
        note: str,
        evidence_path: str | Path | None = None,
        timeout_seconds: int = 300,
    ) -> dict[str, Any]:
        """Independently verify or reject a submitted task."""
        if decision not in {"accept", "reject"}:
            raise ConfigurationError("Verification decision must be 'accept' or 'reject'")
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
                raise TransitionError(f"Task {task_id} is not submitted for verification")
            
            target_state = "verified" if decision == "accept" else "rejected"
            verifier_identity = identity_snapshot(actor, verifier_agent.get("identity"))
            
            # Fetch worker identity from submitted event
            events = self.ledger.read()
            submitted_event = next(
                (e for e in reversed(events) if e.get("action") == "task.submitted" and e.get("task_id") == task_id),
                None,
            )
            worker_identity = submitted_event.get("payload", {}).get("worker_identity") if submitted_event else None
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
                task.get("result", {})
                .get("manifest", {})
                .get("manifest_sha256")
            )
            if (
                isinstance(worker_manifest_sha, str)
                and hmac.compare_digest(
                    worker_manifest_sha.lower(),
                    verifier_evidence["manifest_sha256"].lower(),
                )
            ):
                raise EvidenceError(
                    "Verifier evidence must be independently produced, not the "
                    "worker submission manifest"
                )
            trusted_validation = run_trusted_validations(
                workspace_root=self.root,
                runs_root=self.runs_dir,
                task_id=task_id,
                attempt=task["attempt"],
                actor=actor,
                manifest=verifier_evidence,
                gpu_allowed=bool(task["permissions"].get("gpu", False)),
                network_allowed=bool(task["permissions"].get("network", False)),
                timeout_seconds=timeout_seconds,
            )
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
                    for validation in trusted_validation["validations"]
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
            
            verification_record = {
                "verified_at": utc_now(),
                "verified_by": actor,
                "decision": decision,
                "note": note.strip(),
                "independence": independence,
                "verifier_evidence": {
                    "manifest_sha256": verifier_evidence["manifest_sha256"],
                    "bundle": verifier_bundle,
                },
                "trusted_validation": trusted_validation,
            }
            updated = transition(task, target_state, verification=verification_record)
            self.ledger.append(
                actor=actor,
                action=f"task.{target_state}",
                task_id=task_id,
                payload={
                    "task": updated,
                    "verifier_identity": verifier_identity,
                    "independence": independence,
                    "verifier_evidence": verification_record["verifier_evidence"],
                    "trusted_validation": trusted_validation,
                },
            )
            atomic_write_json(self._task_path(task_id), updated)
            return updated

    def restate_verification(
        self,
        *,
        actor: str,
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
            events = self.ledger.read()
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
                },
            )

    def status(self) -> dict[str, Any]:
        """Return operational status summary for Cogni-OS."""
        tasks = self.list_tasks()
        counts = {state: 0 for state in ("pending", "claimed", "running", "blocked", "submitted", "verified", "rejected", "archived")}
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
