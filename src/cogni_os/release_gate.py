"""Immutable, ledger-bound release gate contracts.

The release gate is operational evidence, not source code.  Writing a gate to a
tracked ``release/RELEASE_GATE.json`` makes a clean source tree impossible: the
file either dirties the commit that it claims to attest, or changes the commit
after it was generated.  This module instead stores one content-addressed
contract below ``archive/release-gates`` and binds its exact bytes to a signed
``release.gate_issued`` ledger event.

Issuance is intentionally conductor-only and fail-closed.  A valid contract
binds the clean Git source, every current-release task verification, the P01
production evidence collection, and one fresh file-backed agent attestation.
Later unrelated ledger events may follow without invalidating the gate.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .actor_capability import authority_for_workspace, scrub_capability_environment
from .errors import (
    AuthorizationError,
    ConfigurationError,
    EvidenceError,
    IntegrityError,
    StateError,
)
from .independence import identity_snapshot
from .ledger import GENESIS_HASH
from .lock import FileLock
from .trust_projection import task_trust_projection
from .util import canonical_json, utc_now
from .verification_lifecycle import require_authoritative_verification_terminal
from .workspace import Workspace

RELEASE_GATE_ACTION = "release.gate_issued"
RELEASE_GATE_SCHEMA_VERSION = 2
P01_TASK_ID = "P01-TRUTH"
MAX_CONTRACT_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
ATTESTATION_MAX_AGE_SECONDS = 90
ARCHIVE_PREFIX = Path("archive") / "release-gates"

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_OPERATIONAL_PREFIXES = (
    ".cogni/",
    ".efo/",
    "agents/",
    "archive/",
    "ledger/",
    "reports/",
    "runs/",
    "submissions/",
    "tasks/",
)
_UNSAFE_OPERATIONAL_SUFFIXES = {
    ".bat",
    ".cfg",
    ".cmd",
    ".com",
    ".cjs",
    ".dll",
    ".exe",
    ".ini",
    ".js",
    ".mjs",
    ".msi",
    ".ps1",
    ".py",
    ".scr",
    ".sh",
    ".toml",
    ".yaml",
    ".yml",
}
_REQUIRED_RELEASE_ARTIFACTS = {
    "production-health-body": "production_health.body.json",
    "production-health-capture": "production_health.capture.json",
    "production-snapshot-body": "production_snapshot.body.json",
    "production-snapshot-capture": "production_snapshot.capture.json",
    "cloudflare-deployment-evidence": "cloudflare_deployment.json",
    "cloudflare-rollback-target-evidence": "cloudflare_rollback_target.json",
    "cloudflare-rollback-dry-run-receipt": "cloudflare_rollback_dry_run.json",
    "cloudflare-current-deployment-body": "cloudflare_current_deployment.body.json",
    "cloudflare-current-deployment-capture": "cloudflare_current_deployment.capture.json",
    "cloudflare-current-project-body": "cloudflare_current_project.body.json",
    "cloudflare-current-project-capture": "cloudflare_current_project.capture.json",
    "cloudflare-rollback-deployment-body": "cloudflare_rollback_deployment.body.json",
    "cloudflare-rollback-deployment-capture": "cloudflare_rollback_deployment.capture.json",
    "cloudflare-rollback-project-body": "cloudflare_rollback_project.body.json",
    "cloudflare-rollback-project-capture": "cloudflare_rollback_project.capture.json",
}

_SECURE_ARCHIVE_PRIMITIVES_AVAILABLE = bool(
    os.name == "posix"
    and os.open in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
    and os.listdir in os.supports_fd
    and getattr(os, "O_DIRECTORY", 0)
    and getattr(os, "O_NOFOLLOW", 0)
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def _validated_actor_capability_receipt(
    value: Any,
    *,
    workspace: Workspace,
    actor: str,
    operation: str,
    task_id: str | None = None,
    run_id: str | None = None,
    task_attempt: int | None = None,
) -> dict[str, Any]:
    """Verify the receipt and require a trust root outside the shared user."""

    try:
        return authority_for_workspace(workspace).validate_receipt(
            value,
            expected_actor=actor,
            expected_operation=operation,
            expected_task_id=task_id,
            expected_run_id=run_id,
            expected_task_attempt=task_attempt,
            require_independent_trust_root=True,
        )
    except (
        AuthorizationError,
        ConfigurationError,
        IntegrityError,
        OSError,
        ValueError,
    ) as exc:
        raise EvidenceError(
            "Actor capability receipt is not independently trusted"
        ) from exc


def _run_git(root: Path, arguments: list[str]) -> bytes:
    environment = {
        **scrub_capability_environment(dict(os.environ)),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={root.as_posix()}",
                "-C",
                str(root),
                *arguments,
            ],
            check=False,
            capture_output=True,
            timeout=15,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError("Git source inspection failed") from exc
    if completed.returncode != 0:
        raise EvidenceError("Git source inspection returned a failure")
    return completed.stdout


def git_release_source_state(root: Path) -> dict[str, Any]:
    """Return a clean, deterministic source state excluding evidence planes."""

    repository = root.resolve()
    commit = (
        _run_git(
            repository,
            ["rev-parse", "--verify", "HEAD^{commit}"],
        )
        .decode("ascii", "strict")
        .strip()
        .lower()
    )
    if not _COMMIT_RE.fullmatch(commit):
        raise EvidenceError("Git returned an invalid source commit")
    tree_listing = _run_git(
        repository,
        ["ls-tree", "-r", "--full-tree", "-z", commit],
    )
    changed = _run_git(
        repository,
        ["diff", "--name-only", "-z", "HEAD", "--"],
    )
    untracked = _run_git(
        repository,
        ["ls-files", "--others", "--exclude-standard", "-z"],
    )
    paths = sorted(
        {
            raw.decode("utf-8", "surrogateescape").replace("\\", "/")
            for raw in (*changed.split(b"\0"), *untracked.split(b"\0"))
            if raw
        }
    )
    source_changes: list[str] = []
    for value in paths:
        operational = value.startswith(_OPERATIONAL_PREFIXES)
        unsafe_operational = operational and Path(value).suffix.lower() in (
            _UNSAFE_OPERATIONAL_SUFFIXES
        )
        if not operational or unsafe_operational:
            source_changes.append(value)
    return {
        "commit": commit,
        "clean": not source_changes,
        "change_count": len(source_changes),
        "changed_paths_sha256": _sha256(canonical_json(source_changes)),
        "tree_fingerprint": _sha256(tree_listing),
    }


def _is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & reparse_flag
    )


def _secure_archive_primitives_available() -> bool:
    """Return whether descriptor-relative archive traversal is available.

    A sequence of path checks followed by a path-based open is not sufficient:
    an attacker can exchange any checked parent before the final open.  The
    release-gate archive therefore requires POSIX ``*at`` operations plus
    ``O_NOFOLLOW`` and keeps every directory descriptor open through the file
    operation.  CPython on Windows does not expose an equivalent safe primitive;
    issuance and validation deliberately fail closed there.
    """

    return _SECURE_ARCHIVE_PRIMITIVES_AVAILABLE


def _require_secure_archive_primitives() -> None:
    if not _secure_archive_primitives_available():
        raise EvidenceError(
            "Release-gate archive requires descriptor-relative no-follow "
            "directory primitives; this platform is fail-closed"
        )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | int(getattr(os, "O_DIRECTORY", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
    )


def _open_directory_at(parent_descriptor: int, component: str) -> int:
    try:
        descriptor = os.open(
            component,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise EvidenceError(
            "Release-gate archive directory cannot be opened safely"
        ) from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise EvidenceError("Release-gate archive component is not a directory")
    return descriptor


@contextmanager
def _secure_archive_directory(
    root: Path,
    relative: PurePosixPath,
    *,
    create: bool,
) -> Iterator[int]:
    """Hold a no-follow descriptor chain from the filesystem root.

    Creation and all later child opens are relative to held descriptors.  A
    rename or symlink swap after a component is checked can therefore neither
    redirect the contract write nor the validation read.
    """

    _require_secure_archive_primitives()
    if relative.is_absolute() or any(
        part in {"", ".", ".."} or ":" in part or not _SAFE_COMPONENT_RE.fullmatch(part)
        for part in relative.parts
    ):
        raise EvidenceError("Archive directory component is unsafe")

    absolute_root = Path(os.path.abspath(root))
    anchor = absolute_root.anchor
    if not anchor:
        raise EvidenceError("Workspace root is not absolute")
    try:
        current = os.open(anchor, _directory_open_flags())
    except OSError as exc:
        raise EvidenceError("Filesystem root cannot be opened safely") from exc
    try:
        root_parts = absolute_root.parts[1:]
        for component in root_parts:
            next_descriptor = _open_directory_at(current, component)
            os.close(current)
            current = next_descriptor

        for component in relative.parts:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise EvidenceError(
                        "Release-gate archive directory cannot be created safely"
                    ) from exc
            next_descriptor = _open_directory_at(current, component)
            os.close(current)
            current = next_descriptor
        yield current
    finally:
        os.close(current)


def _read_descriptor_bounded(descriptor: int, maximum: int) -> bytes:
    before = os.fstat(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        getattr(before, "st_mtime_ns", 0),
        getattr(before, "st_ctime_ns", 0),
    )
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise EvidenceError("Release contract is not a bounded regular file")
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    content = b"".join(chunks)
    after = os.fstat(descriptor)
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        getattr(after, "st_mtime_ns", 0),
        getattr(after, "st_ctime_ns", 0),
    )
    if len(content) > maximum or after_identity != before_identity:
        raise EvidenceError("Release contract changed while being read")
    return content


def _read_release_contract_secure(
    root: Path,
    parent: PurePosixPath,
    *,
    maximum: int,
) -> bytes:
    with _secure_archive_directory(root, parent, create=False) as directory:
        flags = (
            os.O_RDONLY
            | int(getattr(os, "O_NOFOLLOW", 0))
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NONBLOCK", 0))
        )
        try:
            descriptor = os.open(
                "release-gate.json",
                flags,
                dir_fd=directory,
            )
        except OSError as exc:
            raise EvidenceError("Release contract cannot be opened safely") from exc
        try:
            content = _read_descriptor_bounded(descriptor, maximum)
        finally:
            os.close(descriptor)
        if set(os.listdir(directory)) != {"release-gate.json"}:
            raise EvidenceError("Release contract directory inventory is not exact")
        return content


def _store_release_contract_secure(
    root: Path,
    parent: PurePosixPath,
    content: bytes,
) -> bytes:
    with _secure_archive_directory(root, parent, create=True) as directory:
        read_flags = (
            os.O_RDONLY
            | int(getattr(os, "O_NOFOLLOW", 0))
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NONBLOCK", 0))
        )
        try:
            existing_descriptor = os.open(
                "release-gate.json",
                read_flags,
                dir_fd=directory,
            )
        except FileNotFoundError:
            existing_descriptor = None
        except OSError as exc:
            raise EvidenceError("Release contract cannot be opened safely") from exc

        if existing_descriptor is not None:
            try:
                existing = _read_descriptor_bounded(
                    existing_descriptor,
                    MAX_CONTRACT_BYTES,
                )
            finally:
                os.close(existing_descriptor)
            if existing != content:
                raise EvidenceError(
                    "Content-addressed release contract is inconsistent"
                )
        else:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= int(getattr(os, "O_NOFOLLOW", 0))
            flags |= int(getattr(os, "O_CLOEXEC", 0))
            try:
                descriptor = os.open(
                    "release-gate.json",
                    flags,
                    0o600,
                    dir_fd=directory,
                )
            except OSError as exc:
                raise EvidenceError(
                    "Release contract cannot be created exclusively"
                ) from exc
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise EvidenceError("Release contract is not a regular file")
                view = memoryview(content)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short release contract write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory)

        if set(os.listdir(directory)) != {"release-gate.json"}:
            raise EvidenceError("Release contract directory inventory is not exact")
        return _read_release_contract_secure(root, parent, maximum=MAX_CONTRACT_BYTES)


def _safe_relative_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise EvidenceError("Evidence path is not a plain POSIX relative path")
    parts = value.split("/")
    if (
        value.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part for part in parts)
        or any(not _SAFE_COMPONENT_RE.fullmatch(part) for part in parts)
    ):
        raise EvidenceError("Evidence path contains an unsafe component")
    result = PurePosixPath(value)
    if result.is_absolute():
        raise EvidenceError("Evidence path must be relative")
    return result


def _safe_existing_file(
    root: Path,
    value: Any,
    *,
    required_prefix: PurePosixPath,
    maximum: int,
) -> tuple[Path, bytes]:
    relative = _safe_relative_path(value)
    if relative.parts[: len(required_prefix.parts)] != required_prefix.parts:
        raise EvidenceError("Evidence path is outside its required archive root")
    current = root.resolve()
    try:
        for component in relative.parts:
            current = current / component
            metadata = current.lstat()
            if _is_link_or_reparse(current):
                raise EvidenceError("Evidence path crosses a link or reparse point")
    except FileNotFoundError as exc:
        raise EvidenceError("Evidence file is missing") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise EvidenceError("Evidence file is not a bounded regular file")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(current, flags)
    except OSError as exc:
        raise EvidenceError("Evidence file cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            getattr(before, "st_mtime_ns", 0),
            getattr(before, "st_ctime_ns", 0),
        )
        path_identity = (metadata.st_dev, metadata.st_ino, metadata.st_size)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino, before.st_size) != path_identity
        ):
            raise EvidenceError("Evidence identity changed before read")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            getattr(after, "st_mtime_ns", 0),
            getattr(after, "st_ctime_ns", 0),
        )
        final_path = current.lstat()
        if (
            len(content) > maximum
            or after_identity != before_identity
            or _is_link_or_reparse(current)
            or (final_path.st_dev, final_path.st_ino, final_path.st_size)
            != path_identity
        ):
            raise EvidenceError("Evidence changed while being read")
        return current, content
    finally:
        os.close(descriptor)


def _json_object(content: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be a JSON object")
    return value


def _signed_agent_record(
    events: list[dict[str, Any]],
    agent_id: str,
) -> dict[str, Any]:
    candidates = [
        event.get("payload", {}).get("agent")
        for event in events
        if event.get("action") == "agent.added"
        and event.get("payload", {}).get("agent", {}).get("id") == agent_id
    ]
    if len(candidates) != 1 or not isinstance(candidates[0], dict):
        raise IntegrityError("Agent registration is not uniquely ledger-bound")
    return candidates[0]


def _orchestrator_snapshot(
    workspace: Workspace,
    actor: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    if actor != workspace.orchestrator:
        raise AuthorizationError("Only the accountable orchestrator can issue a gate")
    agent = workspace.get_agent(actor)
    signed_agent = _signed_agent_record(events, actor)
    if (
        agent.get("id") != actor
        or agent.get("role") != "orchestrator"
        or signed_agent.get("id") != actor
        or signed_agent.get("role") != "orchestrator"
        or agent.get("identity") != signed_agent.get("identity")
    ):
        raise AuthorizationError("Release gate actor is not the signed orchestrator")
    identity = identity_snapshot(actor, signed_agent.get("identity"))
    if identity is None:
        raise AuthorizationError("Release gate orchestrator identity is missing")
    return {**identity, "role": "orchestrator"}


def _verified_task_event(
    events: list[dict[str, Any]],
    task_id: str,
    attempt: int,
) -> dict[str, Any]:
    candidates = []
    for event in events:
        payload = event.get("payload")
        signed_task = payload.get("task") if isinstance(payload, dict) else None
        if (
            event.get("action") == "task.verified"
            and event.get("task_id") == task_id
            and isinstance(signed_task, dict)
            and signed_task.get("attempt") == attempt
        ):
            candidates.append(event)
    if len(candidates) != 1:
        raise EvidenceError("Task verification event is not unique for its attempt")
    selected = candidates[0]
    signed_task = selected.get("payload", {}).get("task")
    verification = (
        signed_task.get("verification") if isinstance(signed_task, dict) else None
    )
    run_id = verification.get("run_id") if isinstance(verification, dict) else None
    if not isinstance(run_id, str):
        raise EvidenceError("Task verification event has no bound run")
    try:
        require_authoritative_verification_terminal(
            events,
            task_id=task_id,
            run_id=run_id,
            terminal_event=selected,
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceError(
            "Task verification lifecycle is conflicting or incomplete"
        ) from exc
    return selected


def _task_bindings(
    workspace: Workspace,
    source_commit: str,
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    tasks = workspace.list_tasks()
    if not tasks:
        raise StateError("A release gate requires at least one task")
    bindings: list[dict[str, Any]] = []
    task_ids: set[str] = set()
    for task in tasks:
        task_id = task.get("id")
        attempt = task.get("attempt")
        if (
            not isinstance(task_id, str)
            or not task_id
            or task_id in task_ids
            or not isinstance(attempt, int)
            or isinstance(attempt, bool)
            or attempt < 1
        ):
            raise StateError("Release task identity or attempt is invalid")
        task_ids.add(task_id)
        trust = task_trust_projection(
            task,
            current_commit=source_commit,
            workspace_root=workspace.root,
        )
        if (
            trust.get("historical_trusted") is not True
            or trust.get("current_release_validated") is not True
            or trust.get("current_release_state") not in {"verified", "archived"}
            or trust.get("verified_source_commit") != source_commit
        ):
            raise StateError(f"Task {task_id} is not trusted for this release")
        event = _verified_task_event(events, task_id, attempt)
        bindings.append(
            {
                "task_id": task_id,
                "attempt": attempt,
                "state": str(task.get("state")),
                "current_release_state": str(trust["current_release_state"]),
                "verified_source_commit": source_commit,
                "verified_event_sequence": event["sequence"],
                "verified_event_hash": event["event_hash"],
            }
        )
    return sorted(bindings, key=lambda item: item["task_id"])


def _production_evidence_anchor(
    workspace: Workspace,
    source_commit: str,
    events: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
) -> dict[str, Any]:
    p01 = next((item for item in tasks if item["task_id"] == P01_TASK_ID), None)
    if p01 is None:
        raise StateError("P01 task is required for a release gate")
    candidates = []
    for event in events:
        payload = event.get("payload")
        if (
            event.get("action") == "release.evidence_collected"
            and event.get("task_id") == P01_TASK_ID
            and isinstance(payload, dict)
            and payload.get("source_commit") == source_commit
            and payload.get("task_attempt") == p01["attempt"]
        ):
            candidates.append(event)
    if len(candidates) != 1:
        raise EvidenceError("P01 production evidence event is not unique")
    event = candidates[0]
    if (
        not isinstance(event.get("sequence"), int)
        or event["sequence"] >= p01["verified_event_sequence"]
    ):
        raise EvidenceError(
            "P01 production evidence must precede its verification decision"
        )
    payload = event["payload"]
    orchestrator = _orchestrator_snapshot(workspace, workspace.orchestrator, events)
    if event.get("actor") != workspace.orchestrator:
        raise EvidenceError("P01 production evidence was not signed by the conductor")
    producer = payload.get("producer")
    if producer != orchestrator:
        raise EvidenceError("P01 evidence producer is not the signed orchestrator")
    capability = _validated_actor_capability_receipt(
        payload.get("actor_capability"),
        workspace=workspace,
        actor=workspace.orchestrator,
        operation="release.evidence.collect",
        task_id=P01_TASK_ID,
        run_id=None,
        task_attempt=p01["attempt"],
    )
    collection = payload.get("collection")
    if not isinstance(collection, dict):
        raise EvidenceError("P01 evidence collection anchor is missing")
    bundle_path = collection.get("bundle_path")
    bundle_sha256 = collection.get("bundle_sha256")
    if not _is_sha256(bundle_sha256):
        raise EvidenceError("P01 evidence bundle digest is invalid")
    relative = _safe_relative_path(bundle_path)
    expected_prefix = PurePosixPath(
        f"archive/release-evidence/{P01_TASK_ID}/attempt-{p01['attempt']}"
    )
    if (
        relative.parts[: len(expected_prefix.parts)] != expected_prefix.parts
        or relative.name != "bundle.json"
        or relative.parent.name != bundle_sha256
    ):
        raise EvidenceError("P01 evidence bundle path is not content addressed")
    _, bundle_bytes = _safe_existing_file(
        workspace.root,
        bundle_path,
        required_prefix=expected_prefix,
        maximum=MAX_EVIDENCE_BYTES,
    )
    if _sha256(bundle_bytes) != bundle_sha256:
        raise EvidenceError("P01 evidence bundle hash does not match")
    bundle = _json_object(bundle_bytes, label="P01 production evidence bundle")
    if (
        bundle.get("schema_version") != 1
        or bundle.get("kind") != "production-release-evidence"
        or bundle.get("task_id") != P01_TASK_ID
        or bundle.get("task_attempt") != p01["attempt"]
        or bundle.get("source_commit") != source_commit
        or bundle.get("producer") != orchestrator
        or bundle.get("actor_capability") != capability
        or bundle.get("deployment_attestation") != "CLOUDFLARE_API_VERIFIED"
        or bundle.get("rollback_mutation_performed") is not False
    ):
        raise EvidenceError("P01 production evidence provenance is invalid")
    bundle_artifacts = bundle.get("artifacts")
    event_artifacts = collection.get("artifacts")
    if (
        not isinstance(bundle_artifacts, list)
        or not isinstance(event_artifacts, list)
        or len(bundle_artifacts) != len(_REQUIRED_RELEASE_ARTIFACTS)
        or len(event_artifacts) != len(bundle_artifacts)
    ):
        raise EvidenceError("P01 production evidence inventory is invalid")
    bundle_by_kind: dict[str, dict[str, Any]] = {}
    event_by_kind: dict[str, dict[str, Any]] = {}
    for bundle_item, event_item in zip(bundle_artifacts, event_artifacts, strict=True):
        if not isinstance(bundle_item, dict) or not isinstance(event_item, dict):
            raise EvidenceError("P01 production evidence artifact is invalid")
        kind = bundle_item.get("kind")
        if not isinstance(kind, str) or kind in bundle_by_kind:
            raise EvidenceError("P01 production evidence kind is duplicated")
        bundle_by_kind[kind] = bundle_item
        event_by_kind[str(event_item.get("kind"))] = event_item
    if set(bundle_by_kind) != set(_REQUIRED_RELEASE_ARTIFACTS) or set(
        event_by_kind
    ) != set(_REQUIRED_RELEASE_ARTIFACTS):
        raise EvidenceError("P01 production evidence artifact set is incomplete")
    for kind, filename in _REQUIRED_RELEASE_ARTIFACTS.items():
        bundle_item = bundle_by_kind[kind]
        event_item = event_by_kind[kind]
        expected_path = (relative.parent / filename).as_posix()
        digest = bundle_item.get("sha256")
        size = bundle_item.get("size_bytes")
        if (
            bundle_item.get("filename") != filename
            or event_item
            != {
                "kind": kind,
                "archive_path": expected_path,
                "sha256": digest,
                "size_bytes": size,
            }
            or not _is_sha256(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
            or size > MAX_EVIDENCE_BYTES
        ):
            raise EvidenceError("P01 production evidence artifact anchor is invalid")
        _, artifact_bytes = _safe_existing_file(
            workspace.root,
            expected_path,
            required_prefix=expected_prefix,
            maximum=MAX_EVIDENCE_BYTES,
        )
        if len(artifact_bytes) != size or _sha256(artifact_bytes) != digest:
            raise EvidenceError("P01 production evidence artifact changed")
        _json_object(artifact_bytes, label=f"P01 artifact {kind}")
    actual_names = {
        entry.name for entry in (workspace.root / relative.parent).iterdir()
    }
    if actual_names != {"bundle.json", *_REQUIRED_RELEASE_ARTIFACTS.values()}:
        raise EvidenceError("P01 production evidence directory inventory changed")
    return {
        "task_id": P01_TASK_ID,
        "task_attempt": p01["attempt"],
        "event_sequence": event["sequence"],
        "event_hash": event["event_hash"],
        "bundle_path": bundle_path,
        "bundle_sha256": bundle_sha256,
        "actor_capability_receipt_sha256": _sha256(canonical_json(capability)),
        "artifact_anchors_sha256": _sha256(canonical_json(event_artifacts)),
    }


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError("Agent attestation timestamp is missing")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        result = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise EvidenceError("Agent attestation timestamp is invalid") from exc
    if result.tzinfo is None:
        raise EvidenceError("Agent attestation timestamp has no timezone")
    return result.astimezone(timezone.utc)  # noqa: UP017 -- Python 3.10 support


def _agent_attestation(
    workspace: Workspace,
    agent_id: str,
    source_commit: str,
    events: list[dict[str, Any]],
    *,
    require_fresh: bool,
) -> dict[str, Any]:
    if not _SAFE_COMPONENT_RE.fullmatch(agent_id):
        raise EvidenceError("Attesting agent id is unsafe")
    agent = workspace.get_agent(agent_id)
    signed_agent = _signed_agent_record(events, agent_id)
    if (
        signed_agent.get("role") not in {"worker", "orchestrator"}
        or agent.get("role") != signed_agent.get("role")
        or agent.get("identity") != signed_agent.get("identity")
    ):
        raise EvidenceError("Attesting agent is not ledger-bound")
    identity = identity_snapshot(agent_id, signed_agent.get("identity"))
    if identity is None:
        raise EvidenceError("Attesting agent identity is missing")
    runtime = agent.get("runtime_attestation")
    if not isinstance(runtime, dict):
        raise EvidenceError("Agent runtime attestation is missing")
    evidence_path = runtime.get("evidence_path")
    evidence_sha256 = runtime.get("evidence_sha256")
    if (
        runtime.get("ready") is not True
        or runtime.get("source_commit") != source_commit
        or not _is_sha256(evidence_sha256)
    ):
        raise EvidenceError("Agent runtime attestation is not release-ready")
    observed = _parse_utc(runtime.get("observed_at"))
    age = (
        datetime.now(timezone.utc) - observed  # noqa: UP017 -- Python 3.10 support
    ).total_seconds()
    if require_fresh and not 0 <= age <= ATTESTATION_MAX_AGE_SECONDS:
        raise EvidenceError("Agent runtime attestation is stale")
    required_prefix = PurePosixPath(f"reports/{agent_id}")
    _, content = _safe_existing_file(
        workspace.root,
        evidence_path,
        required_prefix=required_prefix,
        maximum=MAX_EVIDENCE_BYTES,
    )
    if _sha256(content) != evidence_sha256:
        raise EvidenceError("Agent runtime attestation evidence changed")
    document = _json_object(content, label="Agent runtime attestation evidence")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "cogni-agent-runtime-attestation"
        or document.get("agent_id") != agent_id
        or document.get("ready") is not True
        or document.get("source_commit") != source_commit
        or document.get("observed_at") != runtime.get("observed_at")
    ):
        raise EvidenceError("Agent runtime attestation document is invalid")
    return {
        "agent_id": agent_id,
        "role": signed_agent["role"],
        "identity": identity,
        "ready": True,
        "observed_at": runtime["observed_at"],
        "source_commit": source_commit,
        "evidence_path": evidence_path,
        "evidence_sha256": evidence_sha256,
    }


def _validate_bound_attestation(
    workspace: Workspace,
    attestation: dict[str, Any],
    source_commit: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Revalidate immutable attestation bytes without following a rotated pointer."""

    agent_id = attestation.get("agent_id")
    if not isinstance(agent_id, str) or not _SAFE_COMPONENT_RE.fullmatch(agent_id):
        raise EvidenceError("Release gate attesting agent id is invalid")
    signed_agent = _signed_agent_record(events, agent_id)
    identity = identity_snapshot(agent_id, signed_agent.get("identity"))
    if (
        signed_agent.get("role") not in {"worker", "orchestrator"}
        or identity is None
        or attestation.get("role") != signed_agent.get("role")
        or attestation.get("identity") != identity
        or attestation.get("ready") is not True
        or attestation.get("source_commit") != source_commit
        or not _is_sha256(attestation.get("evidence_sha256"))
    ):
        raise EvidenceError("Release gate agent identity binding is invalid")
    _parse_utc(attestation.get("observed_at"))
    _, content = _safe_existing_file(
        workspace.root,
        attestation.get("evidence_path"),
        required_prefix=PurePosixPath(f"reports/{agent_id}"),
        maximum=MAX_EVIDENCE_BYTES,
    )
    if _sha256(content) != attestation["evidence_sha256"]:
        raise EvidenceError("Agent runtime attestation evidence changed")
    document = _json_object(content, label="Agent runtime attestation evidence")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "cogni-agent-runtime-attestation"
        or document.get("agent_id") != agent_id
        or document.get("ready") is not True
        or document.get("source_commit") != source_commit
        or document.get("observed_at") != attestation.get("observed_at")
    ):
        raise EvidenceError("Release gate agent attestation document is invalid")
    return attestation


def _append_locked_event(
    workspace: Workspace,
    *,
    actor: str,
    payload: dict[str, Any],
    expected_head: str,
) -> dict[str, Any]:
    events = workspace.ledger.read()
    workspace.ledger._verify_events(events)
    observed_head = events[-1]["event_hash"] if events else GENESIS_HASH
    if observed_head != expected_head:
        raise StateError("Ledger head changed before release gate issuance")
    core = {
        "sequence": len(events) + 1,
        "timestamp": utc_now(),
        "actor": actor,
        "action": RELEASE_GATE_ACTION,
        "task_id": None,
        "payload": payload,
        "previous_hash": expected_head,
    }
    event_hash = _sha256(canonical_json(core))
    signature = hmac.new(
        workspace.ledger._key(),
        event_hash.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    event = {**core, "event_hash": event_hash, "signature": signature}
    with workspace.ledger.path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return event


def _contract_bytes(contract: dict[str, Any]) -> bytes:
    return canonical_json(contract)


def issue_release_gate(
    workspace: Workspace,
    *,
    actor: str,
    capability_secret: str | bytes | None = None,
    attesting_agent_id: str,
) -> dict[str, Any]:
    """Issue one content-addressed release gate for the current clean commit."""

    # This check must precede capability consumption and every persistent
    # operation.  Platforms without descriptor-relative no-follow traversal
    # cannot safely bind an archive path and therefore receive an honest NO_GO.
    _require_secure_archive_primitives()
    # First consume and independently validate an unbound admission capability.
    # No task/Git/ledger/archive state may be read before this authorization.
    # A second receipt below binds the exact P01 attempt after the caller has
    # also been proven to be the accountable workspace orchestrator.
    admission_receipt = workspace.authorize_actor_capability(
        actor=actor,
        operation="release.gate.issue",
        capability_secret=capability_secret,
        require_actor_os_isolation=True,
        task_id=None,
        run_id=None,
        task_attempt=None,
    )
    _validated_actor_capability_receipt(
        admission_receipt,
        workspace=workspace,
        actor=actor,
        operation="release.gate.issue",
        task_id=None,
        run_id=None,
        task_attempt=None,
    )
    if actor != workspace.orchestrator:
        raise AuthorizationError("Only the accountable orchestrator can issue a gate")

    try:
        p01_task = workspace.get_task(P01_TASK_ID)
    except ConfigurationError:
        p01_task = None
    p01_attempt = p01_task.get("attempt") if p01_task is not None else 1
    if (
        not isinstance(p01_attempt, int)
        or isinstance(p01_attempt, bool)
        or p01_attempt < 1
    ):
        raise StateError("P01 task attempt is invalid for release gate issuance")
    capability_receipt = workspace.authorize_actor_capability(
        actor=actor,
        operation="release.gate.issue",
        capability_secret=capability_secret,
        require_actor_os_isolation=True,
        task_id=P01_TASK_ID,
        run_id=None,
        task_attempt=p01_attempt,
    )
    capability_receipt = _validated_actor_capability_receipt(
        capability_receipt,
        workspace=workspace,
        actor=actor,
        operation="release.gate.issue",
        task_id=P01_TASK_ID,
        run_id=None,
        task_attempt=p01_attempt,
    )
    if p01_task is None:
        raise StateError("P01 task is required for release gate issuance")
    initial_events = workspace.ledger.read_verified()
    orchestrator = _orchestrator_snapshot(workspace, actor, initial_events)
    source = git_release_source_state(workspace.root)
    if source["clean"] is not True:
        raise StateError("Release source tree is dirty")
    tasks = _task_bindings(workspace, source["commit"], initial_events)
    production = _production_evidence_anchor(
        workspace,
        source["commit"],
        initial_events,
        tasks,
    )
    attestation = _agent_attestation(
        workspace,
        attesting_agent_id,
        source["commit"],
        initial_events,
        require_fresh=True,
    )
    initial_head = initial_events[-1]["event_hash"] if initial_events else GENESIS_HASH
    contract = {
        "schema_version": RELEASE_GATE_SCHEMA_VERSION,
        "kind": "cogni-release-gate-contract",
        "status": "PASS",
        "issued_at": utc_now(),
        "ledger_head_before_issue": initial_head,
        "actor_capability": capability_receipt,
        "orchestrator": orchestrator,
        "source": source,
        "tasks": tasks,
        "agent_attestation": attestation,
        "p01_production_evidence": production,
    }
    content = _contract_bytes(contract)
    digest = _sha256(content)
    relative = ARCHIVE_PREFIX / source["commit"] / digest / "release-gate.json"
    relative_posix = relative.as_posix()
    payload = {
        "schema_version": 1,
        "source_commit": source["commit"],
        "ledger_head_before_issue": initial_head,
        "contract": {
            "path": relative_posix,
            "sha256": digest,
            "size_bytes": len(content),
        },
    }

    gate_lock = FileLock(workspace.control_dir / "locks" / "release-gate.lock")
    with gate_lock, FileLock(workspace.ledger.lock_path):
        current_events = workspace.ledger.read()
        workspace.ledger._verify_events(current_events)
        current_head = (
            current_events[-1]["event_hash"] if current_events else GENESIS_HASH
        )
        if current_head != initial_head:
            raise StateError("Ledger changed while preparing the release gate")
        if any(
            event.get("action") == RELEASE_GATE_ACTION
            and event.get("payload", {}).get("source_commit") == source["commit"]
            for event in current_events
        ):
            raise StateError("A release gate already exists for this source commit")
        if _orchestrator_snapshot(workspace, actor, current_events) != orchestrator:
            raise StateError("Orchestrator authority changed during issuance")
        if git_release_source_state(workspace.root) != source:
            raise StateError("Release source changed during issuance")
        if _task_bindings(workspace, source["commit"], current_events) != tasks:
            raise StateError("Release task evidence changed during issuance")
        if (
            _production_evidence_anchor(
                workspace,
                source["commit"],
                current_events,
                tasks,
            )
            != production
        ):
            raise StateError("P01 production evidence changed during issuance")
        if (
            _agent_attestation(
                workspace,
                attesting_agent_id,
                source["commit"],
                current_events,
                require_fresh=True,
            )
            != attestation
        ):
            raise StateError("Agent attestation changed during issuance")

        archived_content = _store_release_contract_secure(
            workspace.root,
            PurePosixPath(relative.parent.as_posix()),
            content,
        )
        if archived_content != content:
            raise EvidenceError("Release contract changed after archival")
        if (
            git_release_source_state(workspace.root) != source
            or _task_bindings(workspace, source["commit"], current_events) != tasks
            or _production_evidence_anchor(
                workspace,
                source["commit"],
                current_events,
                tasks,
            )
            != production
            or _agent_attestation(
                workspace,
                attesting_agent_id,
                source["commit"],
                current_events,
                require_fresh=True,
            )
            != attestation
        ):
            raise StateError("Release evidence changed before ledger binding")
        event = _append_locked_event(
            workspace,
            actor=actor,
            payload=payload,
            expected_head=initial_head,
        )

    result = {
        "status": "PASS",
        "source_commit": source["commit"],
        "contract_path": relative_posix,
        "contract_sha256": digest,
        "event_sequence": event["sequence"],
        "event_hash": event["event_hash"],
    }
    validated = validate_release_gate(
        workspace,
        expected_source_commit=source["commit"],
    )
    if (
        validated["contract_sha256"] != digest
        or validated["event_hash"] != event["event_hash"]
    ):
        raise IntegrityError("Issued release gate did not pass immediate validation")
    return result


def validate_release_gate(
    workspace: Workspace,
    *,
    expected_source_commit: str | None = None,
) -> dict[str, Any]:
    """Validate the current commit's gate from immutable bytes and signed events."""

    _require_secure_archive_primitives()
    events = workspace.ledger.read_verified()
    source = git_release_source_state(workspace.root)
    if source["clean"] is not True:
        raise StateError("Release source tree is dirty")
    if (
        expected_source_commit is not None
        and expected_source_commit != source["commit"]
    ):
        raise EvidenceError("Expected release commit does not match workspace HEAD")
    candidates = [
        event
        for event in events
        if event.get("action") == RELEASE_GATE_ACTION
        and event.get("payload", {}).get("source_commit") == source["commit"]
    ]
    if len(candidates) != 1:
        raise EvidenceError("Current release gate event is missing or duplicated")
    event = candidates[0]
    orchestrator = _orchestrator_snapshot(
        workspace,
        workspace.orchestrator,
        events,
    )
    if event.get("actor") != workspace.orchestrator:
        raise AuthorizationError("Release gate event actor is not the orchestrator")
    payload = event.get("payload")
    anchor = payload.get("contract") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or not isinstance(anchor, dict)
        or not _is_sha256(anchor.get("sha256"))
        or not isinstance(anchor.get("size_bytes"), int)
        or isinstance(anchor.get("size_bytes"), bool)
        or not 1 <= anchor["size_bytes"] <= MAX_CONTRACT_BYTES
    ):
        raise EvidenceError("Release gate event payload is invalid")
    relative = _safe_relative_path(anchor.get("path"))
    expected_prefix = PurePosixPath(
        f"archive/release-gates/{source['commit']}/{anchor['sha256']}"
    )
    if relative.parent != expected_prefix or relative.name != "release-gate.json":
        raise EvidenceError("Release gate contract path is not content addressed")
    content = _read_release_contract_secure(
        workspace.root,
        relative.parent,
        maximum=MAX_CONTRACT_BYTES,
    )
    if len(content) != anchor["size_bytes"] or _sha256(content) != anchor["sha256"]:
        raise EvidenceError("Release gate contract bytes changed")
    contract = _json_object(content, label="Release gate contract")
    contract_tasks = contract.get("tasks")
    contract_p01 = (
        next(
            (
                item
                for item in contract_tasks
                if isinstance(item, dict) and item.get("task_id") == P01_TASK_ID
            ),
            None,
        )
        if isinstance(contract_tasks, list)
        else None
    )
    contract_p01_attempt = (
        contract_p01.get("attempt") if isinstance(contract_p01, dict) else None
    )
    _validated_actor_capability_receipt(
        contract.get("actor_capability"),
        workspace=workspace,
        actor=workspace.orchestrator,
        operation="release.gate.issue",
        task_id=P01_TASK_ID,
        run_id=None,
        task_attempt=contract_p01_attempt,
    )
    if (
        contract.get("schema_version") != RELEASE_GATE_SCHEMA_VERSION
        or contract.get("kind") != "cogni-release-gate-contract"
        or contract.get("status") != "PASS"
        or contract.get("ledger_head_before_issue") != event.get("previous_hash")
        or payload.get("ledger_head_before_issue") != event.get("previous_hash")
        or payload.get("source_commit") != source["commit"]
        or contract.get("orchestrator") != orchestrator
        or contract.get("source") != source
    ):
        raise EvidenceError("Release gate contract provenance is invalid")
    tasks = _task_bindings(workspace, source["commit"], events)
    if contract.get("tasks") != tasks:
        raise EvidenceError("Release gate task bindings changed")
    production = _production_evidence_anchor(
        workspace,
        source["commit"],
        events,
        tasks,
    )
    if contract.get("p01_production_evidence") != production:
        raise EvidenceError("Release gate P01 evidence binding changed")
    attestation = contract.get("agent_attestation")
    if not isinstance(attestation, dict) or not isinstance(
        attestation.get("agent_id"), str
    ):
        raise EvidenceError("Release gate agent attestation is missing")
    _validate_bound_attestation(
        workspace,
        attestation,
        source["commit"],
        events,
    )
    return {
        "status": "PASS",
        "source_commit": source["commit"],
        "contract_path": relative.as_posix(),
        "contract_sha256": anchor["sha256"],
        "event_sequence": event["sequence"],
        "event_hash": event["event_hash"],
        "ledger_head_before_issue": event["previous_hash"],
    }


def release_gate_status(
    workspace: Workspace,
    *,
    expected_source_commit: str | None = None,
) -> dict[str, Any]:
    """Return a publisher-friendly fail-closed status without hiding the reason."""

    try:
        return validate_release_gate(
            workspace,
            expected_source_commit=expected_source_commit,
        )
    except (AuthorizationError, EvidenceError, IntegrityError, StateError) as exc:
        return {
            "status": "NO_GO",
            "reason": f"{type(exc).__name__}: {exc}",
            "source_commit": expected_source_commit,
            "contract_path": None,
            "contract_sha256": None,
            "event_sequence": None,
            "event_hash": None,
        }


__all__ = [
    "ARCHIVE_PREFIX",
    "ATTESTATION_MAX_AGE_SECONDS",
    "MAX_CONTRACT_BYTES",
    "P01_TASK_ID",
    "RELEASE_GATE_ACTION",
    "git_release_source_state",
    "issue_release_gate",
    "release_gate_status",
    "validate_release_gate",
]
