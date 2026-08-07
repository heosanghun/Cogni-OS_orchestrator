"""Shared fail-closed projection of raw task states into trusted states."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from . import trusted_runner as _trusted_runner
from .actor_capability import ActorCapabilityAuthority
from .errors import (
    AuthorizationError,
    ConfigurationError,
    EvidenceError,
    IntegrityError,
)
from .ledger import Ledger
from .snapshot_broker_protocol import (
    BROKER_DESCRIPTOR_TYPE,
    BROKER_PROOF_SCOPE,
    SnapshotBrokerError,
    canonical_json_sha256,
    trusted_broker_runtime_binding,
    verify_signed_envelope,
)
from .trusted_runner import (
    COMMAND_POLICY_KEYS,
    COMMAND_RECEIPT_KEYS,
    EXECUTABLE_BINDING_KEYS,
    FIXED_RUNTIME_PATHS,
    ISOLATION_BACKEND_KEYS,
    ISOLATION_POLICY_ID,
    MAX_OUTPUT_BYTES,
    MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_ENTRY_COUNT,
    MAX_SNAPSHOT_FILE_BYTES,
    MAX_SNAPSHOT_PATH_BYTES,
    MAX_SNAPSHOT_PATH_BYTES_TOTAL,
    MAX_SNAPSHOT_TREE_NODE_COUNT,
    SNAPSHOT_MATERIALIZATION_POLICY_ID,
    SNAPSHOT_PROTECTION_POLICY_ID,
    TRUSTED_ISOLATION_BACKEND_ID,
    TRUSTED_RECEIPT_DOCUMENT_KEYS,
    TRUSTED_RECEIPT_RESULT_KEYS,
    TRUSTED_RUNNER_ID,
    TRUSTED_RUNTIME_POLICY_ID,
    TRUSTED_SYSTEM_ROOTS,
    trusted_receipt_preimage_sha256,
    validation_contract_sha256,
)
from .verification_lifecycle import require_authoritative_verification_terminal
from .verifier_attestation_protocol import (
    VerifierAttestationError,
    verify_executor_attestation,
)

MAX_ARCHIVED_JSON_BYTES = 4 * 1024 * 1024
MAX_ARCHIVED_FILE_BYTES = 16 * 1024 * 1024
SAFE_TRUSTED_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
SAFE_BROKER_FD_ALIAS = re.compile(r"^/proc/self/fd/[1-9][0-9]*$")
# Test-only compatibility seam for legacy synthetic fixtures.  Production
# receipts do not consult this boolean: they must carry independently verified
# acquisition and cleanup signatures from the root broker.  Neither branch is
# an execution-success attestation; that is a separate trust domain below.
EXTERNAL_BROKER_SIGNATURE_VERIFICATION_AVAILABLE = False


def _diagnostic_false_return_line(callback: Any) -> int | None:
    """Return only the code line of a fail-closed predicate for CI diagnosis."""

    target = _valid_trusted_verification.__code__
    rejected_at: int | None = None
    previous = sys.gettrace()

    def trace(frame: Any, event: str, value: Any) -> Any:
        nonlocal rejected_at
        if frame.f_code is target and event == "return" and value is False:
            rejected_at = frame.f_lineno
        return trace

    sys.settrace(trace)
    try:
        callback()
    finally:
        sys.settrace(previous)
    return rejected_at


def _signed_broker_protection_valid(
    trusted: dict[str, Any],
    protection: Any,
) -> bool:
    required = {
        "policy_id",
        "platform",
        "broker",
        "runner_euid",
        "owner_uid",
        "actor_write_access",
        "links_rejected",
        "proof",
        "descriptor_type",
        "snapshot_device",
        "snapshot_inode",
        "acquire_attestation_sha256",
        "acquire_attestation",
        "cleanup_attestation",
    }
    if (
        not isinstance(protection, dict)
        or set(protection) != required
        or protection.get("policy_id") != SNAPSHOT_PROTECTION_POLICY_ID
        or protection.get("platform") != "linux"
        or protection.get("broker") != "external-privileged-fd-lease"
        or not isinstance(protection.get("runner_euid"), int)
        or isinstance(protection.get("runner_euid"), bool)
        or protection["runner_euid"] < 1
        or protection.get("owner_uid") != 0
        or protection.get("actor_write_access") is not False
        or protection.get("links_rejected") is not True
        or protection.get("proof") != BROKER_PROOF_SCOPE
        or protection.get("descriptor_type") != BROKER_DESCRIPTOR_TYPE
        or not isinstance(protection.get("snapshot_device"), int)
        or isinstance(protection.get("snapshot_device"), bool)
        or protection["snapshot_device"] < 0
        or not isinstance(protection.get("snapshot_inode"), int)
        or isinstance(protection.get("snapshot_inode"), bool)
        or protection["snapshot_inode"] < 1
        or not _is_sha256(str(protection.get("acquire_attestation_sha256", "")).lower())
    ):
        return False
    try:
        acquire = verify_signed_envelope(
            protection["acquire_attestation"],
            kind="snapshot-acquired",
        )
        cleanup = verify_signed_envelope(
            protection["cleanup_attestation"],
            kind="snapshot-cleaned",
        )
        runtime_binding = trusted_broker_runtime_binding(
            require_current_interpreter=False,
        )
        expected_preimage_sha256 = trusted_receipt_preimage_sha256(trusted)
    except (SnapshotBrokerError, TypeError, ValueError):
        return False
    snapshot = trusted.get("snapshot")
    if not isinstance(snapshot, dict):
        return False
    acquire_sha = canonical_json_sha256(protection["acquire_attestation"])
    return (
        acquire_sha == protection["acquire_attestation_sha256"]
        and acquire["caller_uid"] == protection["runner_euid"]
        and acquire["snapshot_owner_uid"] == protection["owner_uid"]
        and acquire["descriptor_type"] == protection["descriptor_type"]
        and acquire["snapshot_device"] == protection["snapshot_device"]
        and acquire["snapshot_inode"] == protection["snapshot_inode"]
        and acquire["source_commit"] == trusted.get("source_commit")
        and acquire["tree_oid"] == snapshot.get("tree_oid")
        and acquire["snapshot_sha256"] == snapshot.get("sha256")
        and acquire["task_id"] == trusted.get("task_id")
        and acquire["attempt"] == trusted.get("attempt")
        and acquire["actor"] == trusted.get("actor")
        and acquire["run_id"] == trusted.get("run_id")
        and acquire["validation_contract_sha256"]
        == trusted.get("validation_contract_sha256")
        and acquire["broker_runtime_manifest_sha256"]
        == runtime_binding["manifest_sha256"]
        and cleanup["lease_id"] == acquire["lease_id"]
        and cleanup["acquire_attestation_sha256"] == acquire_sha
        and cleanup["snapshot_sha256"] == acquire["snapshot_sha256"]
        and cleanup["snapshot_device"] == acquire["snapshot_device"]
        and cleanup["snapshot_inode"] == acquire["snapshot_inode"]
        and cleanup["caller_uid"] == acquire["caller_uid"]
        and cleanup["caller_gid"] == acquire["caller_gid"]
        and cleanup["task_id"] == acquire["task_id"]
        and cleanup["attempt"] == acquire["attempt"]
        and cleanup["actor"] == acquire["actor"]
        and cleanup["run_id"] == acquire["run_id"]
        and cleanup["validation_contract_sha256"]
        == acquire["validation_contract_sha256"]
        and cleanup["receipt_preimage_sha256"] == trusted.get("receipt_preimage_sha256")
        and cleanup["receipt_preimage_sha256"] == expected_preimage_sha256
        and cleanup["broker_runtime_manifest_sha256"]
        == acquire["broker_runtime_manifest_sha256"]
        and cleanup["namespace_removed"] is True
    )


def _separate_executor_attestation_valid(
    trusted: dict[str, Any],
    attestation: Any,
    verifier_identity: Any,
) -> bool:
    """Require an independent key/domain for command-success evidence.

    A member of the snapshot-broker socket group can choose arbitrary request
    binding strings.  Consequently, even a valid root broker acquisition and
    cleanup signature can establish only snapshot provenance.  It must never
    elevate a receipt to trusted execution without this second proof.
    """

    if not isinstance(verifier_identity, dict):
        return False
    try:
        verify_executor_attestation(
            attestation,
            receipt=trusted,
            verifier_identity=verifier_identity,
        )
    except (VerifierAttestationError, SnapshotBrokerError, TypeError, ValueError):
        return False
    return True


def _verification_run_binding_valid(
    verification: dict[str, Any],
    trusted: dict[str, Any],
) -> bool:
    """Bind the workspace verification lifecycle to the runner receipt."""

    run_id = verification.get("run_id")
    return bool(
        isinstance(run_id, str)
        and SAFE_TRUSTED_RUN_ID.fullmatch(run_id)
        and trusted.get("run_id") == run_id
    )


def _capability_authority(
    workspace_root: Path,
    events: list[dict[str, Any]],
) -> ActorCapabilityAuthority:
    initializations = [
        event for event in events if event.get("action") == "workspace.initialized"
    ]
    if len(initializations) != 1:
        raise ValueError("workspace actor capability authority is ambiguous")
    config = initializations[0].get("payload", {}).get("config")
    workspace_id = config.get("workspace_id") if isinstance(config, dict) else None
    if not isinstance(workspace_id, str) or not workspace_id:
        raise ValueError("workspace actor capability authority is invalid")
    return ActorCapabilityAuthority(
        workspace_root=workspace_root,
        workspace_id=workspace_id,
    )


def _validate_capability_receipt(
    workspace_root: Path,
    events: list[dict[str, Any]],
    receipt: Any,
    *,
    actor: str,
    operation: str,
    task_id: str | None,
    run_id: str | None,
    task_attempt: int | None,
) -> bool:
    """Require a cryptographic receipt and an independent actor trust root."""

    try:
        _capability_authority(workspace_root, events).validate_receipt(
            receipt,
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
    ):
        return False
    return True


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
    )


def _is_reparse_point(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & marker)


def _bounded_file_snapshot(path: Path, *, maximum: int) -> bytes:
    """Read one regular non-reparse file view and reject concurrent mutation."""

    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse_point(before)
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise ValueError("archived evidence is not a bounded regular file")
        content = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    path_after = path.stat()
    if (
        len(content) > maximum
        or len(content) != before.st_size
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(path_after)
    ):
        raise ValueError("archived evidence changed while it was read")
    return content


def _safe_archived_file(
    value: Any,
    *,
    workspace_root: Path,
    required_parent: Path,
) -> Path:
    """Resolve one archive path without accepting symlinks or junctions."""

    if not isinstance(value, str) or not value:
        raise ValueError("archive path is missing")
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError("archive path must be absolute")

    workspace = workspace_root.resolve()
    parent = required_parent.resolve()
    parent.relative_to(workspace)
    lexical = Path(os.path.abspath(candidate))
    relative = lexical.relative_to(parent)
    if any(
        component in {"", ".", ".."} or ":" in component for component in relative.parts
    ):
        raise ValueError("archive path contains an unsafe component")
    cursor = parent
    for component in relative.parts:
        cursor = cursor / component
        metadata = cursor.lstat()
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise ValueError("archive path contains a link or reparse point")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(parent)
    if not resolved.is_file():
        raise ValueError("archive path is not a file")
    return resolved


def _json_object(content: bytes) -> dict[str, Any]:
    value = json.loads(content.decode("utf-8"))
    if not isinstance(value, dict):
        raise TypeError("archived JSON is not an object")
    return value


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value.lower())
    )


def _valid_cuda_visibility(value: Any, *, gpu_allowed: bool) -> bool:
    if not isinstance(value, str):
        return False
    if not gpu_allowed:
        return value == ""
    if value == "":
        return True
    tokens = [token.strip() for token in value.split(",")]
    if (
        not tokens
        or any(not token.isdigit() for token in tokens)
        or len(tokens) != len(set(tokens))
    ):
        return False
    return all(0 <= int(token) <= 5 for token in tokens)


def _canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _trusted_receipt_shape_valid(receipt: Any) -> bool:
    return bool(
        isinstance(receipt, dict)
        and set(receipt) == TRUSTED_RECEIPT_RESULT_KEYS
        and receipt.get("schema_version") == 3
        and receipt.get("runner") == TRUSTED_RUNNER_ID
    )


def _safe_snapshot_relative(value: Any) -> str | None:
    """Return a canonical Git-tree path or reject traversal/aliasing forms."""

    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or value.startswith("/")
    ):
        return None
    parts = value.split("/")
    if any(part in {"", ".", ".."} or ":" in part for part in parts):
        return None
    return "/".join(parts)


def _snapshot_resource_caps_valid(snapshot: Any) -> bool:
    """Mirror runner-side entry/path/file/total caps before deeper projection."""

    if not isinstance(snapshot, dict):
        return False
    files = snapshot.get("files")
    directories = snapshot.get("directories")
    file_count = snapshot.get("file_count")
    size_bytes = snapshot.get("size_bytes")
    if (
        not isinstance(files, list)
        or not isinstance(directories, list)
        or not isinstance(file_count, int)
        or isinstance(file_count, bool)
        or not 1 <= file_count <= MAX_SNAPSHOT_ENTRY_COUNT
        or len(files) != file_count
        or len(files) + len(directories) > MAX_SNAPSHOT_TREE_NODE_COUNT
        or not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or not 0 <= size_bytes <= MAX_SNAPSHOT_BYTES
    ):
        return False
    total_size = 0
    total_path_bytes = 0
    for entry in files:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("path"), str)
            or not isinstance(entry.get("size"), int)
            or isinstance(entry.get("size"), bool)
            or not 0 <= entry["size"] <= MAX_SNAPSHOT_FILE_BYTES
        ):
            return False
        path_bytes = len(entry["path"].encode("utf-8", errors="surrogateescape"))
        if path_bytes > MAX_SNAPSHOT_PATH_BYTES:
            return False
        total_size += entry["size"]
        total_path_bytes += path_bytes
    return (
        total_size == size_bytes
        and total_size <= MAX_SNAPSHOT_BYTES
        and total_path_bytes <= MAX_SNAPSHOT_PATH_BYTES_TOTAL
    )


def _fixed_output_limit_valid(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value == MAX_OUTPUT_BYTES
    )


def _runtime_binding_semantically_valid(binding: Any) -> bool:
    """Validate the production runtime policy without actor PATH/env lookup.

    This narrow, side-effect-free boundary can be replaced by the explicit
    cross-platform test fixture.  Production accepts only administrator-fixed
    Linux runtime paths recorded by the trusted runner policy.
    """

    if not isinstance(binding, dict) or set(binding) != EXECUTABLE_BINDING_KEYS:
        return False
    kind = binding.get("kind")
    path = binding.get("path")
    return bool(
        kind in FIXED_RUNTIME_PATHS
        and binding.get("policy_id") == TRUSTED_RUNTIME_POLICY_ID
        and binding.get("provenance") == "fixed-admin-path-chain"
        and isinstance(path, str)
        and path in FIXED_RUNTIME_PATHS[kind]
        and _is_sha256(str(binding.get("sha256", "")).lower())
        and binding.get("sha256") == str(binding.get("sha256")).lower()
    )


def _expected_sandbox_environment(
    *,
    cuda_visible_devices: str,
    has_python_source: bool,
) -> dict[str, str]:
    return {
        "APPDATA": "/sandbox/appdata",
        "CUDA_VISIBLE_DEVICES": cuda_visible_devices,
        "HOME": "/sandbox",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOCALAPPDATA": "/sandbox/localappdata",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": "/workspace/src" if has_python_source else "",
        "PYTHONUTF8": "1",
        "TEMP": "/sandbox/tmp",
        "TMP": "/sandbox/tmp",
        "USERPROFILE": "/sandbox",
    }


def _receipt_run_directory(
    output_path: Any,
    *,
    workspace_root: Path,
    task_id: Any,
    attempt: Any,
    index: int,
) -> Path | None:
    if not isinstance(output_path, str) or not output_path:
        return None
    supplied = Path(output_path)
    if not supplied.is_absolute():
        return None
    candidate = Path(os.path.abspath(supplied))
    if os.path.normcase(str(candidate)) != os.path.normcase(output_path):
        return None
    try:
        relative = candidate.relative_to(workspace_root.resolve())
    except ValueError:
        return None
    parts = relative.parts
    if (
        len(parts) != 6
        or parts[0] != "runs"
        or parts[1] != "trusted-verifier"
        or parts[2] != task_id
        or not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or parts[3] != f"attempt-{attempt:03d}"
        or SAFE_TRUSTED_RUN_ID.fullmatch(parts[4]) is None
        or parts[5] != f"validation-{index:03d}.log"
    ):
        return None
    return candidate.parent


def _canonical_receipt_path_valid(value: Any, run_directory: Path | None) -> bool:
    if run_directory is None or not isinstance(value, str):
        return False
    expected = run_directory / "receipt.json"
    return value == str(expected) and Path(value).is_absolute()


def _valid_code_path_bindings(
    command_policy: dict[str, Any],
    *,
    workspace_root: Path,
    snapshot_files: dict[str, dict[str, Any]],
) -> bool:
    code_paths = command_policy.get("code_paths")
    if not isinstance(code_paths, list) or not code_paths:
        return False
    seen: set[str] = set()
    for entry in code_paths:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "sha256"}
            or not isinstance(entry.get("path"), str)
            or not entry["path"]
            or not _is_sha256(str(entry.get("sha256", "")).lower())
            or entry.get("sha256") != str(entry.get("sha256")).lower()
        ):
            return False
        candidate = Path(os.path.abspath(entry["path"]))
        if os.path.normcase(str(candidate)) != os.path.normcase(entry["path"]):
            return False
        try:
            relative = candidate.relative_to(workspace_root.resolve()).as_posix()
        except ValueError:
            return False
        snapshot_entry = snapshot_files.get(relative)
        normalized = os.path.normcase(str(candidate))
        if (
            normalized in seen
            or snapshot_entry is None
            or snapshot_entry.get("sha256") != entry["sha256"].lower()
        ):
            return False
        seen.add(normalized)

    code_path = command_policy.get("code_path")
    if code_path is not None:
        if not isinstance(code_path, str) or not code_path:
            return False
        if os.path.normcase(str(Path(os.path.abspath(code_path)))) not in seen:
            return False

    kind = command_policy.get("kind")
    executed = command_policy.get("executed_argv")
    if not isinstance(executed, list) or not executed:
        return False
    if kind in {"node", "powershell-file"} and code_path is None:
        return False
    normalized_code_path = (
        os.path.normcase(str(Path(os.path.abspath(code_path))))
        if isinstance(code_path, str)
        else None
    )
    if kind == "node":
        arguments = executed[1:]
        if any(
            argument.startswith("-")
            and argument not in {"--no-warnings", "--test", "--test-only"}
            for argument in arguments
        ):
            return False
        positional = [
            argument for argument in arguments if not argument.startswith("-")
        ]
        selected = positional if "--test" in arguments else positional[:1]
        selected_paths = {
            os.path.normcase(
                str(
                    Path(os.path.abspath(argument))
                    if Path(argument).is_absolute()
                    else Path(os.path.abspath(workspace_root / argument))
                )
            )
            for argument in selected
        }
        if (
            not selected
            or selected_paths != seen
            or normalized_code_path not in selected_paths
        ):
            return False
    if kind == "powershell-file" and (
        len(executed) < 5
        or [value.lower() for value in executed[1:4]]
        != ["-noprofile", "-noninteractive", "-file"]
        or os.path.normcase(str(Path(os.path.abspath(executed[4]))))
        != normalized_code_path
        or len(seen) != 1
    ):
        return False
    if kind == "python":
        arguments = executed[1:]
        module_mode = len(arguments) >= 2 and arguments[0] == "-m"
        if module_mode:
            module = arguments[1]
            if module not in {"pytest", "unittest"}:
                return False
            try:
                _trusted_runner._python_module_argument_targets(module, arguments[2:])
            except (EvidenceError, TypeError, ValueError):
                return False
        elif code_path is None:
            return False
        else:
            if (
                not arguments
                or arguments[0].startswith("-")
                or os.path.normcase(
                    str(
                        Path(os.path.abspath(arguments[0]))
                        if Path(arguments[0]).is_absolute()
                        else Path(os.path.abspath(workspace_root / arguments[0]))
                    )
                )
                != normalized_code_path
            ):
                return False
    return True


def _expected_isolation_launch_argv(
    validation: dict[str, Any],
    *,
    command_policy: dict[str, Any],
    backend: dict[str, Any],
    workspace_root: Path,
    task_id: Any,
    attempt: Any,
    sandbox_environment: dict[str, str],
    network_allowed: bool,
    index: int,
    snapshot_mount_source: Path | None = None,
) -> list[str] | None:
    run_directory = _receipt_run_directory(
        validation.get("output_path"),
        workspace_root=workspace_root,
        task_id=task_id,
        attempt=attempt,
        index=index,
    )
    canonical = getattr(_trusted_runner, "_canonical_isolation_argv", None)
    if run_directory is None or not callable(canonical):
        return None
    try:
        value = canonical(
            backend=backend,
            command_argv=command_policy["executed_argv"],
            workspace_root=workspace_root,
            snapshot_root=snapshot_mount_source or run_directory / "committed-input",
            scratch_root=run_directory / "sandbox-home",
            sandbox_environment=sandbox_environment,
            network_allowed=network_allowed,
        )
    except (KeyError, OSError, TypeError, ValueError):
        return None
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return None
    return value


def _valid_command_receipt(
    manifest_validation: Any,
    validation: Any,
    *,
    expected_index: int,
    isolation_backend: dict[str, Any],
    sandbox_environment: dict[str, str],
    snapshot_files: dict[str, dict[str, Any]],
    workspace_root: Path,
    task_id: Any,
    attempt: Any,
    network_allowed: bool,
    maximum_output_bytes: int,
    output_evidence: dict[str, set[int]],
    expected_run_directory: Path,
    snapshot_mount_source: Path | None = None,
) -> bool:
    if (
        not isinstance(manifest_validation, dict)
        or not isinstance(validation, dict)
        or set(validation) != COMMAND_RECEIPT_KEYS
        or validation.get("index") != expected_index
    ):
        return False
    if (
        _receipt_run_directory(
            validation.get("output_path"),
            workspace_root=workspace_root,
            task_id=task_id,
            attempt=attempt,
            index=expected_index,
        )
        != expected_run_directory
    ):
        return False
    command_argv = validation.get("command_argv")
    executed_argv = validation.get("executed_argv")
    command_policy = validation.get("command_policy")
    if (
        not isinstance(command_argv, list)
        or not command_argv
        or any(
            not isinstance(item, str) or not item or "\x00" in item
            for item in command_argv
        )
        or not isinstance(executed_argv, list)
        or not executed_argv
        or any(
            not isinstance(item, str) or not item or "\x00" in item
            for item in executed_argv
        )
        or not isinstance(command_policy, dict)
        or set(command_policy) != COMMAND_POLICY_KEYS
        or command_policy.get("schema_version") != 1
        or command_policy.get("kind") not in {"python", "node", "powershell-file"}
        or command_policy.get("executed_argv") != executed_argv
    ):
        return False
    binding = command_policy.get("executable_binding")
    if not _runtime_binding_semantically_valid(binding):
        return False
    if (
        binding.get("kind") != command_policy["kind"]
        or command_policy.get("executable_path") != binding.get("path")
        or command_policy.get("executable_sha256") != binding.get("sha256")
        or executed_argv[0] != binding.get("path")
        or command_argv[0] != binding.get("path")
        or command_argv[1:] != executed_argv[1:]
        or not _valid_code_path_bindings(
            command_policy,
            workspace_root=workspace_root,
            snapshot_files=snapshot_files,
        )
    ):
        return False
    expected_launch = _expected_isolation_launch_argv(
        validation,
        command_policy=command_policy,
        backend=isolation_backend,
        workspace_root=workspace_root,
        task_id=task_id,
        attempt=attempt,
        sandbox_environment=sandbox_environment,
        network_allowed=network_allowed,
        index=expected_index,
        snapshot_mount_source=snapshot_mount_source,
    )
    if (
        expected_launch is None
        or validation.get("isolation_launch_argv") != expected_launch
    ):
        return False
    duration = validation.get("duration_ms")
    timeout = validation.get("timeout_seconds")
    output_size = validation.get("output_size_bytes")
    output_sha256 = validation.get("output_sha256")
    return not (
        manifest_validation.get("command_argv") != command_argv
        or manifest_validation.get("exit_code") != validation.get("exit_code")
        or str(manifest_validation.get("raw_output_sha256", "")).lower()
        != str(output_sha256).lower()
        or validation.get("exit_code") != 0
        or validation.get("timed_out") is not False
        or validation.get("output_truncated") is not False
        or not isinstance(validation.get("started_at"), str)
        or not validation["started_at"]
        or not isinstance(validation.get("completed_at"), str)
        or not validation["completed_at"]
        or not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or duration < 0
        or not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or timeout < 1
        or timeout > 300
        or not _is_sha256(output_sha256)
        or output_sha256 != str(output_sha256).lower()
        or not isinstance(output_size, int)
        or isinstance(output_size, bool)
        or output_size < 0
        or output_size > maximum_output_bytes
        or output_size not in output_evidence.get(str(output_sha256), set())
        or validation.get("executable_sha256_after")
        != command_policy["executable_sha256"]
    )


def _retained_bundle_evidence(
    bundle: dict[str, Any],
    kind: str,
    *,
    workspace_root: Path,
    bundle_directory: Path,
    maximum_bytes: int,
) -> dict[str, set[int]]:
    files = bundle.get("files")
    if not isinstance(files, list):
        return {}
    evidence: dict[str, set[int]] = {}
    for item in files:
        if (
            not isinstance(item, dict)
            or item.get("kind") != kind
            or item.get("retained") is not True
            or not isinstance(item.get("archive_path"), str)
            or not item["archive_path"]
        ):
            continue
        digest = str(item.get("sha256", "")).lower()
        if not _is_sha256(digest):
            continue
        try:
            candidate = _safe_archived_file(
                item["archive_path"],
                workspace_root=workspace_root,
                required_parent=bundle_directory / "files",
            )
            size = item.get("size_bytes")
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or size > maximum_bytes
            ):
                continue
            content = _bounded_file_snapshot(candidate, maximum=size)
            if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
                continue
        except (OSError, ValueError):
            continue
        evidence.setdefault(digest, set()).add(size)
    return evidence


def _retained_bundle_hashes(
    bundle: dict[str, Any],
    kind: str,
    *,
    workspace_root: Path,
    bundle_directory: Path,
) -> set[str]:
    return set(
        _retained_bundle_evidence(
            bundle,
            kind,
            workspace_root=workspace_root,
            bundle_directory=bundle_directory,
            maximum_bytes=MAX_ARCHIVED_FILE_BYTES,
        )
    )


def _retained_json(
    bundle: dict[str, Any],
    kind: str,
    *,
    expected_sha256: str,
    workspace_root: Path,
    bundle_directory: Path,
) -> dict[str, Any] | None:
    """Load exactly one retained JSON object whose bytes match the event hash."""

    files = bundle.get("files")
    if not isinstance(files, list):
        return None
    matches = [
        item
        for item in files
        if isinstance(item, dict)
        and item.get("kind") == kind
        and item.get("retained") is True
        and str(item.get("sha256", "")).lower() == expected_sha256
        and isinstance(item.get("archive_path"), str)
        and bool(item.get("archive_path"))
    ]
    if len(matches) != 1:
        return None
    try:
        candidate = _safe_archived_file(
            matches[0]["archive_path"],
            workspace_root=workspace_root,
            required_parent=bundle_directory / "files",
        )
        size = matches[0].get("size_bytes")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
            or size > MAX_ARCHIVED_JSON_BYTES
        ):
            return None
        content = _bounded_file_snapshot(candidate, maximum=size)
    except (OSError, ValueError):
        return None
    if len(content) != size or hashlib.sha256(content).hexdigest() != expected_sha256:
        return None
    try:
        return _json_object(content)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None


def _authoritative_verification(
    task: dict[str, Any],
    *,
    workspace_root: Path,
) -> (
    tuple[
        dict[str, Any],
        dict[str, Any],
        Path,
        dict[str, Any],
        list[dict[str, Any]],
    ]
    | None
):
    """Rebuild verification truth from a signed event and archived bundle."""

    task_id = task.get("id")
    attempt = task.get("attempt")
    if (
        not isinstance(task_id, str)
        or not task_id
        or not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or attempt < 1
    ):
        return None

    control_directory = workspace_root / ".cogni"
    if not control_directory.is_dir() and (workspace_root / ".efo").is_dir():
        control_directory = workspace_root / ".efo"
    ledger = Ledger(
        workspace_root / "ledger" / "events.jsonl",
        control_directory / "locks" / "ledger.lock",
        control_directory / "ledger.key",
    )
    events = ledger.read_verified()
    candidates = []
    for event in events:
        if event.get("action") != "task.verified" or event.get("task_id") != task_id:
            continue
        payload = event.get("payload")
        signed_task = payload.get("task") if isinstance(payload, dict) else None
        if isinstance(signed_task, dict) and signed_task.get("attempt") == attempt:
            candidates.append(event)
    if len(candidates) != 1:
        return None

    event = candidates[0]
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return None
    signed_task = payload.get("task")
    if not isinstance(signed_task, dict) or signed_task.get("state") != "verified":
        return None
    signed_verification = signed_task.get("verification")
    inline_verification = task.get("verification")
    if not isinstance(signed_verification, dict) or not isinstance(
        inline_verification, dict
    ):
        return None

    # The mutable task file is only a projection.  Every security-relevant
    # field must agree with the signed task.verified snapshot.
    for name in ("id", "attempt", "permissions", "verification"):
        if task.get(name) != signed_task.get(name):
            return None
    if task.get("state") == "verified" and signed_task.get("state") != "verified":
        return None
    event_actor = event.get("actor")
    signed_verifier_evidence = signed_verification.get("verifier_evidence")
    if (
        not isinstance(event_actor, str)
        or not isinstance(signed_verifier_evidence, dict)
        or event_actor != signed_verification.get("verified_by")
        or payload.get("verifier_evidence")
        != signed_verification.get("verifier_evidence")
        or payload.get("trusted_validation")
        != signed_verification.get("trusted_validation")
        or payload.get("independence") != signed_verification.get("independence")
        or payload.get("capability_receipt")
        != signed_verification.get("capability_receipt")
    ):
        return None

    run_id = signed_verification.get("run_id")
    if not isinstance(run_id, str):
        return None
    try:
        start = require_authoritative_verification_terminal(
            events,
            task_id=task_id,
            run_id=run_id,
            terminal_event=event,
        )
    except (TypeError, ValueError):
        return None
    start_payload = start.get("payload", {})
    capability_receipt = signed_verification.get("capability_receipt")
    if (
        start.get("actor") != event.get("actor")
        or start_payload.get("task_attempt") != attempt
        or start_payload.get("capability_receipt") != capability_receipt
        or start_payload.get("verifier_identity")
        != signed_verification.get("verifier_identity")
        or start_payload.get("verifier_manifest_sha256")
        != signed_verifier_evidence.get("manifest_sha256")
        or start_payload.get("worker_manifest_sha256")
        != signed_verification.get("worker_manifest_sha256")
        or start_payload.get("verification_contract_inputs_sha256")
        != signed_verification.get("verification_contract_inputs_sha256")
        or not _validate_capability_receipt(
            workspace_root,
            events,
            capability_receipt,
            actor=event_actor,
            operation="task.verify",
            task_id=task_id,
            run_id=run_id,
            task_attempt=attempt,
        )
    ):
        return None

    verifier_evidence = signed_verification.get("verifier_evidence")
    outer_bundle = (
        verifier_evidence.get("bundle") if isinstance(verifier_evidence, dict) else None
    )
    if not isinstance(outer_bundle, dict):
        return None
    bundle_sha256 = str(outer_bundle.get("manifest_sha256", "")).lower()
    if not _is_sha256(bundle_sha256):
        return None
    bundle_path = _safe_archived_file(
        outer_bundle.get("manifest_path"),
        workspace_root=workspace_root,
        required_parent=workspace_root / "submissions",
    )
    if bundle_path.name != "bundle.json":
        return None
    content = _bounded_file_snapshot(
        bundle_path,
        maximum=MAX_ARCHIVED_JSON_BYTES,
    )
    if hashlib.sha256(content).hexdigest() != bundle_sha256:
        return None
    bundle = _json_object(content)
    bundle_directory = bundle_path.parent
    expected_attempt_directory = (
        workspace_root / "submissions" / task_id / f"attempt-{attempt:03d}"
    ).resolve()

    evidence_manifest_sha = str(verifier_evidence.get("manifest_sha256", "")).lower()
    if (
        bundle_directory.parent != expected_attempt_directory
        or bundle.get("schema_version") != 1
        or bundle.get("task_id") != task_id
        or bundle.get("attempt") != attempt
        or bundle.get("label") != "verifier"
        or bundle.get("manifest_sha256") != evidence_manifest_sha
        or outer_bundle.get("task_id") != bundle.get("task_id")
        or outer_bundle.get("attempt") != bundle.get("attempt")
        or outer_bundle.get("label") != bundle.get("label")
        or outer_bundle.get("files") != bundle.get("files")
        or outer_bundle.get("bundle_id") != bundle_directory.name
        or Path(str(outer_bundle.get("path", ""))).resolve() != bundle_directory
        or Path(str(outer_bundle.get("manifest_path", ""))).resolve() != bundle_path
    ):
        return None
    files = bundle.get("files")
    if not isinstance(files, list):
        return None
    retained_count = sum(
        isinstance(item, dict) and item.get("retained") is True for item in files
    )
    if (
        outer_bundle.get("retained") != retained_count
        or outer_bundle.get("external") != len(files) - retained_count
    ):
        return None
    return signed_verification, bundle, bundle_directory, event, events


def _effective_restatement(
    events: list[dict[str, Any]],
    verification_event: dict[str, Any],
    *,
    workspace_root: Path,
) -> str | None:
    """Return a valid append-only correction for one verification event.

    A restatement is an authorization-bearing trust decision, not commentary.
    Therefore it is accepted only when it is signed by the orchestrator named
    in the immutable workspace initialization event and binds the exact target
    sequence, hash, task, and verifier.  Any malformed restatement for this
    task fails the projection closed.
    """

    initializations = [
        event for event in events if event.get("action") == "workspace.initialized"
    ]
    if len(initializations) != 1:
        raise ValueError("workspace orchestrator authority is ambiguous")
    initialization = initializations[0]
    config = initialization.get("payload", {}).get("config")
    orchestrator = config.get("orchestrator") if isinstance(config, dict) else None
    if (
        not isinstance(orchestrator, str)
        or not orchestrator
        or initialization.get("actor") != orchestrator
    ):
        raise ValueError("workspace orchestrator authority is invalid")

    target_sequence = verification_event.get("sequence")
    target_hash = verification_event.get("event_hash")
    task_id = verification_event.get("task_id")
    verifier = verification_event.get("actor")
    if (
        not isinstance(target_sequence, int)
        or isinstance(target_sequence, bool)
        or not _is_sha256(str(target_hash))
        or not isinstance(task_id, str)
        or not task_id
        or not isinstance(verifier, str)
        or not verifier
    ):
        raise ValueError("verification event identity is invalid")

    verified_by_sequence = {
        event.get("sequence"): event
        for event in events
        if event.get("action") == "task.verified"
        and isinstance(event.get("sequence"), int)
        and not isinstance(event.get("sequence"), bool)
    }
    effective_by_target: dict[int, str] = {}
    effective: str | None = None
    for event in events:
        if event.get("action") != "verification.restatement":
            continue
        if event.get("task_id") != task_id:
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise TypeError("verification restatement payload is invalid")
        restated_sequence = payload.get("target_verification_sequence")
        restated_status = payload.get("effective_status")
        restated_target = (
            verified_by_sequence.get(restated_sequence)
            if isinstance(restated_sequence, int)
            and not isinstance(restated_sequence, bool)
            else None
        )
        reasons = (
            payload.get("reason") if isinstance(payload.get("reason"), str) else ""
        )
        target_task = (
            restated_target.get("payload", {}).get("task")
            if isinstance(restated_target, dict)
            else None
        )
        target_verification = (
            target_task.get("verification") if isinstance(target_task, dict) else None
        )
        target_run_id = (
            target_verification.get("run_id")
            if isinstance(target_verification, dict)
            else None
        )
        target_attempt = (
            target_task.get("attempt") if isinstance(target_task, dict) else None
        )
        if (
            payload.get("schema_version") != 1
            or event.get("actor") != orchestrator
            or restated_target is None
            or restated_target.get("task_id") != task_id
            or payload.get("target_verification_hash")
            != restated_target.get("event_hash")
            or payload.get("original_verifier") != restated_target.get("actor")
            or restated_status not in {"verification_disputed", "verification_revoked"}
            or not reasons.strip()
            or not isinstance(event.get("sequence"), int)
            or isinstance(event.get("sequence"), bool)
            or event["sequence"] <= restated_sequence
            or not _validate_capability_receipt(
                workspace_root,
                events,
                payload.get("capability_receipt"),
                actor=orchestrator,
                operation="task.restate_verification",
                task_id=task_id,
                run_id=target_run_id,
                task_attempt=target_attempt,
            )
        ):
            raise ValueError("verification restatement is not authoritative")
        previous = effective_by_target.get(restated_sequence)
        if previous == "verification_revoked" and restated_status != previous:
            raise ValueError("verification revocation cannot be weakened")
        effective_by_target[restated_sequence] = str(restated_status)
        if restated_sequence == target_sequence:
            if restated_target.get("event_hash") != target_hash:
                raise ValueError("verification restatement target changed")
            effective = str(restated_status)
    return effective


def _valid_trusted_verification(
    verification: dict[str, Any],
    *,
    task: dict[str, Any],
    current_commit: str | None,
    workspace_root: Path,
    bundle: dict[str, Any],
    bundle_directory: Path,
) -> bool:
    verifier_evidence = verification.get("verifier_evidence")
    trusted = verification.get("trusted_validation")
    if not isinstance(verifier_evidence, dict) or not _trusted_receipt_shape_valid(
        trusted
    ):
        return False
    if not _is_sha256(str(verifier_evidence.get("manifest_sha256", "")).lower()):
        return False
    if not _verification_run_binding_valid(verification, trusted):
        return False
    if not _separate_executor_attestation_valid(
        trusted,
        verifier_evidence.get("executor_attestation"),
        verification.get("verifier_identity"),
    ):
        # Root snapshot signatures are intentionally insufficient here.  No
        # production attestation emitter exists yet, so current receipts stay
        # fail-closed until the independent verifier service is deployed.
        return False
    if (
        not isinstance(bundle, dict)
        or not _is_sha256(str(bundle.get("manifest_sha256", "")).lower())
        or bundle.get("task_id") != task.get("id")
        or bundle.get("attempt") != task.get("attempt")
        or bundle.get("label") != "verifier"
    ):
        return False
    manifest_hashes = _retained_bundle_hashes(
        bundle,
        "manifest",
        workspace_root=workspace_root,
        bundle_directory=bundle_directory,
    )
    if verifier_evidence["manifest_sha256"].lower() not in manifest_hashes:
        return False
    if (
        trusted.get("schema_version") != 3
        or trusted.get("runner") != TRUSTED_RUNNER_ID
        or trusted.get("passed") is not True
        or trusted.get("failure") not in {None, ""}
        or trusted.get("source_clean") is not True
        or trusted.get("source_postcheck_passed") is not True
        or trusted.get("source_postcheck_error") not in {None, ""}
        or trusted.get("task_id") != task.get("id")
        or trusted.get("attempt") != task.get("attempt")
        or trusted.get("actor") != verification.get("verified_by")
        or not isinstance(trusted.get("source_commit"), str)
        or len(trusted["source_commit"]) != 40
        or any(
            character not in "0123456789abcdef"
            for character in trusted["source_commit"].lower()
        )
        or not _is_sha256(str(trusted.get("receipt_sha256", "")).lower())
        or not _is_sha256(str(trusted.get("operational_paths_sha256", "")).lower())
        or not _is_sha256(str(trusted.get("environment_sha256", "")).lower())
        or trusted.get("verifier_manifest_sha256")
        != verifier_evidence.get("manifest_sha256")
        or not _is_sha256(str(trusted.get("validation_contract_sha256", "")).lower())
        or trusted.get("isolation_policy") != ISOLATION_POLICY_ID
        or trusted.get("isolation_attested") is not True
        or trusted.get("snapshot_precheck_passed") is not True
        or trusted.get("snapshot_postcheck_passed") is not True
        or trusted.get("snapshot_postcheck_error") not in {None, ""}
    ):
        return False
    if current_commit is not None and trusted["source_commit"] != current_commit:
        return False
    permissions = task.get("permissions")
    if not isinstance(permissions, dict):
        return False
    if trusted["gpu_allowed"] is not bool(permissions.get("gpu", False)):
        return False
    # The only currently attested backend deliberately exposes no host NVIDIA
    # device nodes or driver libraries.  A GPU-positive receipt is therefore
    # impossible and must be treated as forged until a separate GPU sandbox
    # backend is implemented and independently gated.
    if trusted["gpu_allowed"] is True:
        return False
    if not _valid_cuda_visibility(
        trusted.get("cuda_visible_devices"),
        gpu_allowed=trusted["gpu_allowed"],
    ):
        return False
    if trusted["network_allowed"] is not bool(permissions.get("network", False)):
        return False
    isolation_backend = trusted.get("isolation_backend")
    expected_network_enforcement = (
        "task-permitted-via-explicit-share-net"
        if trusted["network_allowed"]
        else "private-network-namespace"
    )
    if (
        not isinstance(isolation_backend, dict)
        or set(isolation_backend) != ISOLATION_BACKEND_KEYS
        or isolation_backend.get("id") != TRUSTED_ISOLATION_BACKEND_ID
        or isolation_backend.get("path") != "/usr/bin/bwrap"
        or not _is_sha256(str(isolation_backend.get("sha256", "")).lower())
        or isolation_backend.get("filesystem_enforcement")
        != "private-mount-namespace-committed-snapshot-ro"
        or isolation_backend.get("network_enforcement") != expected_network_enforcement
        or trusted.get("network_enforcement") != expected_network_enforcement
    ):
        return False
    system_roots = isolation_backend.get("system_roots")
    if (
        not isinstance(system_roots, list)
        or not system_roots
        or system_roots[0] != "/usr"
        or "/lib" not in system_roots
        or len(system_roots) != len(set(system_roots))
        or any(value not in TRUSTED_SYSTEM_ROOTS for value in system_roots)
        or system_roots
        != sorted(system_roots, key=lambda value: TRUSTED_SYSTEM_ROOTS.index(value))
    ):
        return False
    snapshot_protection = trusted.get("snapshot_protection")
    legacy_snapshot_protection_keys = {
        "policy_id",
        "platform",
        "broker",
        "runner_euid",
        "owner_uid",
        "actor_write_access",
        "path_chain_root_owned",
        "path_chain_actor_nonwritable",
        "entries_root_owned",
        "entries_actor_nonwritable",
        "links_rejected",
        "checked_ancestor_count",
        "checked_entry_count",
        "proof",
    }
    if (
        isinstance(snapshot_protection, dict)
        and snapshot_protection.get("broker") == "external-privileged-fd-lease"
    ):
        if not _signed_broker_protection_valid(trusted, snapshot_protection):
            return False
    elif (
        not EXTERNAL_BROKER_SIGNATURE_VERIFICATION_AVAILABLE
        or not isinstance(snapshot_protection, dict)
        or set(snapshot_protection) != legacy_snapshot_protection_keys
        or snapshot_protection.get("policy_id") != SNAPSHOT_PROTECTION_POLICY_ID
        or snapshot_protection.get("platform") != "linux"
        or snapshot_protection.get("broker") != "external-privileged-owner"
        or not isinstance(snapshot_protection.get("runner_euid"), int)
        or isinstance(snapshot_protection.get("runner_euid"), bool)
        or snapshot_protection["runner_euid"] < 1
        or snapshot_protection.get("owner_uid") != 0
        or snapshot_protection.get("actor_write_access") is not False
        or snapshot_protection.get("path_chain_root_owned") is not True
        or snapshot_protection.get("path_chain_actor_nonwritable") is not True
        or snapshot_protection.get("entries_root_owned") is not True
        or snapshot_protection.get("entries_actor_nonwritable") is not True
        or snapshot_protection.get("links_rejected") is not True
        or not isinstance(snapshot_protection.get("checked_ancestor_count"), int)
        or isinstance(snapshot_protection.get("checked_ancestor_count"), bool)
        or snapshot_protection["checked_ancestor_count"] < 2
        or not isinstance(snapshot_protection.get("checked_entry_count"), int)
        or isinstance(snapshot_protection.get("checked_entry_count"), bool)
        or snapshot_protection["checked_entry_count"] < 1
        or snapshot_protection.get("proof") != "root-owner-mode-access-probe"
    ):
        return False
    snapshot = trusted.get("snapshot")
    snapshot_keys = {
        "schema_version",
        "source_commit",
        "tree_oid",
        "object_format",
        "materialization_policy",
        "file_count",
        "directories",
        "size_bytes",
        "sha256",
        "files",
    }
    if (
        not isinstance(snapshot, dict)
        or not _snapshot_resource_caps_valid(snapshot)
        or set(snapshot) != snapshot_keys
        or snapshot.get("schema_version") != 1
        or snapshot.get("source_commit") != trusted["source_commit"]
        or not isinstance(snapshot.get("tree_oid"), str)
        or len(snapshot["tree_oid"]) != 40
        or any(
            character not in "0123456789abcdef"
            for character in snapshot["tree_oid"].lower()
        )
        or snapshot.get("object_format") != "sha1"
        or snapshot.get("materialization_policy") != SNAPSHOT_MATERIALIZATION_POLICY_ID
        or not isinstance(snapshot.get("file_count"), int)
        or isinstance(snapshot.get("file_count"), bool)
        or not 1 <= snapshot["file_count"] <= MAX_SNAPSHOT_ENTRY_COUNT
        or not isinstance(snapshot.get("directories"), list)
        or any(
            not isinstance(value, str) or not value for value in snapshot["directories"]
        )
        or not isinstance(snapshot.get("size_bytes"), int)
        or isinstance(snapshot.get("size_bytes"), bool)
        or not 0 <= snapshot["size_bytes"] <= MAX_SNAPSHOT_BYTES
        or not _is_sha256(str(snapshot.get("sha256", "")).lower())
        or not isinstance(snapshot.get("files"), list)
    ):
        return False
    snapshot_files = snapshot["files"]
    snapshot_directories = snapshot["directories"]
    if (
        len(snapshot_files) != snapshot["file_count"]
        or len(snapshot_files) + len(snapshot_directories)
        > MAX_SNAPSHOT_TREE_NODE_COUNT
    ):
        return False
    expected_file_keys = {"path", "mode", "object", "size", "sha256"}
    paths: list[str] = []
    total_snapshot_size = 0
    total_snapshot_path_bytes = 0
    for entry in snapshot_files:
        path_bytes = (
            len(entry.get("path", "").encode("utf-8", errors="surrogateescape"))
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
            else MAX_SNAPSHOT_PATH_BYTES + 1
        )
        if (
            not isinstance(entry, dict)
            or set(entry) != expected_file_keys
            or _safe_snapshot_relative(entry.get("path")) != entry.get("path")
            or entry.get("mode") not in {"100644", "100755"}
            or not isinstance(entry.get("object"), str)
            or len(entry["object"]) != 40
            or any(
                character not in "0123456789abcdef"
                for character in entry["object"].lower()
            )
            or not isinstance(entry.get("size"), int)
            or isinstance(entry.get("size"), bool)
            or not 0 <= entry["size"] <= MAX_SNAPSHOT_FILE_BYTES
            or path_bytes > MAX_SNAPSHOT_PATH_BYTES
            or not _is_sha256(str(entry.get("sha256", "")).lower())
        ):
            return False
        paths.append(entry["path"])
        total_snapshot_size += entry["size"]
        total_snapshot_path_bytes += path_bytes
    if (
        any(
            _safe_snapshot_relative(directory) != directory
            for directory in snapshot_directories
        )
        or snapshot_directories != sorted(snapshot_directories)
        or len(snapshot_directories) != len(set(snapshot_directories))
        or paths != sorted(paths)
        or len(paths) != len(set(paths))
        or total_snapshot_size != snapshot["size_bytes"]
        or total_snapshot_size > MAX_SNAPSHOT_BYTES
        or total_snapshot_path_bytes > MAX_SNAPSHOT_PATH_BYTES_TOTAL
        or hashlib.sha256(
            json.dumps(
                {
                    "directories": snapshot_directories,
                    "files": snapshot_files,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        != snapshot["sha256"]
    ):
        return False
    snapshot_files_by_path = {entry["path"]: entry for entry in snapshot_files}
    has_python_source = "src" in snapshot_directories or any(
        path.startswith("src/") for path in paths
    )
    sandbox_environment = trusted.get("sandbox_environment")
    expected_sandbox_environment = _expected_sandbox_environment(
        cuda_visible_devices=trusted["cuda_visible_devices"],
        has_python_source=has_python_source,
    )
    if (
        sandbox_environment != expected_sandbox_environment
        or not _is_sha256(str(trusted.get("sandbox_environment_sha256", "")).lower())
        or trusted["sandbox_environment_sha256"].lower()
        != _canonical_json_sha256(expected_sandbox_environment)
    ):
        return False
    operational_count = trusted.get("operational_change_count")
    if (
        not isinstance(operational_count, int)
        or isinstance(operational_count, bool)
        or operational_count < 0
    ):
        return False
    if not isinstance(trusted.get("gpu_allowed"), bool) or not isinstance(
        trusted.get("network_allowed"),
        bool,
    ):
        return False
    maximum = trusted.get("max_output_bytes")
    if not _fixed_output_limit_valid(maximum):
        return False

    receipt_hashes = _retained_bundle_hashes(
        bundle,
        "trusted_runner_receipt",
        workspace_root=workspace_root,
        bundle_directory=bundle_directory,
    )
    if trusted["receipt_sha256"].lower() not in receipt_hashes:
        return False
    retained_manifest = _retained_json(
        bundle,
        "manifest",
        expected_sha256=verifier_evidence["manifest_sha256"].lower(),
        workspace_root=workspace_root,
        bundle_directory=bundle_directory,
    )
    retained_receipt = _retained_json(
        bundle,
        "trusted_runner_receipt",
        expected_sha256=trusted["receipt_sha256"].lower(),
        workspace_root=workspace_root,
        bundle_directory=bundle_directory,
    )
    if retained_manifest is None or retained_receipt is None:
        return False
    if set(retained_receipt) != TRUSTED_RECEIPT_DOCUMENT_KEYS:
        return False
    receipt_view = {
        key: value
        for key, value in trusted.items()
        if key not in {"receipt_path", "receipt_sha256"}
    }
    if retained_receipt != receipt_view:
        return False
    manifest_validations = retained_manifest.get("validations")
    if not isinstance(manifest_validations, list) or not manifest_validations:
        return False
    expected_contract_sha256 = validation_contract_sha256(
        task_id=str(task.get("id")),
        attempt=int(task.get("attempt")),
        actor=str(verification.get("verified_by")),
        source_commit=trusted["source_commit"],
        source_tree=snapshot["tree_oid"],
        snapshot_sha256=snapshot["sha256"],
        manifest_sha256=verifier_evidence["manifest_sha256"].lower(),
        gpu_allowed=trusted["gpu_allowed"],
        network_allowed=trusted["network_allowed"],
        validations=manifest_validations,
    )
    if trusted["validation_contract_sha256"] != expected_contract_sha256:
        return False
    validations = trusted.get("validations")
    if (
        not isinstance(validations, list)
        or not validations
        or len(validations) != len(manifest_validations)
    ):
        return False
    first_run_directory = _receipt_run_directory(
        validations[0].get("output_path") if isinstance(validations[0], dict) else None,
        workspace_root=workspace_root,
        task_id=task.get("id"),
        attempt=task.get("attempt"),
        index=0,
    )
    if first_run_directory is None or not _canonical_receipt_path_valid(
        trusted.get("receipt_path"), first_run_directory
    ):
        return False
    snapshot_mount_source: Path | None = None
    if (
        isinstance(snapshot_protection, dict)
        and snapshot_protection.get("broker") == "external-privileged-fd-lease"
    ):
        first_launch = validations[0].get("isolation_launch_argv")
        if not isinstance(first_launch, list):
            return False
        mount_sources = [
            first_launch[index + 1]
            for index, value in enumerate(first_launch[:-2])
            if value == "--ro-bind" and first_launch[index + 2] == "/workspace"
        ]
        if (
            len(mount_sources) != 1
            or not isinstance(mount_sources[0], str)
            or SAFE_BROKER_FD_ALIAS.fullmatch(mount_sources[0]) is None
        ):
            return False
        snapshot_mount_source = Path(mount_sources[0])
    output_evidence = _retained_bundle_evidence(
        bundle,
        "trusted_runner_output",
        workspace_root=workspace_root,
        bundle_directory=bundle_directory,
        maximum_bytes=MAX_OUTPUT_BYTES,
    )
    for index, (manifest_validation, validation) in enumerate(
        zip(manifest_validations, validations, strict=True)
    ):
        if not _valid_command_receipt(
            manifest_validation,
            validation,
            expected_index=index,
            isolation_backend=isolation_backend,
            sandbox_environment=sandbox_environment,
            snapshot_files=snapshot_files_by_path,
            workspace_root=workspace_root,
            task_id=task.get("id"),
            attempt=task.get("attempt"),
            network_allowed=trusted["network_allowed"],
            maximum_output_bytes=maximum,
            output_evidence=output_evidence,
            expected_run_directory=first_run_directory,
            snapshot_mount_source=snapshot_mount_source,
        ):
            return False
    return True


def task_trust_projection(
    task: dict[str, Any],
    *,
    current_commit: str | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    """Project historical proof separately from current-release eligibility.

    A task that was validly verified at commit A remains part of the immutable
    historical roadmap after commit B is created.  It is *not*, however,
    eligible evidence for release B until revalidated.  Keeping the two axes
    separate prevents progress from being erased without weakening the current
    release gate.
    """

    try:
        state = str(task.get("state", "pending"))
        if state not in {"verified", "archived"}:
            return {
                "recorded_state": state,
                "historical_state": state,
                "historical_trusted": False,
                "verified_source_commit": None,
                "current_release_state": state,
                "current_release_validated": False,
            }
        if workspace_root is None:
            raise ValueError("workspace root is required for verified evidence")
        authoritative = _authoritative_verification(
            task,
            workspace_root=workspace_root.resolve(),
        )
        if authoritative is None:
            raise ValueError("signed verification evidence is unavailable")
        verification, bundle, bundle_directory, verification_event, events = (
            authoritative
        )
        independence = verification.get("independence")
        independent = (
            isinstance(independence, dict) and independence.get("independent") is True
        )
        trusted_valid = _valid_trusted_verification(
            verification,
            task=task,
            current_commit=None,
            workspace_root=workspace_root.resolve(),
            bundle=bundle,
            bundle_directory=bundle_directory,
        )
        if not independent or not trusted_valid:
            if not trusted_valid and os.environ.get("COGNI_TEST_DIAGNOSTICS") == "1":
                rejected_at = _diagnostic_false_return_line(
                    lambda: _valid_trusted_verification(
                        verification,
                        task=task,
                        current_commit=None,
                        workspace_root=workspace_root.resolve(),
                        bundle=bundle,
                        bundle_directory=bundle_directory,
                    )
                )
                print(
                    "COGNI_TRUST_DIAGNOSTIC "
                    f"task={task.get('id')} rejected_at={rejected_at}",
                    file=sys.stderr,
                )
            raise ValueError("historical verification proof is invalid")
        trusted = verification["trusted_validation"]
        verified_source_commit = str(trusted["source_commit"]).lower()
        restated_status = _effective_restatement(
            events,
            verification_event,
            workspace_root=workspace_root,
        )
        if restated_status is not None:
            return {
                "recorded_state": state,
                "historical_state": restated_status,
                "historical_trusted": False,
                "verified_source_commit": None,
                "current_release_state": restated_status,
                "current_release_validated": False,
            }
        current_release_validated = (
            isinstance(current_commit, str)
            and current_commit.lower() == verified_source_commit
        )
        return {
            "recorded_state": state,
            "historical_state": state,
            "historical_trusted": True,
            "verified_source_commit": verified_source_commit,
            "current_release_state": (
                state if current_release_validated else "verification_disputed"
            ),
            "current_release_validated": current_release_validated,
        }
    except Exception:  # noqa: BLE001 - observers must project malformed proof as disputed
        # This function is used by the dashboard publisher and doctor.  Missing,
        # concurrently replaced, malformed, or permission-denied evidence is a
        # trust failure, not a reason for those fail-closed observers to crash.
        return {
            "recorded_state": str(task.get("state", "pending")),
            "historical_state": "verification_disputed",
            "historical_trusted": False,
            "verified_source_commit": None,
            "current_release_state": "verification_disputed",
            "current_release_validated": False,
        }


def task_trust_state(
    task: dict[str, Any],
    *,
    current_commit: str | None = None,
    workspace_root: Path | None = None,
) -> str:
    """Return historical state, or current-release state when commit is supplied."""

    projection = task_trust_projection(
        task,
        current_commit=current_commit,
        workspace_root=workspace_root,
    )
    if current_commit is None:
        return str(projection["historical_state"])
    return str(projection["current_release_state"])
