"""Shared fail-closed projection of raw task states into trusted states."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

TRUSTED_RUNNER_ID = "cogni-os-trusted-runner-v1"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _retained_bundle_hashes(
    verifier_evidence: dict[str, Any],
    kind: str,
    *,
    workspace_root: Path | None,
) -> set[str]:
    bundle = verifier_evidence.get("bundle")
    if not isinstance(bundle, dict):
        return set()
    files = bundle.get("files")
    if not isinstance(files, list):
        return set()
    hashes: set[str] = set()
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
        if workspace_root is not None:
            candidate = Path(item["archive_path"]).resolve()
            try:
                candidate.relative_to(workspace_root.resolve())
            except ValueError:
                continue
            if not candidate.is_file() or _sha256_file(candidate) != digest:
                continue
        hashes.add(digest)
    return hashes


def _valid_trusted_verification(
    verification: dict[str, Any],
    *,
    task: dict[str, Any],
    current_commit: str | None,
    workspace_root: Path | None,
) -> bool:
    verifier_evidence = verification.get("verifier_evidence")
    trusted = verification.get("trusted_validation")
    if not isinstance(verifier_evidence, dict) or not isinstance(trusted, dict):
        return False
    if not _is_sha256(
        str(verifier_evidence.get("manifest_sha256", "")).lower()
    ):
        return False
    bundle = verifier_evidence.get("bundle")
    if (
        not isinstance(bundle, dict)
        or not _is_sha256(str(bundle.get("manifest_sha256", "")).lower())
        or bundle.get("task_id") != task.get("id")
        or bundle.get("attempt") != task.get("attempt")
        or bundle.get("label") != "verifier"
    ):
        return False
    manifest_hashes = _retained_bundle_hashes(
        verifier_evidence,
        "manifest",
        workspace_root=workspace_root,
    )
    if verifier_evidence["manifest_sha256"].lower() not in manifest_hashes:
        return False
    if (
        trusted.get("runner") != TRUSTED_RUNNER_ID
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
        or not _is_sha256(
            str(trusted.get("operational_paths_sha256", "")).lower()
        )
        or not _is_sha256(str(trusted.get("environment_sha256", "")).lower())
    ):
        return False
    if current_commit is not None and trusted["source_commit"] != current_commit:
        return False
    permissions = task.get("permissions")
    if not isinstance(permissions, dict):
        return False
    if trusted["gpu_allowed"] is not bool(permissions.get("gpu", False)):
        return False
    if not _valid_cuda_visibility(
        trusted.get("cuda_visible_devices"),
        gpu_allowed=trusted["gpu_allowed"],
    ):
        return False
    if trusted["network_allowed"] is not bool(
        permissions.get("network", False)
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
    if (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or maximum < 1
        or maximum > 16 * 1024 * 1024
    ):
        return False

    receipt_hashes = _retained_bundle_hashes(
        verifier_evidence,
        "trusted_runner_receipt",
        workspace_root=workspace_root,
    )
    if trusted["receipt_sha256"].lower() not in receipt_hashes:
        return False
    validations = trusted.get("validations")
    if not isinstance(validations, list) or not validations:
        return False
    output_hashes = _retained_bundle_hashes(
        verifier_evidence,
        "trusted_runner_output",
        workspace_root=workspace_root,
    )
    for validation in validations:
        command_policy = (
            validation.get("command_policy")
            if isinstance(validation, dict)
            else None
        )
        if (
            not isinstance(validation, dict)
            or validation.get("exit_code") != 0
            or validation.get("timed_out") is not False
            or validation.get("output_truncated") is not False
            or not isinstance(validation.get("command_argv"), list)
            or not validation["command_argv"]
            or not isinstance(command_policy, dict)
            or command_policy.get("kind")
            not in {"python", "node", "powershell-file"}
            or not _is_sha256(
                str(command_policy.get("executable_sha256", "")).lower()
            )
            or not isinstance(command_policy.get("executable_path"), str)
            or not command_policy["executable_path"]
            or not isinstance(command_policy.get("executable_binding"), str)
            or not command_policy["executable_binding"]
            or not isinstance(validation.get("executed_argv"), list)
            or not validation["executed_argv"]
            or validation["executed_argv"]
            != command_policy.get("executed_argv")
            or not _is_sha256(
                str(validation.get("executable_sha256_after", "")).lower()
            )
            or validation["executable_sha256_after"].lower()
            != command_policy["executable_sha256"].lower()
            or not _is_sha256(
                str(validation.get("output_sha256", "")).lower()
            )
            or not isinstance(validation.get("output_size_bytes"), int)
            or isinstance(validation.get("output_size_bytes"), bool)
            or validation["output_size_bytes"] < 1
            or validation["output_size_bytes"] > maximum
            or validation["output_sha256"].lower() not in output_hashes
        ):
            return False
    return True


def task_trust_state(
    task: dict[str, Any],
    *,
    current_commit: str | None = None,
    workspace_root: Path | None = None,
) -> str:
    """Return a raw task state or verification_disputed when proof is untrusted."""

    state = str(task.get("state", "pending"))
    if state not in {"verified", "archived"}:
        return state
    verification = task.get("verification")
    if not isinstance(verification, dict):
        return "verification_disputed"
    independence = verification.get("independence")
    independent = (
        isinstance(independence, dict)
        and independence.get("independent") is True
    )
    if not independent or not _valid_trusted_verification(
        verification,
        task=task,
        current_commit=current_commit,
        workspace_root=workspace_root,
    ):
        return "verification_disputed"
    return state
