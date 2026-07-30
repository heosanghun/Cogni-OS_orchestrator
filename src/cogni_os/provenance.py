"""Offline Git provenance checks for Cogni-OS proxy submissions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from .errors import AuthorizationError, ConfigurationError, EvidenceError
from .util import is_relative_to, sha256_file, validate_agent_id

COMMIT_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
REMOTE_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")


def _run_git(
    repository: Path,
    arguments: list[str],
    *,
    binary: bool = False,
) -> str | bytes:
    environment = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    completed = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={repository}",
            "-C",
            str(repository),
            *arguments,
        ],
        check=False,
        capture_output=True,
        env=environment,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", "replace").strip()
        raise EvidenceError(
            f"Git provenance command failed ({' '.join(arguments)}): {error}"
        )
    if binary:
        return completed.stdout
    return completed.stdout.decode("utf-8", "strict").strip()


def _validate_remote_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError("Git provenance remote_url must be non-empty")
    remote_url = value.strip()
    parsed = urlsplit(remote_url)
    if parsed.scheme in {"http", "https"} and (
        parsed.username is not None or parsed.password is not None
    ):
        raise AuthorizationError(
            "Git provenance remote_url must not contain embedded credentials"
        )
    if "\n" in remote_url or "\r" in remote_url:
        raise ConfigurationError("Git provenance remote_url contains a line break")
    return remote_url


def validate_git_source_claim(remote_url: Any, branch: Any) -> tuple[str, str]:
    """Validate the immutable source constraints stored in a proxy grant."""
    normalized_remote = _validate_remote_url(remote_url)
    if not isinstance(branch, str) or not branch.strip():
        raise ConfigurationError("Git provenance branch must be non-empty")
    normalized_branch = branch.strip()
    if "\n" in normalized_branch or "\r" in normalized_branch:
        raise ConfigurationError("Git provenance branch contains a line break")
    if normalized_branch.startswith("-"):
        raise ConfigurationError("Git provenance branch cannot start with '-'")
    return normalized_remote, normalized_branch


def validate_git_commit(value: Any) -> str:
    """Return a normalized full Git object ID for preregistration."""
    commit = str(value or "").lower()
    if not COMMIT_RE.fullmatch(commit):
        raise ConfigurationError(
            "Git provenance commit must be a full 40- or 64-character object ID"
        )
    return commit


def _validate_source_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigurationError("Git provenance source_path must be non-empty")
    if (
        "\\" in value
        or ":" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise ConfigurationError(
            "Git provenance source_path must be a plain POSIX relative path"
        )
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ConfigurationError(
            "Git provenance source_path must not escape the repository"
        )
    return path.as_posix()


def _evidence_file_map(evidence: dict[str, Any]) -> dict[Path, str]:
    files: dict[Path, str] = {}
    for artifact in evidence.get("manifest", {}).get("artifacts", []):
        files[Path(artifact["path"]).resolve()] = artifact["sha256"]
    for validation in evidence.get("manifest", {}).get("validations", []):
        raw_output = validation.get("raw_output")
        if raw_output:
            files[Path(raw_output["path"]).resolve()] = raw_output["sha256"]
    return files


def validate_git_provenance(
    provenance_path: str | Path,
    *,
    source_repository: str | Path,
    report_root: str | Path,
    expected_author: str,
    evidence: dict[str, Any],
    max_blob_bytes: int,
) -> dict[str, Any]:
    """Bind every claim-bearing evidence file to raw bytes in one Git commit."""
    provenance = Path(provenance_path).resolve()
    owned_root = Path(report_root).resolve()
    if not is_relative_to(provenance, owned_root):
        raise AuthorizationError(
            f"Provenance manifest must be under the transport report directory: "
            f"{owned_root}"
        )
    if not provenance.is_file():
        raise EvidenceError(f"Git provenance manifest does not exist: {provenance}")
    try:
        payload = json.loads(provenance.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"Invalid Git provenance JSON: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise EvidenceError("Git provenance schema_version must be 1")
    if payload.get("kind") != "git":
        raise EvidenceError("Git provenance kind must be 'git'")

    author = validate_agent_id(str(payload.get("author", "")))
    if author != validate_agent_id(expected_author):
        raise AuthorizationError(
            f"Git provenance author {author!r} does not match task owner "
            f"{expected_author!r}"
        )
    remote_name = str(payload.get("remote_name", "origin"))
    if not REMOTE_NAME_RE.fullmatch(remote_name):
        raise ConfigurationError("Git provenance remote_name is invalid")
    remote_url, branch = validate_git_source_claim(
        payload.get("remote_url"),
        payload.get("branch"),
    )
    commit = validate_git_commit(payload.get("commit"))
    if not isinstance(max_blob_bytes, int) or max_blob_bytes < 1:
        raise ConfigurationError("max_blob_bytes must be a positive integer")

    repository = Path(source_repository).resolve()
    if not repository.is_dir():
        raise EvidenceError(f"Git source repository does not exist: {repository}")
    actual_remote = str(
        _run_git(repository, ["remote", "get-url", remote_name])
    )
    if actual_remote != remote_url:
        raise EvidenceError(
            f"Git remote mismatch: expected {remote_url!r}, observed "
            f"{actual_remote!r}"
        )
    _run_git(repository, ["check-ref-format", "--branch", branch])
    resolved_commit = str(
        _run_git(repository, ["rev-parse", "--verify", f"{commit}^{{commit}}"])
    ).lower()
    if resolved_commit != commit:
        raise EvidenceError(
            f"Git commit mismatch: expected {commit}, observed {resolved_commit}"
        )

    candidates = [
        f"refs/remotes/{remote_name}/{branch}",
        f"refs/heads/{branch}",
    ]
    resolved_ref = None
    ref_tip = None
    for candidate in candidates:
        try:
            tip = str(_run_git(repository, ["rev-parse", "--verify", f"{candidate}^{{commit}}"])).lower()
            resolved_ref = candidate
            ref_tip = tip
            break
        except EvidenceError:
            continue
    if not resolved_ref or not ref_tip:
        raise EvidenceError(f"Branch {branch!r} could not be resolved in {repository}")

    is_ancestor = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={repository}",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            commit,
            ref_tip,
        ],
        check=False,
        capture_output=True,
    ).returncode == 0
    if not is_ancestor:
        raise EvidenceError(
            f"Commit {commit} is not reachable from branch {branch!r} tip ({ref_tip})"
        )

    files = _evidence_file_map(evidence)
    file_provenance: list[dict[str, Any]] = []
    bindings = payload.get("bindings")
    if not isinstance(bindings, list) or not bindings:
        raise EvidenceError("Git provenance bindings must be a non-empty list")

    bound_paths: set[Path] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            raise EvidenceError("Git provenance binding must be an object")
        rel_path = _validate_source_path(binding.get("source_path"))
        try:
            blob_bytes = _run_git(repository, ["cat-file", "-p", f"{commit}:{rel_path}"], binary=True)
        except EvidenceError as exc:
            raise EvidenceError(
                f"Source path {rel_path!r} not found at commit {commit}: {exc}"
            ) from exc
        if not isinstance(blob_bytes, bytes):
            blob_bytes = str(blob_bytes).encode("utf-8")
        if len(blob_bytes) > max_blob_bytes:
            raise EvidenceError(
                f"Source blob {rel_path!r} size ({len(blob_bytes)}) exceeds max allowed bytes ({max_blob_bytes})"
            )
        blob_sha = hashlib.sha256(blob_bytes).hexdigest()

        target_file = (owned_root / rel_path).resolve()
        bound_paths.add(target_file)
        if target_file in files:
            expected_sha = files[target_file]
            if expected_sha != blob_sha:
                raise EvidenceError(
                    f"Blob SHA-256 mismatch for {rel_path!r}: expected {expected_sha}, observed {blob_sha}"
                )

        file_provenance.append({
            "source_path": rel_path,
            "commit": commit,
            "sha256": blob_sha,
            "size_bytes": len(blob_bytes),
        })

    for file_path in files:
        if file_path not in bound_paths:
            raise EvidenceError(
                f"Evidence file {file_path} is missing a corresponding Git provenance binding"
            )

    return {
        "valid": True,
        "kind": "git",
        "author": author,
        "remote_name": remote_name,
        "remote_url": remote_url,
        "branch": branch,
        "commit": commit,
        "ref": resolved_ref,
        "ref_tip": ref_tip,
        "file_provenance": file_provenance,
    }
