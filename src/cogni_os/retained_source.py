"""Fail-closed retention contract for dedicated-verifier source inputs.

The verifier must never execute an actor's mutable working tree.  This module
copies an already-created Git bundle, an independently created verifier
manifest, and a validation contract into a one-time, content-addressed
directory.  Every input and retained output is a bounded regular file, is
opened without following the final symlink where the platform supports it,
and is hashed again from the retained bytes.

This is deliberately *not* a Git implementation.  It does not run Git, prove
that a bundle contains the claimed commit/tree, or materialize a checkout.
It also cannot prove that a caller-selected directory is root-owned and
immutable.  Those operational assurances require the later Linux root E2E
gate recorded in :data:`RETAINED_SOURCE_API_ASSURANCE`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping

RETAINED_SOURCE_CONTRACT_ID: Final = "cogni-os.retained-source.v1"
RETAINED_SOURCE_SCHEMA_VERSION: Final = 1

MAX_GIT_BUNDLE_BYTES: Final = 8 * 1024 * 1024 * 1024
MAX_VERIFIER_MANIFEST_BYTES: Final = 16 * 1024 * 1024
MAX_VALIDATION_CONTRACT_BYTES: Final = 4 * 1024 * 1024
MAX_RETAINED_RECORD_BYTES: Final = 64 * 1024
READ_CHUNK_BYTES: Final = 1024 * 1024
MAX_ATTEMPT: Final = 1_000_000

GIT_BUNDLE_FILENAME: Final = "source.bundle"
VERIFIER_MANIFEST_FILENAME: Final = "verifier-manifest.json"
VALIDATION_CONTRACT_FILENAME: Final = "validation-contract.json"
RECORD_FILENAME: Final = "retained-source.json"
_EXPECTED_FILENAMES: Final = frozenset(
    {
        GIT_BUNDLE_FILENAME,
        VERIFIER_MANIFEST_FILENAME,
        VALIDATION_CONTRACT_FILENAME,
        RECORD_FILENAME,
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_SCOPE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")

_TOP_LEVEL_KEYS: Final = frozenset(
    {
        "schema_version",
        "contract_id",
        "artifact_id",
        "identity",
        "source",
        "verifier_manifest",
        "validation_contract",
        "storage",
        "assurance",
    }
)
_IDENTITY_KEYS: Final = frozenset(
    {"repository_id", "workspace_id", "task_id", "attempt", "run_id"}
)
_SOURCE_KEYS: Final = frozenset({"git_bundle", "commit_oid", "tree_oid"})
_DIGEST_KEYS: Final = frozenset({"sha256", "size_bytes"})
_STORAGE_KEYS: Final = frozenset({"immutable_root_path", "relative_directory", "files"})
_STORAGE_FILE_KEYS: Final = frozenset(
    {"git_bundle", "verifier_manifest", "validation_contract", "record"}
)
_FILE_BINDING_KEYS: Final = frozenset({"name", "sha256", "size_bytes"})
_RECORD_BINDING_KEYS: Final = frozenset({"name"})

RETAINED_SOURCE_API_ASSURANCE: Final[dict[str, Any]] = {
    "actor_working_tree_execution_input": False,
    "ancestor_junction_reparse_chain_verified": False,
    "bounded_regular_files_only": True,
    "content_addressed_once_only": True,
    "retained_bytes_rehashed": True,
    "git_bundle_object_graph_verified": False,
    "git_commit_tree_verified": False,
    "git_materialization_performed": False,
    "linux_root_owned_immutable_store_e2e": False,
    "release_eligible": False,
    "remaining_blockers": [
        "actual-git-bundle-and-commit-tree-verification",
        "git-materialization-from-retained-objects-only",
        "linux-root-owned-immutable-store-e2e",
        "ancestor-junction-reparse-chain-verification",
    ],
}
_ASSURANCE_KEYS: Final = frozenset(RETAINED_SOURCE_API_ASSURANCE)


class RetainedSourceError(RuntimeError):
    """Raised when retained-source creation or verification must fail closed."""


class VerifierIntegrityError(RetainedSourceError):
    """Raised when retained-source inventory violates its bounded contract."""


@dataclass(frozen=True)
class _FileObservation:
    sha256: str
    size_bytes: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class RetainedSourceArtifact:
    """A fully re-read retained artifact; never an actor working-tree path."""

    artifact_id: str
    directory: Path
    record: dict[str, Any]
    record_sha256: str
    created: bool

    @property
    def git_bundle_path(self) -> Path:
        return self.directory / GIT_BUNDLE_FILENAME

    @property
    def verifier_manifest_path(self) -> Path:
        return self.directory / VERIFIER_MANIFEST_FILENAME

    @property
    def validation_contract_path(self) -> Path:
        return self.directory / VALIDATION_CONTRACT_FILENAME


def retained_source_api_assurance() -> dict[str, Any]:
    """Return a detached copy of the API's deliberately bounded assurance."""

    return json.loads(json.dumps(RETAINED_SOURCE_API_ASSURANCE))


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise RetainedSourceError(
            "Retained-source value is not canonical JSON"
        ) from exc
    if len(encoded) > MAX_RETAINED_RECORD_BYTES:
        raise RetainedSourceError("Retained-source record exceeds its fixed size limit")
    return encoded


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_link_or_reparse(file_stat: os.stat_result) -> bool:
    attributes = getattr(file_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(file_stat.st_mode) or bool(attributes & reparse_flag)


def _require_exact_mapping(
    value: Any, expected_keys: frozenset[str], label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise RetainedSourceError(f"{label} schema is not exact")
    if any(not isinstance(key, str) for key in value):
        raise RetainedSourceError(f"{label} contains a non-string key")
    return value


def _validate_identifier(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise RetainedSourceError(f"{label} is invalid")
    return value


def _validate_sha256(value: Any, label: str) -> str:
    return _validate_identifier(value, _SHA256_RE, label)


def _validate_positive_size(value: Any, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RetainedSourceError(f"{label} must be an integer")
    if value < 1 or value > maximum:
        raise RetainedSourceError(f"{label} is outside the fixed bounds")
    return value


def _resolved_existing_directory(path: Path, label: str) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise RetainedSourceError(f"{label} must be an absolute path")
    try:
        raw_stat = path.lstat()
        resolved = path.resolve(strict=True)
        resolved_stat = resolved.lstat()
    except OSError as exc:
        raise RetainedSourceError(f"{label} cannot be inspected") from exc
    if _is_link_or_reparse(raw_stat) or _is_link_or_reparse(resolved_stat):
        raise RetainedSourceError(f"{label} cannot be a symlink or reparse point")
    if not stat.S_ISDIR(resolved_stat.st_mode):
        raise RetainedSourceError(f"{label} must be a directory")
    return resolved


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolved_regular_input(path: Path, label: str) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise RetainedSourceError(f"{label} path must be absolute")
    try:
        raw_stat = path.lstat()
    except OSError as exc:
        raise RetainedSourceError(f"{label} path cannot be inspected") from exc
    if _is_link_or_reparse(raw_stat) or not stat.S_ISREG(raw_stat.st_mode):
        raise RetainedSourceError(f"{label} must be a regular non-link file")
    if raw_stat.st_nlink != 1:
        raise RetainedSourceError(f"{label} must not be hard-linked")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise RetainedSourceError(f"{label} path cannot be resolved") from exc


def _open_regular_file(
    path: Path, maximum: int, label: str
) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RetainedSourceError(f"{label} cannot be inspected") from exc
    if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise RetainedSourceError(f"{label} must be a regular non-link file")
    if before.st_nlink != 1:
        raise RetainedSourceError(f"{label} must not be hard-linked")
    _validate_positive_size(before.st_size, maximum, f"{label} size")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RetainedSourceError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            _is_link_or_reparse(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise RetainedSourceError(f"{label} changed before it was opened")
        _validate_positive_size(opened.st_size, maximum, f"{label} size")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _observe_file(path: Path, maximum: int, label: str) -> _FileObservation:
    descriptor, opened = _open_regular_file(path, maximum, label)
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            size_bytes += len(chunk)
            if size_bytes > maximum:
                raise RetainedSourceError(f"{label} exceeds the fixed size limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        after.st_dev != opened.st_dev
        or after.st_ino != opened.st_ino
        or after.st_size != opened.st_size
        or after.st_mtime_ns != opened.st_mtime_ns
        or after.st_ctime_ns != opened.st_ctime_ns
        or after.st_nlink != 1
        or size_bytes != opened.st_size
    ):
        raise RetainedSourceError(f"{label} changed while it was read")
    return _FileObservation(
        sha256=digest.hexdigest(),
        size_bytes=size_bytes,
        device=opened.st_dev,
        inode=opened.st_ino,
        mtime_ns=opened.st_mtime_ns,
        ctime_ns=opened.st_ctime_ns,
    )


def _same_observation(left: _FileObservation, right: _FileObservation) -> bool:
    return left == right


def _write_exclusive_bytes(path: Path, content: bytes, mode: int = 0o400) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise RetainedSourceError(
            f"Retained file cannot be created exclusively: {path.name}"
        ) from exc
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise RetainedSourceError(f"Retained file write failed: {path.name}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_exclusive(
    source: Path,
    destination: Path,
    maximum: int,
    expected: _FileObservation,
    label: str,
) -> None:
    source_fd, _ = _open_regular_file(source, maximum, label)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        destination_fd = os.open(destination, flags, 0o400)
    except OSError as exc:
        os.close(source_fd)
        raise RetainedSourceError(
            f"Retained file cannot be created exclusively: {destination.name}"
        ) from exc

    digest = hashlib.sha256()
    size_bytes = 0
    try:
        while True:
            chunk = os.read(source_fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            size_bytes += len(chunk)
            if size_bytes > maximum:
                raise RetainedSourceError(f"{label} exceeds the fixed size limit")
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_fd, chunk[offset:])
                if written <= 0:
                    raise RetainedSourceError(
                        f"Retained file write failed: {destination.name}"
                    )
                offset += written
        os.fsync(destination_fd)
        copied_source = os.fstat(source_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)

    current = _FileObservation(
        sha256=digest.hexdigest(),
        size_bytes=size_bytes,
        device=copied_source.st_dev,
        inode=copied_source.st_ino,
        mtime_ns=copied_source.st_mtime_ns,
        ctime_ns=copied_source.st_ctime_ns,
    )
    if copied_source.st_nlink != 1 or not _same_observation(current, expected):
        raise RetainedSourceError(f"{label} changed between inspection and retention")
    retained = _observe_file(destination, maximum, f"retained {label}")
    if retained.sha256 != expected.sha256 or retained.size_bytes != expected.size_bytes:
        raise RetainedSourceError(f"retained {label} bytes do not match the binding")


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _scan_exact_inventory(directory: Path) -> frozenset[str]:
    """Read at most one entry beyond the fixed four-file inventory.

    The fifth entry is sufficient proof that the directory cannot satisfy the
    exact schema.  Continuing to enumerate an attacker-controlled directory
    would provide no additional assurance and could create an unbounded DoS.
    """

    try:
        iterator = os.scandir(directory)
    except OSError as exc:
        raise VerifierIntegrityError(
            "Retained-source inventory cannot be opened"
        ) from exc
    names: set[str] = set()
    try:
        for index, entry in enumerate(iterator, start=1):
            if index > len(_EXPECTED_FILENAMES):
                raise VerifierIntegrityError(
                    "Retained-source inventory exceeds the fixed entry limit"
                )
            names.add(entry.name)
    except OSError as exc:
        raise VerifierIntegrityError(
            "Retained-source inventory cannot be read"
        ) from exc
    finally:
        close = getattr(iterator, "close", None)
        if callable(close):
            close()
    inventory = frozenset(names)
    if inventory != _EXPECTED_FILENAMES:
        raise VerifierIntegrityError("Retained-source inventory is not exact")
    return inventory


def _binding_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    storage = record["storage"]
    return {
        "schema_version": record["schema_version"],
        "contract_id": record["contract_id"],
        "identity": record["identity"],
        "source": record["source"],
        "verifier_manifest": record["verifier_manifest"],
        "validation_contract": record["validation_contract"],
        "immutable_root_path": storage["immutable_root_path"],
        "assurance": record["assurance"],
    }


def _validate_record(record: Any, root: Path, artifact_id: str) -> dict[str, Any]:
    top = _require_exact_mapping(record, _TOP_LEVEL_KEYS, "retained source")
    if top["schema_version"] != RETAINED_SOURCE_SCHEMA_VERSION:
        raise RetainedSourceError("Retained-source schema version is unsupported")
    if top["contract_id"] != RETAINED_SOURCE_CONTRACT_ID:
        raise RetainedSourceError("Retained-source contract id is invalid")
    if top["artifact_id"] != artifact_id:
        raise RetainedSourceError("Retained-source artifact id does not match its path")

    identity = _require_exact_mapping(top["identity"], _IDENTITY_KEYS, "identity")
    _validate_identifier(identity["repository_id"], _SCOPE_ID_RE, "repository_id")
    _validate_identifier(identity["workspace_id"], _SCOPE_ID_RE, "workspace_id")
    _validate_identifier(identity["task_id"], _TASK_ID_RE, "task_id")
    attempt = identity["attempt"]
    if (
        isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or not 1 <= attempt <= MAX_ATTEMPT
    ):
        raise RetainedSourceError("attempt is invalid")
    _validate_identifier(identity["run_id"], _RUN_ID_RE, "run_id")

    source = _require_exact_mapping(top["source"], _SOURCE_KEYS, "source")
    git_bundle = _require_exact_mapping(
        source["git_bundle"], _DIGEST_KEYS, "git bundle"
    )
    _validate_sha256(git_bundle["sha256"], "git bundle sha256")
    _validate_positive_size(
        git_bundle["size_bytes"], MAX_GIT_BUNDLE_BYTES, "git bundle size"
    )
    commit_oid = _validate_identifier(source["commit_oid"], _GIT_OID_RE, "commit_oid")
    tree_oid = _validate_identifier(source["tree_oid"], _GIT_OID_RE, "tree_oid")
    if len(commit_oid) != len(tree_oid):
        raise RetainedSourceError(
            "commit_oid and tree_oid must use the same hash format"
        )

    manifest = _require_exact_mapping(
        top["verifier_manifest"], _DIGEST_KEYS, "verifier manifest"
    )
    _validate_sha256(manifest["sha256"], "verifier manifest sha256")
    _validate_positive_size(
        manifest["size_bytes"], MAX_VERIFIER_MANIFEST_BYTES, "verifier manifest size"
    )
    contract = _require_exact_mapping(
        top["validation_contract"], _DIGEST_KEYS, "validation contract"
    )
    _validate_sha256(contract["sha256"], "validation contract sha256")
    _validate_positive_size(
        contract["size_bytes"],
        MAX_VALIDATION_CONTRACT_BYTES,
        "validation contract size",
    )

    storage = _require_exact_mapping(top["storage"], _STORAGE_KEYS, "storage")
    if storage["immutable_root_path"] != str(root):
        raise RetainedSourceError("Retained-source immutable root binding changed")
    if storage["relative_directory"] != artifact_id:
        raise RetainedSourceError("Retained-source relative directory is invalid")
    files = _require_exact_mapping(
        storage["files"], _STORAGE_FILE_KEYS, "storage files"
    )
    expected_file_bindings = {
        "git_bundle": (GIT_BUNDLE_FILENAME, git_bundle),
        "verifier_manifest": (VERIFIER_MANIFEST_FILENAME, manifest),
        "validation_contract": (VALIDATION_CONTRACT_FILENAME, contract),
    }
    for key, (name, digest_binding) in expected_file_bindings.items():
        binding = _require_exact_mapping(
            files[key], _FILE_BINDING_KEYS, f"storage file {key}"
        )
        if binding["name"] != name or dict(binding) != {
            "name": name,
            **dict(digest_binding),
        }:
            raise RetainedSourceError(
                f"storage file {key} does not match its digest binding"
            )
    record_binding = _require_exact_mapping(
        files["record"], _RECORD_BINDING_KEYS, "storage record"
    )
    if record_binding["name"] != RECORD_FILENAME:
        raise RetainedSourceError("storage record filename is invalid")

    assurance = _require_exact_mapping(top["assurance"], _ASSURANCE_KEYS, "assurance")
    if dict(assurance) != RETAINED_SOURCE_API_ASSURANCE:
        raise RetainedSourceError("Retained-source assurance was widened or changed")

    expected_artifact_id = _sha256_bytes(
        _canonical_json_bytes(_binding_from_record(top))
    )
    if expected_artifact_id != artifact_id:
        raise RetainedSourceError("Retained-source content address is invalid")
    return dict(top)


def _read_record(path: Path) -> tuple[dict[str, Any], str]:
    observation = _observe_file(
        path, MAX_RETAINED_RECORD_BYTES, "retained source record"
    )
    descriptor, _ = _open_regular_file(
        path, MAX_RETAINED_RECORD_BYTES, "retained source record"
    )
    try:
        content = b""
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            content += chunk
    finally:
        os.close(descriptor)
    if (
        _sha256_bytes(content) != observation.sha256
        or len(content) != observation.size_bytes
    ):
        raise RetainedSourceError("Retained-source record changed during reload")
    try:
        decoded = content.decode("utf-8")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetainedSourceError("Retained-source record is not UTF-8 JSON") from exc
    if not isinstance(value, dict) or content != _canonical_json_bytes(value):
        raise RetainedSourceError("Retained-source record is not canonical JSON")
    return value, observation.sha256


def load_retained_source(
    immutable_root: Path, artifact_id: str, *, created: bool = False
) -> RetainedSourceArtifact:
    """Load and rehash one exact content-addressed retained-source artifact."""

    root = _resolved_existing_directory(Path(immutable_root), "immutable root")
    _validate_sha256(artifact_id, "artifact_id")
    directory = root / artifact_id
    try:
        directory_stat = directory.lstat()
    except OSError as exc:
        raise RetainedSourceError("Retained-source directory does not exist") from exc
    if _is_link_or_reparse(directory_stat) or not stat.S_ISDIR(directory_stat.st_mode):
        raise RetainedSourceError(
            "Retained-source directory is not a regular directory"
        )
    _scan_exact_inventory(directory)

    record, record_sha256 = _read_record(directory / RECORD_FILENAME)
    validated = _validate_record(record, root, artifact_id)
    bindings = {
        GIT_BUNDLE_FILENAME: (validated["source"]["git_bundle"], MAX_GIT_BUNDLE_BYTES),
        VERIFIER_MANIFEST_FILENAME: (
            validated["verifier_manifest"],
            MAX_VERIFIER_MANIFEST_BYTES,
        ),
        VALIDATION_CONTRACT_FILENAME: (
            validated["validation_contract"],
            MAX_VALIDATION_CONTRACT_BYTES,
        ),
    }
    for filename, (binding, maximum) in bindings.items():
        observed = _observe_file(directory / filename, maximum, f"retained {filename}")
        if (
            observed.sha256 != binding["sha256"]
            or observed.size_bytes != binding["size_bytes"]
        ):
            raise RetainedSourceError(f"Retained file bytes do not match: {filename}")
    return RetainedSourceArtifact(
        artifact_id=artifact_id,
        directory=directory,
        record=validated,
        record_sha256=record_sha256,
        created=created,
    )


def retain_source_artifact(
    *,
    immutable_root: Path,
    forbidden_actor_working_tree: Path,
    repository_id: str,
    workspace_id: str,
    task_id: str,
    attempt: int,
    run_id: str,
    git_bundle_path: Path,
    git_bundle_sha256: str,
    git_bundle_size_bytes: int,
    commit_oid: str,
    tree_oid: str,
    verifier_manifest_path: Path,
    verifier_manifest_sha256: str,
    validation_contract_path: Path,
    validation_contract_sha256: str,
) -> RetainedSourceArtifact:
    """Retain exact source inputs without running Git or materializing a tree.

    A repeated call with the same binding returns the already-verified artifact.
    A partial, corrupted, or conflicting pre-existing directory is never
    overwritten; it fails closed and requires privileged operator handling.
    """

    root = _resolved_existing_directory(Path(immutable_root), "immutable root")
    actor_root = _resolved_existing_directory(
        Path(forbidden_actor_working_tree), "forbidden actor working tree"
    )
    if _is_relative_to(root, actor_root) or _is_relative_to(actor_root, root):
        raise RetainedSourceError(
            "Immutable root and actor working tree must not overlap"
        )

    source_paths = {
        "git bundle": Path(git_bundle_path),
        "verifier manifest": Path(verifier_manifest_path),
        "validation contract": Path(validation_contract_path),
    }
    for label, path in source_paths.items():
        resolved = _resolved_regular_input(path, label)
        if _is_relative_to(resolved, actor_root):
            raise RetainedSourceError(
                f"{label} cannot come from the actor working tree"
            )
        if _is_relative_to(resolved, root):
            raise RetainedSourceError(f"{label} cannot alias the retained-source store")
        source_paths[label] = resolved

    repository_id = _validate_identifier(repository_id, _SCOPE_ID_RE, "repository_id")
    workspace_id = _validate_identifier(workspace_id, _SCOPE_ID_RE, "workspace_id")
    task_id = _validate_identifier(task_id, _TASK_ID_RE, "task_id")
    if (
        isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or not 1 <= attempt <= MAX_ATTEMPT
    ):
        raise RetainedSourceError("attempt is invalid")
    run_id = _validate_identifier(run_id, _RUN_ID_RE, "run_id")
    commit_oid = _validate_identifier(commit_oid, _GIT_OID_RE, "commit_oid")
    tree_oid = _validate_identifier(tree_oid, _GIT_OID_RE, "tree_oid")
    if len(commit_oid) != len(tree_oid):
        raise RetainedSourceError(
            "commit_oid and tree_oid must use the same hash format"
        )

    expected_bundle_sha = _validate_sha256(git_bundle_sha256, "git bundle sha256")
    expected_bundle_size = _validate_positive_size(
        git_bundle_size_bytes, MAX_GIT_BUNDLE_BYTES, "git bundle size"
    )
    expected_manifest_sha = _validate_sha256(
        verifier_manifest_sha256, "verifier manifest sha256"
    )
    expected_contract_sha = _validate_sha256(
        validation_contract_sha256, "validation contract sha256"
    )

    bundle = _observe_file(
        source_paths["git bundle"], MAX_GIT_BUNDLE_BYTES, "git bundle"
    )
    manifest = _observe_file(
        source_paths["verifier manifest"],
        MAX_VERIFIER_MANIFEST_BYTES,
        "verifier manifest",
    )
    contract = _observe_file(
        source_paths["validation contract"],
        MAX_VALIDATION_CONTRACT_BYTES,
        "validation contract",
    )
    if (
        bundle.sha256 != expected_bundle_sha
        or bundle.size_bytes != expected_bundle_size
    ):
        raise RetainedSourceError("Git bundle bytes do not match the dispatch binding")
    if manifest.sha256 != expected_manifest_sha:
        raise RetainedSourceError(
            "Verifier manifest bytes do not match the dispatch binding"
        )
    if contract.sha256 != expected_contract_sha:
        raise RetainedSourceError(
            "Validation contract bytes do not match the dispatch binding"
        )

    binding = {
        "schema_version": RETAINED_SOURCE_SCHEMA_VERSION,
        "contract_id": RETAINED_SOURCE_CONTRACT_ID,
        "identity": {
            "repository_id": repository_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "attempt": attempt,
            "run_id": run_id,
        },
        "source": {
            "git_bundle": {"sha256": bundle.sha256, "size_bytes": bundle.size_bytes},
            "commit_oid": commit_oid,
            "tree_oid": tree_oid,
        },
        "verifier_manifest": {
            "sha256": manifest.sha256,
            "size_bytes": manifest.size_bytes,
        },
        "validation_contract": {
            "sha256": contract.sha256,
            "size_bytes": contract.size_bytes,
        },
        "immutable_root_path": str(root),
        "assurance": retained_source_api_assurance(),
    }
    artifact_id = _sha256_bytes(_canonical_json_bytes(binding))
    directory = root / artifact_id
    storage = {
        "immutable_root_path": str(root),
        "relative_directory": artifact_id,
        "files": {
            "git_bundle": {
                "name": GIT_BUNDLE_FILENAME,
                "sha256": bundle.sha256,
                "size_bytes": bundle.size_bytes,
            },
            "verifier_manifest": {
                "name": VERIFIER_MANIFEST_FILENAME,
                "sha256": manifest.sha256,
                "size_bytes": manifest.size_bytes,
            },
            "validation_contract": {
                "name": VALIDATION_CONTRACT_FILENAME,
                "sha256": contract.sha256,
                "size_bytes": contract.size_bytes,
            },
            "record": {"name": RECORD_FILENAME},
        },
    }
    record = {
        "schema_version": RETAINED_SOURCE_SCHEMA_VERSION,
        "contract_id": RETAINED_SOURCE_CONTRACT_ID,
        "artifact_id": artifact_id,
        "identity": binding["identity"],
        "source": binding["source"],
        "verifier_manifest": binding["verifier_manifest"],
        "validation_contract": binding["validation_contract"],
        "storage": storage,
        "assurance": binding["assurance"],
    }
    _validate_record(record, root, artifact_id)

    try:
        os.mkdir(directory, 0o700)
        created = True
    except FileExistsError:
        existing = load_retained_source(root, artifact_id, created=False)
        if existing.record != record:
            raise RetainedSourceError("Existing retained-source binding conflicts")
        return existing
    except OSError as exc:
        raise RetainedSourceError(
            "Retained-source directory cannot be created exclusively"
        ) from exc

    # The directory itself is the once-only claim.  Failure leaves a visibly
    # incomplete, non-reusable artifact rather than silently replacing bytes.
    _copy_exclusive(
        source_paths["git bundle"],
        directory / GIT_BUNDLE_FILENAME,
        MAX_GIT_BUNDLE_BYTES,
        bundle,
        "git bundle",
    )
    _copy_exclusive(
        source_paths["verifier manifest"],
        directory / VERIFIER_MANIFEST_FILENAME,
        MAX_VERIFIER_MANIFEST_BYTES,
        manifest,
        "verifier manifest",
    )
    _copy_exclusive(
        source_paths["validation contract"],
        directory / VALIDATION_CONTRACT_FILENAME,
        MAX_VALIDATION_CONTRACT_BYTES,
        contract,
        "validation contract",
    )
    _write_exclusive_bytes(directory / RECORD_FILENAME, _canonical_json_bytes(record))
    _fsync_directory(directory)
    if os.name == "posix":
        for name in _EXPECTED_FILENAMES:
            os.chmod(directory / name, 0o400)
        os.chmod(directory, 0o500)
        _fsync_directory(root)
    return load_retained_source(root, artifact_id, created=created)
