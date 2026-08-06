"""Portable, fail-closed verification of a retained Git bundle.

This module is the trust boundary between :mod:`cogni_os.retained_source`
and later source-tree materialization.  It deliberately consumes a retained
artifact by content address and never accepts an actor working-tree path.

The implementation is portable enough to exercise the complete Git contract
on Windows, but portability is not production assurance.  In particular it
does not prove a root-owned quarantine, a root-owned retained store, POSIX
``openat``/``O_NOFOLLOW`` ancestry, snapshot-broker handoff, or bwrap
execution.  Successful output therefore always has ``release_ready=false``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .retained_source import RetainedSourceArtifact, load_retained_source

RETAINED_GIT_CONTRACT_ID: Final = "cogni-os.retained-git-object-graph.v1"
RETAINED_GIT_SCHEMA_VERSION: Final = 1
RETAINED_GIT_POLICY_ID: Final = "retained-bundle-quarantine-sha1-v1"

MAX_BUNDLE_HEADER_BYTES: Final = 1024 * 1024
MAX_BUNDLE_HEADER_LINE_BYTES: Final = 16 * 1024
MAX_GIT_CONTROL_OUTPUT_BYTES: Final = 4 * 1024 * 1024
MAX_GIT_OBJECT_OUTPUT_BYTES: Final = 16 * 1024 * 1024
MAX_GIT_STDERR_BYTES: Final = 256 * 1024
GIT_COMMAND_TIMEOUT_SECONDS: Final = 30
READ_CHUNK_BYTES: Final = 1024 * 1024

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_POLICY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REF_RE = re.compile(r"^(?:HEAD|refs/[A-Za-z0-9._/-]{1,1024})$")

_MANIFEST_KEYS: Final = frozenset(
    {
        "manifest_sha256",
        "schema_version",
        "contract_id",
        "policy_id",
        "retained_source",
        "git",
        "bundle",
        "source",
        "object_graph",
        "verification",
        "limits",
        "assurance",
    }
)
_MANIFEST_RETAINED_SOURCE_KEYS: Final = frozenset(
    {"artifact_id", "record_sha256", "bundle_sha256", "bundle_size_bytes"}
)
_MANIFEST_GIT_KEYS: Final = frozenset(
    {"binding_policy_id", "executable_sha256", "provenance", "object_format"}
)
_MANIFEST_BUNDLE_KEYS: Final = frozenset(
    {"format_version", "capabilities", "prerequisite_count", "heads"}
)
_MANIFEST_HEAD_KEYS: Final = frozenset({"oid", "ref"})
_MANIFEST_SOURCE_KEYS: Final = frozenset({"commit_oid", "tree_oid"})
_MANIFEST_OBJECT_GRAPH_KEYS: Final = frozenset(
    {
        "object_count",
        "total_inflated_bytes",
        "max_object_bytes",
        "total_disk_bytes",
        "max_disk_object_bytes",
        "inventory_sha256",
        "pack_file_count",
        "pack_total_bytes",
        "max_pack_file_bytes",
        "pack_inventory_sha256",
    }
)
_MANIFEST_VERIFICATION_KEYS: Final = frozenset(
    {"command_plan_sha256", "command_results"}
)
_MANIFEST_RESULT_KEYS: Final = frozenset(
    {"returncode", "stdout_sha256", "stderr_sha256"}
)
_COMMAND_PHASES: Final = (
    "init",
    "object-format-before",
    "bundle-verify",
    "bundle-list-heads",
    "bundle-import",
    "object-format-after",
    "forbidden-config",
    "replace-refs",
    "exact-commit",
    "exact-tree",
    "fsck",
    "object-inventory",
)


@dataclass(frozen=True)
class RetainedGitLimits:
    """Hard ceilings applied after bundle import and before any checkout."""

    max_object_count: int = 50_000
    max_total_object_bytes: int = 512 * 1024 * 1024
    max_single_object_bytes: int = 64 * 1024 * 1024
    max_total_object_disk_bytes: int = 1024 * 1024 * 1024
    max_single_object_disk_bytes: int = 256 * 1024 * 1024
    max_pack_file_count: int = 256
    max_pack_total_bytes: int = 1024 * 1024 * 1024
    max_single_pack_file_bytes: int = 1024 * 1024 * 1024
    max_bundle_heads: int = 1


DEFAULT_RETAINED_GIT_LIMITS: Final = RetainedGitLimits()

RETAINED_GIT_API_ASSURANCE: Final[dict[str, Any]] = {
    "actor_working_tree_execution_input": False,
    "retained_bundle_rehashed": True,
    "git_bundle_verified": True,
    "bundle_prerequisites_allowed": False,
    "extra_bundle_heads_allowed": False,
    "git_object_format": "sha1-only",
    "git_object_graph_bounded": False,
    "portable_post_import_object_graph_bounds_enforced": True,
    "git_commit_tree_verified": True,
    "git_materialization_performed": False,
    "linux_root_owned_quarantine_e2e": False,
    "linux_root_owned_immutable_store_e2e": False,
    "snapshot_broker_handoff_e2e": False,
    "bwrap_network_gpu_isolation_e2e": False,
    "release_ready": False,
    "remaining_blockers": [
        "linux-root-owned-quarantine-and-retained-store-e2e",
        "root-owned-allowlisted-git-binding-and-exec-e2e",
        "pre-import-cpu-memory-disk-quota-e2e",
        "posix-dirfd-ancestor-and-nofollow-e2e",
        "materialization-from-verified-object-store-only",
        "snapshot-broker-fd-handoff-and-signed-cleanup-e2e",
        "bwrap-network-off-gpu-off-execution-e2e",
        "verifier-journal-and-terminal-ledger-receipt-integration",
    ],
}


class RetainedGitError(RuntimeError):
    """Raised when retained Git verification must fail closed."""


@dataclass(frozen=True)
class TrustedGitBinding:
    """A caller-established fixed Git executable binding.

    The module never performs ``PATH`` discovery.  A privileged caller must
    select the executable and bind its digest before invoking verification.
    The digest is checked before and after every command, including commands
    handled by an injected runner.
    """

    policy_id: str
    executable: Path
    sha256: str
    provenance: str


@dataclass(frozen=True)
class GitCommand:
    """One bounded, shell-free Git invocation in the verification plan."""

    phase: str
    argv: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    timeout_seconds: int
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    accepted_returncodes: tuple[int, ...] = (0,)


@dataclass(frozen=True)
class GitCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


GitCommandRunner = Callable[[GitCommand], GitCommandResult]


@dataclass(frozen=True)
class VerifiedRetainedGit:
    """Content-addressed evidence for a verified retained object graph."""

    retained_artifact: RetainedSourceArtifact
    manifest: dict[str, Any]
    manifest_sha256: str
    canonical_manifest_bytes: bytes
    command_plan: tuple[GitCommand, ...]


@dataclass(frozen=True)
class _BundleHeader:
    version: int
    capabilities: tuple[str, ...]
    prerequisites: tuple[str, ...]
    heads: tuple[tuple[str, str], ...]


def retained_git_api_assurance() -> dict[str, Any]:
    """Return a detached copy of the deliberately bounded assurance."""

    return json.loads(json.dumps(RETAINED_GIT_API_ASSURANCE))


def _require_exact_mapping(
    value: Any, expected_keys: frozenset[str], label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise RetainedGitError(f"{label} schema is not exact")
    if any(not isinstance(key, str) for key in value):
        raise RetainedGitError(f"{label} contains a non-string key")
    return value


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (
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
        raise RetainedGitError("Object-graph manifest is not canonical JSON") from exc


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path, *, maximum: int | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                size_bytes += len(chunk)
                if maximum is not None and size_bytes > maximum:
                    raise RetainedGitError(f"File exceeds its fixed bound: {path.name}")
                digest.update(chunk)
    except OSError as exc:
        raise RetainedGitError(f"Cannot hash fixed file: {path}") from exc
    return digest.hexdigest(), size_bytes


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _resolved_existing_directory(path: Path, label: str) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise RetainedGitError(f"{label} must be an absolute path")
    try:
        raw = path.lstat()
        resolved = path.resolve(strict=True)
        current = resolved.lstat()
    except OSError as exc:
        raise RetainedGitError(f"{label} cannot be inspected") from exc
    if _is_link_or_reparse(raw) or _is_link_or_reparse(current):
        raise RetainedGitError(f"{label} cannot be a link or reparse point")
    if not stat.S_ISDIR(current.st_mode):
        raise RetainedGitError(f"{label} must be a directory")
    return resolved


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_limits(limits: RetainedGitLimits) -> RetainedGitLimits:
    if not isinstance(limits, RetainedGitLimits):
        raise RetainedGitError("Retained Git limits have an invalid schema")
    for field_name, value in vars(limits).items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise RetainedGitError(f"Retained Git limit is invalid: {field_name}")
        if value > getattr(DEFAULT_RETAINED_GIT_LIMITS, field_name):
            raise RetainedGitError(
                f"Retained Git limit exceeds the fixed policy ceiling: {field_name}"
            )
    if limits.max_bundle_heads != 1:
        raise RetainedGitError("The current policy requires exactly one bundle head")
    if limits.max_single_object_bytes > limits.max_total_object_bytes:
        raise RetainedGitError("Single-object bound exceeds total-object bound")
    if limits.max_single_object_disk_bytes > limits.max_total_object_disk_bytes:
        raise RetainedGitError("Single disk-object bound exceeds total disk bound")
    if limits.max_single_pack_file_bytes > limits.max_pack_total_bytes:
        raise RetainedGitError("Single-pack bound exceeds total-pack bound")
    return limits


def _validate_binding(binding: TrustedGitBinding) -> TrustedGitBinding:
    if not isinstance(binding, TrustedGitBinding):
        raise RetainedGitError("Trusted Git binding has an invalid schema")
    if _POLICY_ID_RE.fullmatch(binding.policy_id) is None:
        raise RetainedGitError("Trusted Git policy id is invalid")
    if not isinstance(binding.provenance, str) or not binding.provenance.strip():
        raise RetainedGitError("Trusted Git provenance is invalid")
    if _SHA256_RE.fullmatch(binding.sha256) is None:
        raise RetainedGitError("Trusted Git digest is invalid")
    path = Path(binding.executable)
    if not path.is_absolute():
        raise RetainedGitError("Trusted Git executable must use a fixed absolute path")
    try:
        raw = path.lstat()
        resolved = path.resolve(strict=True)
        current = resolved.lstat()
    except OSError as exc:
        raise RetainedGitError("Trusted Git executable cannot be inspected") from exc
    if (
        _is_link_or_reparse(raw)
        or _is_link_or_reparse(current)
        or not stat.S_ISREG(current.st_mode)
    ):
        raise RetainedGitError("Trusted Git executable must be a regular non-link file")
    try:
        if any(
            component.exists() and _is_link_or_reparse(component.lstat())
            for component in (path, *path.parents[:-1])
        ):
            raise RetainedGitError(
                "Trusted Git executable ancestry contains a link or reparse point"
            )
    except OSError as exc:
        raise RetainedGitError(
            "Trusted Git executable ancestry cannot be inspected"
        ) from exc
    actual, _ = _sha256_file(resolved)
    if actual != binding.sha256:
        raise RetainedGitError("Trusted Git executable digest does not match binding")
    return TrustedGitBinding(
        policy_id=binding.policy_id,
        executable=resolved,
        sha256=binding.sha256,
        provenance=binding.provenance,
    )


def _assert_binding_unchanged(binding: TrustedGitBinding) -> None:
    current, _ = _sha256_file(binding.executable)
    if current != binding.sha256:
        raise RetainedGitError("Trusted Git executable changed during verification")


def _read_bundle_header(
    artifact: RetainedSourceArtifact, limits: RetainedGitLimits
) -> _BundleHeader:
    """Parse only the bounded textual prefix before the bundle's PACK bytes."""

    consumed = 0
    capabilities: list[str] = []
    prerequisites: list[str] = []
    heads: list[tuple[str, str]] = []
    try:
        with artifact.git_bundle_path.open("rb") as handle:
            first = handle.readline(MAX_BUNDLE_HEADER_LINE_BYTES + 1)
            consumed += len(first)
            if len(first) > MAX_BUNDLE_HEADER_LINE_BYTES:
                raise RetainedGitError("Git bundle header line exceeds its bound")
            if first == b"# v2 git bundle\n":
                version = 2
            elif first == b"# v3 git bundle\n":
                version = 3
            else:
                raise RetainedGitError("Git bundle header version is unsupported")
            while True:
                line = handle.readline(MAX_BUNDLE_HEADER_LINE_BYTES + 1)
                consumed += len(line)
                if len(line) > MAX_BUNDLE_HEADER_LINE_BYTES:
                    raise RetainedGitError("Git bundle header line exceeds its bound")
                if consumed > MAX_BUNDLE_HEADER_BYTES:
                    raise RetainedGitError("Git bundle header exceeds its fixed bound")
                if line in (b"\n", b"\r\n"):
                    break
                if not line:
                    raise RetainedGitError("Git bundle header is truncated")
                try:
                    text = line.rstrip(b"\r\n").decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise RetainedGitError("Git bundle header is not UTF-8") from exc
                if text.startswith("@"):  # v3 capability
                    capabilities.append(text[1:])
                    continue
                if text.startswith("-"):
                    oid = text[1:].split(" ", 1)[0].lower()
                    if _SHA1_RE.fullmatch(oid) is None:
                        raise RetainedGitError("Git bundle prerequisite OID is invalid")
                    prerequisites.append(oid)
                    continue
                try:
                    oid, refname = text.split(" ", 1)
                except ValueError as exc:
                    raise RetainedGitError("Git bundle head line is invalid") from exc
                oid = oid.lower()
                if (
                    _SHA1_RE.fullmatch(oid) is None
                    or _REF_RE.fullmatch(refname) is None
                ):
                    raise RetainedGitError("Git bundle head is invalid")
                heads.append((oid, refname))
                if len(heads) > limits.max_bundle_heads:
                    raise RetainedGitError("Git bundle contains extra heads")
    except OSError as exc:
        raise RetainedGitError("Retained Git bundle cannot be read") from exc

    if prerequisites:
        raise RetainedGitError("Git bundle prerequisites are forbidden")
    if version == 2 and capabilities:
        raise RetainedGitError("Git bundle v2 cannot declare capabilities")
    if any(item != "object-format=sha1" for item in capabilities):
        raise RetainedGitError(
            "Filtered or unknown Git bundle capabilities are forbidden"
        )
    object_formats = [
        item.split("=", 1)[1].lower()
        for item in capabilities
        if item.startswith("object-format=") and "=" in item
    ]
    if object_formats and object_formats != ["sha1"]:
        raise RetainedGitError("SHA-256 Git repositories are unsupported")
    if len(heads) != 1:
        raise RetainedGitError("Git bundle must contain exactly one head")
    return _BundleHeader(
        version=version,
        capabilities=tuple(capabilities),
        prerequisites=tuple(prerequisites),
        heads=tuple(heads),
    )


def _git_environment(binding: TrustedGitBinding, scratch: Path) -> dict[str, str]:
    home = scratch / "home"
    temporary = scratch / "tmp"
    config_home = home / ".config"
    for directory in (home, temporary, config_home):
        directory.mkdir(parents=True, exist_ok=True)
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": str(binding.executable.parent),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "XDG_CONFIG_HOME": str(config_home),
    }


def _base_argv(binding: TrustedGitBinding) -> list[str]:
    return [
        str(binding.executable),
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "credential.helper=",
        "-c",
        "core.askPass=",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "diff.external=",
        "-c",
        "protocol.allow=never",
        "-c",
        "transfer.fsckObjects=true",
        "-c",
        "fetch.fsckObjects=true",
        "-c",
        "receive.fsckObjects=true",
    ]


def _command(
    *,
    phase: str,
    binding: TrustedGitBinding,
    git_dir: Path,
    bundle_path: Path,
    scratch: Path,
    arguments: Sequence[str],
    stdout_limit: int = MAX_GIT_CONTROL_OUTPUT_BYTES,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> GitCommand:
    expanded = [
        str(git_dir)
        if value == "<GIT_DIR>"
        else str(bundle_path)
        if value == "<BUNDLE>"
        else value
        for value in arguments
    ]
    return GitCommand(
        phase=phase,
        argv=(*_base_argv(binding), *expanded),
        cwd=scratch,
        environment=_git_environment(binding, scratch),
        timeout_seconds=GIT_COMMAND_TIMEOUT_SECONDS,
        stdout_limit_bytes=stdout_limit,
        stderr_limit_bytes=MAX_GIT_STDERR_BYTES,
        accepted_returncodes=accepted_returncodes,
    )


def build_retained_git_command_plan(
    *,
    binding: TrustedGitBinding,
    git_dir: Path,
    bundle_path: Path,
    scratch: Path,
    expected_commit_oid: str,
) -> tuple[GitCommand, ...]:
    """Build the fixed command sequence without consulting an actor tree."""

    if _SHA1_RE.fullmatch(expected_commit_oid) is None:
        raise RetainedGitError("Expected commit must be a SHA-1 object id")
    return (
        _command(
            phase="init",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=("init", "--bare", "--object-format=sha1", "<GIT_DIR>"),
        ),
        _command(
            phase="object-format-before",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(f"--git-dir={git_dir}", "rev-parse", "--show-object-format"),
        ),
        _command(
            phase="bundle-verify",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(f"--git-dir={git_dir}", "bundle", "verify", "<BUNDLE>"),
        ),
        _command(
            phase="bundle-list-heads",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(f"--git-dir={git_dir}", "bundle", "list-heads", "<BUNDLE>"),
        ),
        _command(
            phase="bundle-import",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(f"--git-dir={git_dir}", "bundle", "unbundle", "<BUNDLE>"),
        ),
        _command(
            phase="object-format-after",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(f"--git-dir={git_dir}", "rev-parse", "--show-object-format"),
        ),
        _command(
            phase="forbidden-config",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(
                f"--git-dir={git_dir}",
                "config",
                "--local",
                "--get-regexp",
                r"^(extensions\.partialClone|remote\..*\.promisor)$",
            ),
            accepted_returncodes=(0, 1),
        ),
        _command(
            phase="replace-refs",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(
                f"--git-dir={git_dir}",
                "for-each-ref",
                "--format=%(refname)",
                "refs/replace/",
            ),
        ),
        _command(
            phase="exact-commit",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(
                f"--git-dir={git_dir}",
                "rev-parse",
                "--verify",
                f"{expected_commit_oid}^{{commit}}",
            ),
        ),
        _command(
            phase="exact-tree",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(
                f"--git-dir={git_dir}",
                "rev-parse",
                "--verify",
                f"{expected_commit_oid}^{{tree}}",
            ),
        ),
        _command(
            phase="fsck",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(
                f"--git-dir={git_dir}",
                "fsck",
                "--full",
                "--strict",
                "--no-reflogs",
                "--unreachable",
                expected_commit_oid,
            ),
        ),
        _command(
            phase="object-inventory",
            binding=binding,
            git_dir=git_dir,
            bundle_path=bundle_path,
            scratch=scratch,
            arguments=(
                f"--git-dir={git_dir}",
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname) %(objecttype) %(objectsize) %(objectsize:disk)",
            ),
            stdout_limit=MAX_GIT_OBJECT_OUTPUT_BYTES,
        ),
    )


def _read_bounded_stream(stream: Any, limit: int, overflow: threading.Event) -> bytes:
    output = bytearray()
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        remaining = limit - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])
        if len(chunk) > remaining:
            overflow.set()
    return bytes(output)


def _subprocess_runner(command: GitCommand) -> GitCommandResult:
    process: subprocess.Popen[bytes] | None = None
    stdout_overflow = threading.Event()
    stderr_overflow = threading.Event()
    stdout_value: list[bytes] = []
    stderr_value: list[bytes] = []
    try:
        process = subprocess.Popen(
            command.argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=command.cwd,
            env=dict(command.environment),
            close_fds=True,
        )
        if process.stdout is None or process.stderr is None:
            raise RetainedGitError("Trusted Git pipes were not created")
        stdout_thread = threading.Thread(
            target=lambda: stdout_value.append(
                _read_bounded_stream(
                    process.stdout, command.stdout_limit_bytes, stdout_overflow
                )
            ),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=lambda: stderr_value.append(
                _read_bounded_stream(
                    process.stderr, command.stderr_limit_bytes, stderr_overflow
                )
            ),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            returncode = process.wait(timeout=command.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=2)
            raise RetainedGitError(
                f"Trusted Git timed out during {command.phase}"
            ) from exc
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        if stdout_overflow.is_set() or stderr_overflow.is_set():
            raise RetainedGitError(
                f"Trusted Git output exceeded its bound during {command.phase}"
            )
        return GitCommandResult(
            returncode=returncode,
            stdout=stdout_value[0] if stdout_value else b"",
            stderr=stderr_value[0] if stderr_value else b"",
        )
    except RetainedGitError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise RetainedGitError(
            f"Trusted Git could not run during {command.phase}"
        ) from exc
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.SubprocessError:
                pass
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


def _execute_command(
    command: GitCommand,
    binding: TrustedGitBinding,
    runner: GitCommandRunner,
) -> GitCommandResult:
    if command.argv[0] != str(binding.executable):
        raise RetainedGitError("Git command escaped the fixed executable binding")
    _assert_binding_unchanged(binding)
    result = runner(command)
    _assert_binding_unchanged(binding)
    if not isinstance(result, GitCommandResult):
        raise RetainedGitError("Trusted Git runner returned an invalid result")
    if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes):
        raise RetainedGitError("Trusted Git runner output must be bytes")
    if result.returncode not in command.accepted_returncodes:
        detail = result.stderr[:4096].decode("utf-8", errors="replace").strip()
        raise RetainedGitError(f"Trusted Git failed during {command.phase}: {detail}")
    if len(result.stdout) > command.stdout_limit_bytes:
        raise RetainedGitError(
            f"Trusted Git stdout exceeded its bound during {command.phase}"
        )
    if len(result.stderr) > command.stderr_limit_bytes:
        raise RetainedGitError(
            f"Trusted Git stderr exceeded its bound during {command.phase}"
        )
    return result


def _parse_single_ascii_oid(output: bytes, label: str) -> str:
    try:
        value = output.decode("ascii", errors="strict").strip().lower()
    except UnicodeDecodeError as exc:
        raise RetainedGitError(f"{label} output is not ASCII") from exc
    if _SHA1_RE.fullmatch(value) is None:
        raise RetainedGitError(f"{label} output is not one SHA-1 object id")
    return value


def _parse_list_heads(output: bytes) -> tuple[tuple[str, str], ...]:
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise RetainedGitError("bundle list-heads output is not UTF-8") from exc
    heads: list[tuple[str, str]] = []
    for line in lines:
        try:
            oid, refname = line.split(" ", 1)
        except ValueError as exc:
            raise RetainedGitError("bundle list-heads output is invalid") from exc
        oid = oid.lower()
        if _SHA1_RE.fullmatch(oid) is None or _REF_RE.fullmatch(refname) is None:
            raise RetainedGitError("bundle list-heads output is invalid")
        heads.append((oid, refname))
        if len(heads) > 1:
            raise RetainedGitError("bundle list-heads returned extra heads")
    if len(heads) != 1:
        raise RetainedGitError("bundle list-heads must return exactly one head")
    return tuple(heads)


def _parse_object_inventory(
    output: bytes,
    limits: RetainedGitLimits,
    *,
    expected_commit_oid: str,
    expected_tree_oid: str,
) -> tuple[dict[str, Any], str]:
    try:
        lines = output.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise RetainedGitError("Git object inventory is not ASCII") from exc
    entries: list[tuple[str, str, int, int]] = []
    total_bytes = 0
    total_disk_bytes = 0
    max_bytes = 0
    max_disk_bytes = 0
    seen: set[str] = set()
    types_by_oid: dict[str, str] = {}
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 4:
            raise RetainedGitError("Git object inventory line is invalid")
        oid, object_type, size_text, disk_text = parts
        oid = oid.lower()
        if _SHA1_RE.fullmatch(oid) is None or object_type not in {
            "blob",
            "commit",
            "tag",
            "tree",
        }:
            raise RetainedGitError("Git object inventory identity is invalid")
        if oid in seen:
            raise RetainedGitError("Git object inventory contains a duplicate OID")
        seen.add(oid)
        types_by_oid[oid] = object_type
        try:
            size_bytes = int(size_text, 10)
            disk_bytes = int(disk_text, 10)
        except ValueError as exc:
            raise RetainedGitError("Git object inventory size is invalid") from exc
        if size_bytes < 0 or disk_bytes < 0:
            raise RetainedGitError("Git object inventory size is negative")
        if size_bytes > limits.max_single_object_bytes:
            raise RetainedGitError("Git object exceeds the single-object bound")
        if disk_bytes > limits.max_single_object_disk_bytes:
            raise RetainedGitError("Git object exceeds the disk-object bound")
        total_bytes += size_bytes
        total_disk_bytes += disk_bytes
        if total_bytes > limits.max_total_object_bytes:
            raise RetainedGitError("Git objects exceed the total inflated-byte bound")
        if total_disk_bytes > limits.max_total_object_disk_bytes:
            raise RetainedGitError("Git objects exceed the total disk-byte bound")
        entries.append((oid, object_type, size_bytes, disk_bytes))
        if len(entries) > limits.max_object_count:
            raise RetainedGitError("Git object count exceeds its fixed bound")
        max_bytes = max(max_bytes, size_bytes)
        max_disk_bytes = max(max_disk_bytes, disk_bytes)
    if not entries:
        raise RetainedGitError("Git object inventory is empty")
    if expected_commit_oid not in seen or expected_tree_oid not in seen:
        raise RetainedGitError("Expected commit/tree is absent from object inventory")
    if (
        types_by_oid[expected_commit_oid] != "commit"
        or types_by_oid[expected_tree_oid] != "tree"
    ):
        raise RetainedGitError("Expected commit/tree has the wrong object type")
    entries.sort()
    inventory_bytes = _canonical_json_bytes(
        {"objects": [list(entry) for entry in entries]}
    )
    return (
        {
            "object_count": len(entries),
            "total_inflated_bytes": total_bytes,
            "max_object_bytes": max_bytes,
            "total_disk_bytes": total_disk_bytes,
            "max_disk_object_bytes": max_disk_bytes,
        },
        _sha256_bytes(inventory_bytes),
    )


def _reject_forbidden_repository_features(git_dir: Path) -> None:
    forbidden_files = (
        git_dir / "objects" / "info" / "alternates",
        git_dir / "info" / "grafts",
        git_dir / "shallow",
    )
    for path in forbidden_files:
        if path.exists() or path.is_symlink():
            raise RetainedGitError(
                f"Forbidden Git repository feature exists: {path.name}"
            )
    pack_dir = git_dir / "objects" / "pack"
    if pack_dir.exists():
        try:
            iterator = os.scandir(pack_dir)
            try:
                for entry in iterator:
                    if entry.name.endswith(".promisor"):
                        raise RetainedGitError("Promisor object stores are forbidden")
            finally:
                iterator.close()
        except OSError as exc:
            raise RetainedGitError("Git pack directory cannot be inspected") from exc


def _pack_inventory(
    git_dir: Path, limits: RetainedGitLimits
) -> tuple[dict[str, Any], str]:
    pack_dir = git_dir / "objects" / "pack"
    if not pack_dir.is_dir():
        raise RetainedGitError("Git pack directory is missing")
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    max_bytes = 0
    allowed_suffixes = {".pack", ".idx", ".rev", ".bitmap"}
    try:
        iterator = os.scandir(pack_dir)
        try:
            for entry in iterator:
                if len(entries) >= limits.max_pack_file_count:
                    raise RetainedGitError(
                        "Git pack file count exceeds its fixed bound"
                    )
                metadata = entry.stat(follow_symlinks=False)
                if (
                    entry.is_symlink()
                    or _is_link_or_reparse(metadata)
                    or not stat.S_ISREG(metadata.st_mode)
                ):
                    raise RetainedGitError(
                        "Git pack inventory contains a non-regular file"
                    )
                suffix = Path(entry.name).suffix
                if suffix == ".promisor":
                    raise RetainedGitError("Promisor object stores are forbidden")
                if suffix not in allowed_suffixes:
                    raise RetainedGitError(
                        "Git pack inventory contains an unknown file"
                    )
                if metadata.st_size > limits.max_single_pack_file_bytes:
                    raise RetainedGitError(
                        "Git pack file exceeds the single-file bound"
                    )
                total_bytes += metadata.st_size
                max_bytes = max(max_bytes, metadata.st_size)
                if total_bytes > limits.max_pack_total_bytes:
                    raise RetainedGitError("Git pack files exceed the total-byte bound")
                digest, observed_size = _sha256_file(
                    Path(entry.path), maximum=limits.max_single_pack_file_bytes
                )
                if observed_size != metadata.st_size:
                    raise RetainedGitError("Git pack file changed while being hashed")
                entries.append(
                    {"name": entry.name, "sha256": digest, "size_bytes": observed_size}
                )
        finally:
            iterator.close()
    except OSError as exc:
        raise RetainedGitError("Git pack inventory cannot be inspected") from exc
    entries.sort(key=lambda item: item["name"])
    inventory_bytes = _canonical_json_bytes({"files": entries})
    return (
        {
            "pack_file_count": len(entries),
            "pack_total_bytes": total_bytes,
            "max_pack_file_bytes": max_bytes,
        },
        _sha256_bytes(inventory_bytes),
    )


def _normalized_command_plan_sha256(plan: Sequence[GitCommand]) -> str:
    normalized: list[dict[str, Any]] = []
    for command in plan:
        argv = []
        for value in command.argv[1:]:
            if value.startswith("--git-dir="):
                value = "--git-dir=<QUARANTINE>"
            elif value == str(command.cwd.parent / "repo.git"):
                value = "<QUARANTINE>"
            elif value.endswith("source.bundle") and Path(value).is_absolute():
                value = "<RETAINED_BUNDLE>"
            argv.append(value)
        normalized.append(
            {
                "phase": command.phase,
                "arguments": argv,
                "timeout_seconds": command.timeout_seconds,
                "stdout_limit_bytes": command.stdout_limit_bytes,
                "stderr_limit_bytes": command.stderr_limit_bytes,
                "accepted_returncodes": list(command.accepted_returncodes),
            }
        )
    return _sha256_bytes(_canonical_json_bytes({"commands": normalized}))


def _result_hashes(results: Mapping[str, GitCommandResult]) -> dict[str, Any]:
    return {
        phase: {
            "returncode": result.returncode,
            "stdout_sha256": _sha256_bytes(result.stdout),
            "stderr_sha256": _sha256_bytes(result.stderr),
        }
        for phase, result in sorted(results.items())
    }


def validate_retained_git_manifest(manifest: Any) -> dict[str, Any]:
    """Validate the exact output schema and its embedded content address."""

    top = _require_exact_mapping(manifest, _MANIFEST_KEYS, "retained Git manifest")
    if top["schema_version"] != RETAINED_GIT_SCHEMA_VERSION:
        raise RetainedGitError("Retained Git manifest schema version is unsupported")
    if top["contract_id"] != RETAINED_GIT_CONTRACT_ID:
        raise RetainedGitError("Retained Git manifest contract id is invalid")
    if top["policy_id"] != RETAINED_GIT_POLICY_ID:
        raise RetainedGitError("Retained Git manifest policy id is invalid")
    if (
        not isinstance(top["manifest_sha256"], str)
        or _SHA256_RE.fullmatch(top["manifest_sha256"]) is None
    ):
        raise RetainedGitError("Retained Git manifest content address is invalid")

    retained = _require_exact_mapping(
        top["retained_source"],
        _MANIFEST_RETAINED_SOURCE_KEYS,
        "manifest retained source",
    )
    for name in ("artifact_id", "record_sha256", "bundle_sha256"):
        if (
            not isinstance(retained[name], str)
            or _SHA256_RE.fullmatch(retained[name]) is None
        ):
            raise RetainedGitError(f"Manifest {name} is invalid")
    if (
        isinstance(retained["bundle_size_bytes"], bool)
        or not isinstance(retained["bundle_size_bytes"], int)
        or retained["bundle_size_bytes"] < 1
    ):
        raise RetainedGitError("Manifest bundle size is invalid")

    git = _require_exact_mapping(top["git"], _MANIFEST_GIT_KEYS, "manifest Git")
    if git["object_format"] != "sha1":
        raise RetainedGitError("Manifest Git object format is unsupported")
    if (
        not isinstance(git["executable_sha256"], str)
        or _SHA256_RE.fullmatch(git["executable_sha256"]) is None
    ):
        raise RetainedGitError("Manifest Git executable digest is invalid")
    if not all(
        isinstance(git[name], str) and git[name]
        for name in ("binding_policy_id", "provenance")
    ):
        raise RetainedGitError("Manifest Git binding is invalid")

    bundle = _require_exact_mapping(
        top["bundle"], _MANIFEST_BUNDLE_KEYS, "manifest bundle"
    )
    if bundle["format_version"] not in (2, 3) or bundle["prerequisite_count"] != 0:
        raise RetainedGitError("Manifest bundle format is invalid")
    if not isinstance(bundle["capabilities"], list) or any(
        not isinstance(item, str) for item in bundle["capabilities"]
    ):
        raise RetainedGitError("Manifest bundle capabilities are invalid")
    if (
        bundle["format_version"] == 2
        and bundle["capabilities"]
        or bundle["format_version"] == 3
        and bundle["capabilities"] not in ([], ["object-format=sha1"])
    ):
        raise RetainedGitError("Manifest bundle capabilities violate policy")
    heads = bundle["heads"]
    if not isinstance(heads, list) or len(heads) != 1:
        raise RetainedGitError("Manifest bundle heads are invalid")
    head = _require_exact_mapping(heads[0], _MANIFEST_HEAD_KEYS, "manifest bundle head")
    if (
        not isinstance(head["oid"], str)
        or _SHA1_RE.fullmatch(head["oid"]) is None
        or not isinstance(head["ref"], str)
        or _REF_RE.fullmatch(head["ref"]) is None
    ):
        raise RetainedGitError("Manifest bundle head is invalid")

    source = _require_exact_mapping(
        top["source"], _MANIFEST_SOURCE_KEYS, "manifest source"
    )
    for name in ("commit_oid", "tree_oid"):
        if (
            not isinstance(source[name], str)
            or _SHA1_RE.fullmatch(source[name]) is None
        ):
            raise RetainedGitError(f"Manifest source {name} is invalid")
    if head["oid"] != source["commit_oid"]:
        raise RetainedGitError("Manifest head and source commit do not match")

    object_graph = _require_exact_mapping(
        top["object_graph"],
        _MANIFEST_OBJECT_GRAPH_KEYS,
        "manifest object graph",
    )
    for name in _MANIFEST_OBJECT_GRAPH_KEYS - {
        "inventory_sha256",
        "pack_inventory_sha256",
    }:
        if (
            isinstance(object_graph[name], bool)
            or not isinstance(object_graph[name], int)
            or object_graph[name] < 0
        ):
            raise RetainedGitError(f"Manifest object graph metric is invalid: {name}")
    if object_graph["object_count"] < 1:
        raise RetainedGitError("Manifest object graph is empty")
    for name in ("inventory_sha256", "pack_inventory_sha256"):
        if (
            not isinstance(object_graph[name], str)
            or _SHA256_RE.fullmatch(object_graph[name]) is None
        ):
            raise RetainedGitError(f"Manifest object graph digest is invalid: {name}")

    verification = _require_exact_mapping(
        top["verification"],
        _MANIFEST_VERIFICATION_KEYS,
        "manifest verification",
    )
    if (
        not isinstance(verification["command_plan_sha256"], str)
        or _SHA256_RE.fullmatch(verification["command_plan_sha256"]) is None
    ):
        raise RetainedGitError("Manifest command-plan digest is invalid")
    command_results = _require_exact_mapping(
        verification["command_results"],
        frozenset(_COMMAND_PHASES),
        "manifest command results",
    )
    for phase, value in command_results.items():
        result = _require_exact_mapping(
            value, _MANIFEST_RESULT_KEYS, f"manifest command result {phase}"
        )
        allowed_returncodes = (0, 1) if phase == "forbidden-config" else (0,)
        if (
            isinstance(result["returncode"], bool)
            or not isinstance(result["returncode"], int)
            or result["returncode"] not in allowed_returncodes
        ):
            raise RetainedGitError("Manifest command return code is invalid")
        for name in ("stdout_sha256", "stderr_sha256"):
            if (
                not isinstance(result[name], str)
                or _SHA256_RE.fullmatch(result[name]) is None
            ):
                raise RetainedGitError("Manifest command output digest is invalid")

    limit_keys = frozenset(vars(DEFAULT_RETAINED_GIT_LIMITS))
    limit_values = _require_exact_mapping(top["limits"], limit_keys, "manifest limits")
    limits = _validate_limits(RetainedGitLimits(**dict(limit_values)))
    bounded_metrics = {
        "object_count": limits.max_object_count,
        "total_inflated_bytes": limits.max_total_object_bytes,
        "max_object_bytes": limits.max_single_object_bytes,
        "total_disk_bytes": limits.max_total_object_disk_bytes,
        "max_disk_object_bytes": limits.max_single_object_disk_bytes,
        "pack_file_count": limits.max_pack_file_count,
        "pack_total_bytes": limits.max_pack_total_bytes,
        "max_pack_file_bytes": limits.max_single_pack_file_bytes,
    }
    for name, maximum in bounded_metrics.items():
        if object_graph[name] > maximum:
            raise RetainedGitError(
                f"Manifest object graph metric exceeds its limit: {name}"
            )
    for maximum_name, total_name in (
        ("max_object_bytes", "total_inflated_bytes"),
        ("max_disk_object_bytes", "total_disk_bytes"),
        ("max_pack_file_bytes", "pack_total_bytes"),
    ):
        if object_graph[maximum_name] > object_graph[total_name]:
            raise RetainedGitError(
                f"Manifest object graph metrics are inconsistent: {maximum_name}"
            )
    assurance = _require_exact_mapping(
        top["assurance"], frozenset(RETAINED_GIT_API_ASSURANCE), "manifest assurance"
    )
    if dict(assurance) != RETAINED_GIT_API_ASSURANCE:
        raise RetainedGitError("Manifest assurance was widened or changed")

    without_id = {key: value for key, value in top.items() if key != "manifest_sha256"}
    if _sha256_bytes(_canonical_json_bytes(without_id)) != top["manifest_sha256"]:
        raise RetainedGitError("Retained Git manifest content address does not match")
    return json.loads(json.dumps(dict(top)))


def _remove_quarantine(path: Path) -> None:
    """Remove only the verifier-created temporary tree, including read-only Git files."""

    def make_writable_and_retry(
        function: Callable[[str], object], value: str, _: Any
    ) -> None:
        try:
            os.chmod(value, stat.S_IWRITE | stat.S_IREAD)
            function(value)
        except OSError:
            return

    shutil.rmtree(path, onerror=make_writable_and_retry)
    if path.exists():
        raise RetainedGitError("Verifier quarantine cleanup did not complete")


def verify_retained_git_artifact(
    *,
    immutable_root: Path,
    artifact_id: str,
    quarantine_root: Path,
    git_binding: TrustedGitBinding,
) -> VerifiedRetainedGit:
    """Production-shaped entrypoint with fixed runner and resource ceilings."""

    return _verify_retained_git_artifact(
        immutable_root=immutable_root,
        artifact_id=artifact_id,
        quarantine_root=quarantine_root,
        git_binding=git_binding,
        command_runner=_subprocess_runner,
        limits=DEFAULT_RETAINED_GIT_LIMITS,
    )


def _verify_retained_git_artifact(
    *,
    immutable_root: Path,
    artifact_id: str,
    quarantine_root: Path,
    git_binding: TrustedGitBinding,
    command_runner: GitCommandRunner,
    limits: RetainedGitLimits = DEFAULT_RETAINED_GIT_LIMITS,
) -> VerifiedRetainedGit:
    """Verify one retained bundle in an ephemeral, isolated bare repository.

    Only ``immutable_root`` plus ``artifact_id`` identify source input.  No
    actor checkout, actor repository, branch name, or actor Git object database
    is accepted by this API.
    """

    limits = _validate_limits(limits)
    binding = _validate_binding(git_binding)
    artifact = load_retained_source(Path(immutable_root), artifact_id)
    quarantine_parent = _resolved_existing_directory(
        Path(quarantine_root), "quarantine root"
    )
    if _is_relative_to(quarantine_parent, artifact.directory) or _is_relative_to(
        artifact.directory, quarantine_parent
    ):
        raise RetainedGitError("Quarantine root and retained artifact must not overlap")

    source = artifact.record["source"]
    bundle_binding = source["git_bundle"]
    if bundle_binding["size_bytes"] > limits.max_pack_total_bytes:
        raise RetainedGitError(
            "Retained bundle exceeds the pre-import pack/disk ceiling"
        )
    expected_commit = source["commit_oid"].lower()
    expected_tree = source["tree_oid"].lower()
    if len(expected_commit) != 40 or len(expected_tree) != 40:
        raise RetainedGitError("SHA-256 Git repositories are unsupported")
    if (
        _SHA1_RE.fullmatch(expected_commit) is None
        or _SHA1_RE.fullmatch(expected_tree) is None
    ):
        raise RetainedGitError("Retained source commit/tree OIDs are invalid")
    header = _read_bundle_header(artifact, limits)
    if header.heads[0][0] != expected_commit:
        raise RetainedGitError("Git bundle head does not equal the expected commit")

    runner = command_runner
    run_directory = Path(
        tempfile.mkdtemp(
            prefix=f"cogni-retained-git-{artifact.artifact_id[:12]}-",
            dir=quarantine_parent,
        )
    )
    git_dir = run_directory / "repo.git"
    scratch = run_directory / "scratch"
    scratch.mkdir(mode=0o700)
    plan: tuple[GitCommand, ...] = ()
    results: dict[str, GitCommandResult] = {}
    try:
        plan = build_retained_git_command_plan(
            binding=binding,
            git_dir=git_dir,
            bundle_path=artifact.git_bundle_path,
            scratch=scratch,
            expected_commit_oid=expected_commit,
        )
        for command in plan:
            result = _execute_command(command, binding, runner)
            results[command.phase] = result
            if command.phase in {"object-format-before", "object-format-after"}:
                if result.stdout.decode("ascii", errors="strict").strip() != "sha1":
                    raise RetainedGitError("SHA-256 Git repositories are unsupported")
            elif command.phase == "bundle-list-heads":
                listed_heads = _parse_list_heads(result.stdout)
                if (
                    listed_heads != header.heads
                    or listed_heads[0][0] != expected_commit
                ):
                    raise RetainedGitError(
                        "bundle list-heads does not match retained header"
                    )
            elif command.phase == "bundle-import":
                imported_heads = _parse_list_heads(result.stdout)
                if imported_heads != header.heads:
                    raise RetainedGitError(
                        "bundle import does not match retained header"
                    )
                _reject_forbidden_repository_features(git_dir)
            elif command.phase == "forbidden-config":
                if result.stdout.strip():
                    raise RetainedGitError(
                        "Partial-clone or promisor configuration is forbidden"
                    )
            elif command.phase == "replace-refs":
                if result.stdout.strip():
                    raise RetainedGitError("Git replace refs are forbidden")
            elif command.phase == "exact-commit":
                if (
                    _parse_single_ascii_oid(result.stdout, "exact commit")
                    != expected_commit
                ):
                    raise RetainedGitError(
                        "Imported commit does not equal the expected commit"
                    )
            elif (
                command.phase == "exact-tree"
                and _parse_single_ascii_oid(result.stdout, "exact tree")
                != expected_tree
            ):
                raise RetainedGitError("Imported tree does not equal the expected tree")

        _reject_forbidden_repository_features(git_dir)
        object_metrics, object_inventory_sha256 = _parse_object_inventory(
            results["object-inventory"].stdout,
            limits,
            expected_commit_oid=expected_commit,
            expected_tree_oid=expected_tree,
        )
        pack_metrics, pack_inventory_sha256 = _pack_inventory(git_dir, limits)
        bundle_digest, bundle_size = _sha256_file(artifact.git_bundle_path)
        if (
            bundle_digest != bundle_binding["sha256"]
            or bundle_size != bundle_binding["size_bytes"]
        ):
            raise RetainedGitError("Retained bundle changed during Git verification")
        _assert_binding_unchanged(binding)

        manifest_without_id = {
            "schema_version": RETAINED_GIT_SCHEMA_VERSION,
            "contract_id": RETAINED_GIT_CONTRACT_ID,
            "policy_id": RETAINED_GIT_POLICY_ID,
            "retained_source": {
                "artifact_id": artifact.artifact_id,
                "record_sha256": artifact.record_sha256,
                "bundle_sha256": bundle_digest,
                "bundle_size_bytes": bundle_size,
            },
            "git": {
                "binding_policy_id": binding.policy_id,
                "executable_sha256": binding.sha256,
                "provenance": binding.provenance,
                "object_format": "sha1",
            },
            "bundle": {
                "format_version": header.version,
                "capabilities": list(header.capabilities),
                "prerequisite_count": 0,
                "heads": [
                    {"oid": oid, "ref": refname} for oid, refname in header.heads
                ],
            },
            "source": {
                "commit_oid": expected_commit,
                "tree_oid": expected_tree,
            },
            "object_graph": {
                **object_metrics,
                "inventory_sha256": object_inventory_sha256,
                **pack_metrics,
                "pack_inventory_sha256": pack_inventory_sha256,
            },
            "verification": {
                "command_plan_sha256": _normalized_command_plan_sha256(plan),
                "command_results": _result_hashes(results),
            },
            "limits": dict(vars(limits)),
            "assurance": retained_git_api_assurance(),
        }
        manifest_sha256 = _sha256_bytes(_canonical_json_bytes(manifest_without_id))
        manifest = {"manifest_sha256": manifest_sha256, **manifest_without_id}
        manifest = validate_retained_git_manifest(manifest)
        canonical = _canonical_json_bytes(manifest)
        return VerifiedRetainedGit(
            retained_artifact=artifact,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            canonical_manifest_bytes=canonical,
            command_plan=plan,
        )
    finally:
        _remove_quarantine(run_directory)
