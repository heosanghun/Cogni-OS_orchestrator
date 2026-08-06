"""Bounded, shell-free execution of independent verifier commands."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, BinaryIO, TypeVar

from .errors import EvidenceError

# Imported lazily nowhere else: this public constant makes the receipt state
# explicitly that the root broker proves snapshot provenance, not execution.
from .snapshot_broker_protocol import (
    BROKER_PROOF_SCOPE,
    SNAPSHOT_MATERIALIZATION_POLICY_ID,
)
from .util import atomic_write_json, sha256_file, utc_now

MAX_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_SNAPSHOT_FILE_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_ENTRY_COUNT = 50_000
MAX_SNAPSHOT_PATH_BYTES = 4_096
MAX_SNAPSHOT_PATH_BYTES_TOTAL = 32 * 1024 * 1024
MAX_SNAPSHOT_TREE_NODE_COUNT = MAX_SNAPSHOT_ENTRY_COUNT * 2 + 1
MAX_GIT_CONTROL_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_GIT_TREE_RECORD_BYTES = MAX_SNAPSHOT_PATH_BYTES + 256
MAX_GIT_CAT_HEADER_BYTES = 128
GIT_STREAM_CHUNK_BYTES = 64 * 1024
MAX_GIT_STDERR_BYTES = 64 * 1024
GIT_INSPECTION_TIMEOUT_SECONDS = 15
ALLOWED_GPU_IDS = tuple(range(6))
ISOLATION_POLICY_ID = "cogni-os-deny-by-default-v2"
TRUSTED_ISOLATION_BACKEND_ID = "linux-bubblewrap-v1"
TRUSTED_GIT_POLICY_ID = "fixed-os-install-readonly-v1"
TRUSTED_RUNTIME_POLICY_ID = "fixed-admin-runtime-readonly-v1"
SNAPSHOT_PROTECTION_POLICY_ID = "cogni-os-root-broker-snapshot-v1"
TRUSTED_RUNNER_ID = "cogni-os-trusted-runner-v3"
SNAPSHOT_BROKER_PROTOCOL_ID = "cogni-os-snapshot-fd-lease-v1"
SNAPSHOT_BROKER_SOCKET_PATH = "/run/cogni-os/trusted-snapshot-broker.sock"
SNAPSHOT_BROKER_ROOT = "/run/cogni-os/trusted-snapshots"
OPERATIONAL_PATH_PREFIXES = (
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
SAFE_ENVIRONMENT_KEYS = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATH",
    "PATHEXT",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "WINDIR",
)
ALLOWED_PYTHON_MODULES = {
    "pytest",
    "unittest",
}
SAFE_DOTTED_TEST = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
SAFE_PYTEST_FLAGS = {
    "-q",
    "-x",
    "--disable-warnings",
    "--strict-config",
    "--strict-markers",
}
SAFE_UNITTEST_FLAGS = {
    "-b",
    "-c",
    "-f",
    "-q",
    "-v",
    "--buffer",
    "--catch",
    "--failfast",
    "--locals",
    "--verbose",
}
SAFE_NODE_FLAGS = {
    "--no-warnings",
    "--test",
    "--test-only",
}
POWERSHELL_EXECUTABLE_NAMES = {"powershell.exe", "pwsh", "pwsh.exe"}
POWERSHELL_CANONICAL_FLAGS = {"-noprofile", "-noninteractive"}
POWERSHELL_ENGINE_OPTIONS = {
    "command",
    "configurationname",
    "custompipename",
    "encodedcommand",
    "executionpolicy",
    "file",
    "inputformat",
    "interactive",
    "login",
    "mta",
    "nologo",
    "noninteractive",
    "noprofile",
    "outputformat",
    "servermode",
    "settingsfile",
    "sta",
    "version",
    "windowstyle",
    "workingdirectory",
}
POWERSHELL_FORBIDDEN_ARGUMENT_CHARACTERS = frozenset("`\"';&|<>$(){}[]")
FIXED_POWERSHELL_RUNTIME_ROOT = "/opt/microsoft/powershell/7"
# Bubblewrap starts from an empty tmpfs root.  /usr and /lib provide the
# runtime/ELF loader baseline.  The only /opt exposure is the fixed PowerShell
# installation directory; binding all of /opt would leak unrelated workloads.
TRUSTED_SYSTEM_ROOTS = (
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    FIXED_POWERSHELL_RUNTIME_ROOT,
)
FIXED_RUNTIME_PATHS = {
    "python": (
        "/usr/bin/python3.12",
        "/usr/bin/python3.10",
    ),
    "node": ("/usr/bin/node",),
    "powershell-file": ("/opt/microsoft/powershell/7/pwsh",),
}
EXECUTABLE_BINDING_KEYS = frozenset(
    {"policy_id", "kind", "path", "sha256", "provenance"}
)
COMMAND_POLICY_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "executable_path",
        "executable_sha256",
        "executable_binding",
        "executed_argv",
        "code_path",
        "code_paths",
    }
)
ISOLATION_BACKEND_KEYS = frozenset(
    {
        "id",
        "path",
        "sha256",
        "filesystem_enforcement",
        "network_enforcement",
        "system_roots",
    }
)
COMMAND_RECEIPT_KEYS = frozenset(
    {
        "index",
        "command_argv",
        "executed_argv",
        "isolation_launch_argv",
        "command_policy",
        "started_at",
        "completed_at",
        "duration_ms",
        "timeout_seconds",
        "timed_out",
        "output_truncated",
        "exit_code",
        "output_path",
        "output_sha256",
        "output_size_bytes",
        "executable_sha256_after",
    }
)
TRUSTED_RECEIPT_DOCUMENT_KEYS = frozenset(
    {
        "schema_version",
        "runner",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "source_commit",
        "verifier_manifest_sha256",
        "validation_contract_sha256",
        "receipt_preimage_sha256",
        "source_clean",
        "source_postcheck_passed",
        "source_postcheck_error",
        "isolation_policy",
        "isolation_attested",
        "isolation_backend",
        "snapshot",
        "snapshot_precheck_passed",
        "snapshot_protection",
        "snapshot_postcheck_passed",
        "snapshot_postcheck_error",
        "operational_change_count",
        "operational_paths_sha256",
        "started_at",
        "completed_at",
        "gpu_allowed",
        "cuda_visible_devices",
        "network_allowed",
        "network_enforcement",
        "environment_sha256",
        "sandbox_environment",
        "sandbox_environment_sha256",
        "max_output_bytes",
        "validations",
        "passed",
        "failure",
    }
)
TRUSTED_RECEIPT_RESULT_KEYS = TRUSTED_RECEIPT_DOCUMENT_KEYS | frozenset(
    {"receipt_path", "receipt_sha256"}
)

_GitStreamResult = TypeVar("_GitStreamResult")


def _trusted_git_candidate_paths() -> tuple[Path, ...]:
    """Return fixed control-plane Git locations without consulting ``PATH``.

    Trusted source inspection runs before verifier code.  It therefore cannot
    use actor-controlled executable discovery or an inherited environment.
    Custom/user-local Git installations intentionally fail closed until an
    administrator-managed binary policy is implemented.
    """

    if os.name == "nt":
        return (
            Path(r"C:\Program Files\Git\cmd\git.exe"),
            Path(r"C:\Program Files\Git\bin\git.exe"),
        )
    if os.name == "posix" and sys.platform.startswith("linux"):
        return (Path("/usr/bin/git"),)
    return ()


def _trusted_git_binding() -> dict[str, str]:
    """Resolve and hash a fixed-path Git executable or fail closed.

    Linux additionally requires root ownership and rejects group/world
    writable binaries.  Windows accepts only the fixed Program Files policy
    paths and link-free path components; publisher-signature/ACL provenance is
    not attested by this function (and Windows verifier execution remains
    unavailable regardless).
    """

    for candidate in _trusted_git_candidate_paths():
        if not candidate.is_absolute():
            continue
        try:
            path_chain = (candidate, *candidate.parents[:-1])
            if any(
                component.exists() and _is_reparse_or_symlink(component)
                for component in path_chain
            ):
                continue
        except OSError:
            continue
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        if os.name == "posix":
            try:
                path_metadata = [component.stat() for component in path_chain]
            except OSError:
                continue
            if any(
                value.st_uid != 0 or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                for value in path_metadata
            ):
                continue
        resolved = candidate.resolve()
        return {
            "policy_id": TRUSTED_GIT_POLICY_ID,
            "path": str(resolved),
            "sha256": sha256_file(resolved),
            "provenance": (
                "fixed-path-root-owned-nonwritable"
                if os.name == "posix"
                else "fixed-program-files-path-hash-only"
            ),
        }
    raise EvidenceError(
        "Trusted Git executable is unavailable under the fixed-path policy; "
        "refusing source inspection"
    )


def _trusted_git_environment(git_path: Path, scratch_root: Path) -> dict[str, str]:
    """Build a minimal Git environment from policy constants only.

    No parent ``COGNI_*``, ``CLOUDFLARE_*``, ``GIT_*``, ``PYTHON*``, ``SSH*``
    or proxy variable is copied.  The GIT-prefixed values below are newly
    assigned deny-by-default policy controls, not inherited values.
    """

    home = scratch_root / "home"
    config_home = home / ".config"
    temporary = scratch_root / "tmp"
    for directory in (home, config_home, temporary):
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
        "PATH": str(git_path.parent),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "XDG_CONFIG_HOME": str(config_home),
    }


def _is_reparse_or_symlink(path: Path) -> bool:
    """Return true for links/junctions without following the final component."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceError(f"Cannot inspect isolation path: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_attribute)


def _require_plain_directory(path: Path, *, label: str) -> None:
    if not path.is_dir() or _is_reparse_or_symlink(path):
        raise EvidenceError(
            f"Trusted verifier {label} must be a plain directory, not a link/reparse"
        )


def _require_root_owned_nonwritable_path_chain(
    path: Path,
    *,
    executable: bool,
) -> Path:
    """Require an absolute, link-free administrator-owned path and ancestors."""

    if not path.is_absolute():
        raise EvidenceError("Trusted administrator path must be absolute")
    chain = (path, *path.parents)
    try:
        metadata = [component.stat(follow_symlinks=False) for component in chain]
    except OSError as exc:
        raise EvidenceError("Cannot inspect trusted administrator path") from exc
    if any(stat.S_ISLNK(value.st_mode) for value in metadata):
        raise EvidenceError("Trusted administrator path chain contains a link")
    if any(
        value.st_uid != 0 or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        for value in metadata
    ):
        raise EvidenceError(
            "Trusted administrator path chain is writable by a non-root actor"
        )
    if executable and (
        not stat.S_ISREG(metadata[0].st_mode) or not os.access(path, os.X_OK)
    ):
        raise EvidenceError("Trusted administrator runtime is not executable")
    if not executable and not stat.S_ISDIR(metadata[0].st_mode):
        raise EvidenceError("Trusted administrator system root is not a directory")
    return path.resolve()


def _root_owned_nonwritable_executable(path: Path) -> dict[str, Any]:
    """Bind the Linux isolation launcher to an administrator-owned binary."""

    resolved = _require_root_owned_nonwritable_path_chain(path, executable=True)
    system_roots: list[str] = []
    for value in TRUSTED_SYSTEM_ROOTS:
        candidate = Path(value)
        if not candidate.exists():
            continue
        # usr-merged distributions commonly expose /lib*, /bin and /sbin as
        # root-owned symlinks into /usr.  The symlink itself is safe only when
        # its parent chain is root-owned/non-writable and its resolved target
        # independently satisfies the same invariant.
        leaf = candidate.lstat()
        if stat.S_ISLNK(leaf.st_mode):
            if leaf.st_uid != 0:
                raise EvidenceError("Trusted system-root link is not root-owned")
            for ancestor in candidate.parents:
                _require_root_owned_nonwritable_path_chain(
                    ancestor,
                    executable=False,
                )
            resolved_root = _require_root_owned_nonwritable_path_chain(
                candidate.resolve(strict=True),
                executable=False,
            )
            if not resolved_root.is_dir():
                raise EvidenceError(
                    "Trusted system-root link target is not a directory"
                )
        else:
            resolved_root = _require_root_owned_nonwritable_path_chain(
                candidate,
                executable=False,
            )
            if str(resolved_root) != value:
                raise EvidenceError("Trusted system root does not resolve to itself")
        system_roots.append(value)
    if "/usr" not in system_roots or "/lib" not in system_roots:
        raise EvidenceError(
            "Trusted isolation requires attested /usr and /lib runtime roots"
        )
    return {
        "id": TRUSTED_ISOLATION_BACKEND_ID,
        "path": str(resolved),
        "sha256": sha256_file(resolved),
        "filesystem_enforcement": "private-mount-namespace-committed-snapshot-ro",
        "network_enforcement": "private-network-namespace",
        "system_roots": system_roots,
    }


def _require_isolation_backend(
    *,
    gpu_allowed: bool,
    network_allowed: bool,
) -> dict[str, Any]:
    """Return a verified OS sandbox or refuse to create trusted evidence.

    Environment variables, proxy settings, a changed working directory, Python
    audit hooks, and post-run diffs are *not* security boundaries.  On Windows
    there is no safely deployable AppContainer/restricted-token launcher in this
    repository yet, so the correct result is NO_GO rather than an unconfined
    verifier receipt.
    """

    if gpu_allowed:
        raise EvidenceError(
            "Trusted verifier GPU isolation is unsupported: the current sandbox "
            "does not bind NVIDIA devices or driver libraries; refusing execution "
            "rather than exposing any host GPU (especially denied devices 6-7)"
        )
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise EvidenceError(
            "Trusted verifier OS isolation is unavailable on this platform; "
            "refusing attestation before command execution"
        )
    launcher = Path("/usr/bin/bwrap")
    if not launcher.is_file():
        raise EvidenceError(
            "Trusted verifier requires administrator-owned /usr/bin/bwrap; "
            "refusing unisolated attestation"
        )
    backend = _root_owned_nonwritable_executable(launcher)
    if network_allowed:
        backend = {
            **backend,
            "network_enforcement": "task-permitted-via-explicit-share-net",
        }
    return backend


def snapshot_broker_contract() -> dict[str, Any]:
    """Describe the only privileged snapshot hand-off accepted by production.

    The broker is deliberately external to this repository.  It must
    receive an unprivileged caller-materialized, sealed directory descriptor,
    copy its bytes beneath the fixed root-owned tree without invoking Git, pass
    an O_PATH directory descriptor with SCM_RIGHTS, and retain exclusive cleanup
    ownership.  Broker proof establishes copy provenance and cleanup only; the
    unprivileged runner remains responsible for source authenticity.
    """

    return {
        "protocol_id": SNAPSHOT_BROKER_PROTOCOL_ID,
        "transport": "fixed-root-owned-unix-socket-bidirectional-scm-rights",
        "socket_path": SNAPSHOT_BROKER_SOCKET_PATH,
        "broker_root": SNAPSHOT_BROKER_ROOT,
        "peer_uid": 0,
        "snapshot_owner_uid": 0,
        "snapshot_mode": "0555",
        "entry_modes": ["0444", "0555"],
        "descriptor_type": "O_PATH-directory",
        "source_descriptor_type": "sealed-O_RDONLY-directory",
        "source_authenticity": "not-attested-by-broker",
        "caller_authentication": "SO_PEERCRED-pid-uid-gid",
        "signature": "Ed25519-detached-fixed-sha-bound-openssl",
        "private_key_path": "/etc/cogni-os/snapshot-broker/ed25519-private.pem",
        "public_key_path": "/etc/cogni-os/snapshot-broker/ed25519-public.pem",
        "openssl_path": "/usr/bin/openssl",
        "openssl_sha256_path": "/etc/cogni-os/snapshot-broker/openssl.sha256",
        "replay_protection": "root-owned-O_EXCL-nonce-with-expiry",
        "request_binding": [
            "source_commit",
            "tree_oid",
            "snapshot_sha256",
            "materialization_policy",
            "nonce",
        ],
        "acquire_reply_binding": [
            "lease_id",
            "source_commit",
            "tree_oid",
            "snapshot_sha256",
            "snapshot_device",
            "snapshot_inode",
            "broker_nonce",
        ],
        "cleanup": "broker-release-lease-after-runner-close",
        "runner_unlink_allowed": False,
    }


def _require_external_snapshot_broker_contract() -> Any:
    """Preflight and return the fixed-path privileged FD-lease client.

    Importing lazily avoids a module cycle because the root daemon reuses this
    module's bounded Git materializer.  Windows and a missing/unsafe daemon,
    public key or SHA-bound OpenSSL installation remain hard NO_GO before any
    run directory is created.  Unit tests patch this seam to ``None`` to cover
    downstream receipt logic without pretending to be production evidence.
    """

    from .snapshot_broker import SnapshotBrokerClient

    client = SnapshotBrokerClient()
    client.preflight()
    return client


def _safe_archive_relative(value: str) -> Path:
    normalized = value.replace("\\", "/")
    components = normalized.split("/")
    if (
        not normalized
        or normalized.startswith("/")
        or any(component in {"", ".", ".."} for component in components)
        or any(":" in component for component in components)
    ):
        raise EvidenceError("Committed snapshot contains an unsafe path")
    return Path(*components)


def _test_snapshot_path_writer_enabled() -> bool:
    """Production-false seam patched only by the cross-platform test adapter."""

    return False


def _open_posix_directory_nofollow(path: Path) -> int:
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise EvidenceError("Descriptor-relative snapshot creation requires Linux")
    required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, flag) for flag in required_flags):
        raise EvidenceError("Secure no-follow directory primitives are unavailable")
    absolute = path.absolute()
    if not absolute.is_absolute():
        raise EvidenceError("Secure snapshot directory must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(os.path.sep, flags)
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise EvidenceError(
            "Cannot open the snapshot path descriptor-relative without links"
        ) from exc


def _create_snapshot_root(snapshot_root: Path) -> int | None:
    if os.name == "posix" and sys.platform.startswith("linux"):
        parent_descriptor = _open_posix_directory_nofollow(snapshot_root.parent)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            os.mkdir(snapshot_root.name, mode=0o700, dir_fd=parent_descriptor)
            descriptor = os.open(
                snapshot_root.name,
                flags,
                dir_fd=parent_descriptor,
            )
            os.fsync(parent_descriptor)
            return descriptor
        except OSError as exc:
            raise EvidenceError(
                "Cannot create the committed snapshot descriptor-relative"
            ) from exc
        finally:
            os.close(parent_descriptor)
    if not _test_snapshot_path_writer_enabled():
        raise EvidenceError(
            "Committed snapshot path writer is unavailable outside the Linux "
            "descriptor-relative implementation"
        )
    snapshot_root.mkdir(parents=True, exist_ok=False)
    return None


def _write_snapshot_file_descriptor_relative(
    root_descriptor: int,
    relative: Path,
    content: bytes,
    *,
    executable: bool,
) -> None:
    directory_descriptor = os.dup(root_descriptor)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        for component in relative.parts[:-1]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=directory_descriptor)
                os.fsync(directory_descriptor)
            except FileExistsError:
                pass
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        file_flags |= getattr(os, "O_CLOEXEC", 0)
        file_descriptor = os.open(
            relative.parts[-1],
            file_flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        try:
            with os.fdopen(file_descriptor, "wb", closefd=False) as output:
                output.write(content)
                output.flush()
            os.fsync(file_descriptor)
            os.fchmod(file_descriptor, 0o555 if executable else 0o444)
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)
        os.fsync(directory_descriptor)
    except OSError as exc:
        raise EvidenceError(
            "Cannot write the committed snapshot descriptor-relative"
        ) from exc
    finally:
        os.close(directory_descriptor)


def _snapshot_directory_inventory(entries: list[dict[str, Any]]) -> list[str]:
    if len(entries) > MAX_SNAPSHOT_ENTRY_COUNT:
        raise EvidenceError("Committed snapshot directory inventory is too large")
    maximum_directories = MAX_SNAPSHOT_TREE_NODE_COUNT - len(entries)
    directories: set[str] = set()
    for entry in entries:
        parent = Path(str(entry["path"])).parent
        while parent != Path("."):
            value = parent.as_posix()
            if value not in directories:
                if len(directories) >= maximum_directories:
                    raise EvidenceError(
                        "Committed snapshot ancestor inventory exceeds its tree-node limit"
                    )
                directories.add(value)
            parent = parent.parent
    return sorted(directories)


def _open_relative_directory_nofollow(root_descriptor: int, relative: Path) -> int:
    descriptor = os.dup(root_descriptor)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        for component in relative.parts:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise EvidenceError(
            "Cannot seal a committed snapshot directory without following links"
        ) from exc


def _seal_snapshot_directories(
    snapshot_root: Path,
    root_descriptor: int | None,
    directories: list[str],
) -> None:
    if root_descriptor is not None:
        for value in sorted(
            directories,
            key=lambda item: len(Path(item).parts),
            reverse=True,
        ):
            descriptor = _open_relative_directory_nofollow(
                root_descriptor,
                _safe_archive_relative(value),
            )
            try:
                os.fchmod(descriptor, 0o555)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fchmod(root_descriptor, 0o555)
        os.fsync(root_descriptor)
        return
    for value in sorted(
        directories,
        key=lambda item: len(Path(item).parts),
        reverse=True,
    ):
        (snapshot_root / _safe_archive_relative(value)).chmod(0o555)
    snapshot_root.chmod(0o555)


def _validated_git_object_id(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 40 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise EvidenceError(f"Trusted Git returned an invalid {label}")
    return normalized


def _consume_git_nul_records(
    stream: BinaryIO,
    consumer: Callable[[bytes], None],
) -> None:
    """Parse a NUL protocol without retaining the complete Git response."""

    pending = bytearray()
    while True:
        chunk = stream.read(GIT_STREAM_CHUNK_BYTES)
        if not chunk:
            break
        pending.extend(chunk)
        while True:
            separator = pending.find(0)
            if separator < 0:
                break
            if separator == 0:
                raise EvidenceError("Trusted Git returned an empty tree record")
            record = bytes(pending[:separator])
            del pending[: separator + 1]
            consumer(record)
        if len(pending) > MAX_GIT_TREE_RECORD_BYTES:
            raise EvidenceError("Trusted Git tree record exceeded its limit")
    if pending:
        raise EvidenceError("Trusted Git tree stream was truncated")


def _committed_tree_manifest(
    workspace_root: Path,
    source_commit: str,
) -> dict[str, Any]:
    """Read an exact commit tree without archive attributes or moving refs."""

    commit = _validated_git_object_id(source_commit, label="source commit")
    tree_oid = _validated_git_object_id(
        _run_git(
            workspace_root,
            ["rev-parse", "--verify", f"{commit}^{{tree}}"],
        )
        .decode("ascii", errors="ignore")
        .strip(),
        label="source tree",
    )
    entries: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_portable_paths: set[str] = set()
    total = 0
    path_bytes_total = 0

    def consume_record(record: bytes) -> None:
        nonlocal total, path_bytes_total
        if len(entries) >= MAX_SNAPSHOT_ENTRY_COUNT:
            raise EvidenceError(
                "Committed verifier snapshot exceeds the entry-count limit"
            )
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode_value, object_type, object_id, size_value = metadata.split()
        except ValueError as exc:
            raise EvidenceError("Trusted Git returned an invalid tree entry") from exc
        if not raw_path or len(raw_path) > MAX_SNAPSHOT_PATH_BYTES:
            raise EvidenceError("Trusted Git tree path exceeded its byte limit")
        path_bytes_total += len(raw_path)
        if path_bytes_total > MAX_SNAPSHOT_PATH_BYTES_TOTAL:
            raise EvidenceError("Trusted Git tree paths exceeded their total limit")
        try:
            path_value = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EvidenceError("Trusted Git tree path is not valid UTF-8") from exc
        if "\\" in path_value:
            raise EvidenceError("Trusted Git tree path contains a backslash")
        relative = _safe_archive_relative(path_value)
        relative_value = relative.as_posix()
        if relative_value in seen_paths:
            raise EvidenceError("Trusted Git tree contains a duplicate path")
        seen_paths.add(relative_value)
        portable_path = unicodedata.normalize("NFC", relative_value).casefold()
        if portable_path in seen_portable_paths:
            raise EvidenceError("Trusted Git tree contains a portable path collision")
        seen_portable_paths.add(portable_path)
        try:
            mode = mode_value.decode("ascii")
            entry_type = object_type.decode("ascii")
            object_oid = _validated_git_object_id(
                object_id.decode("ascii"),
                label="tree object",
            )
        except UnicodeDecodeError as exc:
            raise EvidenceError("Trusted Git returned an invalid tree entry") from exc
        if mode == "120000":
            raise EvidenceError(
                "Committed verifier snapshot forbids committed symlinks"
            )
        if mode == "160000" or entry_type == "commit":
            raise EvidenceError(
                "Committed verifier snapshot forbids committed submodules"
            )
        if entry_type != "blob" or mode not in {"100644", "100755"}:
            raise EvidenceError(
                "Committed verifier snapshot contains an unsupported Git entry"
            )
        try:
            size = int(size_value.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise EvidenceError("Trusted Git returned an invalid blob size") from exc
        if size < 0 or size > MAX_SNAPSHOT_FILE_BYTES:
            raise EvidenceError("Committed verifier input exceeds the file limit")
        total += size
        if total > MAX_SNAPSHOT_BYTES:
            raise EvidenceError("Committed verifier snapshot exceeds the size limit")
        entries.append(
            {
                "path": relative_value,
                "mode": mode,
                "object": object_oid,
                "size": size,
            }
        )

    def consume_tree(stream: BinaryIO) -> None:
        _consume_git_nul_records(stream, consume_record)

    _run_git_stream(
        workspace_root,
        ["ls-tree", "-r", "-z", "-l", "--full-tree", commit],
        consume_tree,
    )
    entries.sort(key=lambda entry: entry["path"])
    return {
        "schema_version": 1,
        "source_commit": commit,
        "tree_oid": tree_oid,
        "file_count": len(entries),
        "size_bytes": total,
        "entries": entries,
    }


def _stream_committed_blobs(
    workspace_root: Path,
    entries: list[dict[str, Any]],
    consumer: Callable[[dict[str, Any], bytes], None],
) -> None:
    """Read and consume one exact blob at a time from ``cat-file --batch``."""

    if not entries:
        return

    def requests() -> Iterable[bytes]:
        for entry in entries:
            yield f"{entry['object']}\n".encode("ascii")

    def read_exact(stream: BinaryIO, size: int) -> bytes:
        content = bytearray()
        remaining = size
        while remaining:
            chunk = stream.read(min(GIT_STREAM_CHUNK_BYTES, remaining))
            if not chunk:
                raise EvidenceError("Trusted Git blob batch was truncated")
            content.extend(chunk)
            remaining -= len(chunk)
        return bytes(content)

    def consume_batch(stream: BinaryIO) -> None:
        for entry in entries:
            header_line = stream.readline(MAX_GIT_CAT_HEADER_BYTES + 1)
            if (
                not header_line.endswith(b"\n")
                or len(header_line) > MAX_GIT_CAT_HEADER_BYTES
            ):
                raise EvidenceError("Trusted Git blob batch returned an invalid header")
            header = header_line[:-1].split()
            if len(header) != 3:
                raise EvidenceError("Trusted Git blob batch returned an invalid header")
            try:
                actual_oid = _validated_git_object_id(
                    header[0].decode("ascii"),
                    label="blob object",
                )
                object_type = header[1].decode("ascii")
                size = int(header[2].decode("ascii"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise EvidenceError(
                    "Trusted Git blob batch returned an invalid header"
                ) from exc
            if (
                actual_oid != entry["object"]
                or object_type != "blob"
                or size != entry["size"]
            ):
                raise EvidenceError(
                    "Trusted Git blob batch does not match the committed tree"
                )
            if size < 0 or size > MAX_SNAPSHOT_FILE_BYTES:
                raise EvidenceError("Committed verifier input exceeds the file limit")
            content = read_exact(stream, size)
            if stream.read(1) != b"\n":
                raise EvidenceError("Trusted Git blob batch was truncated")
            consumer(entry, content)
        if stream.read(1):
            raise EvidenceError("Trusted Git blob batch returned trailing bytes")

    _run_git_stream(
        workspace_root,
        ["cat-file", "--batch"],
        consume_batch,
        input_chunks=requests(),
    )


def _snapshot_manifest_sha256(
    files: list[dict[str, Any]],
    directories: list[str],
) -> str:
    return hashlib.sha256(
        json.dumps(
            {"directories": directories, "files": files},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _committed_snapshot_manifest(
    workspace_root: Path,
    source_commit: str,
) -> dict[str, Any]:
    """Hash an exact committed snapshot without creating actor-owned paths."""

    committed = _committed_tree_manifest(workspace_root, source_commit)
    directories = _snapshot_directory_inventory(committed["entries"])
    files: list[dict[str, Any]] = []

    def hash_entry(entry: dict[str, Any], content: bytes) -> None:
        if len(content) != entry["size"]:
            raise EvidenceError("Committed snapshot blob size does not match its tree")
        files.append({**entry, "sha256": hashlib.sha256(content).hexdigest()})

    _stream_committed_blobs(workspace_root, committed["entries"], hash_entry)
    return {
        "schema_version": 1,
        "source_commit": committed["source_commit"],
        "tree_oid": committed["tree_oid"],
        "object_format": "sha1",
        "materialization_policy": SNAPSHOT_MATERIALIZATION_POLICY_ID,
        "file_count": len(files),
        "directories": directories,
        "size_bytes": committed["size_bytes"],
        "sha256": _snapshot_manifest_sha256(files, directories),
        "files": files,
    }


def _materialize_committed_snapshot(
    workspace_root: Path,
    snapshot_root: Path,
    source_commit: str,
) -> dict[str, Any]:
    """Materialize exact tree/blob bytes for one already-pinned commit OID."""

    if snapshot_root.exists():
        raise EvidenceError("Trusted verifier snapshot destination already exists")
    committed = _committed_tree_manifest(workspace_root, source_commit)
    directories = _snapshot_directory_inventory(committed["entries"])
    root_descriptor = _create_snapshot_root(snapshot_root)
    files: list[dict[str, Any]] = []

    def write_entry(entry: dict[str, Any], content: bytes) -> None:
        relative = _safe_archive_relative(entry["path"])
        if len(content) != entry["size"]:
            raise EvidenceError("Committed snapshot blob size does not match its tree")
        if root_descriptor is not None:
            _write_snapshot_file_descriptor_relative(
                root_descriptor,
                relative,
                content,
                executable=entry["mode"] == "100755",
            )
        else:
            destination = snapshot_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            destination.chmod(0o555 if entry["mode"] == "100755" else 0o444)
        files.append(
            {
                **entry,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )

    try:
        _stream_committed_blobs(
            workspace_root,
            committed["entries"],
            write_entry,
        )
        _seal_snapshot_directories(snapshot_root, root_descriptor, directories)
    finally:
        if root_descriptor is not None:
            os.close(root_descriptor)
    snapshot = {
        "schema_version": 1,
        "source_commit": committed["source_commit"],
        "tree_oid": committed["tree_oid"],
        "object_format": "sha1",
        "materialization_policy": SNAPSHOT_MATERIALIZATION_POLICY_ID,
        "file_count": len(files),
        "directories": directories,
        "size_bytes": committed["size_bytes"],
        "sha256": _snapshot_manifest_sha256(files, directories),
        "files": files,
    }
    if _committed_snapshot_postcheck(snapshot_root, snapshot) != snapshot:
        raise EvidenceError(
            "Committed snapshot failed its immediate Git-object manifest check"
        )
    return snapshot


def _iter_snapshot_tree_bounded(snapshot_root: Path) -> Iterable[Path]:
    """Walk a snapshot without an unbounded recursive path list."""

    pending_directories = [snapshot_root]
    count = 0
    while pending_directories:
        directory = pending_directories.pop()
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    count += 1
                    if count > MAX_SNAPSHOT_TREE_NODE_COUNT:
                        raise EvidenceError(
                            "Committed sandbox snapshot exceeds its tree-node limit"
                        )
                    candidate = directory / entry.name
                    yield candidate
                    if entry.is_dir(follow_symlinks=False):
                        pending_directories.append(candidate)
        except EvidenceError:
            raise
        except OSError as exc:
            raise EvidenceError(
                "Cannot enumerate the committed sandbox snapshot"
            ) from exc


def _require_broker_protected_snapshot(snapshot_root: Path) -> dict[str, Any]:
    """Attest that the current actor cannot swap snapshot names or bytes.

    A chmod-only tree below a user-owned run directory is not immutable: the
    same user can rename a file or its parent while Bubblewrap reads it and put
    the original bytes back before the postcheck.  The currently accepted
    mechanism is therefore deliberately narrow: a non-root Linux runner may
    consume a link-free tree and complete ancestor chain owned by uid 0 only
    when its own effective uid has no write access (including ACL access).

    This repository does not implement the privileged broker that creates such
    a tree.  Normal same-user materialization consequently returns NO_GO before
    verifier execution; test code may patch this private check only through the
    dedicated unit-test adapter.
    """

    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise EvidenceError(
            "Trusted snapshot requires an external privileged Linux broker; "
            "same-user snapshot immutability is not attested"
        )
    get_euid = getattr(os, "geteuid", None)
    if not callable(get_euid):
        raise EvidenceError("Trusted snapshot cannot determine the runner identity")
    runner_euid = int(get_euid())
    if runner_euid == 0:
        raise EvidenceError(
            "Trusted snapshot separation is absent when the verifier runner is root"
        )

    snapshot_root = snapshot_root.absolute()
    _require_plain_directory(snapshot_root, label="snapshot root")
    ancestors = list(snapshot_root.parents)
    if len(ancestors) < 2:
        raise EvidenceError("Broker snapshot ancestry is incomplete")

    def require_protected(path: Path, *, label: str) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise EvidenceError(f"Cannot inspect broker snapshot {label}") from exc
        if _is_reparse_or_symlink(path):
            raise EvidenceError("Broker snapshot path chain contains a link/reparse")
        if metadata.st_uid != 0:
            raise EvidenceError("Broker snapshot path chain is not root-owned")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise EvidenceError("Broker snapshot path is group/world writable")
        try:
            actor_can_write = os.access(path, os.W_OK, effective_ids=True)
        except (NotImplementedError, OSError, TypeError) as exc:
            raise EvidenceError(
                "Broker snapshot effective-identity access probe is unavailable"
            ) from exc
        if actor_can_write:
            raise EvidenceError("Current actor retains write access to broker snapshot")

    for ancestor in ancestors:
        require_protected(ancestor, label="ancestor")
    checked_entry_count = 1
    require_protected(snapshot_root, label="entry")
    for entry in _iter_snapshot_tree_bounded(snapshot_root):
        checked_entry_count += 1
        require_protected(entry, label="entry")
        try:
            metadata = entry.lstat()
        except OSError as exc:
            raise EvidenceError("Cannot restat broker snapshot entry") from exc
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise EvidenceError("Broker snapshot contains a special file")

    return {
        "policy_id": SNAPSHOT_PROTECTION_POLICY_ID,
        "platform": "linux",
        "broker": "external-privileged-owner",
        "runner_euid": runner_euid,
        "owner_uid": 0,
        "actor_write_access": False,
        "path_chain_root_owned": True,
        "path_chain_actor_nonwritable": True,
        "entries_root_owned": True,
        "entries_actor_nonwritable": True,
        "links_rejected": True,
        "checked_ancestor_count": len(ancestors),
        "checked_entry_count": checked_entry_count,
        "proof": "root-owner-mode-access-probe",
    }


def _committed_snapshot_postcheck(
    snapshot_root: Path,
    expected_snapshot: dict[str, Any] | None = None,
    *,
    snapshot_descriptor: int | None = None,
) -> dict[str, Any]:
    """Re-hash the sandbox input against its exact Git-object manifest."""

    files: list[dict[str, Any]] = []
    directories: list[str] = []
    expected_files: dict[str, dict[str, Any]] | None = None
    expected_directories: list[str] | None = None
    if expected_snapshot is not None:
        raw_expected = expected_snapshot.get("files")
        raw_directories = expected_snapshot.get("directories")
        if (
            not isinstance(raw_expected, list)
            or any(not isinstance(entry, dict) for entry in raw_expected)
            or not isinstance(raw_directories, list)
            or any(not isinstance(value, str) or not value for value in raw_directories)
        ):
            raise EvidenceError("Committed sandbox snapshot manifest is invalid")
        expected_files = {str(entry.get("path", "")): entry for entry in raw_expected}
        if len(expected_files) != len(raw_expected) or "" in expected_files:
            raise EvidenceError("Committed sandbox snapshot manifest is invalid")
        expected_directories = sorted(raw_directories)
        if expected_directories != raw_directories or len(expected_directories) != len(
            set(expected_directories)
        ):
            raise EvidenceError("Committed sandbox snapshot manifest is invalid")
    total = 0
    if snapshot_descriptor is None:
        if _is_reparse_or_symlink(snapshot_root) or not snapshot_root.is_dir():
            raise EvidenceError(
                "Committed sandbox snapshot root is not a plain directory"
            )
        root_metadata = snapshot_root.lstat()
    else:
        if snapshot_root != Path(f"/proc/self/fd/{snapshot_descriptor}"):
            raise EvidenceError("Committed snapshot FD alias is not canonical")
        try:
            root_metadata = os.fstat(snapshot_descriptor)
        except OSError as exc:
            raise EvidenceError("Committed snapshot lease FD is unavailable") from exc
        if not stat.S_ISDIR(root_metadata.st_mode) or not snapshot_root.is_dir():
            raise EvidenceError("Committed snapshot lease FD is not a directory")
    if os.name == "posix" and stat.S_IMODE(root_metadata.st_mode) != 0o555:
        raise EvidenceError("Committed sandbox snapshot root mode is not 0555")
    for candidate in _iter_snapshot_tree_bounded(snapshot_root):
        if _is_reparse_or_symlink(candidate):
            raise EvidenceError("Committed sandbox snapshot acquired a link/reparse")
        metadata = candidate.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            relative = candidate.relative_to(snapshot_root).as_posix()
            if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o555:
                raise EvidenceError(
                    "Committed sandbox snapshot directory mode is not 0555"
                )
            directories.append(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError("Committed sandbox snapshot acquired a special file")
        relative = candidate.relative_to(snapshot_root).as_posix()
        size = metadata.st_size
        total += size
        if size > MAX_SNAPSHOT_FILE_BYTES or total > MAX_SNAPSHOT_BYTES:
            raise EvidenceError("Committed sandbox snapshot exceeded its size limit")
        sha256 = sha256_file(candidate)
        if expected_files is None:
            files.append({"path": relative, "size": size, "sha256": sha256})
            continue
        expected = expected_files.get(relative)
        if expected is None:
            raise EvidenceError("Committed sandbox snapshot acquired an extra file")
        if size != expected.get("size") or sha256 != expected.get("sha256"):
            raise EvidenceError(
                "Committed sandbox snapshot bytes differ from the Git object"
            )
        if os.name == "posix":
            expected_permissions = 0o555 if expected.get("mode") == "100755" else 0o444
            if stat.S_IMODE(metadata.st_mode) != expected_permissions:
                raise EvidenceError(
                    "Committed sandbox snapshot mode differs from the Git tree"
                )
        files.append(
            {
                "path": relative,
                "mode": expected.get("mode"),
                "object": expected.get("object"),
                "size": size,
                "sha256": sha256,
            }
        )
    if expected_files is not None and len(files) != len(expected_files):
        raise EvidenceError("Committed sandbox snapshot is missing a Git tree file")
    files.sort(key=lambda entry: str(entry["path"]))
    directories.sort()
    if expected_directories is not None and directories != expected_directories:
        raise EvidenceError(
            "Committed sandbox snapshot directory set differs from the Git tree"
        )
    result = {
        "file_count": len(files),
        "directories": directories,
        "size_bytes": total,
        "sha256": _snapshot_manifest_sha256(files, directories),
    }
    if expected_snapshot is not None:
        result = {
            "schema_version": expected_snapshot.get("schema_version"),
            "source_commit": expected_snapshot.get("source_commit"),
            "tree_oid": expected_snapshot.get("tree_oid"),
            "object_format": expected_snapshot.get("object_format"),
            "materialization_policy": expected_snapshot.get("materialization_policy"),
            **result,
            "files": files,
        }
    return result


def _remove_committed_snapshot(snapshot_root: Path) -> None:
    """Remove the verified regular-file snapshot without following links."""

    postcheck = _committed_snapshot_postcheck(snapshot_root)
    if not isinstance(postcheck.get("sha256"), str):
        raise EvidenceError("Committed sandbox snapshot cleanup precheck failed")
    directories: list[Path] = []
    for candidate in _iter_snapshot_tree_bounded(snapshot_root):
        if candidate.is_file():
            candidate.chmod(0o600)
        elif candidate.is_dir():
            directories.append(candidate)
    for candidate in sorted(
        directories, key=lambda path: len(path.parts), reverse=True
    ):
        candidate.chmod(0o700)
    snapshot_root.chmod(0o700)
    shutil.rmtree(snapshot_root)


def _translate_workspace_argument(workspace_root: Path, argument: str) -> str:
    candidate = Path(argument)
    if not candidate.is_absolute():
        return argument.replace("\\", "/")
    try:
        relative = candidate.resolve().relative_to(workspace_root.resolve())
    except (OSError, ValueError):
        return argument
    return "/workspace/" + relative.as_posix()


def _sandbox_environment(
    *,
    snapshot_root: Path,
    cuda_visible_devices: str,
) -> dict[str, str]:
    """Return the complete deterministic environment visible inside bwrap."""

    return {
        "APPDATA": "/sandbox/appdata",
        "CUDA_VISIBLE_DEVICES": cuda_visible_devices,
        "HOME": "/sandbox",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOCALAPPDATA": "/sandbox/localappdata",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": "/workspace/src" if (snapshot_root / "src").is_dir() else "",
        "PYTHONUTF8": "1",
        "TEMP": "/sandbox/tmp",
        "TMP": "/sandbox/tmp",
        "USERPROFILE": "/sandbox",
    }


def _canonical_isolation_argv(
    *,
    backend: dict[str, Any],
    command_argv: list[str],
    workspace_root: Path,
    snapshot_root: Path,
    scratch_root: Path,
    sandbox_environment: dict[str, str],
    network_allowed: bool,
) -> list[str]:
    """Build the one canonical bwrap argv accepted by receipt projection."""

    if not isinstance(command_argv, list) or not command_argv:
        raise EvidenceError("Trusted isolation command argv is invalid")
    launcher = backend["path"]
    argv = [
        launcher,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
    ]
    if network_allowed:
        argv.append("--share-net")
    argv.extend(["--tmpfs", "/", "--proc", "/proc", "--dev", "/dev"])
    system_roots = backend.get("system_roots")
    if (
        not isinstance(system_roots, list)
        or not system_roots
        or "/usr" not in system_roots
        or "/lib" not in system_roots
        or len(system_roots) != len(set(system_roots))
        or any(value not in TRUSTED_SYSTEM_ROOTS for value in system_roots)
        or system_roots != sorted(system_roots, key=TRUSTED_SYSTEM_ROOTS.index)
    ):
        raise EvidenceError("Trusted isolation backend system roots are invalid")
    runtime_path = command_argv[0]
    needs_powershell_root = runtime_path in FIXED_RUNTIME_PATHS["powershell-file"]
    if needs_powershell_root and FIXED_POWERSHELL_RUNTIME_ROOT not in system_roots:
        raise EvidenceError("Trusted PowerShell runtime root is not attested")
    roots_to_bind = [
        value
        for value in system_roots
        if value != FIXED_POWERSHELL_RUNTIME_ROOT or needs_powershell_root
    ]
    for system_root in roots_to_bind:
        argv.extend(["--ro-bind", system_root, system_root])
    argv.extend(
        [
            "--ro-bind",
            str(snapshot_root),
            "/workspace",
            "--bind",
            str(scratch_root),
            "/sandbox",
            "--chdir",
            "/workspace",
            "--clearenv",
        ]
    )
    if any(
        not isinstance(key, str)
        or not key
        or not isinstance(value, str)
        or "\x00" in key
        or "\x00" in value
        for key, value in sandbox_environment.items()
    ):
        raise EvidenceError("Trusted sandbox environment is invalid")
    for key, value in sorted(sandbox_environment.items()):
        argv.extend(["--setenv", key, value])
    argv.append("--")
    argv.extend(
        [
            command_argv[0],
            *[
                _translate_workspace_argument(workspace_root, argument)
                for argument in command_argv[1:]
            ],
        ]
    )
    return argv


def _isolated_argv(
    *,
    backend: dict[str, Any],
    command_argv: list[str],
    workspace_root: Path,
    snapshot_root: Path,
    scratch_root: Path,
    environment: dict[str, str],
    network_allowed: bool,
) -> list[str]:
    """Compatibility wrapper that derives the deterministic sandbox env."""

    return _canonical_isolation_argv(
        backend=backend,
        command_argv=command_argv,
        workspace_root=workspace_root,
        snapshot_root=snapshot_root,
        scratch_root=scratch_root,
        sandbox_environment=_sandbox_environment(
            snapshot_root=snapshot_root,
            cuda_visible_devices=environment.get("CUDA_VISIBLE_DEVICES", ""),
        ),
        network_allowed=network_allowed,
    )


def validation_contract_sha256(
    *,
    task_id: str,
    attempt: int,
    actor: str,
    source_commit: str,
    source_tree: str,
    snapshot_sha256: str,
    manifest_sha256: str,
    gpu_allowed: bool,
    network_allowed: bool,
    validations: list[dict[str, Any]],
) -> str:
    """Hash the immutable verifier inputs that the trusted runner executes.

    ``validations`` may be the normalized manifest returned by
    :func:`validate_manifest` or the retained raw JSON manifest.  Supporting
    both representations lets the read-side projection independently rebuild
    the same contract from archived bytes instead of trusting mutable task
    fields.
    """

    normalized: list[dict[str, Any]] = []
    for validation in validations:
        raw_output = validation.get("raw_output")
        raw_output_sha256 = (
            raw_output.get("sha256")
            if isinstance(raw_output, dict)
            else validation.get("raw_output_sha256")
        )
        normalized.append(
            {
                "command_argv": validation.get("command_argv"),
                "exit_code": validation.get("exit_code"),
                "raw_output_sha256": raw_output_sha256,
            }
        )
    contract = {
        "schema_version": 3,
        "runner": TRUSTED_RUNNER_ID,
        "task_id": task_id,
        "attempt": attempt,
        "actor": actor,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "snapshot_sha256": snapshot_sha256,
        "verifier_manifest_sha256": manifest_sha256,
        "gpu_allowed": gpu_allowed,
        "network_allowed": network_allowed,
        "validations": normalized,
    }
    return hashlib.sha256(
        json.dumps(
            contract,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def trusted_receipt_preimage_sha256(document: dict[str, Any]) -> str:
    """Hash the final receipt without its cleanup signature or self hash.

    The signed cleanup statement binds this digest.  Replacing the cleanup
    envelope with ``None`` breaks the otherwise circular dependency while the
    remaining receipt (including the acquire proof and execution results)
    remains fully committed.
    """

    payload = {
        key: document[key]
        for key in TRUSTED_RECEIPT_DOCUMENT_KEYS
        if key != "receipt_preimage_sha256" and key in document
    }
    protection = payload.get("snapshot_protection")
    if isinstance(protection, dict):
        protection = dict(protection)
        protection["cleanup_attestation"] = None
        payload["snapshot_protection"] = protection
    return hashlib.sha256(
        json.dumps(
            {
                "domain": "cogni-os-trusted-receipt-preimage-v1",
                "receipt": payload,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class _BrokerLeaseGuard:
    """Drive broker cleanup, retrying only the exact release after response loss."""

    def __init__(self) -> None:
        self.lease: Any = None
        self.attempted = False
        self.receipt_preimage_sha256: str | None = None

    def attach(self, lease: Any) -> None:
        if self.lease is not None:
            raise EvidenceError("Trusted verifier acquired more than one broker lease")
        self.lease = lease

    def release(self, receipt_preimage_sha256: str) -> dict[str, Any]:
        if self.lease is None:
            raise EvidenceError("Trusted verifier broker cleanup lifecycle is invalid")
        if self.attempted:
            if (
                self.receipt_preimage_sha256 != receipt_preimage_sha256
                or self.lease.released
            ):
                raise EvidenceError(
                    "Trusted verifier broker cleanup lifecycle is invalid"
                )
            return self.lease.release(
                receipt_preimage_sha256=receipt_preimage_sha256,
            )
        self.attempted = True
        self.receipt_preimage_sha256 = receipt_preimage_sha256
        return self.lease.release(
            receipt_preimage_sha256=receipt_preimage_sha256,
        )

    def cleanup_after_abort(self) -> None:
        if self.lease is None:
            return
        if not self.attempted:
            abort_hash = hashlib.sha256(
                json.dumps(
                    {
                        "domain": "cogni-os-trusted-receipt-abort-v1",
                        "acquire_attestation_sha256": self.lease.acquire_attestation_sha256,
                        "task_id": self.lease.task_id,
                        "attempt": self.lease.attempt,
                        "actor": self.lease.actor,
                        "run_id": self.lease.run_id,
                        "validation_contract_sha256": self.lease.validation_contract_sha256,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            self.attempted = True
            self.receipt_preimage_sha256 = abort_hash
            try:
                self.lease.release(receipt_preimage_sha256=abort_hash)
            except BaseException:  # noqa: BLE001 - finally must not mask the original failure
                self.lease.close_without_claiming_cleanup()
        elif not self.lease.released:
            try:
                if self.receipt_preimage_sha256 is None:
                    raise EvidenceError(
                        "Trusted verifier cleanup retry lost its receipt binding"
                    )
                self.lease.release(
                    receipt_preimage_sha256=self.receipt_preimage_sha256,
                )
            except BaseException:  # noqa: BLE001 - finally must not mask the original failure
                self.lease.close_without_claiming_cleanup()


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _trusted_git_argv(
    workspace_root: Path,
    git_path: Path,
    arguments: list[str],
) -> list[str]:
    return [
        str(git_path),
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
        f"safe.directory={workspace_root.as_posix()}",
        "-C",
        str(workspace_root),
        *arguments,
    ]


def _assert_git_binding_unchanged(git_path: Path, expected_sha256: str) -> None:
    try:
        git_sha256_after = sha256_file(git_path)
    except OSError as exc:
        raise EvidenceError(
            "Trusted Git executable disappeared during source inspection"
        ) from exc
    if git_sha256_after != expected_sha256:
        raise EvidenceError("Trusted Git executable changed during source inspection")


def _run_git_stream(
    workspace_root: Path,
    arguments: list[str],
    stdout_consumer: Callable[[BinaryIO], _GitStreamResult],
    *,
    input_chunks: Iterable[bytes] | None = None,
) -> _GitStreamResult:
    """Run fixed Git while consuming stdout incrementally and bounding stderr."""

    workspace_root = workspace_root.resolve()
    binding = _trusted_git_binding()
    git_path = Path(binding["path"])
    stderr_prefix = bytearray()
    stderr_overflow = threading.Event()
    timed_out = threading.Event()
    writer_error: list[BaseException] = []
    process: subprocess.Popen[bytes] | None = None
    timer: threading.Timer | None = None
    stderr_thread: threading.Thread | None = None
    writer_thread: threading.Thread | None = None
    result: _GitStreamResult

    def kill_for_timeout() -> None:
        timed_out.set()
        if process is not None and process.poll() is None:
            process.kill()

    def drain_stderr(stream: BinaryIO) -> None:
        while True:
            chunk = stream.read(GIT_STREAM_CHUNK_BYTES)
            if not chunk:
                return
            remaining = MAX_GIT_STDERR_BYTES - len(stderr_prefix)
            if remaining > 0:
                stderr_prefix.extend(chunk[:remaining])
            if len(chunk) > remaining:
                stderr_overflow.set()

    def write_stdin(stream: BinaryIO, chunks: Iterable[bytes]) -> None:
        try:
            for chunk in chunks:
                if not isinstance(chunk, bytes) or not chunk:
                    raise EvidenceError("Trusted Git input chunk is invalid")
                stream.write(chunk)
                stream.flush()
        except BrokenPipeError:
            # The return code and bounded stderr provide the authoritative error.
            pass
        except BaseException as exc:  # noqa: BLE001 - transfer to caller thread
            writer_error.append(exc)
            if process is not None and process.poll() is None:
                process.kill()
        finally:
            stream.close()

    try:
        with tempfile.TemporaryDirectory(prefix="cogni-trusted-git-") as temporary:
            scratch_root = Path(temporary)
            environment = _trusted_git_environment(git_path, scratch_root)
            process = subprocess.Popen(
                _trusted_git_argv(workspace_root, git_path, arguments),
                shell=False,
                stdin=(
                    subprocess.PIPE if input_chunks is not None else subprocess.DEVNULL
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                cwd=scratch_root,
                env=environment,
            )
            if process.stdout is None or process.stderr is None:
                raise EvidenceError("Trusted Git pipes were not created")
            stderr_thread = threading.Thread(
                target=drain_stderr,
                args=(process.stderr,),
                name="cogni-git-stderr",
                daemon=True,
            )
            stderr_thread.start()
            if input_chunks is not None:
                if process.stdin is None:
                    raise EvidenceError("Trusted Git input pipe was not created")
                writer_thread = threading.Thread(
                    target=write_stdin,
                    args=(process.stdin, input_chunks),
                    name="cogni-git-stdin",
                    daemon=True,
                )
                writer_thread.start()
            timer = threading.Timer(
                GIT_INSPECTION_TIMEOUT_SECONDS,
                kill_for_timeout,
            )
            timer.daemon = True
            timer.start()
            try:
                result = stdout_consumer(process.stdout)
            except BaseException:
                if process.poll() is None:
                    process.kill()
                raise
            finally:
                process.stdout.close()
            return_code = process.wait(timeout=2)
            if writer_thread is not None:
                writer_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
    except EvidenceError:
        _assert_git_binding_unchanged(git_path, binding["sha256"])
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        _assert_git_binding_unchanged(git_path, binding["sha256"])
        raise EvidenceError(f"Cannot inspect trusted source state: {exc}") from exc
    finally:
        if timer is not None:
            timer.cancel()
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.SubprocessError:
                pass
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass

    _assert_git_binding_unchanged(git_path, binding["sha256"])
    if timed_out.is_set():
        raise EvidenceError("Trusted source inspection timed out")
    if writer_error:
        error = writer_error[0]
        if isinstance(error, EvidenceError):
            raise error
        raise EvidenceError(f"Trusted Git input failed: {error}") from error
    if return_code != 0:
        detail = stderr_prefix.decode("utf-8", errors="replace").strip()
        if stderr_overflow.is_set():
            detail += " [stderr truncated]"
        raise EvidenceError(f"Trusted source inspection failed: {detail}")
    return result


def _run_git(
    workspace_root: Path,
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    """Collect only small Git control output under a hard byte ceiling."""

    def collect(stream: BinaryIO) -> bytes:
        output = bytearray()
        while True:
            chunk = stream.read(GIT_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_GIT_CONTROL_OUTPUT_BYTES:
                raise EvidenceError("Trusted Git control output exceeded its limit")
        return bytes(output)

    chunks = None if input_bytes is None else (input_bytes,)
    return _run_git_stream(
        workspace_root,
        arguments,
        collect,
        input_chunks=chunks,
    )


def trusted_git_source_commit(workspace_root: Path) -> str:
    """Capture the initial full HEAD commit through hardened pre-sandbox Git."""

    commit = (
        _run_git(workspace_root, ["rev-parse", "--verify", "HEAD^{commit}"])
        .decode("ascii", errors="ignore")
        .strip()
        .lower()
    )
    return _validated_git_object_id(commit, label="source commit")


def _source_state(
    workspace_root: Path,
    *,
    source_commit: str | None = None,
) -> dict[str, Any]:
    commit = (
        trusted_git_source_commit(workspace_root)
        if source_commit is None
        else _validated_git_object_id(source_commit, label="source commit")
    )

    tracked = _run_git(
        workspace_root,
        ["diff", "--name-only", "-z", commit, "--"],
    )
    untracked = _run_git(
        workspace_root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
    )
    dirty_paths = sorted(
        {
            value.decode("utf-8", errors="surrogateescape").replace("\\", "/")
            for value in (*tracked.split(b"\0"), *untracked.split(b"\0"))
            if value
        }
    )
    source_dirty = [
        path
        for path in dirty_paths
        if not any(path.startswith(prefix) for prefix in OPERATIONAL_PATH_PREFIXES)
    ]
    if source_dirty:
        preview = ", ".join(source_dirty[:8])
        suffix = "" if len(source_dirty) <= 8 else f" (+{len(source_dirty) - 8})"
        raise EvidenceError(
            "Trusted verifier refuses a dirty source tree; commit or remove "
            f"source-bearing changes first: {preview}{suffix}"
        )
    operational_fingerprint = hashlib.sha256(
        "\0".join(dirty_paths).encode("utf-8", errors="surrogateescape")
    ).hexdigest()
    return {
        "commit": commit,
        "source_clean": True,
        "operational_change_count": len(dirty_paths),
        "operational_paths_sha256": operational_fingerprint,
    }


def _tracked_workspace_file(
    workspace_root: Path,
    value: str,
    *,
    allow_operational: bool = False,
    snapshot_root: Path | None = None,
) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = workspace_root / candidate
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(workspace_root.resolve()).as_posix()
    except ValueError as exc:
        raise EvidenceError(
            f"Trusted verifier code path escapes the committed workspace: {resolved}"
        ) from exc
    if snapshot_root is None and not resolved.is_file():
        raise EvidenceError(f"Trusted verifier code file does not exist: {resolved}")
    if not allow_operational and any(
        relative.startswith(prefix) for prefix in OPERATIONAL_PATH_PREFIXES
    ):
        raise EvidenceError(
            "Trusted verifier cannot execute code from an operational evidence "
            f"directory: {relative}"
        )
    if snapshot_root is None:
        _run_git(
            workspace_root,
            ["ls-files", "--error-unmatch", "--", relative],
        )
    else:
        snapshot_candidate = snapshot_root / _safe_archive_relative(relative)
        if not snapshot_candidate.is_file() or _is_reparse_or_symlink(
            snapshot_candidate
        ):
            raise EvidenceError(
                "Trusted verifier code file is absent from the pinned snapshot: "
                f"{relative}"
            )
    return resolved


def _tracked_dotted_test(
    workspace_root: Path,
    target: str,
    *,
    snapshot_root: Path | None = None,
) -> Path:
    """Resolve a dotted unittest target to its committed module without imports."""
    components = target.split(".")
    for length in range(len(components), 0, -1):
        module_parts = components[:length]
        for prefix in (Path("src"), Path()):
            module_relative = prefix.joinpath(*module_parts).with_suffix(".py")
            package_relative = prefix.joinpath(*module_parts, "__init__.py")
            for relative in (module_relative, package_relative):
                inspection_root = snapshot_root or workspace_root
                if (inspection_root / relative).is_file():
                    return _tracked_workspace_file(
                        workspace_root,
                        str(workspace_root / relative),
                        snapshot_root=snapshot_root,
                    )
    raise EvidenceError(
        f"Trusted unittest target does not resolve to committed source: {target}"
    )


def _python_module_argument_targets(module: str, arguments: list[str]) -> list[str]:
    """Parse the exact module CLI subset shared by runner and projection."""

    if module == "unittest":
        if "discover" in arguments:
            raise EvidenceError(
                "Trusted unittest discovery must be wrapped by a committed "
                "validation script; implicit filesystem discovery is forbidden"
            )
        targets: list[str] = []
        for argument in arguments:
            if argument.startswith("-"):
                if argument not in SAFE_UNITTEST_FLAGS:
                    raise EvidenceError(
                        f"Trusted unittest option is not allowlisted: {argument}"
                    )
                continue
            targets.append(argument)
        if not targets or any(
            SAFE_DOTTED_TEST.fullmatch(target) is None for target in targets
        ):
            raise EvidenceError(
                "Trusted unittest requires explicit dotted test targets"
            )
        return targets

    if module == "pytest":
        test_targets: list[str] = []
        for argument in arguments:
            if argument in SAFE_PYTEST_FLAGS:
                continue
            if argument.startswith("--maxfail="):
                value = argument.partition("=")[2]
                if not value.isdigit() or not 1 <= int(value) <= 10:
                    raise EvidenceError("Trusted pytest --maxfail is invalid")
                continue
            if argument.startswith("--tb="):
                if argument.partition("=")[2] not in {
                    "auto",
                    "long",
                    "short",
                    "line",
                    "native",
                    "no",
                }:
                    raise EvidenceError("Trusted pytest traceback mode is invalid")
                continue
            if argument.startswith("-"):
                raise EvidenceError(
                    f"Trusted pytest option is not allowlisted: {argument}"
                )
            test_targets.append(argument)
        if not test_targets:
            raise EvidenceError(
                "Trusted pytest requires explicit committed test file targets"
            )
        return test_targets

    raise EvidenceError(f"Trusted Python module is not supported: {module}")


def _validate_python_module_arguments(
    workspace_root: Path,
    module: str,
    arguments: list[str],
    *,
    snapshot_root: Path | None = None,
) -> list[Path]:
    targets = _python_module_argument_targets(module, arguments)
    if module == "unittest":
        return [
            _tracked_dotted_test(
                workspace_root,
                target,
                snapshot_root=snapshot_root,
            )
            for target in targets
        ]
    return [
        _tracked_workspace_file(
            workspace_root,
            target.split("::", 1)[0],
            snapshot_root=snapshot_root,
        )
        for target in targets
    ]


def _trusted_powershell_candidate_paths(executable_name: str) -> tuple[Path, ...]:
    """Return fixed PowerShell locations without consulting actor ``PATH``."""

    if executable_name not in POWERSHELL_EXECUTABLE_NAMES:
        return ()
    if os.name == "nt":
        if executable_name == "powershell.exe":
            return (Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),)
        return (Path(r"C:\Program Files\PowerShell\7\pwsh.exe"),)
    if os.name == "posix" and sys.platform.startswith("linux"):
        if executable_name.startswith("pwsh"):
            return (Path("/usr/bin/pwsh"),)
    return ()


def _trusted_powershell_binding(
    *,
    executable_name: str,
    supplied_value: str,
) -> dict[str, str]:
    """Compatibility wrapper around the shared fixed runtime authority."""

    if executable_name not in POWERSHELL_EXECUTABLE_NAMES:
        raise EvidenceError("Trusted PowerShell executable alias is not allowed")
    return _trusted_runtime_binding(
        command_kind="powershell-file",
        supplied_value=supplied_value,
    )


def _powershell_option_prefix(value: str) -> bool:
    """Return true when ``value`` abbreviates a PowerShell host option."""

    if not value.startswith(("-", "/")):
        return False
    normalized = value.lstrip("-/").partition(":")[0].lower()
    return bool(normalized) and any(
        option.startswith(normalized) for option in POWERSHELL_ENGINE_OPTIONS
    )


def _validated_powershell_script_arguments(arguments: list[str]) -> list[str]:
    validated: list[str] = []
    for argument in arguments:
        if not isinstance(argument, str) or not argument or len(argument) > 1024:
            raise EvidenceError("Trusted PowerShell script argument is invalid")
        slash_alias = argument.startswith("/") and not Path(argument).is_absolute()
        if argument in {"-", "--%"} or argument.startswith(("@", "--")) or slash_alias:
            raise EvidenceError(
                "Trusted PowerShell forbids stdin, stop-parsing, aliases, and splatting"
            )
        if "\x00" in argument or any(ord(character) < 32 for character in argument):
            raise EvidenceError("Trusted PowerShell argument contains control bytes")
        if any(
            character in POWERSHELL_FORBIDDEN_ARGUMENT_CHARACTERS
            for character in argument
        ):
            raise EvidenceError("Trusted PowerShell argument contains metacharacters")
        if argument.startswith("-") and (
            ":" in argument or _powershell_option_prefix(argument)
        ):
            raise EvidenceError(
                "Trusted PowerShell script argument resembles a host option"
            )
        validated.append(argument)
    return validated


def _validate_powershell_argv(
    workspace_root: Path,
    argv: list[str],
    *,
    snapshot_root: Path | None = None,
) -> dict[str, Any]:
    """Parse a strict ``-File`` form and reconstruct the actual host argv."""

    executable_name = Path(argv[0]).name.lower()
    if executable_name not in POWERSHELL_EXECUTABLE_NAMES:
        raise EvidenceError("Trusted PowerShell executable alias is not allowed")
    arguments = argv[1:]
    if any(argument in {"-", "--%"} for argument in arguments):
        raise EvidenceError("Trusted PowerShell forbids stdin and stop-parsing tokens")

    file_positions = [
        index for index, argument in enumerate(arguments) if argument.lower() == "-file"
    ]
    if len(file_positions) != 1:
        raise EvidenceError(
            "Trusted PowerShell requires exactly one unabbreviated -File option"
        )
    file_index = file_positions[0]
    host_arguments = arguments[:file_index]
    if len({argument.lower() for argument in host_arguments}) != len(host_arguments):
        raise EvidenceError("Trusted PowerShell host options must not be duplicated")
    if any(
        argument.lower() not in POWERSHELL_CANONICAL_FLAGS
        for argument in host_arguments
    ):
        raise EvidenceError(
            "Trusted PowerShell host options must be exact and unabbreviated"
        )
    try:
        script_value = arguments[file_index + 1]
    except IndexError as exc:
        raise EvidenceError("Trusted PowerShell -File requires a script") from exc
    if not script_value or script_value.startswith(("-", "@")):
        raise EvidenceError("Trusted PowerShell script path is invalid")
    code_path = _tracked_workspace_file(
        workspace_root,
        script_value,
        snapshot_root=snapshot_root,
    )
    script_arguments = _validated_powershell_script_arguments(
        arguments[file_index + 2 :]
    )
    trust_binding = _trusted_powershell_binding(
        executable_name=executable_name,
        supplied_value=argv[0],
    )
    return {
        "schema_version": 1,
        "kind": "powershell-file",
        "executable_path": trust_binding["path"],
        "executable_sha256": trust_binding["sha256"],
        "executable_binding": trust_binding,
        "executed_argv": [
            trust_binding["path"],
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(code_path.resolve()),
            *script_arguments,
        ],
        "code_path": str(code_path),
        "code_paths": [
            {
                "path": str(code_path),
                "sha256": _committed_code_sha256(
                    workspace_root,
                    code_path,
                    snapshot_root=snapshot_root,
                ),
            }
        ],
    }


def _committed_code_sha256(
    workspace_root: Path,
    code_path: Path,
    *,
    snapshot_root: Path | None,
) -> str:
    if snapshot_root is None:
        return sha256_file(code_path)
    try:
        relative = code_path.relative_to(workspace_root.resolve())
    except ValueError as exc:
        raise EvidenceError("Trusted verifier code path escaped its snapshot") from exc
    candidate = snapshot_root / relative
    if not candidate.is_file() or _is_reparse_or_symlink(candidate):
        raise EvidenceError("Trusted verifier code file is absent from its snapshot")
    return sha256_file(candidate)


def _trusted_runtime_binding(
    *,
    command_kind: str,
    supplied_value: str,
) -> dict[str, str]:
    """Bind argv[0] only to an immutable administrator-selected runtime."""

    if command_kind not in FIXED_RUNTIME_PATHS:
        raise EvidenceError("Trusted runtime kind is not allowlisted")
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise EvidenceError(
            "Trusted fixed administrator runtime policy is unavailable on this platform"
        )
    supplied_path = Path(supplied_value)
    if not supplied_path.is_absolute():
        raise EvidenceError(
            "Actor PATH and relative executable selection are forbidden"
        )
    selected: Path | None = None
    for value in FIXED_RUNTIME_PATHS[command_kind]:
        candidate = Path(value)
        if not candidate.is_file():
            continue
        resolved = _require_root_owned_nonwritable_path_chain(
            candidate,
            executable=True,
        )
        # Preserve one lexical representation from policy through receipt
        # projection.  Aliases, symlinks and dot segments are rejected rather
        # than executed and later producing an unverifiable receipt.
        if _runtime_path_is_lexically_canonical(supplied_path, resolved):
            selected = resolved
            break
    if selected is None:
        raise EvidenceError(
            "Verifier-selected executable does not match the fixed administrator "
            f"{command_kind} runtime"
        )
    return {
        "policy_id": TRUSTED_RUNTIME_POLICY_ID,
        "kind": command_kind,
        "path": str(selected),
        "sha256": sha256_file(selected),
        "provenance": "fixed-admin-path-chain",
    }


def _runtime_path_is_lexically_canonical(supplied: Path, fixed: Path) -> bool:
    """Reject aliases and normalization-dependent spellings of a fixed runtime."""

    return supplied.is_absolute() and os.path.normcase(
        str(supplied)
    ) == os.path.normcase(str(fixed))


def _validate_command_argv(
    workspace_root: Path,
    argv: list[str],
    *,
    snapshot_root: Path | None = None,
) -> dict[str, Any]:
    actor_executable_name = Path(argv[0]).name.lower()
    if actor_executable_name in POWERSHELL_EXECUTABLE_NAMES:
        return _validate_powershell_argv(
            workspace_root,
            argv,
            snapshot_root=snapshot_root,
        )
    executable_name = actor_executable_name
    code_path: Path | None = None
    code_paths: list[Path] = []
    command_kind: str

    if executable_name.startswith("python"):
        command_kind = "python"
        arguments = argv[1:]
        if any(argument in {"-c", "-"} for argument in arguments):
            raise EvidenceError(
                "Trusted Python validation must use an allowlisted module or "
                "a committed script; inline/stdin code is forbidden"
            )
        if arguments and arguments[0] == "-m":
            if len(arguments) < 2:
                raise EvidenceError("Trusted Python -m requires a module")
            module = arguments[1]
            if module not in ALLOWED_PYTHON_MODULES:
                raise EvidenceError(
                    f"Trusted Python module is not allowlisted: {module}"
                )
            code_paths = _validate_python_module_arguments(
                workspace_root,
                module,
                arguments[2:],
                snapshot_root=snapshot_root,
            )
        else:
            if not arguments or arguments[0].startswith("-"):
                raise EvidenceError(
                    "Trusted Python requires exactly '-m <module> ...' or a "
                    "committed script as argv[1]; interpreter options are forbidden"
                )
            code_path = _tracked_workspace_file(
                workspace_root,
                arguments[0],
                snapshot_root=snapshot_root,
            )
            code_paths = [code_path]
    elif executable_name in {"node", "node.exe"}:
        command_kind = "node"
        arguments = argv[1:]
        for argument in arguments:
            if argument.startswith("-") and argument not in SAFE_NODE_FLAGS:
                raise EvidenceError(
                    f"Trusted Node option is not allowlisted: {argument}"
                )
        positional = [
            argument
            for argument in arguments
            if argument and not argument.startswith("-")
        ]
        if not positional:
            raise EvidenceError(
                "Trusted Node validation requires explicit committed code targets"
            )
        values_to_validate = positional if "--test" in arguments else positional[:1]
        for value in values_to_validate:
            code_paths.append(
                _tracked_workspace_file(
                    workspace_root,
                    value,
                    snapshot_root=snapshot_root,
                )
            )
        code_path = code_paths[0]
    else:
        raise EvidenceError(
            "Trusted verifier executable is not allowlisted; use Python, Node, "
            "or PowerShell with committed validation code"
        )

    trust_binding = _trusted_runtime_binding(
        command_kind=command_kind,
        supplied_value=argv[0],
    )
    return {
        "schema_version": 1,
        "kind": command_kind,
        "executable_path": trust_binding["path"],
        "executable_sha256": trust_binding["sha256"],
        "executable_binding": trust_binding,
        "executed_argv": [trust_binding["path"], *argv[1:]],
        "code_path": str(code_path) if code_path else None,
        "code_paths": [
            {
                "path": str(path),
                "sha256": _committed_code_sha256(
                    workspace_root,
                    path,
                    snapshot_root=snapshot_root,
                ),
            }
            for path in code_paths
        ],
    }


def _trusted_environment(
    *,
    workspace_root: Path,
    scratch_root: Path,
    gpu_allowed: bool,
    network_allowed: bool,
) -> dict[str, str]:
    environment = {
        key: value
        for key in SAFE_ENVIRONMENT_KEYS
        if isinstance((value := os.environ.get(key)), str)
    }
    if "PATH" not in environment:
        environment["PATH"] = os.defpath
    scratch_root.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "APPDATA": str(scratch_root / "appdata"),
            "HOME": str(scratch_root),
            "LOCALAPPDATA": str(scratch_root / "localappdata"),
            "PYTHONPATH": (
                str(workspace_root / "src") if (workspace_root / "src").is_dir() else ""
            ),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "TEMP": str(scratch_root / "tmp"),
            "TMP": str(scratch_root / "tmp"),
            "USERPROFILE": str(scratch_root),
        }
    )
    for path in (
        Path(environment["APPDATA"]),
        Path(environment["LOCALAPPDATA"]),
        Path(environment["TEMP"]),
    ):
        path.mkdir(parents=True, exist_ok=True)
    environment["CUDA_VISIBLE_DEVICES"] = _bounded_cuda_visible_devices(
        gpu_allowed=gpu_allowed,
    )
    if not network_allowed:
        offline_proxy = "http://127.0.0.1:9"
        environment.update(
            {
                "ALL_PROXY": offline_proxy,
                "HTTP_PROXY": offline_proxy,
                "HTTPS_PROXY": offline_proxy,
                "NO_PROXY": "",
                "HF_HUB_OFFLINE": "1",
                "PIP_NO_INDEX": "1",
                "TRANSFORMERS_OFFLINE": "1",
            }
        )
    return environment


def _numeric_device_list(value: str, *, variable: str) -> list[int]:
    normalized = value.strip()
    if normalized in {"", "-1"}:
        return []
    tokens = [token.strip() for token in normalized.split(",")]
    if not tokens or any(
        re.fullmatch(r"(?:0|[1-9][0-9]*)", token) is None for token in tokens
    ):
        raise EvidenceError(
            f"{variable} must contain only unambiguous numeric GPU indices"
        )
    devices = [int(token) for token in tokens]
    if len(devices) != len(set(devices)):
        raise EvidenceError(f"{variable} contains duplicate GPU indices")
    return devices


def _bounded_cuda_visible_devices(*, gpu_allowed: bool) -> str:
    """Return a physical GPU 0-5 subset or fail on UUID/remapping ambiguity."""
    if not gpu_allowed:
        return ""

    physical_allowlist = list(ALLOWED_GPU_IDS)
    nvidia_visible = os.environ.get("NVIDIA_VISIBLE_DEVICES")
    if nvidia_visible is not None:
        exposed = _numeric_device_list(
            nvidia_visible,
            variable="NVIDIA_VISIBLE_DEVICES",
        )
        if exposed != list(range(len(exposed))) or any(
            device not in ALLOWED_GPU_IDS for device in exposed
        ):
            raise EvidenceError(
                "NVIDIA_VISIBLE_DEVICES introduces an ambiguous or denied GPU remap"
            )
        physical_allowlist = exposed

    existing = os.environ.get("CUDA_VISIBLE_DEVICES")
    if existing is None:
        selected = physical_allowlist
    else:
        requested = _numeric_device_list(
            existing,
            variable="CUDA_VISIBLE_DEVICES",
        )
        allowed = set(physical_allowlist)
        selected = [device for device in requested if device in allowed]
    return ",".join(str(device) for device in selected)


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                shell=False,
                check=False,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            process.kill()
    else:
        try:
            os.killpg(process.pid, 9)
        except (OSError, ProcessLookupError):
            process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def _run_bounded_command(
    *,
    argv: list[str],
    workspace_root: Path,
    environment: dict[str, str],
    output_path: Path,
    timeout_seconds: int,
    pass_fds: tuple[int, ...] = (),
) -> dict[str, Any]:
    temporary_path = output_path.with_suffix(output_path.suffix + ".part")
    timed_out = False
    output_truncated = False
    start_error: str | None = None
    exit_code: int | None = None
    started = time.monotonic()
    creation: dict[str, Any] = {}
    if os.name == "nt":
        creation["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        creation["start_new_session"] = True
        creation["pass_fds"] = pass_fds
    try:
        with temporary_path.open("wb") as output:
            process = subprocess.Popen(
                argv,
                cwd=workspace_root,
                env=environment,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                **creation,
            )
            while True:
                exit_code = process.poll()
                output.flush()
                size = temporary_path.stat().st_size
                elapsed = time.monotonic() - started
                if size > MAX_OUTPUT_BYTES:
                    output_truncated = True
                    _terminate_process_tree(process)
                    exit_code = process.poll()
                    break
                if elapsed > timeout_seconds:
                    timed_out = True
                    _terminate_process_tree(process)
                    exit_code = process.poll()
                    break
                if exit_code is not None:
                    break
                time.sleep(0.025)
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        start_error = str(exc)
        _atomic_write_bytes(
            temporary_path, start_error.encode("utf-8", errors="replace")
        )
    if temporary_path.stat().st_size > MAX_OUTPUT_BYTES:
        with temporary_path.open("r+b") as output:
            output.truncate(MAX_OUTPUT_BYTES)
            output.flush()
            os.fsync(output.fileno())
    os.replace(temporary_path, output_path)
    return {
        "exit_code": exit_code,
        "timed_out": timed_out,
        "output_truncated": output_truncated,
        "start_error": start_error,
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
    }


def _run_trusted_validations_impl(
    *,
    workspace_root: Path,
    runs_root: Path,
    task_id: str,
    attempt: int,
    actor: str,
    run_id: str,
    manifest: dict[str, Any],
    gpu_allowed: bool,
    network_allowed: bool,
    timeout_seconds: int = MAX_TIMEOUT_SECONDS,
    _lease_guard: _BrokerLeaseGuard,
) -> dict[str, Any]:
    """Execute every validated verifier argv and bind results to raw bytes."""
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise EvidenceError(
            f"Trusted verifier timeout must be 1..{MAX_TIMEOUT_SECONDS} seconds"
        )
    if re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        raise EvidenceError(
            "Trusted verifier run id must be 32 lowercase hexadecimal chars"
        )
    workspace_root = Path(workspace_root)
    runs_root = Path(runs_root)
    _require_plain_directory(workspace_root, label="workspace root")
    try:
        runs_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise EvidenceError("Trusted verifier cannot create the runs root") from exc
    _require_plain_directory(runs_root, label="runs root")
    try:
        runs_root.resolve().relative_to(workspace_root.resolve())
    except ValueError as exc:
        raise EvidenceError(
            "Trusted verifier runs root must remain inside the workspace"
        ) from exc
    source = _source_state(workspace_root)
    verifier_manifest_sha256 = str(manifest.get("manifest_sha256", "")).lower()
    if len(verifier_manifest_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in verifier_manifest_sha256
    ):
        raise EvidenceError("Trusted verifier manifest SHA-256 is invalid")
    validations = manifest.get("validations")
    if not isinstance(validations, list):
        raise EvidenceError("Trusted verifier validations must be a list")
    for index, validation in enumerate(validations):
        if not isinstance(validation, dict):
            raise EvidenceError(f"validations[{index}] is not an object")
        argv = validation.get("command_argv")
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(argument, str) or not argument for argument in argv)
        ):
            raise EvidenceError(f"validations[{index}].command_argv was not validated")
    isolation_backend = _require_isolation_backend(
        gpu_allowed=gpu_allowed,
        network_allowed=network_allowed,
    )
    # Git inspection and committed-tree materialization remain unprivileged.
    # The root broker receives only a sealed directory FD and copies it without
    # importing Git or parsing actor-owned repository metadata.  Its signature
    # proves copied snapshot provenance/cleanup, never source authenticity.
    broker_client = _require_external_snapshot_broker_contract()
    started_at = utc_now()
    run_directory = (
        runs_root / "trusted-verifier" / task_id / f"attempt-{attempt:03d}" / run_id
    ).resolve()
    run_directory.mkdir(parents=True, exist_ok=False)
    _require_plain_directory(run_directory, label="run directory")
    broker_lease = None
    if broker_client is None:
        # Test-only direct materialization seam.  Production preflight always
        # returns a real broker client or raises before reaching this branch.
        snapshot_root = run_directory / "committed-input"
        snapshot = _materialize_committed_snapshot(
            workspace_root,
            snapshot_root,
            source["commit"],
        )
        snapshot_descriptor = None
    else:
        caller_source_root = run_directory / "caller-sealed-source"
        expected_snapshot = _materialize_committed_snapshot(
            workspace_root,
            caller_source_root,
            source["commit"],
        )
        contract_sha256 = validation_contract_sha256(
            task_id=task_id,
            attempt=attempt,
            actor=actor,
            source_commit=source["commit"],
            source_tree=expected_snapshot["tree_oid"],
            snapshot_sha256=expected_snapshot["sha256"],
            manifest_sha256=verifier_manifest_sha256,
            gpu_allowed=gpu_allowed,
            network_allowed=network_allowed,
            validations=validations,
        )
        try:
            broker_lease = broker_client.acquire(
                source_root=caller_source_root,
                source_commit=source["commit"],
                tree_oid=expected_snapshot["tree_oid"],
                task_id=task_id,
                attempt=attempt,
                actor=actor,
                run_id=run_id,
                validation_contract_sha256=contract_sha256,
                expected_snapshot_sha256=expected_snapshot["sha256"],
            )
            # Attach before deleting the caller materialization.  If local
            # cleanup itself fails, the public runner's finally block must
            # still release the already-created root broker lease.
            _lease_guard.attach(broker_lease)
        finally:
            if caller_source_root.exists():
                _remove_committed_snapshot(caller_source_root)
        snapshot_root = broker_lease.snapshot_root
        snapshot_descriptor = broker_lease.descriptor
        snapshot = broker_lease.snapshot
    snapshot_precheck = _committed_snapshot_postcheck(
        snapshot_root,
        snapshot,
        snapshot_descriptor=snapshot_descriptor,
    )
    if snapshot_precheck != snapshot:
        raise EvidenceError(
            "Trusted verifier pinned snapshot does not match its Git object manifest"
        )
    if broker_client is None:
        contract_sha256 = validation_contract_sha256(
            task_id=task_id,
            attempt=attempt,
            actor=actor,
            source_commit=source["commit"],
            source_tree=snapshot["tree_oid"],
            snapshot_sha256=snapshot["sha256"],
            manifest_sha256=verifier_manifest_sha256,
            gpu_allowed=gpu_allowed,
            network_allowed=network_allowed,
            validations=validations,
        )
    snapshot_protection = (
        _require_broker_protected_snapshot(snapshot_root)
        if broker_lease is None
        else None
    )
    command_policies = [
        _validate_command_argv(
            workspace_root,
            validation["command_argv"],
            snapshot_root=snapshot_root,
        )
        for validation in validations
    ]
    scratch_root = run_directory / "sandbox-home"
    environment = _trusted_environment(
        workspace_root=workspace_root,
        scratch_root=scratch_root,
        gpu_allowed=gpu_allowed,
        network_allowed=network_allowed,
    )
    environment_sha256 = hashlib.sha256(
        json.dumps(
            environment,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    sandbox_environment = _sandbox_environment(
        snapshot_root=snapshot_root,
        cuda_visible_devices=environment["CUDA_VISIBLE_DEVICES"],
    )
    sandbox_environment_sha256 = hashlib.sha256(
        json.dumps(
            sandbox_environment,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    receipts: list[dict[str, Any]] = []
    failure: str | None = None
    for index, validation in enumerate(validations):
        argv = validation["command_argv"]
        command_policy = command_policies[index]
        command_started_at = utc_now()
        output_path = run_directory / f"validation-{index:03d}.log"
        isolation_launch_argv = _canonical_isolation_argv(
            backend=isolation_backend,
            command_argv=command_policy["executed_argv"],
            workspace_root=workspace_root,
            snapshot_root=snapshot_root,
            scratch_root=scratch_root,
            sandbox_environment=sandbox_environment,
            network_allowed=network_allowed,
        )
        execution = _run_bounded_command(
            argv=isolation_launch_argv,
            workspace_root=run_directory,
            environment=environment,
            output_path=output_path,
            timeout_seconds=timeout_seconds,
            pass_fds=(snapshot_descriptor,) if snapshot_descriptor is not None else (),
        )
        output_sha256 = sha256_file(output_path)
        executable_path = Path(command_policy["executable_path"])
        executable_sha256_after = (
            sha256_file(executable_path) if executable_path.is_file() else None
        )
        receipt = {
            "index": index,
            "command_argv": list(argv),
            "executed_argv": list(command_policy["executed_argv"]),
            "isolation_launch_argv": isolation_launch_argv,
            "command_policy": command_policy,
            "started_at": command_started_at,
            "completed_at": utc_now(),
            "duration_ms": execution["duration_ms"],
            "timeout_seconds": timeout_seconds,
            "timed_out": execution["timed_out"],
            "output_truncated": execution["output_truncated"],
            "exit_code": execution["exit_code"],
            "output_path": str(output_path),
            "output_sha256": output_sha256,
            "output_size_bytes": output_path.stat().st_size,
            "executable_sha256_after": executable_sha256_after,
        }
        receipts.append(receipt)
        if execution["start_error"]:
            failure = (
                "Trusted verifier command could not start: " + execution["start_error"]
            )
        elif execution["timed_out"]:
            failure = f"Trusted verifier validation {index} timed out"
        elif execution["output_truncated"]:
            failure = (
                f"Trusted verifier validation {index} exceeded the "
                f"{MAX_OUTPUT_BYTES}-byte output limit"
            )
        elif executable_sha256_after != command_policy["executable_sha256"]:
            failure = f"Trusted verifier executable changed during validation {index}"
        elif execution["exit_code"] != 0:
            failure = (
                f"Trusted verifier validation {index} failed with "
                f"exit code {execution['exit_code']}"
            )
        elif execution["exit_code"] != validation.get("exit_code"):
            failure = f"Trusted verifier validation {index} exit code was forged"
        elif output_sha256 != validation["raw_output"]["sha256"]:
            failure = f"Trusted verifier validation {index} output was forged"
        if failure:
            break

    source_postcheck_error: str | None = None
    try:
        _source_state(workspace_root, source_commit=source["commit"])
    except EvidenceError as exc:
        source_postcheck_error = f"Trusted verifier source postcheck failed: {exc}"
    if source_postcheck_error and failure is None:
        failure = source_postcheck_error

    snapshot_postcheck_error: str | None = None
    try:
        completed_snapshot = _committed_snapshot_postcheck(
            snapshot_root,
            snapshot,
            snapshot_descriptor=snapshot_descriptor,
        )
        if completed_snapshot != snapshot:
            snapshot_postcheck_error = (
                "Trusted verifier committed sandbox snapshot changed during validation"
            )
    except EvidenceError as exc:
        snapshot_postcheck_error = (
            f"Trusted verifier sandbox snapshot postcheck failed: {exc}"
        )
    if snapshot_postcheck_error and failure is None:
        failure = snapshot_postcheck_error
    if broker_lease is not None:
        acquire_payload = broker_lease.acquire_attestation["payload"]
        snapshot_protection = {
            "policy_id": SNAPSHOT_PROTECTION_POLICY_ID,
            "platform": "linux",
            "broker": "external-privileged-fd-lease",
            "runner_euid": acquire_payload["caller_uid"],
            "owner_uid": acquire_payload["snapshot_owner_uid"],
            "actor_write_access": False,
            "links_rejected": True,
            "proof": BROKER_PROOF_SCOPE,
            "descriptor_type": acquire_payload["descriptor_type"],
            "snapshot_device": acquire_payload["snapshot_device"],
            "snapshot_inode": acquire_payload["snapshot_inode"],
            "acquire_attestation_sha256": broker_lease.acquire_attestation_sha256,
            "acquire_attestation": broker_lease.acquire_attestation,
            "cleanup_attestation": None,
        }
    elif snapshot_postcheck_error is None:
        try:
            _remove_committed_snapshot(snapshot_root)
        except (EvidenceError, OSError) as exc:
            if failure is None:
                failure = f"Trusted verifier sandbox cleanup failed: {exc}"

    receipt_document = {
        "schema_version": 3,
        "runner": TRUSTED_RUNNER_ID,
        "task_id": task_id,
        "attempt": attempt,
        "actor": actor,
        "run_id": run_id,
        "source_commit": source["commit"],
        "verifier_manifest_sha256": verifier_manifest_sha256,
        "validation_contract_sha256": contract_sha256,
        "receipt_preimage_sha256": "",
        "source_clean": source["source_clean"],
        "source_postcheck_passed": source_postcheck_error is None,
        "source_postcheck_error": source_postcheck_error,
        "isolation_policy": ISOLATION_POLICY_ID,
        "isolation_attested": True,
        "isolation_backend": isolation_backend,
        "snapshot": snapshot,
        "snapshot_precheck_passed": snapshot_precheck == snapshot,
        "snapshot_protection": snapshot_protection,
        "snapshot_postcheck_passed": snapshot_postcheck_error is None,
        "snapshot_postcheck_error": snapshot_postcheck_error,
        "operational_change_count": source["operational_change_count"],
        "operational_paths_sha256": source["operational_paths_sha256"],
        "started_at": started_at,
        "completed_at": utc_now(),
        "gpu_allowed": gpu_allowed,
        "cuda_visible_devices": environment["CUDA_VISIBLE_DEVICES"],
        "network_allowed": network_allowed,
        "network_enforcement": isolation_backend["network_enforcement"],
        "environment_sha256": environment_sha256,
        "sandbox_environment": sandbox_environment,
        "sandbox_environment_sha256": sandbox_environment_sha256,
        "max_output_bytes": MAX_OUTPUT_BYTES,
        "validations": receipts,
        "passed": failure is None and len(receipts) == len(validations),
        "failure": failure,
    }
    receipt_preimage_sha256 = trusted_receipt_preimage_sha256(receipt_document)
    receipt_document["receipt_preimage_sha256"] = receipt_preimage_sha256
    if broker_lease is not None:
        try:
            snapshot_protection["cleanup_attestation"] = _lease_guard.release(
                receipt_preimage_sha256
            )
        except EvidenceError as exc:
            if failure is None:
                failure = f"Trusted verifier broker cleanup failed: {exc}"
            receipt_document["passed"] = False
            receipt_document["failure"] = failure
    receipt_path = run_directory / "receipt.json"
    atomic_write_json(receipt_path, receipt_document)
    result = {
        **receipt_document,
        "receipt_path": str(receipt_path),
        "receipt_sha256": sha256_file(receipt_path),
    }
    if failure:
        raise EvidenceError(f"{failure}; receipt={result['receipt_sha256']}")
    return result


def run_trusted_validations(
    *,
    workspace_root: Path,
    runs_root: Path,
    task_id: str,
    attempt: int,
    actor: str,
    run_id: str,
    manifest: dict[str, Any],
    gpu_allowed: bool,
    network_allowed: bool,
    timeout_seconds: int = MAX_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run trusted validations and always attempt broker lease cleanup."""

    if re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        raise EvidenceError(
            "Trusted verifier run id must be 32 lowercase hexadecimal chars"
        )
    lease_guard = _BrokerLeaseGuard()
    try:
        return _run_trusted_validations_impl(
            workspace_root=workspace_root,
            runs_root=runs_root,
            task_id=task_id,
            attempt=attempt,
            actor=actor,
            run_id=run_id,
            manifest=manifest,
            gpu_allowed=gpu_allowed,
            network_allowed=network_allowed,
            timeout_seconds=timeout_seconds,
            _lease_guard=lease_guard,
        )
    finally:
        lease_guard.cleanup_after_abort()
