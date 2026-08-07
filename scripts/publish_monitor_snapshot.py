#!/usr/bin/env python3
"""Publish a signed, metadata-only Cogni-OS operations snapshot.

This process is an optional outbound monitoring gateway. It is deliberately
separate from Cogni-Core inference, never accepts inbound control, and exports
only the allowlisted operational schema consumed by Cloudflare Pages.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import json
import math
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cogni_os.independence import identity_snapshot
from cogni_os.lock import FileLock
from cogni_os.release_gate import release_gate_status
from cogni_os.roadmap import phase_contracts, roadmap_snapshot
from cogni_os.trust_projection import task_trust_projection
from cogni_os.workspace import Workspace

COLLECTOR_VERSION = "1.2.0"
SNAPSHOT_SCHEMA_VERSION = "1.2"
GPU_ALLOWED_IDS = (0, 1, 2, 3, 4, 5)
GPU_DENIED_IDS = (6, 7)
GPU_BOUNDARY_ATTESTATION_ENV = "COGNI_GPU_BOUNDARY_ATTESTATION_PATH"
GPU_BOUNDARY_KEYRING_ENV = "COGNI_GPU_BOUNDARY_HMAC_KEYS"
PUBLIC_PROJECTION_SECRET_ENV = "COGNI_PUBLIC_PROJECTION_SECRET"
GPU_BOUNDARY_MAX_BYTES = 64 * 1024
GPU_BOUNDARY_MAX_LIFETIME_SECONDS = 120
GPU_BOUNDARY_SCOPE = (
    "host-inventory",
    "host-processes",
    "containers",
    "scheduler",
)
OPERATIONAL_ROOT_PREFIXES = (
    ".cogni/",
    ".efo/",
    "archive/",
    "ledger/",
    "reports/",
    "runs/",
    "submissions/",
    "tasks/",
)
EVIDENCE_ROOTS = ("archive", "reports", "runs", "submissions")
UNSAFE_OPERATIONAL_SUFFIXES = {
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
INGEST_PROTOCOL = "COGNI-SNAPSHOT-V2"
ACK_CLOCK_SKEW_SECONDS = 300
ACK_RECEIVED_AT_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)
DEFAULT_ENDPOINT = "https://cogni-os-orchestrator.pages.dev/api/ingest"
DEFAULT_ENDPOINT_HOST = "cogni-os-orchestrator.pages.dev"
PRODUCTION_RUNTIME_ENV = "COGNI_PUBLISHER_PRODUCTION"
PRODUCTION_BINARY_MANIFEST_ENV = "COGNI_PUBLISHER_BINARY_MANIFEST"
PRODUCTION_SOURCE_COMMIT_ENV = "COGNI_PUBLISHER_SOURCE_COMMIT"
PRODUCTION_CODE_MANIFEST_ENV = "COGNI_PUBLISHER_CODE_MANIFEST_SHA256"
DEFAULT_JOURNAL_MAX_BYTES = 8 * 1024 * 1024
MAX_AUDITED_EVIDENCE_BYTES = 50 * 1024 * 1024
MAX_DEPLOYMENT_EVIDENCE_BYTES = 1024 * 1024
RELEASE_ARTIFACT_FILES = {
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
PUBLIC_TASK_LABELS = {
    **{contract["id"]: contract["title"] for contract in phase_contracts()},
    "T-001": "Legacy trust audit",
}

_PRODUCTION_EXECUTABLES: dict[str, dict[str, str]] = {}
_PRODUCTION_SOURCE_COMMIT = ""
_PRODUCTION_CODE_MANIFEST_SHA256 = ""
MAX_SUBPROCESS_STDOUT_BYTES = 2 * 1024 * 1024
MAX_SUBPROCESS_STDERR_BYTES = 128 * 1024
MAX_GIT_STDOUT_BYTES = 256 * 1024
MAX_COLLECTOR_CODE_FILES = 4096
MAX_COLLECTOR_CODE_DIRECTORIES = 4096
MAX_COLLECTOR_CODE_PATH_CHARACTERS = 1024 * 1024
MAX_COLLECTOR_CODE_FILE_BYTES = 64 * 1024 * 1024
MAX_COLLECTOR_CODE_TOTAL_BYTES = 512 * 1024 * 1024


def _bounded_file_sha256(path: Path, *, maximum: int = 1024 * 1024 * 1024) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > maximum:
        raise RuntimeError("trusted executable is not a bounded regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _assert_non_reparse_path(path: Path) -> Path:
    candidate = path.absolute()
    if not candidate.is_absolute():
        raise RuntimeError("trusted executable path is not absolute")
    chain = [candidate, *candidate.parents]
    for component in chain:
        info = component.lstat()
        attributes = int(getattr(info, "st_file_attributes", 0))
        if stat.S_ISLNK(info.st_mode) or attributes & int(
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise RuntimeError("trusted executable path crosses a link or reparse point")
        if os.name != "nt" and (
            int(getattr(info, "st_uid", -1)) != 0 or info.st_mode & 0o022
        ):
            raise RuntimeError("trusted executable path is not root-owned and immutable")
    return candidate


def _verify_production_executable(name: str) -> tuple[Path, str]:
    record = _PRODUCTION_EXECUTABLES.get(name)
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise RuntimeError(f"trusted executable record is missing: {name}")
    path = _assert_non_reparse_path(Path(str(record["path"])))
    expected = str(record["sha256"])
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError(f"trusted executable digest is invalid: {name}")
    observed = _bounded_file_sha256(path)
    if not hmac.compare_digest(observed, expected):
        raise RuntimeError(f"trusted executable digest changed: {name}")
    return path, expected


def _production_subprocess_env() -> dict[str, str]:
    allowed: dict[str, str] = {}
    for name in ("SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP", "USERPROFILE"):
        value = os.environ.get(name)
        if value:
            allowed[name] = value
    allowed.update(
        {
            "PATH": "",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return allowed


def _run_capped_command(
    command: list[str],
    *,
    timeout: int,
    text: bool,
    env: dict[str, str] | None = None,
    stdout_limit: int = MAX_SUBPROCESS_STDOUT_BYTES,
    stderr_limit: int = MAX_SUBPROCESS_STDERR_BYTES,
) -> subprocess.CompletedProcess[Any]:
    """Run a child with concurrent, in-flight stdout/stderr memory bounds."""

    if timeout < 1 or timeout > 60:
        raise RuntimeError("subprocess timeout is outside the fixed safety range")
    if stdout_limit < 1024 or stderr_limit < 1024:
        raise RuntimeError("subprocess capture limit is below the safety minimum")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        shell=False,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    exceeded: list[str] = []
    lock = threading.Lock()

    def drain(name: str, stream: Any) -> None:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            with lock:
                remaining = limits[name] - len(buffers[name])
                if remaining > 0:
                    buffers[name].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    exceeded.append(name)
                    with contextlib.suppress(OSError):
                        process.kill()
                    return

    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    timeout_error: subprocess.TimeoutExpired | None = None
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        timeout_error = error
        with contextlib.suppress(OSError):
            process.kill()
    finally:
        if process.poll() is None:
            with contextlib.suppress(OSError):
                process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        # Popen does not close PIPE file objects until the process object is
        # collected.  The publisher calls this helper repeatedly, so relying
        # on garbage collection leaks descriptors and emits ResourceWarning.
        for stream in (process.stdout, process.stderr):
            with contextlib.suppress(OSError):
                stream.close()
    if any(reader.is_alive() for reader in readers):
        raise RuntimeError("subprocess capture reader did not terminate")
    if timeout_error is not None:
        raise subprocess.TimeoutExpired(command, timeout) from timeout_error
    if exceeded:
        raise RuntimeError(
            f"subprocess {exceeded[0]} exceeded the in-flight capture limit"
        )
    stdout_bytes = bytes(buffers["stdout"])
    stderr_bytes = bytes(buffers["stderr"])
    stdout: Any = stdout_bytes.decode("utf-8", errors="replace") if text else stdout_bytes
    stderr: Any = stderr_bytes.decode("utf-8", errors="replace") if text else stderr_bytes
    completed = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if process.returncode:
        raise subprocess.CalledProcessError(
            process.returncode,
            command,
            output=stdout,
            stderr=stderr,
        )
    return completed


def _run_production_binary(
    name: str,
    arguments: list[str],
    *,
    timeout: int,
    text: bool,
    stdout_limit: int = MAX_SUBPROCESS_STDOUT_BYTES,
    stderr_limit: int = MAX_SUBPROCESS_STDERR_BYTES,
) -> subprocess.CompletedProcess[Any]:
    path, expected = _verify_production_executable(name)
    result = _run_capped_command(
        [str(path), *arguments],
        timeout=timeout,
        text=text,
        env=_production_subprocess_env(),
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
    )
    observed = _bounded_file_sha256(path)
    if not hmac.compare_digest(observed, expected):
        raise RuntimeError(f"trusted executable changed while running: {name}")
    return result


def _collector_code_manifest(root: Path) -> tuple[str, int]:
    paths = [
        root / "scripts" / "publisher_binary_trust.ps1",
        root / "scripts" / "publisher_production_preflight.ps1",
        root / "scripts" / "run_monitor_publisher.ps1",
        root / "scripts" / "publish_monitor_snapshot.py",
    ]
    path_characters = sum(len(str(path)) for path in paths)
    directory_count = 0
    code_root = root / "src" / "cogni_os"
    for directory, directory_names, file_names in os.walk(
        code_root, topdown=True, followlinks=False
    ):
        directory_count += 1
        if directory_count > MAX_COLLECTOR_CODE_DIRECTORIES:
            raise RuntimeError("collector code directory-count budget was exceeded")
        directory_path = Path(directory)
        for name in directory_names:
            candidate = directory_path / name
            info = candidate.lstat()
            attributes = int(getattr(info, "st_file_attributes", 0))
            if stat.S_ISLNK(info.st_mode) or attributes & int(
                getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise RuntimeError("collector code tree contains a link or reparse point")
        for name in file_names:
            if not name.endswith(".py"):
                continue
            candidate = directory_path / name
            paths.append(candidate)
            path_characters += len(str(candidate))
            if len(paths) > MAX_COLLECTOR_CODE_FILES:
                raise RuntimeError("collector code file-count budget was exceeded")
            if path_characters > MAX_COLLECTOR_CODE_PATH_CHARACTERS:
                raise RuntimeError("collector code path budget was exceeded")
    records: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(set(paths), key=lambda value: value.as_posix()):
        checked = _assert_non_reparse_path(path)
        info = checked.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("collector code manifest contains a non-regular file")
        if info.st_size <= 0 or info.st_size > MAX_COLLECTOR_CODE_FILE_BYTES:
            raise RuntimeError("collector code file exceeds the per-file budget")
        total_bytes += info.st_size
        if total_bytes > MAX_COLLECTOR_CODE_TOTAL_BYTES:
            raise RuntimeError("collector code byte budget was exceeded")
        records.append(
            {
                "path": checked.relative_to(root).as_posix(),
                "size": info.st_size,
                "sha256": _bounded_file_sha256(
                    checked, maximum=MAX_COLLECTOR_CODE_FILE_BYTES
                ),
            }
        )
    canonical = json.dumps(
        records, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest(), len(records)


def _configure_production_runtime(args: argparse.Namespace) -> None:
    global _PRODUCTION_EXECUTABLES
    global _PRODUCTION_SOURCE_COMMIT
    global _PRODUCTION_CODE_MANIFEST_SHA256

    # Classify the destination only after applying the same validation used by
    # the network publisher.  Comparing the caller supplied string before this
    # check allowed alternate spellings of the production origin to reach the
    # canonical ingest endpoint without the trusted PowerShell bootstrap.
    args.endpoint = validate_publish_endpoint(
        args.endpoint,
        allowed_hosts={
            DEFAULT_ENDPOINT_HOST,
            *args.allowed_endpoint_host,
        },
    )
    production_endpoint = args.endpoint == DEFAULT_ENDPOINT and not args.dry_run
    enabled = os.environ.get(PRODUCTION_RUNTIME_ENV) == "1"
    if production_endpoint and not enabled:
        raise RuntimeError(
            "canonical production ingest requires the trusted PowerShell bootstrap"
        )
    if not enabled:
        return
    try:
        manifest = json.loads(os.environ[PRODUCTION_BINARY_MANIFEST_ENV])
    except (KeyError, json.JSONDecodeError) as error:
        raise RuntimeError("production binary manifest is missing or invalid") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "executables",
    }:
        raise RuntimeError("production binary manifest schema is not exact")
    executables = manifest.get("executables")
    if manifest.get("schema_version") != 1 or not isinstance(executables, dict):
        raise RuntimeError("production binary manifest schema is invalid")
    if not {"git", "powershell", "python"}.issubset(executables):
        raise RuntimeError("production binary manifest omits a required executable")
    _PRODUCTION_EXECUTABLES = {
        str(name): dict(record)
        for name, record in executables.items()
        if isinstance(name, str) and isinstance(record, dict)
    }
    python_path, _ = _verify_production_executable("python")
    if python_path != _assert_non_reparse_path(Path(sys.executable)):
        raise RuntimeError("running Python differs from the attested executable")
    for name in _PRODUCTION_EXECUTABLES:
        _verify_production_executable(name)
    source_commit = os.environ.get(PRODUCTION_SOURCE_COMMIT_ENV, "")
    code_manifest = os.environ.get(PRODUCTION_CODE_MANIFEST_ENV, "")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise RuntimeError("production source commit is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", code_manifest):
        raise RuntimeError("production collector code manifest is invalid")
    _PRODUCTION_SOURCE_COMMIT = source_commit
    _PRODUCTION_CODE_MANIFEST_SHA256 = code_manifest
    _assert_production_source_state()


def _assert_production_source_state() -> None:
    if not _PRODUCTION_SOURCE_COMMIT:
        return
    root = Path(__file__).resolve().parents[1]
    observed_manifest, _ = _collector_code_manifest(root)
    if not hmac.compare_digest(
        observed_manifest, _PRODUCTION_CODE_MANIFEST_SHA256
    ):
        raise RuntimeError("collector code manifest changed after bootstrap")
    observed_commit = git_commit(root)
    if observed_commit != _PRODUCTION_SOURCE_COMMIT:
        raise RuntimeError("collector source commit changed after bootstrap")


class PublisherAlreadyRunning(RuntimeError):
    """Raised when another publisher owns the OS-level instance lock."""


class PublisherInstanceLock:
    """Hold a crash-safe, OS-released lock for the publisher lifetime.

    Unlike an age-based lock file, this lock cannot be stolen merely because a
    healthy publisher has been running for a long time. Windows and POSIX both
    release the underlying file lock when the process exits or the PC reboots.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: Any | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b", buffering=0)
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as error:
            handle.close()
            raise PublisherAlreadyRunning(
                f"monitor publisher already owns {self.path}"
            ) from error

        self._handle = handle
        metadata = canonical_json(
            {
                "pid": os.getpid(),
                "acquired_at": utc_now(),
            }
        )
        handle.seek(1)
        handle.write(metadata)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
            self._handle = None

    def __enter__(self) -> PublisherInstanceLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


def process_is_alive(pid: int) -> bool:
    """Return whether a local supervisor process is still running."""

    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.windll.kernel32
        open_process = kernel32.OpenProcess
        open_process.argtypes = (
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        open_process.restype = wintypes.HANDLE
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        get_exit_code.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        handle = open_process(
            process_query_limited_information,
            False,
            pid,
        )
        if not handle:
            return False
        exit_code = wintypes.DWORD()
        try:
            if not get_exit_code(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == still_active
        finally:
            close_handle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_for_supervisor(
    delay_seconds: float,
    supervisor_pid: int,
    *,
    check_interval: float = 1.0,
) -> bool:
    """Sleep in bounded slices and stop when the task supervisor disappears."""

    deadline = time.monotonic() + max(0.0, delay_seconds)
    while True:
        if not process_is_alive(supervisor_pid):
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        time.sleep(min(max(0.05, check_interval), remaining))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_after(seconds: float) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=max(0.0, seconds))
    ).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def compute_backoff_seconds(
    interval_seconds: float,
    consecutive_failures: int,
    max_backoff_seconds: float,
) -> float:
    """Return bounded deterministic exponential retry delay."""

    base = max(5.0, float(interval_seconds))
    failures = max(1, int(consecutive_failures))
    cap = max(base, float(max_backoff_seconds))
    exponent = min(failures - 1, 16)
    return min(cap, base * (2**exponent))


def sanitize_error(error: BaseException, *, secret: str = "") -> str:
    """Create a bounded, single-line error string without secret material."""

    message = str(error).replace("\r", " ").replace("\n", " ")
    if secret:
        message = message.replace(secret, "[REDACTED]")
    return " ".join(message.split())[:512]


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f".tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def write_runtime_state(
    state_dir: Path,
    *,
    status: str,
    consecutive_failures: int,
    last_success_at: str | None,
    next_retry_at: str | None,
    last_error: str | None = None,
) -> None:
    """Atomically expose secret-free local publisher health."""

    _atomic_write_json(
        state_dir / "monitor_publisher_runtime.json",
        {
            "schema_version": 1,
            "status": status,
            "pid": os.getpid(),
            "updated_at": utc_now(),
            "consecutive_failures": consecutive_failures,
            "last_success_at": last_success_at,
            "next_retry_at": next_retry_at,
            "last_error": last_error,
            "gpu_telemetry_default": "DISABLED",
            "gpu_allowed_ids": [0, 1, 2, 3, 4, 5],
            "gpu_denied_ids": [6, 7],
        },
    )


def append_runtime_journal(
    state_dir: Path,
    event: str,
    *,
    max_bytes: int = DEFAULT_JOURNAL_MAX_BYTES,
    **fields: Any,
) -> None:
    """Append a bounded local operations journal with segment rollover."""

    state_dir.mkdir(parents=True, exist_ok=True)
    journal = state_dir / "monitor_publisher_journal.jsonl"
    if journal.exists() and journal.stat().st_size >= max(1024, max_bytes):
        archived = state_dir / "monitor_publisher_journal.previous.jsonl"
        with contextlib.suppress(FileNotFoundError):
            archived.unlink()
        os.replace(journal, archived)
    payload = {
        "schema_version": 1,
        "observed_at": utc_now(),
        "event": event,
        "pid": os.getpid(),
        **fields,
    }
    encoded = canonical_json(payload) + b"\n"
    fd = os.open(journal, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)


def signature_message(
    *,
    key_id: str,
    workspace_id: str,
    sequence: int,
    observed_at: str,
    nonce: str,
    body_sha256: str,
) -> bytes:
    return "\n".join(
        (
            INGEST_PROTOCOL,
            key_id,
            workspace_id,
            str(sequence),
            observed_at,
            nonce,
            body_sha256,
        )
    ).encode("utf-8")


def hmac_signature(secret: str, message: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def validate_publish_endpoint(
    endpoint: str,
    *,
    allowed_hosts: set[str] | None = None,
) -> str:
    if not isinstance(endpoint, str) or not endpoint:
        raise RuntimeError("Monitoring endpoint must be a canonical HTTPS URL")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as error:
        raise RuntimeError(
            "Monitoring endpoint must be a canonical HTTPS URL"
        ) from error
    allowed = {
        host.strip().lower()
        for host in (allowed_hosts or {DEFAULT_ENDPOINT_HOST})
        if isinstance(host, str) and host.strip()
    }
    hostname = (parsed.hostname or "").lower()
    canonical = f"https://{hostname}/api/ingest" if hostname else ""
    if (
        parsed.scheme != "https"
        or not hostname
        or not hostname.isascii()
        or hostname.endswith(".")
        or hostname not in allowed
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/api/ingest"
        or endpoint != canonical
    ):
        raise RuntimeError(
            "Monitoring endpoint must be a canonical allowlisted HTTPS "
            "host with the exact /api/ingest path"
        )
    return canonical


def _projection_secret() -> bytes | None:
    value = os.environ.get(PUBLIC_PROJECTION_SECRET_ENV, "")
    return value.encode("utf-8") if len(value) >= 32 else None


def _public_alias(kind: str, value: Any, secret: bytes | None) -> str:
    if secret is None:
        return f"{kind}-redacted"
    digest = hmac.new(
        secret,
        f"{kind}\0{value}".encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()
    return f"{kind}-{digest[:16]}"


def _public_digest(kind: str, value: Any, secret: bytes | None) -> str:
    if secret is None:
        return hashlib.sha256(f"{kind}-redacted".encode("utf-8")).hexdigest()
    return hmac.new(
        secret,
        f"{kind}\0{value}".encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()


def _public_task_id(value: Any, secret: bytes | None) -> str:
    task_id = str(value or "unknown")[:128]
    if task_id in PUBLIC_TASK_LABELS:
        return task_id
    return _public_alias("task", task_id, secret)


def _public_role(value: Any) -> str:
    lowered = str(value or "").lower()
    if "verif" in lowered or "audit" in lowered:
        return "verifier"
    if "conduct" in lowered or "orchestrat" in lowered:
        return "conductor"
    return "worker"


def _public_mode(value: Any) -> str:
    return "command" if str(value or "").lower() == "command" else "manual"


def _public_action(value: Any) -> str:
    action = str(value or "").lower()
    if action == "task.submitted":
        return "TASK_SUBMITTED"
    if "verified" in action or "accepted" in action:
        return "TASK_VERIFIED"
    if "blocked" in action or "rejected" in action or "revoked" in action:
        return "TASK_BLOCKED"
    if action.startswith("release."):
        return "RELEASE_EVIDENCE"
    if action.startswith("task."):
        return "TASK_STATE"
    return "SYSTEM_EVENT"


def collector_host_id(workspace_id: str, secret: bytes | None = None) -> str:
    """Return a stable pseudonym without publishing the machine hostname."""

    return _public_alias("host", f"{workspace_id}\0{socket.gethostname()}", secret)


def _git_command(
    root: Path,
    *arguments: str,
    timeout: int,
    text: bool,
) -> subprocess.CompletedProcess[Any]:
    command = [
        "-c",
        "credential.helper=",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null" if os.name != "nt" else "core.hooksPath=NUL",
        "-c",
        "diff.external=",
        "-c",
        f"safe.directory={root.as_posix()}",
        "-C",
        str(root),
        *arguments,
    ]
    if _PRODUCTION_EXECUTABLES:
        return _run_production_binary(
            "git",
            command,
            timeout=timeout,
            text=text,
            stdout_limit=MAX_GIT_STDOUT_BYTES,
            stderr_limit=MAX_SUBPROCESS_STDERR_BYTES,
        )
    return _run_capped_command(
        ["git", *command],
        timeout=timeout,
        text=text,
        stdout_limit=MAX_GIT_STDOUT_BYTES,
        stderr_limit=MAX_SUBPROCESS_STDERR_BYTES,
    )


def git_commit(root: Path) -> str:
    try:
        result = _git_command(
            root,
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
            timeout=5,
            text=True,
        )
        value = result.stdout.strip().lower()
        if 7 <= len(value) <= 64:
            return value
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def git_tree_status(root: Path) -> dict[str, Any]:
    """Separate source-bearing edits from append-only operational evidence.

    Ledger, task, report, run, and submission files are expected to change while
    the control-plane source remains immutable. Treating those files as source
    changes creates a permanent false release alarm, so both classes are
    measured and fingerprinted independently.
    """

    try:
        tracked = _git_command(
            root,
            "diff",
            "--no-ext-diff",
            "--name-only",
            "-z",
            "HEAD",
            "--",
            timeout=10,
            text=False,
        )
        untracked = _git_command(
            root,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            timeout=10,
            text=False,
        )
        ignored_evidence = _git_command(
            root,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
            "--",
            *EVIDENCE_ROOTS,
            timeout=10,
            text=False,
        )
        changed_paths = sorted(
            {
                value.decode("utf-8", errors="surrogateescape").replace("\\", "/")
                for value in (
                    *tracked.stdout.split(b"\0"),
                    *untracked.stdout.split(b"\0"),
                    *ignored_evidence.stdout.split(b"\0"),
                )
                if value
            }
        )
        operational_changes: list[str] = []
        unclassified_changes: list[str] = []
        source_changes: list[str] = []
        for path in changed_paths:
            is_task_projection = (
                path.startswith("tasks/")
                and path.count("/") == 1
                and path.endswith(".json")
            )
            is_unsafe_operational = (
                path.startswith(tuple(f"{name}/" for name in EVIDENCE_ROOTS))
                and Path(path).suffix.lower() in UNSAFE_OPERATIONAL_SUFFIXES
            )
            is_operational = (
                not is_unsafe_operational
                and (
                    path == "ledger/events.jsonl"
                    or is_task_projection
                    or path.startswith(
                        ("archive/", "reports/", "runs/", "submissions/")
                    )
                )
            )
            if is_operational:
                operational_changes.append(path)
            elif any(path.startswith(prefix) for prefix in OPERATIONAL_ROOT_PREFIXES):
                unclassified_changes.append(path)
            else:
                source_changes.append(path)

        def fingerprint_records(paths: list[str]) -> list[dict[str, Any]]:
            records: list[dict[str, Any]] = []
            for path in paths:
                candidate = root / Path(path)
                record: dict[str, Any] = {"path": path}
                try:
                    metadata = candidate.lstat()
                    record["size"] = int(metadata.st_size)
                    if stat.S_ISLNK(metadata.st_mode):
                        target = os.readlink(candidate)
                        record["kind"] = "symlink"
                        record["sha256"] = hashlib.sha256(
                            os.fsencode(target)
                        ).hexdigest()
                    elif stat.S_ISREG(metadata.st_mode):
                        record["kind"] = "file"
                        record["sha256"] = _sha256_file(candidate)
                    elif stat.S_ISDIR(metadata.st_mode):
                        record["kind"] = "directory"
                    else:
                        record["kind"] = "other"
                except FileNotFoundError:
                    record["kind"] = "missing"
                    record["size"] = 0
                records.append(record)
            return records

        source_records = fingerprint_records(source_changes)
        operational_records = fingerprint_records(operational_changes)
        unclassified_records = fingerprint_records(unclassified_changes)
        source_material = json.dumps(
            {
                "commit": git_commit(root),
                "records": source_records,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="surrogateescape")
        operational_material = json.dumps(
            operational_records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="surrogateescape")
        unclassified_material = json.dumps(
            unclassified_records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="surrogateescape")
        return {
            "clean": not source_changes,
            "change_count": len(source_changes),
            "fingerprint": hashlib.sha256(source_material).hexdigest(),
            "operational_change_count": len(operational_changes),
            "operational_fingerprint": hashlib.sha256(
                operational_material
            ).hexdigest(),
            "operational_records": operational_records,
            "unclassified_change_count": len(unclassified_changes),
            "unclassified_fingerprint": hashlib.sha256(
                unclassified_material
            ).hexdigest(),
            "unclassified_records": unclassified_records,
        }
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return {
            "clean": False,
            "change_count": 1,
            "fingerprint": hashlib.sha256(b"git-status-unavailable").hexdigest(),
            "operational_change_count": 0,
            "operational_fingerprint": hashlib.sha256(b"").hexdigest(),
            "operational_records": [],
            "unclassified_change_count": 1,
            "unclassified_fingerprint": hashlib.sha256(
                b"git-status-unavailable"
            ).hexdigest(),
            "unclassified_records": [
                {"kind": "unavailable", "path": "git-status-unavailable", "size": 0}
            ],
        }


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def _workspace_relative_path(
    root: Path,
    value: Any,
    *,
    allow_legacy_absolute: bool = False,
) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw_value = value.strip()
    if "\x00" in raw_value:
        return None
    raw_components = raw_value.replace("\\", "/").split("/")
    for index, component in enumerate(raw_components):
        if component in {".", ".."}:
            return None
        if ":" in component and not (
            allow_legacy_absolute
            and index == 0
            and len(component) == 2
            and component[0].isalpha()
            and component[1] == ":"
        ):
            # Reject NTFS alternate data streams and drive-relative paths.
            return None
    candidate = Path(raw_value)
    if candidate.drive and not candidate.is_absolute():
        return None
    if candidate.is_absolute():
        if not allow_legacy_absolute:
            return None
        try:
            if candidate.drive.lower() != root.resolve().drive.lower():
                return None
        except OSError:
            return None
    else:
        candidate = root / candidate
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_safe_ledger_component(value: Any, *, maximum: int = 128) -> bool:
    """Return whether an actor, task, bundle, or evidence kind is path-safe."""

    return bool(
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and value not in {".", ".."}
        and all(character.isalnum() or character in "._-" for character in value)
    )


def _is_git_object_id(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and 7 <= len(value) <= 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _regular_file_without_reparse(root: Path, relative: str) -> tuple[Path, int] | None:
    """Resolve a workspace file without traversing symlinks or reparse points."""

    if not isinstance(relative, str) or not relative:
        return None
    raw_components = relative.replace("\\", "/").split("/")
    if (
        relative.startswith(("/", "\\"))
        or any(component in {"", ".", ".."} for component in raw_components)
        or any(":" in component for component in raw_components)
        or Path(relative).drive
        or Path(relative).is_absolute()
    ):
        return None
    candidate = root.resolve()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    try:
        for component in Path(relative).parts:
            if component in {"", ".", ".."}:
                return None
            candidate = candidate / component
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or (
                int(getattr(metadata, "st_file_attributes", 0)) & reparse_flag
            ):
                return None
        metadata = candidate.lstat()
    except (FileNotFoundError, OSError):
        return None
    if not stat.S_ISREG(metadata.st_mode):
        return None
    return candidate, int(metadata.st_size)


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(getattr(metadata, "st_mtime_ns", 0)),
        int(getattr(metadata, "st_ctime_ns", 0)),
    )


def _path_handle_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    # Windows can expose slightly different timestamp precision through lstat
    # and fstat immediately after an fsync.  Device/inode/size bind the path to
    # the opened object; handle timestamps are still compared before/after.
    return (int(metadata.st_dev), int(metadata.st_ino), int(metadata.st_size))


def _hash_regular_file_without_reparse(
    root: Path,
    relative: str,
    *,
    maximum: int = MAX_AUDITED_EVIDENCE_BYTES,
) -> tuple[str, int] | None:
    """Hash a bounded regular file through one stable handle, fail closed on races."""

    candidate_record = _regular_file_without_reparse(root, relative)
    if candidate_record is None:
        return None
    candidate, declared_size = candidate_record
    if declared_size < 0 or declared_size > maximum:
        return None
    try:
        path_before = candidate.lstat()
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(candidate, flags)
    except OSError:
        return None
    try:
        handle_before = os.fstat(descriptor)
        before_identity = _stable_file_identity(handle_before)
        if (
            not stat.S_ISREG(handle_before.st_mode)
            or _path_handle_identity(handle_before) != _path_handle_identity(path_before)
            or handle_before.st_size > maximum
        ):
            return None
        digest = hashlib.sha256()
        observed_size = 0
        while True:
            remaining = maximum + 1 - observed_size
            if remaining <= 0:
                return None
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            observed_size += len(chunk)
            digest.update(chunk)
        handle_after = os.fstat(descriptor)
        try:
            path_after = candidate.lstat()
        except OSError:
            return None
        if (
            observed_size != handle_before.st_size
            or _stable_file_identity(handle_after) != before_identity
            or _path_handle_identity(path_after) != _path_handle_identity(handle_before)
            or _regular_file_without_reparse(root, relative) is None
        ):
            return None
        return digest.hexdigest(), observed_size
    finally:
        os.close(descriptor)


def _read_regular_file_without_reparse(
    root: Path,
    relative: str,
    *,
    maximum: int,
) -> tuple[bytes, str, int] | None:
    candidate_record = _regular_file_without_reparse(root, relative)
    if candidate_record is None:
        return None
    candidate, declared_size = candidate_record
    if declared_size < 0 or declared_size > maximum:
        return None
    try:
        path_before = candidate.lstat()
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(candidate, flags)
    except OSError:
        return None
    try:
        handle_before = os.fstat(descriptor)
        before_identity = _stable_file_identity(handle_before)
        if (
            not stat.S_ISREG(handle_before.st_mode)
            or _path_handle_identity(handle_before) != _path_handle_identity(path_before)
            or handle_before.st_size > maximum
        ):
            return None
        chunks: list[bytes] = []
        observed_size = 0
        while True:
            remaining = maximum + 1 - observed_size
            if remaining <= 0:
                return None
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            observed_size += len(chunk)
        handle_after = os.fstat(descriptor)
        try:
            path_after = candidate.lstat()
        except OSError:
            return None
        if (
            observed_size != handle_before.st_size
            or _stable_file_identity(handle_after) != before_identity
            or _path_handle_identity(path_after) != _path_handle_identity(handle_before)
            or _regular_file_without_reparse(root, relative) is None
        ):
            return None
        value = b"".join(chunks)
        return value, hashlib.sha256(value).hexdigest(), observed_size
    finally:
        os.close(descriptor)


def _ledger_evidence_references(
    root: Path,
    events: list[dict[str, Any]],
) -> tuple[dict[str, str], dict[str, int], list[str]]:
    """Extract only explicitly archived, identity-bound ledger evidence.

    ``reports/`` and ``runs/`` are mutable staging areas.  They are deliberately
    ignored even when a nested payload happens to contain a plausible path/hash
    pair.  Task evidence becomes truth only after archival under
    ``submissions/``; production release evidence is accepted only from the
    accountable conductor's exact collection event under ``archive/``.
    """

    references: dict[str, str] = {}
    reference_sizes: dict[str, int] = {}
    errors: list[str] = []

    def registered_orchestrator_producer() -> tuple[str, dict[str, Any]] | None:
        try:
            config = json.loads(
                (root / ".cogni" / "workspace.json").read_text(encoding="utf-8")
            )
            orchestrator = str(config["orchestrator"])
            agent = json.loads(
                (root / "agents" / f"{orchestrator}.json").read_text(
                    encoding="utf-8"
                )
            )
            if agent.get("id") != orchestrator or agent.get("role") != "orchestrator":
                return None
            identity = identity_snapshot(orchestrator, agent.get("identity"))
            if identity is None:
                return None
            return orchestrator, {**identity, "role": "orchestrator"}
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    registered_producer = registered_orchestrator_producer()

    def reject(event_index: int, reason: str) -> None:
        errors.append(f"event-{event_index}:{reason}")

    def record(
        event_index: int,
        path_value: Any,
        hash_value: Any,
        *,
        required_prefix: str,
        exact_path: str | None = None,
        allow_legacy_absolute: bool = False,
        size_bytes: int | None = None,
    ) -> str | None:
        relative = _workspace_relative_path(
            root,
            path_value,
            allow_legacy_absolute=allow_legacy_absolute,
        )
        if relative is None or not _is_sha256(hash_value):
            reject(event_index, "invalid-path-or-sha256")
            return None
        if not relative.startswith(required_prefix):
            reject(event_index, f"untrusted-root:{relative}")
            return None
        if exact_path is not None and relative != exact_path:
            reject(event_index, f"unexpected-path:{relative}")
            return None
        normalized_hash = str(hash_value).lower()
        observed = references.get(relative)
        if observed is not None and observed != normalized_hash:
            reject(event_index, f"conflicting-sha256:{relative}")
            return None
        references[relative] = normalized_hash
        if size_bytes is not None:
            observed_size = reference_sizes.get(relative)
            if observed_size is not None and observed_size != size_bytes:
                reject(event_index, f"conflicting-size:{relative}")
                return None
            reference_sizes[relative] = size_bytes
        return relative

    def task_context(
        event_index: int,
        event: dict[str, Any],
        action: str,
    ) -> tuple[str, str, int, dict[str, Any], dict[str, Any]] | None:
        actor = event.get("actor")
        task_id = event.get("task_id")
        payload = event.get("payload")
        if not _is_safe_ledger_component(actor):
            reject(event_index, f"{action}:invalid-actor")
            return None
        if not _is_safe_ledger_component(task_id):
            reject(event_index, f"{action}:invalid-task-id")
            return None
        if not isinstance(payload, dict) or not isinstance(payload.get("task"), dict):
            reject(event_index, f"{action}:missing-task-payload")
            return None
        task = payload["task"]
        if task.get("id") != task_id or not _is_positive_int(task.get("attempt")):
            reject(event_index, f"{action}:task-attempt-mismatch")
            return None
        attempt = int(task["attempt"])
        if action == "task.submitted":
            result = task.get("result")
            worker_identity = payload.get("worker_identity")
            if result is not None and not isinstance(result, dict):
                reject(event_index, f"{action}:invalid-result")
                return None
            if worker_identity is not None and (
                not isinstance(worker_identity, dict)
                or worker_identity.get("actor") != actor
            ):
                reject(event_index, f"{action}:worker-identity-mismatch")
                return None
            submitted_by = (result or {}).get("submitted_by")
            if task.get("owner") not in {None, actor} or submitted_by not in {
                None,
                actor,
            }:
                reject(event_index, f"{action}:actor-mismatch")
                return None
        else:
            verification = task.get("verification")
            verifier_identity = payload.get("verifier_identity")
            if verification is not None and not isinstance(verification, dict):
                reject(event_index, f"{action}:invalid-verification")
                return None
            if verifier_identity is not None and (
                not isinstance(verifier_identity, dict)
                or verifier_identity.get("actor") != actor
            ):
                reject(event_index, f"{action}:verifier-identity-mismatch")
                return None
            verified_by = (verification or {}).get("verified_by")
            if verified_by not in {None, actor}:
                reject(event_index, f"{action}:actor-mismatch")
                return None
        return str(actor), str(task_id), attempt, payload, task

    def task_bundle(
        event_index: int,
        *,
        task_id: str,
        attempt: int,
        label: str,
        bundle: Any,
        allowed_kinds: set[str],
    ) -> set[str]:
        if not isinstance(bundle, dict):
            reject(event_index, f"task.{label}:missing-bundle")
            return set()
        for field, expected in (
            ("task_id", task_id),
            ("attempt", attempt),
            ("label", label),
        ):
            # The first C:\comunity T-001 bundle predates these redundant
            # summary fields; when present they remain mandatory identity binds.
            if field in bundle and bundle.get(field) != expected:
                reject(event_index, f"task.{label}:bundle-{field}-mismatch")
        bundle_id = bundle.get("bundle_id")
        if not _is_safe_ledger_component(bundle_id) or not str(bundle_id).startswith(
            f"{label}-"
        ):
            reject(event_index, f"task.{label}:invalid-bundle-id")
            return set()
        bundle_root = (
            f"submissions/{task_id}/attempt-{attempt:03d}/{bundle_id}"
        )
        if "path" in bundle:
            observed_root = _workspace_relative_path(
                root,
                bundle.get("path"),
                allow_legacy_absolute=True,
            )
            if observed_root != bundle_root:
                reject(event_index, f"task.{label}:bundle-root-mismatch")
        record(
            event_index,
            bundle.get("manifest_path"),
            bundle.get("manifest_sha256"),
            required_prefix="submissions/",
            exact_path=f"{bundle_root}/bundle.json",
            allow_legacy_absolute=True,
            size_bytes=None,
        )
        files = bundle.get("files")
        if not isinstance(files, list):
            reject(event_index, f"task.{label}:invalid-files")
            return set()
        observed_kinds: set[str] = set()
        retained_count = 0
        external_count = 0
        for file_index, item in enumerate(files):
            if not isinstance(item, dict):
                reject(event_index, f"task.{label}:invalid-file-{file_index}")
                continue
            kind = item.get("kind")
            digest = item.get("sha256")
            size_bytes = item.get("size_bytes")
            retained = item.get("retained")
            if kind not in allowed_kinds or not _is_sha256(digest):
                reject(event_index, f"task.{label}:invalid-kind-or-sha-{file_index}")
                continue
            if (
                not isinstance(size_bytes, int)
                or isinstance(size_bytes, bool)
                or size_bytes < 0
                or not isinstance(retained, bool)
            ):
                reject(event_index, f"task.{label}:invalid-metadata-{file_index}")
                continue
            observed_kinds.add(str(kind))
            if retained:
                retained_count += 1
                relative = record(
                    event_index,
                    item.get("archive_path"),
                    digest,
                    required_prefix="submissions/",
                    allow_legacy_absolute=True,
                    size_bytes=size_bytes,
                )
                expected_prefix = f"{bundle_root}/files/{digest}_"
                if relative is not None and not relative.startswith(expected_prefix):
                    reject(event_index, f"task.{label}:archive-path-{file_index}")
                    references.pop(relative, None)
            else:
                external_count += 1
                if item.get("archive_path") is not None:
                    reject(event_index, f"task.{label}:external-path-{file_index}")
        if "manifest" not in observed_kinds:
            reject(event_index, f"task.{label}:missing-archived-manifest")
        if "retained" in bundle and bundle.get("retained") != retained_count:
            reject(event_index, f"task.{label}:retained-count-mismatch")
        if "external" in bundle and bundle.get("external") != external_count:
            reject(event_index, f"task.{label}:external-count-mismatch")
        return observed_kinds

    def release_collection(event_index: int, event: dict[str, Any]) -> None:
        expected_payload_keys = {
            "schema_version",
            "producer",
            "source_commit",
            "task_attempt",
            "collection",
        }
        payload = event.get("payload")
        if (
            not _is_safe_ledger_component(event.get("actor"))
            or event.get("task_id") != "P01-TRUTH"
            or not isinstance(payload, dict)
            or set(payload) != expected_payload_keys
        ):
            reject(event_index, "release:identity-or-payload-schema")
            return
        producer = payload.get("producer")
        if (
            payload.get("schema_version") != 1
            or not isinstance(producer, dict)
            or producer.get("schema_version") != 1
            or producer.get("actor") != event.get("actor")
            or producer.get("role") != "orchestrator"
            or not _is_safe_ledger_component(producer.get("control_principal"))
            or not _is_safe_ledger_component(producer.get("model_family"))
            or not _is_git_object_id(payload.get("source_commit"))
            or len(str(payload.get("source_commit"))) != 40
            or not _is_positive_int(payload.get("task_attempt"))
            or registered_producer is None
            or event.get("actor") != registered_producer[0]
            or producer != registered_producer[1]
        ):
            reject(event_index, "release:producer-commit-or-attempt")
            return
        collection = payload.get("collection")
        if not isinstance(collection, dict) or set(collection) != {
            "kind",
            "bundle_path",
            "bundle_sha256",
            "artifacts",
        }:
            reject(event_index, "release:collection-schema")
            return
        if collection.get("kind") != "production-release-evidence":
            reject(event_index, "release:collection-kind")
            return
        bundle_digest = collection.get("bundle_sha256")
        if not _is_sha256(bundle_digest):
            reject(event_index, "release:bundle-sha256")
            return
        collection_root = (
            "archive/release-evidence/P01-TRUTH/"
            f"attempt-{payload['task_attempt']}/{bundle_digest}"
        )
        bundle_relative = record(
            event_index,
            collection.get("bundle_path"),
            bundle_digest,
            required_prefix="archive/release-evidence/",
            exact_path=f"{collection_root}/bundle.json",
        )
        if bundle_relative is None:
            return
        artifacts = collection.get("artifacts")
        if not isinstance(artifacts, list) or len(artifacts) != len(
            RELEASE_ARTIFACT_FILES
        ):
            reject(event_index, "release:missing-artifacts")
            return
        kinds: set[str] = set()
        archive_paths: set[str] = {bundle_relative}
        for artifact_index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict) or set(artifact) != {
                "kind",
                "archive_path",
                "sha256",
                "size_bytes",
            }:
                reject(event_index, f"release:artifact-schema-{artifact_index}")
                continue
            kind = artifact.get("kind")
            size_bytes = artifact.get("size_bytes")
            expected_filename = RELEASE_ARTIFACT_FILES.get(str(kind))
            if (
                expected_filename is None
                or kind in kinds
                or not isinstance(size_bytes, int)
                or isinstance(size_bytes, bool)
                or size_bytes < 0
                or size_bytes > MAX_AUDITED_EVIDENCE_BYTES
            ):
                reject(event_index, f"release:artifact-metadata-{artifact_index}")
                continue
            kinds.add(str(kind))
            relative = record(
                event_index,
                artifact.get("archive_path"),
                artifact.get("sha256"),
                required_prefix="archive/release-evidence/",
                exact_path=f"{collection_root}/{expected_filename}",
                size_bytes=size_bytes,
            )
            if relative is None:
                continue
            artifact_path = Path(relative)
            if (
                artifact_path.parent.as_posix() != collection_root
                or artifact_path.name == "bundle.json"
                or relative in archive_paths
            ):
                reject(event_index, f"release:artifact-path-{artifact_index}")
                references.pop(relative, None)
                continue
            archive_paths.add(relative)

        if kinds != set(RELEASE_ARTIFACT_FILES):
            reject(event_index, "release:artifact-kind-set")

    for event_index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        action = event.get("action")
        if action == "release.evidence_collected":
            release_collection(event_index, event)
            continue
        if action not in {"task.submitted", "task.verified", "task.rejected"}:
            # verification.started may bind mutable verifier staging metadata,
            # but it is never a release-truth root.
            continue
        context = task_context(event_index, event, str(action))
        if context is None:
            continue
        _actor, task_id, attempt, payload, _task = context
        if action == "task.submitted":
            task_bundle(
                event_index,
                task_id=task_id,
                attempt=attempt,
                label="worker",
                bundle=payload.get("bundle"),
                allowed_kinds={"artifact", "manifest", "raw_output", "report"},
            )
            continue
        verifier_evidence = payload.get("verifier_evidence")
        if verifier_evidence is None:
            # Compatibility for the original signed C:\comunity T-001 event,
            # whose worker archive remains the only immutable evidence root.
            continue
        if not isinstance(verifier_evidence, dict):
            reject(event_index, f"{action}:invalid-verifier-evidence")
            continue
        observed_kinds = task_bundle(
            event_index,
            task_id=task_id,
            attempt=attempt,
            label="verifier",
            bundle=verifier_evidence.get("bundle"),
            allowed_kinds={
                "artifact",
                "manifest",
                "raw_output",
                "report",
                "trusted_runner_output",
                "trusted_runner_receipt",
            },
        )
        manifest_digest = verifier_evidence.get("manifest_sha256")
        verifier_bundle = verifier_evidence.get("bundle")
        bundle_files = (
            verifier_bundle.get("files", [])
            if isinstance(verifier_bundle, dict)
            else []
        )
        archived_manifests = {
            item.get("sha256")
            for item in bundle_files
            if isinstance(item, dict) and item.get("kind") == "manifest"
        }
        if not _is_sha256(manifest_digest) or manifest_digest not in archived_manifests:
            reject(event_index, f"{action}:verifier-manifest-mismatch")
        if payload.get("trusted_validation") is not None and not {
            "trusted_runner_receipt",
            "trusted_runner_output",
        }.issubset(observed_kinds):
            reject(event_index, f"{action}:trusted-output-not-archived")

    return references, reference_sizes, sorted(set(errors))


def release_deployment_binding(
    root: Path,
    events: list[dict[str, Any]],
    *,
    source_commit: str,
) -> dict[str, Any] | None:
    references, reference_sizes, errors = _ledger_evidence_references(root, events)
    if errors:
        return None
    for event in reversed(events):
        if event.get("action") != "release.evidence_collected":
            continue
        payload = event.get("payload")
        collection = payload.get("collection") if isinstance(payload, dict) else None
        if (
            not isinstance(collection, dict)
            or payload.get("source_commit") != source_commit
        ):
            continue
        artifact = next(
            (
                item
                for item in collection.get("artifacts", [])
                if isinstance(item, dict)
                and item.get("kind") == "cloudflare-deployment-evidence"
            ),
            None,
        )
        if not isinstance(artifact, dict):
            continue
        relative = _workspace_relative_path(root, artifact.get("archive_path"))
        if relative is None or references.get(relative) != artifact.get("sha256"):
            continue
        read = _read_regular_file_without_reparse(
            root,
            relative,
            maximum=MAX_DEPLOYMENT_EVIDENCE_BYTES,
        )
        if read is None:
            continue
        value, digest, size = read
        if (
            not hmac.compare_digest(digest, str(artifact.get("sha256")))
            or size != artifact.get("size_bytes")
            or reference_sizes.get(relative) != size
        ):
            continue
        try:
            document = json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(document, dict):
            continue
        alias = document.get("production_alias")
        alias_receipt = alias.get("api_request") if isinstance(alias, dict) else None
        deployment_receipt = document.get("api_request")
        latest_stage = document.get("latest_stage")
        trigger = document.get("trigger")
        deployment_id = document.get("deployment_id")
        deployment_url = document.get("url")
        if (
            document.get("document_type")
            != "cloudflare-pages-deployment-evidence"
            or document.get("attestation_level") != "CLOUDFLARE_API_VERIFIED"
            or document.get("provider") != "cloudflare-pages"
            or document.get("project_name") != "cogni-os-orchestrator"
            or document.get("environment") != "production"
            or document.get("source_commit") != source_commit
            or document.get("is_skipped") is not False
            or not isinstance(latest_stage, dict)
            or latest_stage.get("status") != "success"
            or not isinstance(trigger, dict)
            or trigger.get("branch") != "main"
            or trigger.get("commit_dirty") is not False
            or not _is_safe_ledger_component(deployment_id)
            or not isinstance(deployment_receipt, dict)
            or deployment_receipt.get("method") != "GET"
            or deployment_receipt.get("resource") != "pages-deployment"
            or deployment_receipt.get("tls_verified") is not True
            or deployment_receipt.get("response_status") != 200
            or not isinstance(alias, dict)
            or alias.get("api_verified") is not True
            or alias.get("canonical_url")
            != "https://cogni-os-orchestrator.pages.dev"
            or alias.get("deployment_id") != deployment_id
            or alias.get("deployment_url") != deployment_url
            or alias.get("source_commit") != source_commit
            or not isinstance(alias_receipt, dict)
            or alias_receipt.get("method") != "GET"
            or alias_receipt.get("resource") != "pages-project"
            or alias_receipt.get("tls_verified") is not True
            or alias_receipt.get("response_status") != 200
        ):
            continue
        try:
            parsed = urlsplit(str(deployment_url))
        except ValueError:
            continue
        hostname = (parsed.hostname or "").lower()
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or hostname == "cogni-os-orchestrator.pages.dev"
            or not hostname.endswith(".cogni-os-orchestrator.pages.dev")
        ):
            continue
        return {
            "provider": "cloudflare-pages",
            "api_verified": True,
            "deployment_id": str(deployment_id),
            "deployment_url": f"https://{hostname}",
            "canonical_url": "https://cogni-os-orchestrator.pages.dev",
            "source_commit": source_commit,
        }
    return None


def audit_operational_evidence(
    root: Path,
    events: list[dict[str, Any]],
    tree: dict[str, Any],
) -> dict[str, Any]:
    references, reference_sizes, conflicts = _ledger_evidence_references(root, events)
    unbound: list[str] = []
    mismatched: list[str] = []
    missing_or_unsafe: list[str] = []

    # Forward audit: every immutable ledger reference must still exist as the
    # same regular, non-reparse file.  This catches deletion even when Git no
    # longer reports an ignored archive path in the reverse inventory.
    for path, expected in sorted(references.items()):
        observed = _hash_regular_file_without_reparse(root, path)
        if observed is None:
            missing_or_unsafe.append(path)
            continue
        observed_hash, observed_size = observed
        if not hmac.compare_digest(observed_hash, expected):
            mismatched.append(path)
        expected_size = reference_sizes.get(path)
        if expected_size is not None and observed_size != expected_size:
            mismatched.append(path)

    # Reverse audit: every current immutable archive/submission file must have
    # an identity-bound ledger reference.  Mutable reports/runs are staging and
    # intentionally do not participate in release truth.
    for record in tree.get("operational_records", []):
        path = str(record.get("path", ""))
        if not path.startswith(("archive/", "submissions/")):
            continue
        expected = references.get(path)
        if expected is None:
            unbound.append(path)
        elif record.get("kind") != "file" or record.get("sha256") != expected:
            mismatched.append(path)
    mismatched = sorted(set(mismatched))
    missing_or_unsafe = sorted(set(missing_or_unsafe))
    unbound = sorted(set(unbound))
    audit_material = json.dumps(
        {
            "conflicts": conflicts,
            "mismatched": mismatched,
            "missing_or_unsafe": missing_or_unsafe,
            "reference_count": len(references),
            "references": sorted(references.items()),
            "unbound": unbound,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="surrogateescape")
    return {
        "valid": bool(
            not conflicts
            and not mismatched
            and not missing_or_unsafe
            and not unbound
        ),
        "reference_count": len(references),
        "conflict_count": len(conflicts),
        "missing_count": len(missing_or_unsafe),
        "unbound_count": len(unbound),
        "hash_mismatch_count": (
            len(mismatched) + len(missing_or_unsafe) + len(conflicts)
        ),
        "audit_fingerprint": hashlib.sha256(audit_material).hexdigest(),
    }


def export_tasks(
    tasks: list[dict[str, Any]],
    *,
    current_commit: str | None = None,
    workspace_root: Path | None = None,
    projection_secret: bytes | None = None,
) -> list[dict[str, Any]]:
    exported: list[dict[str, Any]] = []
    for task in tasks:
        trust = task_trust_projection(
            task,
            current_commit=current_commit,
            workspace_root=workspace_root,
        )
        historical_state = str(trust["historical_state"])
        current_release_state = str(trust["current_release_state"])
        measured_progress = task.get("measured_progress")
        if not isinstance(measured_progress, (int, float)) or not math.isfinite(
            float(measured_progress)
        ):
            measured_progress = (
                100 if trust.get("historical_trusted") is True else None
            )
        task_id = _public_task_id(task.get("id"), projection_secret)
        exported.append(
            {
                "id": task_id,
                "title": "Operational task",
                "owner": _public_alias(
                    "principal", task.get("owner", "unassigned"), projection_secret
                ),
                "state": historical_state,
                "raw_state": str(task.get("state", "unknown"))[:64],
                "historical_state": historical_state,
                "historical_trusted": bool(trust["historical_trusted"]),
                "verified_source_commit": trust["verified_source_commit"],
                "current_release_state": current_release_state,
                "current_release_validated": bool(
                    trust["current_release_validated"]
                ),
                "progress": measured_progress,
                "next_step": _next_step(current_release_state),
                "updated_at": str(task.get("updated_at") or utc_now()),
                "attempt": int(task.get("attempt", 0) or 0),
            }
        )
    return exported


def _next_step(state: str) -> str:
    return {
        "pending": "작업 선점 대기",
        "claimed": "실행 시작",
        "running": "증거 포함 구현 계속",
        "blocked": "차단 원인 해소",
        "submitted": "독립 검증 대기",
        "verified": "검증 증거 보관",
        "verification_disputed": "신뢰 실행기로 재검증",
        "verification_revoked": "폐기된 검증을 새 독립 증거로 대체",
        "rejected": "수정 후 재제출",
        "archived": "보관",
        "invalidated": "교정 태스크 생성",
    }.get(state, "상태 확인")


def task_summary(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(task["state"] for task in tasks)
    total = len(tasks)
    trusted_complete = sum(bool(task.get("historical_trusted")) for task in tasks)
    current_release_validated = sum(
        bool(task.get("current_release_validated")) for task in tasks
    )
    completion = (trusted_complete / total * 100.0) if total else None
    return {
        "total": total,
        "pending": counts["pending"],
        "claimed": counts["claimed"],
        "running": counts["running"],
        "blocked": counts["blocked"],
        "submitted": counts["submitted"],
        "trusted_verified": trusted_complete,
        "verification_disputed": counts["verification_disputed"],
        "verification_revoked": counts["verification_revoked"],
        "rejected": counts["rejected"],
        "current_release_validated": current_release_validated,
        "completion_percentage": round(completion, 1) if completion is not None else None,
        "progress_basis": "historically-trusted-ledger-task-states",
    }


def export_agents(
    workspace: Workspace,
    tasks: list[dict[str, Any]],
    commit: str,
    *,
    projection_secret: bytes | None = None,
) -> list[dict[str, Any]]:
    active_states = {"claimed", "running", "submitted"}
    result: list[dict[str, Any]] = []
    for path in sorted(workspace.agents_dir.glob("*.json")):
        try:
            agent = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        agent_id = str(agent.get("id", path.stem))
        current = next(
            (
                task
                for task in sorted(
                    tasks,
                    key=lambda item: str(item.get("updated_at", "")),
                    reverse=True,
                )
                if task.get("owner")
                == _public_alias("principal", agent_id, projection_secret)
                and task.get("current_release_state") in active_states
            ),
            None,
        )
        attestation = agent.get("runtime_attestation")
        status = "UNATTESTED"
        attestation_evidence_sha256 = None
        attested_at = None
        attested_source_commit = None
        if agent.get("mode") == "command" and agent.get("command"):
            status = "CONFIGURED"
        if isinstance(attestation, dict) and attestation.get("ready") is True:
            observed = _parse_timestamp(attestation.get("observed_at"))
            evidence_hash = str(attestation.get("evidence_sha256", "")).lower()
            commit_matches = attestation.get("source_commit") == commit
            evidence_valid = len(evidence_hash) == 64 and all(
                char in "0123456789abcdef" for char in evidence_hash
            )
            evidence_path_value = attestation.get("evidence_path")
            evidence_file_valid = False
            if isinstance(evidence_path_value, str) and evidence_path_value:
                candidate = (workspace.root / evidence_path_value).resolve()
                try:
                    candidate.relative_to(workspace.root.resolve())
                    evidence_file_valid = (
                        candidate.is_file() and _sha256_file(candidate) == evidence_hash
                    )
                except ValueError:
                    evidence_file_valid = False
            if (
                observed
                and 0 <= (datetime.now(timezone.utc) - observed).total_seconds() <= 90
                and evidence_valid
                and evidence_file_valid
                and commit_matches
            ):
                status = "READY"
                attestation_evidence_sha256 = evidence_hash
                attested_at = str(attestation.get("observed_at"))
                attested_source_commit = commit
        result.append(
            {
                "id": _public_alias("principal", agent_id, projection_secret),
                "role": _public_role(agent.get("role")),
                "status": status,
                "current_task": (
                    _public_task_id(current.get("id"), projection_secret)
                    if current
                    else None
                ),
                "task_progress": current.get("progress") if current else None,
                "next_step": current.get("next_step") if current else "실행 주체 attestation 대기",
                "mode": _public_mode(agent.get("mode")),
                "attestation_evidence_sha256": attestation_evidence_sha256,
                "attested_at": attested_at,
                "attested_source_commit": attested_source_commit,
            }
        )
    return result


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _finite_float(value: str, default: float = 0.0) -> float:
    try:
        parsed = float(value)
        return parsed if math.isfinite(parsed) else default
    except (TypeError, ValueError):
        return default


def _measurement_command(arguments: list[str], *, timeout: int = 8) -> str | None:
    try:
        if _PRODUCTION_EXECUTABLES:
            if not arguments:
                return None
            result = _run_production_binary(
                arguments[0], arguments[1:], timeout=timeout, text=True
            )
        else:
            result = _run_capped_command(
                arguments,
                timeout=timeout,
                text=True,
            )
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return None
    output = result.stdout
    if len(output.encode("utf-8", errors="replace")) > 2 * 1024 * 1024:
        return None
    return output


def _empty_gpu_boundary_receipt(state: str = "UNMEASURED") -> dict[str, Any]:
    return {
        "state": state,
        "issuer": None,
        "key_id": None,
        "observed_at": None,
        "expires_at": None,
        "evidence_sha256": None,
        "scope": [],
    }


def _gpu_boundary_attestation(
    workspace_id: str,
    *,
    now: datetime | None = None,
) -> tuple[str, set[int], dict[str, Any], dict[str, int]]:
    """Verify a signed external host boundary without inspecting GPU 6 or 7.

    The publisher is deliberately incapable of establishing full-host coverage.
    Only a short-lived HMAC document produced by the separately isolated host or
    scheduler authority can close this evidence source.
    """

    path_value = os.environ.get(GPU_BOUNDARY_ATTESTATION_ENV, "").strip()
    keyring_value = os.environ.get(GPU_BOUNDARY_KEYRING_ENV, "").strip()
    if not path_value or not keyring_value or not workspace_id:
        return (
            "UNAVAILABLE",
            set(),
            _empty_gpu_boundary_receipt(),
            {"container_claims": 0, "scheduler_reservations": 0},
        )
    try:
        path = Path(path_value)
        metadata = path.lstat()
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or bool(attributes & reparse_flag)
            or metadata.st_size < 2
            or metadata.st_size > GPU_BOUNDARY_MAX_BYTES
        ):
            raise ValueError("unsafe boundary attestation file")
        raw = path.read_bytes()
        if len(raw) != metadata.st_size:
            raise ValueError("boundary attestation changed during read")
        document = json.loads(raw.decode("utf-8"))
        keyring = json.loads(keyring_value)
        if not isinstance(document, dict) or not isinstance(keyring, dict):
            raise ValueError("boundary evidence must be objects")
        expected_keys = {
            "schema_version",
            "document_type",
            "workspace_id",
            "issuer",
            "key_id",
            "observed_at",
            "expires_at",
            "nonce",
            "scope",
            "allowed_ids",
            "denied_ids",
            "inventory_complete",
            "violating_ids",
            "container_claims",
            "scheduler_reservations",
            "signature",
        }
        if set(document) != expected_keys:
            raise ValueError("boundary evidence fields differ from contract")
        key_id = str(document["key_id"])
        secret = keyring.get(key_id)
        if (
            document["schema_version"] != 1
            or document["document_type"] != "cogni-gpu-boundary-attestation"
            or document["workspace_id"] != workspace_id
            or not isinstance(secret, str)
            or len(secret) < 32
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key_id)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", str(document["issuer"]))
            or not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", str(document["nonce"]))
            or document["scope"] != list(GPU_BOUNDARY_SCOPE)
            or document["allowed_ids"] != list(GPU_ALLOWED_IDS)
            or document["denied_ids"] != list(GPU_DENIED_IDS)
            or document["inventory_complete"] is not True
            or not isinstance(document["violating_ids"], list)
            or any(item not in GPU_DENIED_IDS for item in document["violating_ids"])
            or not isinstance(document["container_claims"], int)
            or isinstance(document["container_claims"], bool)
            or not 0 <= document["container_claims"] <= 1_000_000
            or not isinstance(document["scheduler_reservations"], int)
            or isinstance(document["scheduler_reservations"], bool)
            or not 0 <= document["scheduler_reservations"] <= 1_000_000
        ):
            raise ValueError("boundary evidence policy contract is invalid")
        signature = str(document["signature"])
        if not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
            raise ValueError("boundary evidence signature is invalid")
        signed = {key: value for key, value in document.items() if key != "signature"}
        message = b"COGNI-GPU-BOUNDARY-V1\n" + canonical_json(signed)
        expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature[7:], expected):
            raise ValueError("boundary evidence signature mismatch")
        observed = datetime.fromisoformat(str(document["observed_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(document["expires_at"]).replace("Z", "+00:00"))
        if observed.tzinfo is None or expires.tzinfo is None:
            raise ValueError("boundary timestamps must include timezone")
        current = now or datetime.now(timezone.utc)
        if (
            observed > current + timedelta(seconds=5)
            or expires < current
            or expires <= observed
            or (expires - observed).total_seconds() > GPU_BOUNDARY_MAX_LIFETIME_SECONDS
        ):
            raise ValueError("boundary evidence is stale")
        issuer_alias = "boundary-" + hmac.new(
            secret.encode("utf-8"),
            str(document["issuer"]).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:16]
        key_alias = "key-" + hmac.new(
            secret.encode("utf-8"), key_id.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:16]
        receipt = {
            "state": "VERIFIED",
            "issuer": issuer_alias,
            "key_id": key_alias,
            "observed_at": observed.astimezone(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            "expires_at": expires.astimezone(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "scope": list(GPU_BOUNDARY_SCOPE),
        }
        return (
            "MEASURED",
            set(document["violating_ids"]),
            receipt,
            {
                "container_claims": document["container_claims"],
                "scheduler_reservations": document["scheduler_reservations"],
            },
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        return (
            "UNAVAILABLE",
            set(),
            _empty_gpu_boundary_receipt("INVALID"),
            {"container_claims": 0, "scheduler_reservations": 0},
        )


def collect_gpus(
    enabled: bool,
    *,
    workspace_id: str = "",
) -> tuple[list[dict[str, Any]], str, list[int], dict[str, Any]]:
    if not enabled:
        return [], "UNMEASURED", [], {
            "measurement_complete": False,
            "source_states": {
                "telemetry": "DISABLED",
                "processes": "DISABLED",
                "containers": "DISABLED",
                "scheduler": "DISABLED",
                "boundary": "DISABLED",
            },
            "evidence_counts": {
                "processes": 0,
                "container_claims": 0,
                "scheduler_reservations": 0,
            },
            "boundary_attestation": _empty_gpu_boundary_receipt(),
        }
    gpus: list[dict[str, Any]] = []
    violating_ids: set[int] = set()
    uuid_to_id: dict[str, int] = {}
    telemetry_valid = True
    process_valid = True
    process_count = 0
    for requested_id in GPU_ALLOWED_IDS:
        telemetry_output = _measurement_command(
            [
                "nvidia-smi",
                f"--id={requested_id}",
                (
                    "--query-gpu=index,uuid,name,utilization.gpu,memory.used,"
                    "memory.total,temperature.gpu,power.draw"
                ),
                "--format=csv,noheader,nounits",
            ]
        )
        lines = [line for line in (telemetry_output or "").splitlines() if line.strip()]
        if len(lines) != 1:
            telemetry_valid = False
            continue
        fields = [field.strip() for field in lines[0].split(",")]
        if len(fields) != 8:
            telemetry_valid = False
            continue
        try:
            gpu_id = int(fields[0])
        except ValueError:
            telemetry_valid = False
            continue
        if gpu_id != requested_id or not fields[1] or fields[1] in uuid_to_id:
            telemetry_valid = False
            continue
        uuid_to_id[fields[1]] = gpu_id
        utilization = _finite_float(fields[3])
        memory_used_mib = _finite_float(fields[4])
        gpus.append(
            {
                "id": gpu_id,
                "name": fields[2][:256],
                "utilization": utilization,
                "vram_used_gib": round(memory_used_mib / 1024, 3),
                "vram_total_gib": round(_finite_float(fields[5]) / 1024, 3),
                "temperature_c": _finite_float(fields[6]),
                "power_w": _finite_float(fields[7]),
            }
        )
        process_output = _measurement_command(
            [
                "nvidia-smi",
                f"--id={requested_id}",
                "--query-compute-apps=gpu_uuid,pid,process_name,used_gpu_memory",
                "--format=csv,noheader,nounits",
            ]
        )
        if process_output is None:
            process_valid = False
            continue
        for line in process_output.splitlines():
            fields = [field.strip() for field in line.split(",", 3)]
            if not fields or fields[0].lower().startswith("no running"):
                continue
            if (
                len(fields) != 4
                or fields[0] not in uuid_to_id
                or uuid_to_id[fields[0]] != requested_id
                or not fields[1].isdigit()
            ):
                process_valid = False
                break
            process_count += 1

    telemetry_state = (
        "MEASURED"
        if telemetry_valid and set(uuid_to_id.values()) == set(GPU_ALLOWED_IDS)
        else "UNAVAILABLE"
    )
    process_state = "MEASURED" if process_valid and telemetry_state == "MEASURED" else "UNAVAILABLE"

    # Full-host container and scheduler discovery is deliberately delegated to
    # the separately isolated authority.  Running unfiltered docker/scheduler
    # discovery here would cross the GPU 0-5 collection boundary.  Only the
    # short-lived signed attestation may establish those source states, counts,
    # or forbidden-device claims.
    boundary_state, boundary_denied, boundary_receipt, boundary_counts = (
        _gpu_boundary_attestation(workspace_id)
    )
    violating_ids.update(boundary_denied)
    source_states = {
        "telemetry": telemetry_state,
        "processes": process_state,
        "containers": boundary_state,
        "scheduler": boundary_state,
        "boundary": boundary_state,
    }
    complete = all(value == "MEASURED" for value in source_states.values())
    state = (
        "POLICY_VIOLATION"
        if violating_ids
        else "MEASURED" if complete else "UNMEASURED"
    )
    evidence = {
        "measurement_complete": complete,
        "source_states": source_states,
        "evidence_counts": {
            "processes": process_count,
            "container_claims": boundary_counts["container_claims"],
            "scheduler_reservations": boundary_counts[
                "scheduler_reservations"
            ],
        },
        "boundary_attestation": boundary_receipt,
    }
    return (
        sorted(gpus, key=lambda item: item["id"]),
        state,
        sorted(violating_ids),
        evidence,
    )


def collect_resources(root: Path) -> dict[str, Any]:
    disk = shutil.disk_usage(root)
    resources: dict[str, Any] = {
        "disk": {
            "used_gib": round(disk.used / (1024**3), 2),
            "total_gib": round(disk.total / (1024**3), 2),
            "percent": round(disk.used / disk.total * 100, 1) if disk.total else None,
        },
        "memory": None,
        "load_average_1m": None,
        "uptime_seconds": None,
    }
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        values: dict[str, int] = {}
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            key, _, raw = line.partition(":")
            if raw:
                values[key] = int(raw.strip().split()[0]) * 1024
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        resources["memory"] = {
            "used_gib": round((total - available) / (1024**3), 2),
            "total_gib": round(total / (1024**3), 2),
            "percent": round((total - available) / total * 100, 1) if total else None,
        }
    try:
        resources["load_average_1m"] = round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):
        pass
    uptime = Path("/proc/uptime")
    if uptime.is_file():
        resources["uptime_seconds"] = int(float(uptime.read_text().split()[0]))
    return resources


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_gate(
    workspace: Workspace,
    commit: str,
    tasks: list[dict[str, Any]],
    ledger: dict[str, Any],
    tree: dict[str, Any],
    projection_audit: dict[str, Any],
    gpu_violations: list[int],
    *,
    gpu_telemetry_state: str | None = None,
    gpu_measurement: dict[str, Any] | None = None,
    release_deployment: dict[str, Any] | None = None,
    collector_commit: str | None = None,
    collector_tree: dict[str, Any] | None = None,
    operational_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Project the immutable release-gate event into the public snapshot.

    The authoritative PASS is produced by ``release_gate_status`` from a
    content-addressed contract and its signed ``release.gate_issued`` event.
    The publisher adds live collector, projection, and GPU policy checks, but
    never reads the retired tracked ``release/RELEASE_GATE.json`` file.
    """

    reasons: list[str] = []
    immutable_gate = release_gate_status(
        workspace,
        expected_source_commit=commit,
    )
    if immutable_gate.get("status") != "PASS":
        reasons.append(
            "현재 소스 커밋에 결합된 immutable release gate 검증이 "
            "완료되지 않았습니다."
        )
    if release_deployment is None:
        reasons.append(
            "canonical production alias와 Cloudflare deployment 결합 증거가 없습니다."
        )
    if any(
        task.get("current_release_state")
        in {"verification_disputed", "verification_revoked"}
        for task in tasks
    ):
        reasons.append("증거가 부족한 VERIFIED 태스크가 있습니다.")
    if any(
        task.get("current_release_state") not in {"verified", "archived"}
        for task in tasks
    ):
        reasons.append("모든 릴리스 태스크가 신뢰 검증을 완료하지 않았습니다.")
    if not ledger.get("valid") or not ledger.get("signed"):
        reasons.append("원장이 서명 검증을 통과하지 않았습니다.")
    if not tree.get("clean"):
        reasons.append("소스 트리에 커밋되지 않은 변경이 있습니다.")
    if collector_commit in {None, "unknown"}:
        reasons.append("수집기 제어면 커밋을 확인할 수 없습니다.")
    elif collector_commit != commit:
        reasons.append("운영 워크스페이스와 수집기 제어면 커밋이 다릅니다.")
    if not collector_tree or not collector_tree.get("clean"):
        reasons.append("수집기 제어면 소스 트리가 깨끗하지 않습니다.")
    if not operational_state or not operational_state.get("valid"):
        reasons.append("운영 증거 변경의 원장·projection 검증이 완료되지 않았습니다.")
    if not projection_audit.get("valid"):
        reasons.append("태스크 원장과 projection 파일이 일치하지 않습니다.")
    if (
        gpu_telemetry_state != "MEASURED"
        or not gpu_measurement
        or gpu_measurement.get("measurement_complete") is not True
    ):
        reasons.append(
            "GPU 프로세스·컨테이너·스케줄러 예약 증거가 완전 측정되지 않았습니다."
        )
    if gpu_violations:
        reasons.append(
            "사용 금지 GPU가 활성 상태입니다: "
            + ", ".join(f"GPU {gpu_id}" for gpu_id in gpu_violations)
        )
    evidence_hash = immutable_gate.get("contract_sha256")
    return {
        "status": "PASS" if not reasons else "NO_GO",
        "reasons": reasons,
        "evidence_sha256": (
            str(evidence_hash).lower()
            if not reasons and isinstance(evidence_hash, str)
            else None
        ),
    }


def build_snapshot(
    workspace: Workspace,
    *,
    sequence: int,
    include_gpu: bool,
) -> dict[str, Any]:
    observed_at = utc_now()
    raw_tasks = workspace.list_tasks()
    ledger = workspace.ledger.verify()
    events = workspace.ledger.read()
    commit = git_commit(workspace.root)
    collector_root = Path(__file__).resolve().parents[1]
    collector_commit = git_commit(collector_root)
    collector_tree = git_tree_status(collector_root)
    projection_secret = _projection_secret()
    tasks = export_tasks(
        raw_tasks,
        current_commit=commit,
        workspace_root=workspace.root,
        projection_secret=projection_secret,
    )
    tree = git_tree_status(workspace.root)
    raw_projection_audit = workspace.audit_projections()
    projection_audit = {
        "valid": bool(raw_projection_audit.get("valid")),
        "events_count": int(raw_projection_audit.get("events_count", 0) or 0),
        "projected_count": int(raw_projection_audit.get("projected_count", 0) or 0),
        "actual_count": int(raw_projection_audit.get("actual_count", 0) or 0),
        "mismatch_count": len(raw_projection_audit.get("mismatches", []) or []),
    }
    evidence_audit = audit_operational_evidence(workspace.root, events, tree)
    release_deployment = release_deployment_binding(
        workspace.root,
        events,
        source_commit=commit,
    )
    operational_state = {
        "valid": bool(
            ledger.get("valid")
            and ledger.get("signed")
            and projection_audit.get("valid")
            and evidence_audit.get("valid")
            and int(tree.get("unclassified_change_count", 1)) == 0
        ),
        "change_count": int(tree["operational_change_count"]),
        "fingerprint": str(tree["operational_fingerprint"]),
        "unclassified_count": int(tree.get("unclassified_change_count", 0)),
        "unclassified_fingerprint": str(tree["unclassified_fingerprint"]),
        "reference_count": int(evidence_audit["reference_count"]),
        "conflict_count": int(evidence_audit["conflict_count"]),
        "missing_count": int(evidence_audit["missing_count"]),
        "unbound_count": int(evidence_audit["unbound_count"]),
        "hash_mismatch_count": int(evidence_audit["hash_mismatch_count"]),
        "audit_fingerprint": str(evidence_audit["audit_fingerprint"]),
    }
    agents = export_agents(
        workspace,
        tasks,
        commit,
        projection_secret=projection_secret,
    )
    gpus, telemetry_state, gpu_violations, gpu_measurement = collect_gpus(
        include_gpu,
        workspace_id=str(workspace.config["workspace_id"]),
    )
    gate = release_gate(
        workspace,
        commit,
        tasks,
        ledger,
        tree,
        projection_audit,
        gpu_violations,
        gpu_telemetry_state=telemetry_state,
        gpu_measurement=gpu_measurement,
        release_deployment=release_deployment,
        collector_commit=collector_commit,
        collector_tree=collector_tree,
        operational_state=operational_state,
    )
    alerts: list[dict[str, Any]] = []
    disputed = [
        task["id"]
        for task in tasks
        if task.get("current_release_state")
        in {"verification_disputed", "verification_revoked"}
    ]
    if disputed:
        alerts.append(
            {
                "severity": "critical",
                "code": "UNTRUSTED_VERIFICATION",
                "message": "독립 재현 증거가 없는 VERIFIED 태스크: " + ", ".join(disputed),
                "observed_at": observed_at,
            }
        )
    if gpu_violations:
        alerts.append(
            {
                "severity": "critical",
                "code": "GPU_POLICY_VIOLATION",
                "message": "사용 금지 GPU가 활성 상태입니다: "
                + ", ".join(f"GPU {gpu_id}" for gpu_id in gpu_violations),
                "observed_at": observed_at,
            }
        )
    if not tree["clean"]:
        alerts.append(
            {
                "severity": "critical",
                "code": "DIRTY_SOURCE_TREE",
                "message": "커밋되지 않은 소스 변경 때문에 릴리스 증거가 무효입니다.",
                "observed_at": observed_at,
            }
        )
    if telemetry_state != "MEASURED":
        alerts.append(
            {
                "severity": "critical",
                "code": "GPU_EVIDENCE_UNMEASURED",
                "message": (
                    "GPU 프로세스·컨테이너·스케줄러 예약 증거가 완전 측정되지 "
                    "않아 릴리스 게이트를 닫았습니다."
                ),
                "observed_at": observed_at,
            }
        )
    if collector_commit != commit:
        alerts.append(
            {
                "severity": "critical",
                "code": "PROVENANCE_COMMIT_MISMATCH",
                "message": "운영 워크스페이스와 수집기 제어면 커밋이 일치하지 않습니다.",
                "observed_at": observed_at,
            }
        )
    if not collector_tree["clean"]:
        alerts.append(
            {
                "severity": "critical",
                "code": "DIRTY_COLLECTOR_SOURCE",
                "message": "수집기 제어면에 커밋되지 않은 소스 변경이 있습니다.",
                "observed_at": observed_at,
            }
        )
    if not operational_state["valid"]:
        alerts.append(
            {
                "severity": "critical",
                "code": "UNVERIFIED_OPERATIONAL_STATE",
                "message": "운영 증거 변경이 원장·projection 정책을 통과하지 못했습니다.",
                "observed_at": observed_at,
            }
        )
    resources = collect_resources(workspace.root)
    disk = resources.get("disk") or {}
    if isinstance(disk.get("percent"), (int, float)) and disk["percent"] >= 90:
        alerts.append(
            {
                "severity": "warning",
                "code": "DISK_PRESSURE",
                "message": f"저장공간 사용률 {disk['percent']}%",
                "observed_at": observed_at,
            }
        )
    title_by_id = {task["id"]: task["title"] for task in tasks}
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "system": "Cogni-OS Operations",
        "workspace_id": str(workspace.config["workspace_id"]),
        "workspace_name": "Cogni-OS Evidence Operations",
        "sequence": sequence,
        "observed_at": observed_at,
        "collector": {
            "id": "cogni-monitor-publisher",
            "version": COLLECTOR_VERSION,
            "host": collector_host_id(
                str(workspace.config["workspace_id"]), projection_secret
            ),
            "platform": platform.system(),
            "attribution": {
                "source_commit": collector_commit,
                "source_tree_clean": bool(collector_tree["clean"]),
                "source_tree_fingerprint": str(collector_tree["fingerprint"]),
                "entrypoint_sha256": _sha256_file(Path(__file__).resolve()),
            },
        },
        "data_classification": "operational-metadata-only",
        "orchestrator": {
            "id": _public_alias(
                "principal", workspace.orchestrator, projection_secret
            ),
            "role": "conductor",
            "status": "ACCOUNTABLE_NOT_ATTESTED",
        },
        "tasks_summary": task_summary(tasks),
        "roadmap": roadmap_snapshot(tasks),
        "agents": agents,
        "tasks": tasks,
        "ledger_events": [
            {
                "timestamp": event.get("timestamp"),
                "actor": _public_alias(
                    "principal", event.get("actor", "unknown"), projection_secret
                ),
                "action": _public_action(event.get("action")),
                "task_id": (
                    _public_task_id(event.get("task_id"), projection_secret)
                    if event.get("task_id") is not None
                    else None
                ),
                "task_title": title_by_id.get(
                    _public_task_id(event.get("task_id"), projection_secret)
                ),
                "event_hash": _public_digest(
                    "event", event.get("event_hash"), projection_secret
                ),
            }
            for event in events[-100:]
        ],
        "ledger": {
            "status": "VERIFIED" if ledger["valid"] else "NOT_VERIFIED",
            "valid": bool(ledger["valid"]),
            "events": int(ledger["events"]),
            "head": str(ledger["head"]),
            "signed": bool(ledger.get("signed", False)),
        },
        "gpus": gpus,
        "gpu_policy": {
            "allowed_ids": [0, 1, 2, 3, 4, 5],
            "denied_ids": [6, 7],
            "telemetry_state": telemetry_state,
            "violating_ids": gpu_violations,
            **gpu_measurement,
        },
        "resources": resources,
        "alerts": alerts,
        "release_gate": gate,
        "release_deployment": release_deployment,
        "source": {
            "git_commit": commit,
            "status_scope": "trusted-source-v1",
            "tree_clean": bool(tree["clean"]),
            "tree_fingerprint": str(tree["fingerprint"]),
            "change_count": int(tree["change_count"]),
            "operational_state": operational_state,
            "task_projection_audit": projection_audit,
        },
    }


def _state_path(workspace: Workspace, state_dir: Path | None = None) -> Path:
    root = state_dir if state_dir is not None else workspace.control_dir
    return root / "monitor_publish_state.json"


def next_sequence(
    workspace: Workspace,
    *,
    state_dir: Path | None = None,
) -> int:
    state_path = _state_path(workspace, state_dir)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    sequence = peek_next_sequence(workspace, state_dir=state_dir)
    temporary = state_path.with_suffix(f".tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(
            {"last_sequence": sequence, "reserved_at": utc_now()},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, state_path)
    return sequence


def peek_next_sequence(
    workspace: Workspace,
    *,
    state_dir: Path | None = None,
) -> int:
    """Read the next sequence without mutating the workspace."""

    state_path = _state_path(workspace, state_dir)
    try:
        current = json.loads(state_path.read_text(encoding="utf-8"))
        return int(current.get("last_sequence", 0)) + 1
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 1


def _validate_ingest_acknowledgement(
    *,
    status: int,
    payload: Any,
    response_headers: Any,
    snapshot: dict[str, Any],
    body_sha256: str,
    request_started_at: datetime,
    response_received_at: datetime,
) -> dict[str, Any]:
    """Fail closed unless the server ACK binds to the exact submitted snapshot."""

    if status != 202:
        raise RuntimeError(f"ingest rejected with HTTP {status}")
    if not isinstance(payload, dict) or set(payload) != {"ok", "accepted"}:
        raise RuntimeError("ingest acknowledgement has an unexpected envelope")
    if payload["ok"] is not True or not isinstance(payload["accepted"], dict):
        raise RuntimeError("ingest acknowledgement did not accept the snapshot")

    accepted = payload["accepted"]
    expected_keys = {
        "workspace_id",
        "sequence",
        "observed_at",
        "received_at",
        "body_sha256",
        "signature_verified",
    }
    if set(accepted) != expected_keys:
        raise RuntimeError("ingest acknowledgement has an unexpected accepted schema")
    if type(accepted["workspace_id"]) is not str or accepted["workspace_id"] != snapshot[
        "workspace_id"
    ]:
        raise RuntimeError("ingest acknowledgement workspace does not match the request")
    if type(accepted["sequence"]) is not int or accepted["sequence"] != snapshot[
        "sequence"
    ]:
        raise RuntimeError("ingest acknowledgement sequence does not match the request")
    if type(accepted["observed_at"]) is not str or accepted["observed_at"] != snapshot[
        "observed_at"
    ]:
        raise RuntimeError("ingest acknowledgement timestamp does not match the request")
    if (
        type(accepted["body_sha256"]) is not str
        or accepted["body_sha256"] != body_sha256
    ):
        raise RuntimeError("ingest acknowledgement digest does not match the request")
    if accepted["signature_verified"] is not True:
        raise RuntimeError("ingest acknowledgement did not verify the signature")

    received_at_text = accepted["received_at"]
    received_at = _parse_timestamp(received_at_text)
    if (
        type(received_at_text) is not str
        or ACK_RECEIVED_AT_PATTERN.fullmatch(received_at_text) is None
        or received_at is None
        or received_at.tzinfo is None
        or received_at.utcoffset() != timedelta(0)
    ):
        raise RuntimeError("ingest acknowledgement has an invalid UTC receipt timestamp")
    for boundary in (request_started_at, response_received_at):
        if boundary.tzinfo is None or boundary.utcoffset() is None:
            raise RuntimeError("publisher receipt boundary must include a timezone")
    request_started_at = request_started_at.astimezone(timezone.utc)
    response_received_at = response_received_at.astimezone(timezone.utc)
    observed_at = _parse_timestamp(snapshot["observed_at"])
    if observed_at is None or observed_at.tzinfo is None:
        raise RuntimeError("submitted snapshot timestamp must include a timezone")
    observed_at = observed_at.astimezone(timezone.utc)
    clock_skew = timedelta(seconds=ACK_CLOCK_SKEW_SECONDS)
    if (
        response_received_at < request_started_at
        or received_at < request_started_at - clock_skew
        or received_at > response_received_at + clock_skew
        or received_at < observed_at - clock_skew
    ):
        raise RuntimeError("ingest acknowledgement receipt time is outside the request window")

    if response_headers.get("X-Cogni-Sequence") != str(snapshot["sequence"]):
        raise RuntimeError("ingest acknowledgement sequence header does not match")
    if response_headers.get("X-Cogni-Body-SHA256") != body_sha256:
        raise RuntimeError("ingest acknowledgement digest header does not match")
    return payload


def _reject_duplicate_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON member in ingest acknowledgement")
        document[key] = value
    return document


def publish(
    *,
    endpoint: str,
    allowed_hosts: set[str] | None = None,
    key_id: str,
    secret: str,
    snapshot: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    endpoint = validate_publish_endpoint(
        endpoint,
        allowed_hosts=allowed_hosts,
    )
    if not math.isfinite(timeout) or timeout < 1 or timeout > 60:
        raise RuntimeError("Publisher timeout must be between 1 and 60 seconds")
    body = canonical_json(snapshot)
    body_sha256 = hashlib.sha256(body).hexdigest()
    nonce = secrets.token_urlsafe(24)
    message = signature_message(
        key_id=key_id,
        workspace_id=snapshot["workspace_id"],
        sequence=snapshot["sequence"],
        observed_at=snapshot["observed_at"],
        nonce=nonce,
        body_sha256=body_sha256,
    )
    signature = hmac_signature(secret, message)
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": f"Cogni-Monitor-Publisher/{COLLECTOR_VERSION}",
            "X-Cogni-Key-Id": key_id,
            "X-Cogni-Workspace": snapshot["workspace_id"],
            "X-Cogni-Sequence": str(snapshot["sequence"]),
            "X-Cogni-Observed-At": snapshot["observed_at"],
            "X-Cogni-Nonce": nonce,
            "X-Cogni-Signature": f"sha256={signature}",
        },
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    request_started_at = datetime.now(timezone.utc)
    try:
        with opener.open(request, timeout=timeout) as response:
            response_bytes = response.read(64 * 1024 + 1)
            response_received_at = datetime.now(timezone.utc)
            if len(response_bytes) > 64 * 1024:
                raise RuntimeError("ingest response exceeded the 64 KiB limit")
            try:
                payload = json.loads(
                    response_bytes.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_json_members,
                )
            except (UnicodeDecodeError, ValueError) as error:
                raise RuntimeError(
                    "ingest acknowledgement was not valid UTF-8 JSON"
                ) from error
            return _validate_ingest_acknowledgement(
                status=response.status,
                payload=payload,
                response_headers=response.headers,
                snapshot=snapshot,
                body_sha256=body_sha256,
                request_started_at=request_started_at,
                response_received_at=response_received_at,
            )
    except urllib.error.HTTPError as error:
        body_text = error.read().decode("utf-8", errors="replace")[:2048]
        raise RuntimeError(f"ingest failed HTTP {error.code}: {body_text}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"ingest connection failed: {error.reason}") from error


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Publish a signed Cogni-OS monitoring snapshot.",
    )
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument(
        "--allowed-endpoint-host",
        action="append",
        default=[],
        help=(
            "Explicit additional HTTPS hostname allowed to receive operational "
            "metadata. The production Pages host is always allowed."
        ),
    )
    parser.add_argument(
        "--secret-env",
        default="COGNI_MONITOR_INGEST_SECRET",
        help="Environment variable that holds the HMAC secret.",
    )
    parser.add_argument(
        "--key-id",
        default=os.environ.get("COGNI_MONITOR_KEY_ID", ""),
        help="Publisher key id registered in the Cloudflare secret keyring.",
    )
    parser.add_argument("--include-gpu", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--state-dir",
        type=Path,
        help=(
            "Writable publisher-only sequence and lock directory. "
            "Defaults to the Cogni workspace control directory."
        ),
    )
    parser.add_argument("--interval-seconds", type=float, default=0.0)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    parser.add_argument(
        "--max-backoff-seconds",
        type=float,
        default=300.0,
        help="Maximum retry delay after consecutive publish failures.",
    )
    return parser.parse_args(argv)


def run_once(
    args: argparse.Namespace,
    workspace: Workspace,
) -> dict[str, Any]:
    _assert_production_source_state()
    if args.dry_run:
        snapshot = build_snapshot(
            workspace,
            sequence=peek_next_sequence(
                workspace,
                state_dir=args.state_dir,
            ),
            include_gpu=args.include_gpu,
        )
        print(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return {
            "accepted": {
                "sequence": snapshot["sequence"],
                "body_sha256": hashlib.sha256(
                    canonical_json(snapshot)
                ).hexdigest(),
            },
            "dry_run": True,
        }
    lock_root = args.state_dir or workspace.control_dir
    with FileLock(lock_root / "locks" / "monitor-publisher.lock"):
        sequence = next_sequence(
            workspace,
            state_dir=args.state_dir,
        )
        snapshot = build_snapshot(
            workspace,
            sequence=sequence,
            include_gpu=args.include_gpu,
        )
    secret = os.environ.get(args.secret_env, "")
    if len(secret) < 32:
        raise RuntimeError(
            f"{args.secret_env} must contain an HMAC secret of at least 32 characters"
        )
    if (
        not 3 <= len(args.key_id) <= 64
        or any(
            not (char.isalnum() or char in "._:-")
            for char in args.key_id
        )
    ):
        raise RuntimeError(
            "--key-id or COGNI_MONITOR_KEY_ID must be a safe 3-64 character id"
        )
    accepted = publish(
        endpoint=args.endpoint,
        allowed_hosts={
            DEFAULT_ENDPOINT_HOST,
            *args.allowed_endpoint_host,
        },
        key_id=args.key_id,
        secret=secret,
        snapshot=snapshot,
        timeout=args.timeout_seconds,
    )
    _assert_production_source_state()
    for executable_name in _PRODUCTION_EXECUTABLES:
        _verify_production_executable(executable_name)
    acknowledgement = accepted["accepted"]
    print(
        "accepted "
        f"sequence={acknowledgement['sequence']} "
        f"sha256={acknowledgement['body_sha256']}"
    )
    return accepted


def _validate_runtime_args(args: argparse.Namespace) -> None:
    numeric = (
        ("--interval-seconds", args.interval_seconds, 0.0, 3600.0),
        ("--timeout-seconds", args.timeout_seconds, 1.0, 60.0),
        ("--max-backoff-seconds", args.max_backoff_seconds, 5.0, 3600.0),
    )
    for label, value, lower, upper in numeric:
        if not math.isfinite(value) or value < lower or value > upper:
            raise RuntimeError(
                f"{label} must be between {lower:g} and {upper:g} seconds"
            )
    if (
        args.interval_seconds > 0
        and args.max_backoff_seconds < max(5.0, args.interval_seconds)
    ):
        raise RuntimeError(
            "--max-backoff-seconds cannot be lower than the publish interval"
        )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    _validate_runtime_args(args)
    _configure_production_runtime(args)
    workspace = Workspace(args.workspace.resolve())
    state_dir = (args.state_dir or workspace.control_dir).resolve()
    instance_lock = PublisherInstanceLock(
        state_dir / "locks" / "monitor-publisher.instance.lock"
    )
    try:
        instance_lock.acquire()
    except PublisherAlreadyRunning as error:
        append_runtime_journal(
            state_dir,
            "duplicate_instance_rejected",
            error=sanitize_error(error),
        )
        print(f"monitor publisher not started: {error}", file=sys.stderr)
        # EX_TEMPFAIL keeps a supervised process eligible for restart after
        # the prior instance exits (for example, during a task replacement).
        return 75

    consecutive_failures = 0
    last_success_at: str | None = None
    last_error_message: str | None = None
    secret = os.environ.get(args.secret_env, "")
    supervisor_pid = os.getppid() if args.interval_seconds > 0 else 0
    append_runtime_journal(
        state_dir,
        "publisher_started",
        workspace_id=str(workspace.config["workspace_id"]),
        interval_seconds=args.interval_seconds,
        max_backoff_seconds=args.max_backoff_seconds,
        gpu_telemetry="ENABLED" if args.include_gpu else "DISABLED",
        supervisor_pid=supervisor_pid or None,
    )
    write_runtime_state(
        state_dir,
        status="STARTING",
        consecutive_failures=0,
        last_success_at=None,
        next_retry_at=None,
    )
    exit_code = 0
    try:
        while True:
            if supervisor_pid and not process_is_alive(supervisor_pid):
                append_runtime_journal(
                    state_dir,
                    "supervisor_lost",
                    supervisor_pid=supervisor_pid,
                )
                break
            delay_seconds = max(5.0, args.interval_seconds)
            try:
                accepted = run_once(args, workspace)
                acknowledgement = accepted["accepted"]
                consecutive_failures = 0
                last_error_message = None
                if not args.dry_run:
                    last_success_at = utc_now()
                append_runtime_journal(
                    state_dir,
                    "snapshot_accepted" if not args.dry_run else "dry_run_complete",
                    sequence=acknowledgement["sequence"],
                    body_sha256=acknowledgement["body_sha256"],
                )
                next_retry_at = (
                    utc_after(delay_seconds)
                    if args.interval_seconds > 0
                    else None
                )
                write_runtime_state(
                    state_dir,
                    status="HEALTHY" if not args.dry_run else "DRY_RUN",
                    consecutive_failures=0,
                    last_success_at=last_success_at,
                    next_retry_at=next_retry_at,
                )
            except KeyboardInterrupt:
                exit_code = 130
                break
            except Exception as error:
                consecutive_failures += 1
                error_message = sanitize_error(error, secret=secret)
                last_error_message = error_message
                print(
                    f"monitor publisher error: {error_message}",
                    file=sys.stderr,
                )
                append_runtime_journal(
                    state_dir,
                    "publish_failed",
                    consecutive_failures=consecutive_failures,
                    error_type=type(error).__name__,
                    error=error_message,
                )
                if args.interval_seconds <= 0:
                    write_runtime_state(
                        state_dir,
                        status="FAILED",
                        consecutive_failures=consecutive_failures,
                        last_success_at=last_success_at,
                        next_retry_at=None,
                        last_error=error_message,
                    )
                    exit_code = 1
                    break
                delay_seconds = compute_backoff_seconds(
                    args.interval_seconds,
                    consecutive_failures,
                    args.max_backoff_seconds,
                )
                next_retry_at = utc_after(delay_seconds)
                append_runtime_journal(
                    state_dir,
                    "retry_scheduled",
                    consecutive_failures=consecutive_failures,
                    delay_seconds=delay_seconds,
                    next_retry_at=next_retry_at,
                )
                write_runtime_state(
                    state_dir,
                    status="BACKOFF",
                    consecutive_failures=consecutive_failures,
                    last_success_at=last_success_at,
                    next_retry_at=next_retry_at,
                    last_error=error_message,
                )
            if args.interval_seconds <= 0:
                break
            if not wait_for_supervisor(delay_seconds, supervisor_pid):
                append_runtime_journal(
                    state_dir,
                    "supervisor_lost",
                    supervisor_pid=supervisor_pid,
                )
                break
    finally:
        append_runtime_journal(
            state_dir,
            "publisher_stopped",
            exit_code=exit_code,
            consecutive_failures=consecutive_failures,
        )
        write_runtime_state(
            state_dir,
            status="STOPPED" if exit_code == 0 else "FAILED",
            consecutive_failures=consecutive_failures,
            last_success_at=last_success_at,
            next_retry_at=None,
            last_error=last_error_message,
        )
        instance_lock.release()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
