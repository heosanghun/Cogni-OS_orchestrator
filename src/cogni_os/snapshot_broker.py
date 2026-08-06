"""Privileged POSIX snapshot broker and unprivileged FD-lease client.

The production entrypoint is Linux-only.  The daemon must run as uid 0, uses
``SO_PEERCRED`` for caller identity, copies a caller-materialized sealed source
directory through a received descriptor into a fixed root-owned store, and
passes an ``O_PATH`` snapshot descriptor with ``SCM_RIGHTS``.  The root daemon
never imports or executes Git and does not attest source authenticity.  Only
the daemon may remove the copied tree; successful removal is returned as a
separately signed cleanup acknowledgement.
"""

from __future__ import annotations

import argparse
import array
import errno
import hashlib
import json
import os
import secrets
import socket
import stat
import struct
import sys
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # pragma: no cover - imported only on POSIX production hosts
    import fcntl
    import grp
    import pwd
except ImportError:  # Windows is an explicit NO_GO platform.
    fcntl = None  # type: ignore[assignment]
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

from .errors import EvidenceError
from .snapshot_broker_protocol import (
    ACQUIRE_RESPONSE_KEYS,
    BROKER_DESCRIPTOR_TYPE,
    BROKER_LEASE_ROOT,
    BROKER_LOCK_PATH,
    BROKER_NONCE_ROOT,
    BROKER_PROTOCOL_ID,
    BROKER_SCHEMA_VERSION,
    BROKER_SOCKET_PATH,
    BROKER_SOURCE_DESCRIPTOR_TYPE,
    BROKER_STORE_ROOT,
    ERROR_RESPONSE_KEYS,
    MAX_BROKER_ERROR_MESSAGE_BYTES,
    MAX_BROKER_FRAME_BYTES,
    RELEASE_RESPONSE_KEYS,
    SNAPSHOT_MATERIALIZATION_POLICY_ID,
    SnapshotBrokerError,
    canonical_json_bytes,
    canonical_json_sha256,
    decode_frame_from_stream,
    encode_frame,
    sign_payload,
    trusted_broker_runtime_binding,
    validate_request,
    verify_signed_envelope,
)

MAX_ACTIVE_BROKER_LEASES = 64
MAX_REPLAY_FILES_SCANNED = 4096
MAX_NONCES_PER_UID = 256
MAX_NONCES_TOTAL = 4096
MAX_NONCE_UID_DIRECTORIES = 1024
BROKER_LEASE_TTL_SECONDS = 3600
BROKER_CONNECTION_TIMEOUT_SECONDS = 5
MAX_BROKER_CONNECTION_WORKERS = 8
MAX_BROKER_PENDING_CONNECTIONS = 16
MAX_PERSISTED_LEASE_FILES = MAX_ACTIVE_BROKER_LEASES * 2
MAX_CLEANUP_TOMBSTONES = MAX_ACTIVE_BROKER_LEASES * 2
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_ENTRY_COUNT = 50_000
MAX_SOURCE_TREE_NODE_COUNT = MAX_SOURCE_ENTRY_COUNT * 2 + 1
MAX_SOURCE_PATH_BYTES = 4_096
MAX_SOURCE_PATH_BYTES_TOTAL = 32 * 1024 * 1024
SOURCE_COPY_CHUNK_BYTES = 64 * 1024
BROKER_GROUP_NAME = "cogni-broker"
MIN_BROKER_CLIENT_UID = 1000
SO_PEERCRED_STRUCT = struct.Struct("3i")


def _open_posix_directory_nofollow(path: Path) -> int:
    """Open every absolute path component without following links."""

    _require_linux()
    absolute = path.absolute()
    if not absolute.is_absolute():
        raise SnapshotBrokerError("Broker directory path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(os.path.sep, flags)
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise SnapshotBrokerError(
            "Broker directory cannot be opened link-free"
        ) from exc


def _source_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_sealed_source_entry(
    metadata: os.stat_result,
    *,
    caller_uid: int,
    directory: bool,
) -> None:
    expected_modes = {0o555} if directory else {0o444, 0o555}
    if (
        metadata.st_uid != caller_uid
        or (
            not stat.S_ISDIR(metadata.st_mode)
            if directory
            else not stat.S_ISREG(metadata.st_mode)
        )
        or stat.S_IMODE(metadata.st_mode) not in expected_modes
    ):
        raise SnapshotBrokerError(
            "Caller source descriptor is not a sealed caller-owned regular tree"
        )


def _require_sealed_source_descriptor(
    descriptor: int,
    *,
    caller_uid: int,
) -> os.stat_result:
    """Require the promised read-only, close-on-exec directory descriptor."""

    _require_linux()
    if fcntl is None:
        raise SnapshotBrokerError("POSIX descriptor inspection is unavailable")
    metadata = os.fstat(descriptor)
    _require_sealed_source_entry(
        metadata,
        caller_uid=caller_uid,
        directory=True,
    )
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    if (
        flags & os.O_ACCMODE != os.O_RDONLY
        or flags & getattr(os, "O_PATH", 0)
        or os.get_inheritable(descriptor)
    ):
        raise SnapshotBrokerError(
            "Caller source descriptor is not read-only and close-on-exec"
        )
    return metadata


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written < 1:
            raise SnapshotBrokerError("Snapshot copy write made no progress")
        offset += written


def _copy_sealed_source_descriptor(
    source_descriptor: int,
    snapshot_path: Path,
    *,
    caller_uid: int,
    source_commit: str,
    tree_oid: str,
) -> dict[str, Any]:
    """Copy a sealed caller tree without paths, Git, or actor metadata parsing."""

    source_root_before = _require_sealed_source_descriptor(
        source_descriptor,
        caller_uid=caller_uid,
    )
    parent = _open_posix_directory_nofollow(snapshot_path.parent)
    destination_root = -1
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    files: list[dict[str, Any]] = []
    directories: list[str] = []
    seen_portable_paths: set[str] = set()
    total_bytes = 0
    path_bytes_total = 0
    tree_nodes = 0

    def register_path(parts: tuple[str, ...]) -> str:
        nonlocal path_bytes_total, tree_nodes
        tree_nodes += 1
        if tree_nodes > MAX_SOURCE_TREE_NODE_COUNT:
            raise SnapshotBrokerError("Caller source exceeds the tree-node limit")
        value = "/".join(parts)
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SnapshotBrokerError("Caller source path is not UTF-8") from exc
        if not value or "\\" in value or len(encoded) > MAX_SOURCE_PATH_BYTES:
            raise SnapshotBrokerError("Caller source path is unsafe")
        path_bytes_total += len(encoded)
        if path_bytes_total > MAX_SOURCE_PATH_BYTES_TOTAL:
            raise SnapshotBrokerError("Caller source paths exceed the total limit")
        portable = unicodedata.normalize("NFC", value).casefold()
        if portable in seen_portable_paths:
            raise SnapshotBrokerError("Caller source has a portable path collision")
        seen_portable_paths.add(portable)
        return value

    def copy_directory(
        source: int,
        destination: int,
        parts: tuple[str, ...],
    ) -> None:
        nonlocal total_bytes
        before = os.fstat(source)
        _require_sealed_source_entry(before, caller_uid=caller_uid, directory=True)
        try:
            names = sorted(os.listdir(source))
        except OSError as exc:
            raise SnapshotBrokerError("Caller source cannot be enumerated") from exc
        if len(names) > MAX_SOURCE_TREE_NODE_COUNT:
            raise SnapshotBrokerError("Caller source directory is unbounded")
        for name in names:
            if not isinstance(name, str) or name in {"", ".", ".."} or "/" in name:
                raise SnapshotBrokerError("Caller source contains an unsafe name")
            child_parts = (*parts, name)
            relative = register_path(child_parts)
            try:
                linked = os.stat(name, dir_fd=source, follow_symlinks=False)
            except OSError as exc:
                raise SnapshotBrokerError(
                    "Caller source entry cannot be inspected"
                ) from exc
            if stat.S_ISDIR(linked.st_mode):
                source_child = os.open(name, directory_flags, dir_fd=source)
                try:
                    if _source_identity(os.fstat(source_child)) != _source_identity(
                        linked
                    ):
                        raise SnapshotBrokerError("Caller source directory raced open")
                    _require_sealed_source_entry(
                        linked,
                        caller_uid=caller_uid,
                        directory=True,
                    )
                    os.mkdir(name, 0o700, dir_fd=destination)
                    destination_child = os.open(
                        name,
                        directory_flags,
                        dir_fd=destination,
                    )
                    try:
                        copy_directory(source_child, destination_child, child_parts)
                        os.fchmod(destination_child, 0o555)
                        os.fsync(destination_child)
                    finally:
                        os.close(destination_child)
                finally:
                    os.close(source_child)
                directories.append(relative)
                continue
            if not stat.S_ISREG(linked.st_mode):
                raise SnapshotBrokerError(
                    "Caller source contains a link or special file"
                )
            _require_sealed_source_entry(
                linked,
                caller_uid=caller_uid,
                directory=False,
            )
            if linked.st_size < 0 or linked.st_size > MAX_SOURCE_FILE_BYTES:
                raise SnapshotBrokerError("Caller source file exceeds its size limit")
            total_bytes += linked.st_size
            if total_bytes > MAX_SOURCE_BYTES or len(files) >= MAX_SOURCE_ENTRY_COUNT:
                raise SnapshotBrokerError("Caller source exceeds snapshot limits")
            source_file_flags = os.O_RDONLY | os.O_NOFOLLOW
            source_file_flags |= getattr(os, "O_CLOEXEC", 0)
            source_file = os.open(name, source_file_flags, dir_fd=source)
            destination_file = -1
            try:
                opened = os.fstat(source_file)
                if _source_identity(opened) != _source_identity(linked):
                    raise SnapshotBrokerError("Caller source file raced open")
                destination_file = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=destination,
                )
                sha256 = hashlib.sha256()
                # Preserve the caller-generated manifest's content-object
                # identity field without invoking or interpreting Git.
                object_digest = hashlib.sha1()
                object_digest.update(f"blob {opened.st_size}\0".encode("ascii"))
                remaining = opened.st_size
                while remaining:
                    chunk = os.read(
                        source_file, min(SOURCE_COPY_CHUNK_BYTES, remaining)
                    )
                    if not chunk:
                        raise SnapshotBrokerError("Caller source file was truncated")
                    _write_all(destination_file, chunk)
                    sha256.update(chunk)
                    object_digest.update(chunk)
                    remaining -= len(chunk)
                if os.read(source_file, 1):
                    raise SnapshotBrokerError("Caller source file grew during copy")
                if _source_identity(os.fstat(source_file)) != _source_identity(opened):
                    raise SnapshotBrokerError("Caller source file changed during copy")
                mode = "100755" if stat.S_IMODE(opened.st_mode) == 0o555 else "100644"
                os.fsync(destination_file)
                os.fchmod(destination_file, 0o555 if mode == "100755" else 0o444)
                os.fsync(destination_file)
                files.append(
                    {
                        "path": relative,
                        "mode": mode,
                        "object": object_digest.hexdigest(),
                        "size": opened.st_size,
                        "sha256": sha256.hexdigest(),
                    }
                )
            finally:
                if destination_file >= 0:
                    os.close(destination_file)
                os.close(source_file)
        try:
            names_after = sorted(os.listdir(source))
        except OSError as exc:
            raise SnapshotBrokerError("Caller source postcheck failed") from exc
        if names_after != names or _source_identity(
            os.fstat(source)
        ) != _source_identity(before):
            raise SnapshotBrokerError("Caller source directory changed during copy")
        os.fsync(destination)

    try:
        os.mkdir(snapshot_path.name, mode=0o700, dir_fd=parent)
        destination_root = os.open(
            snapshot_path.name,
            directory_flags,
            dir_fd=parent,
        )
        copy_directory(source_descriptor, destination_root, ())
        if _source_identity(os.fstat(source_descriptor)) != _source_identity(
            source_root_before
        ):
            raise SnapshotBrokerError("Caller source root changed during copy")
        os.fchmod(destination_root, 0o555)
        os.fsync(destination_root)
        os.fsync(parent)
    finally:
        if destination_root >= 0:
            os.close(destination_root)
        os.close(parent)
    files.sort(key=lambda entry: entry["path"])
    directories.sort()
    snapshot_sha256 = hashlib.sha256(
        json.dumps(
            {"directories": directories, "files": files},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": 1,
        "source_commit": source_commit,
        "tree_oid": tree_oid,
        "object_format": "sha1",
        "materialization_policy": SNAPSHOT_MATERIALIZATION_POLICY_ID,
        "file_count": len(files),
        "directories": directories,
        "size_bytes": total_bytes,
        "sha256": snapshot_sha256,
        "files": files,
    }


def _remove_committed_snapshot(snapshot_root: Path) -> None:
    """Remove only the fixed root-owned regular snapshot tree, without links."""

    parent = _open_posix_directory_nofollow(snapshot_root.parent)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)

    def remove_directory(descriptor: int) -> None:
        os.fchmod(descriptor, 0o700)
        for name in os.listdir(descriptor):
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if metadata.st_uid != 0:
                raise SnapshotBrokerError(
                    "Broker snapshot cleanup found foreign ownership"
                )
            if stat.S_ISREG(metadata.st_mode):
                os.unlink(name, dir_fd=descriptor)
            elif stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, flags, dir_fd=descriptor)
                try:
                    remove_directory(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=descriptor)
            else:
                raise SnapshotBrokerError(
                    "Broker snapshot cleanup found an unsafe entry"
                )
        os.fsync(descriptor)

    root = -1
    try:
        root = os.open(snapshot_root.name, flags, dir_fd=parent)
        metadata = os.fstat(root)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
            raise SnapshotBrokerError("Broker snapshot cleanup root is unsafe")
        remove_directory(root)
        os.close(root)
        root = -1
        os.rmdir(snapshot_root.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        if root >= 0:
            os.close(root)
        os.close(parent)


@dataclass(frozen=True)
class BrokerPaths:
    socket_path: Path = BROKER_SOCKET_PATH
    lock_path: Path = BROKER_LOCK_PATH
    store_root: Path = BROKER_STORE_ROOT
    nonce_root: Path = BROKER_NONCE_ROOT
    lease_root: Path = BROKER_LEASE_ROOT


@dataclass
class BrokerLease:
    """A client-held pinned descriptor and its broker acquisition proof."""

    client: SnapshotBrokerClient
    lease_id: str
    descriptor: int
    snapshot_root: Path
    snapshot: dict[str, Any]
    acquire_attestation: dict[str, Any]
    acquire_attestation_sha256: str
    task_id: str
    attempt: int
    actor: str
    run_id: str
    validation_contract_sha256: str
    released: bool = False
    release_started: bool = False
    release_request: dict[str, Any] | None = None

    def release(self, *, receipt_preimage_sha256: str) -> dict[str, Any]:
        if self.released:
            raise SnapshotBrokerError("Snapshot broker lease was already released")
        # The broker's namespace removal acknowledgement is meaningful only
        # after this process has dropped its pinned copy.  A subprocess may
        # receive the descriptor solely through pass_fds; the parent never
        # makes it globally inheritable.
        if not self.release_started:
            if self.descriptor < 0:
                raise SnapshotBrokerError("Snapshot broker lease descriptor is closed")
            os.close(self.descriptor)
            self.descriptor = -1
            self.release_started = True
        cleanup = self.client.release(
            self,
            receipt_preimage_sha256=receipt_preimage_sha256,
        )
        self.released = True
        return cleanup

    def close_without_claiming_cleanup(self) -> None:
        """Close a leaked client FD without manufacturing a cleanup proof."""

        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class _ServerLease:
    lease_id: str
    caller_uid: int
    caller_gid: int
    caller_pid: int
    snapshot_path: Path
    snapshot: dict[str, Any]
    snapshot_device: int
    snapshot_inode: int
    acquire_attestation_sha256: str
    expires_at: int
    task_id: str
    attempt: int
    actor: str
    run_id: str
    validation_contract_sha256: str


@dataclass(frozen=True)
class _CleanupTombstone:
    caller_uid: int
    caller_gid: int
    request_sha256: str
    expires_at: int
    response: dict[str, Any]


LEASE_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "lease_id",
        "caller_uid",
        "caller_gid",
        "caller_pid",
        "snapshot_path",
        "snapshot_sha256",
        "snapshot_device",
        "snapshot_inode",
        "acquire_attestation_sha256",
        "expires_at",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "validation_contract_sha256",
    }
)


def _require_linux() -> None:
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise SnapshotBrokerError(
            "Privileged snapshot FD leases are Linux-only; this platform is NO_GO"
        )
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_PATH")
    if (
        any(not hasattr(os, value) for value in required)
        or not hasattr(socket, "SCM_RIGHTS")
        or not hasattr(socket, "MSG_CMSG_CLOEXEC")
    ):
        raise SnapshotBrokerError(
            "Required Linux descriptor primitives are unavailable"
        )


def _require_root() -> None:
    _require_linux()
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise SnapshotBrokerError("Snapshot broker daemon must run as uid 0")


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, SO_PEERCRED_STRUCT.size
        )
        pid, uid, gid = SO_PEERCRED_STRUCT.unpack(raw)
    except (AttributeError, OSError, struct.error) as exc:
        raise SnapshotBrokerError(
            "Cannot authenticate the Unix peer with SO_PEERCRED"
        ) from exc
    if pid <= 0 or uid < 0 or gid < 0:
        raise SnapshotBrokerError("Unix peer credentials are invalid")
    return pid, uid, gid


def _broker_group() -> Any:
    _require_linux()
    if grp is None:
        raise SnapshotBrokerError("POSIX group lookup is unavailable")
    try:
        return grp.getgrnam(BROKER_GROUP_NAME)
    except KeyError as exc:
        raise SnapshotBrokerError(
            f"Required broker group does not exist: {BROKER_GROUP_NAME}"
        ) from exc


def _require_authorized_peer(*, uid: int, gid: int) -> None:
    """Allow only a non-root local account enrolled in ``cogni-broker``."""

    if uid < MIN_BROKER_CLIENT_UID or pwd is None:
        raise SnapshotBrokerError("Snapshot broker peer UID is not allowed")
    group = _broker_group()
    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError as exc:
        raise SnapshotBrokerError(
            "Snapshot broker peer account does not exist"
        ) from exc
    if gid != group.gr_gid and username not in set(group.gr_mem):
        raise SnapshotBrokerError(
            "Snapshot broker peer is not enrolled in cogni-broker"
        )


def _root_directory_metadata(
    path: Path, *, expected_mode: int | None = None
) -> os.stat_result:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise SnapshotBrokerError(f"Broker path is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (
            expected_mode is not None
            and stat.S_IMODE(metadata.st_mode) != expected_mode
        )
    ):
        raise SnapshotBrokerError(f"Broker path ownership or mode is unsafe: {path}")
    return metadata


def _ensure_root_directory(path: Path, *, mode: int) -> None:
    """Create a fixed absolute directory one component at a time with openat."""

    _require_root()
    if not path.is_absolute():
        raise SnapshotBrokerError("Broker directory must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open("/", flags)
    try:
        for index, component in enumerate(path.parts[1:]):
            leaf = index == len(path.parts[1:]) - 1
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=mode if leaf else 0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.fsync(descriptor)
            metadata = os.fstat(next_descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                os.close(next_descriptor)
                raise SnapshotBrokerError(
                    "Broker directory chain is not root-protected"
                )
            os.close(descriptor)
            descriptor = next_descriptor
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class _NonceReplayStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._lock = threading.Lock()

    def consume(self, *, uid: int, nonce: str, expires_at: int) -> None:
        with self._lock:
            self._consume_locked(uid=uid, nonce=nonce, expires_at=expires_at)

    def _consume_locked(self, *, uid: int, nonce: str, expires_at: int) -> None:
        _ensure_root_directory(self.root, mode=0o700)
        self._prune_expired(now=int(time.time()))
        uid_root = self.root / f"uid-{uid}"
        _ensure_root_directory(uid_root, mode=0o700)
        active_for_uid = self._count_files(uid_root, maximum=MAX_NONCES_PER_UID)
        if active_for_uid >= MAX_NONCES_PER_UID:
            raise SnapshotBrokerError(
                "Snapshot broker per-UID nonce rate limit reached"
            )
        if self._total_count() >= MAX_NONCES_TOTAL:
            raise SnapshotBrokerError("Snapshot broker global nonce limit reached")
        root_descriptor = _open_posix_directory_nofollow(uid_root)
        name = hashlib.sha256(f"{uid}:{nonce}".encode()).hexdigest()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=root_descriptor)
        except FileExistsError as exc:
            os.close(root_descriptor)
            raise SnapshotBrokerError(
                "Snapshot broker nonce replay was rejected"
            ) from exc
        try:
            payload = f"{expires_at}\n".encode("ascii")
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.fsync(root_descriptor)
        finally:
            os.close(descriptor)
            os.close(root_descriptor)

    @staticmethod
    def _count_files(root: Path, *, maximum: int) -> int:
        count = 0
        with os.scandir(root) as iterator:
            for entry in iterator:
                if not entry.is_file(follow_symlinks=False):
                    raise SnapshotBrokerError(
                        "Snapshot nonce store contains a non-file"
                    )
                count += 1
                if count > maximum:
                    raise SnapshotBrokerError("Snapshot nonce store exceeds its bound")
        return count

    def _total_count(self) -> int:
        total = 0
        uid_directories = 0
        with os.scandir(self.root) as iterator:
            for entry in iterator:
                if not entry.is_dir(follow_symlinks=False):
                    raise SnapshotBrokerError(
                        "Snapshot nonce root contains an unsafe entry"
                    )
                uid_directories += 1
                if uid_directories > MAX_NONCE_UID_DIRECTORIES:
                    raise SnapshotBrokerError(
                        "Snapshot nonce UID directory limit reached"
                    )
                total += self._count_files(Path(entry.path), maximum=MAX_NONCES_PER_UID)
                if total > MAX_NONCES_TOTAL:
                    raise SnapshotBrokerError(
                        "Snapshot nonce store exceeds its global bound"
                    )
        return total

    def _prune_expired(self, *, now: int) -> None:
        if not self.root.exists():
            return
        scanned = 0
        with os.scandir(self.root) as uid_iterator:
            uid_entries = list(uid_iterator)
        if len(uid_entries) > MAX_NONCE_UID_DIRECTORIES:
            raise SnapshotBrokerError("Snapshot nonce UID directory limit reached")
        for uid_entry in uid_entries:
            if not uid_entry.is_dir(follow_symlinks=False):
                raise SnapshotBrokerError(
                    "Snapshot nonce root contains an unsafe entry"
                )
            uid_root = Path(uid_entry.path)
            descriptor = _open_posix_directory_nofollow(uid_root)
            try:
                with os.scandir(uid_root) as iterator:
                    for entry in iterator:
                        scanned += 1
                        if scanned > MAX_REPLAY_FILES_SCANNED:
                            raise SnapshotBrokerError(
                                "Snapshot nonce prune bound exceeded"
                            )
                        if not entry.is_file(follow_symlinks=False):
                            raise SnapshotBrokerError(
                                "Snapshot nonce store contains a non-file"
                            )
                        try:
                            value = Path(entry.path).read_text(encoding="ascii").strip()
                            expired = int(value) + 5 < now
                        except (OSError, UnicodeError, ValueError) as exc:
                            raise SnapshotBrokerError(
                                "Snapshot nonce state is malformed"
                            ) from exc
                        if expired:
                            os.unlink(entry.name, dir_fd=descriptor)
                with os.scandir(uid_root) as remaining:
                    empty = next(remaining, None) is None
                if empty:
                    parent = _open_posix_directory_nofollow(self.root)
                    try:
                        os.rmdir(uid_root.name, dir_fd=parent)
                    finally:
                        os.close(parent)
            finally:
                os.close(descriptor)


def _send_frame_with_descriptor(
    connection: socket.socket, document: dict[str, Any], descriptor: int | None = None
) -> None:
    frame = encode_frame(document)
    if descriptor is None:
        connection.sendall(frame)
        return
    descriptors = array.array("i", [descriptor])
    sent = connection.sendmsg(
        [frame],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors.tobytes())],
    )
    if sent <= 0:
        raise SnapshotBrokerError("Snapshot broker could not pass the lease descriptor")
    if sent < len(frame):
        connection.sendall(frame[sent:])


def _send_response(
    connection: socket.socket, response: dict[str, Any], descriptor: int | None = None
) -> None:
    _send_frame_with_descriptor(connection, response, descriptor)


def _error_response(
    operation: str, request_id: str, exc: BaseException
) -> dict[str, Any]:
    message = str(exc).encode("utf-8", errors="replace")[
        :MAX_BROKER_ERROR_MESSAGE_BYTES
    ]
    return {
        "schema_version": BROKER_SCHEMA_VERSION,
        "protocol_id": BROKER_PROTOCOL_ID,
        "operation": operation if operation in {"acquire", "release"} else "error",
        "request_id": request_id if request_id else "unknown",
        "ok": False,
        "error_code": type(exc).__name__,
        "message": message.decode("utf-8", errors="replace"),
    }


class SnapshotBrokerDaemon:
    def __init__(self, *, paths: BrokerPaths | None = None) -> None:
        self.paths = paths if paths is not None else BrokerPaths()
        self._leases: dict[str, _ServerLease] = {}
        self._cleanup_tombstones: dict[str, _CleanupTombstone] = {}
        self._nonces = _NonceReplayStore(self.paths.nonce_root)
        self._runtime_binding: dict[str, str] | None = None
        self._singleton_descriptor = -1
        self._lease_lock = threading.RLock()
        self._connection_slots = threading.BoundedSemaphore(
            MAX_BROKER_PENDING_CONNECTIONS
        )

    def _prepare(self) -> None:
        _require_root()
        _ensure_root_directory(self.paths.socket_path.parent, mode=0o755)
        _ensure_root_directory(self.paths.store_root, mode=0o700)
        _ensure_root_directory(self.paths.nonce_root, mode=0o700)
        _ensure_root_directory(self.paths.lease_root, mode=0o700)
        _root_directory_metadata(self.paths.store_root, expected_mode=0o700)
        _root_directory_metadata(self.paths.nonce_root, expected_mode=0o700)
        _root_directory_metadata(self.paths.lease_root, expected_mode=0o700)
        _broker_group()
        self._acquire_singleton_lock()
        self._runtime_binding = trusted_broker_runtime_binding()
        self._recover_persisted_leases()

    def _acquire_singleton_lock(self) -> None:
        """Acquire the process singleton before inspecting persisted state."""

        if fcntl is None or self._singleton_descriptor >= 0:
            raise SnapshotBrokerError("Snapshot broker singleton lock is unavailable")
        parent = _open_posix_directory_nofollow(self.paths.lock_path.parent)
        descriptor = -1
        try:
            descriptor = os.open(
                self.paths.lock_path.name,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise SnapshotBrokerError("Snapshot broker lock file is unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise SnapshotBrokerError(
                    "Another snapshot broker owns the singleton lock"
                ) from exc
            self._singleton_descriptor = descriptor
            descriptor = -1
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent)

    def _release_singleton_lock(self) -> None:
        descriptor = self._singleton_descriptor
        self._singleton_descriptor = -1
        if descriptor < 0:
            return
        try:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def serve_forever(self) -> None:
        listener: socket.socket | None = None
        socket_identity: tuple[int, int] | None = None
        try:
            self._prepare()
            self._remove_stale_socket()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self.paths.socket_path))
            os.chown(self.paths.socket_path, 0, _broker_group().gr_gid)
            os.chmod(self.paths.socket_path, 0o660)
            metadata = self.paths.socket_path.stat(follow_symlinks=False)
            socket_identity = (metadata.st_dev, metadata.st_ino)
            listener.listen(MAX_BROKER_PENDING_CONNECTIONS)
            with ThreadPoolExecutor(
                max_workers=MAX_BROKER_CONNECTION_WORKERS,
                thread_name_prefix="cogni-snapshot-broker",
            ) as executor:
                while True:
                    connection, _ = listener.accept()
                    if not self._connection_slots.acquire(blocking=False):
                        connection.close()
                        continue
                    try:
                        executor.submit(self._handle_connection_slot, connection)
                    except BaseException:
                        self._connection_slots.release()
                        connection.close()
                        raise
        finally:
            if listener is not None:
                listener.close()
            if socket_identity is not None:
                try:
                    metadata = self.paths.socket_path.stat(follow_symlinks=False)
                    if (metadata.st_dev, metadata.st_ino) == socket_identity:
                        parent = _open_posix_directory_nofollow(
                            self.paths.socket_path.parent
                        )
                        try:
                            os.unlink(self.paths.socket_path.name, dir_fd=parent)
                        finally:
                            os.close(parent)
                except OSError:
                    pass
            self._release_singleton_lock()

    def _handle_connection_slot(self, connection: socket.socket) -> None:
        try:
            with connection:
                connection.settimeout(BROKER_CONNECTION_TIMEOUT_SECONDS)
                self.handle_connection(connection)
        finally:
            self._connection_slots.release()

    def _lease_record_path(self, lease_id: str) -> Path:
        return self.paths.lease_root / f"{lease_id}.json"

    @staticmethod
    def _lease_record(lease: _ServerLease) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "lease_id": lease.lease_id,
            "caller_uid": lease.caller_uid,
            "caller_gid": lease.caller_gid,
            "caller_pid": lease.caller_pid,
            "snapshot_path": str(lease.snapshot_path),
            "snapshot_sha256": lease.snapshot["sha256"],
            "snapshot_device": lease.snapshot_device,
            "snapshot_inode": lease.snapshot_inode,
            "acquire_attestation_sha256": lease.acquire_attestation_sha256,
            "expires_at": lease.expires_at,
            "task_id": lease.task_id,
            "attempt": lease.attempt,
            "actor": lease.actor,
            "run_id": lease.run_id,
            "validation_contract_sha256": lease.validation_contract_sha256,
        }

    def _persist_lease(self, lease: _ServerLease) -> None:
        document = self._lease_record(lease)
        content = canonical_json_bytes(document)
        parent = _open_posix_directory_nofollow(self.paths.lease_root)
        descriptor = -1
        final_name = self._lease_record_path(lease.lease_id).name
        temporary_name = f".{final_name}.{secrets.token_hex(16)}.tmp"
        try:
            try:
                os.stat(final_name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise SnapshotBrokerError("Snapshot broker lease record already exists")
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent,
            )
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written < 1:
                    raise SnapshotBrokerError(
                        "Snapshot broker lease record write made no progress"
                    )
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.rename(
                temporary_name,
                final_name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
            )
            os.fsync(parent)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)

    def _delete_lease_record(self, lease_id: str) -> None:
        parent = _open_posix_directory_nofollow(self.paths.lease_root)
        try:
            try:
                os.unlink(self._lease_record_path(lease_id).name, dir_fd=parent)
            except FileNotFoundError:
                return
            os.fsync(parent)
        finally:
            os.close(parent)

    def _decode_lease_record(self, path: Path) -> _ServerLease:
        metadata = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < 2
            or metadata.st_size > MAX_BROKER_FRAME_BYTES
        ):
            raise SnapshotBrokerError("Snapshot broker lease record is unsafe")
        content = path.read_bytes()
        try:
            document = json.loads(content.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SnapshotBrokerError(
                "Snapshot broker lease record is malformed"
            ) from exc
        if (
            not isinstance(document, dict)
            or set(document) != LEASE_RECORD_KEYS
            or canonical_json_bytes(document) != content
            or document.get("schema_version") != 1
            or document.get("lease_id") != path.stem
            or not isinstance(document.get("lease_id"), str)
            or len(document["lease_id"]) != 38
            or not document["lease_id"].startswith("lease-")
            or any(
                character not in "0123456789abcdef"
                for character in document["lease_id"][6:]
            )
            or document.get("snapshot_path") != str(self.paths.store_root / path.stem)
            or not isinstance(document.get("expires_at"), int)
            or isinstance(document.get("expires_at"), bool)
            or not isinstance(document.get("attempt"), int)
            or isinstance(document.get("attempt"), bool)
            or document["attempt"] < 1
        ):
            raise SnapshotBrokerError("Snapshot broker lease record schema is invalid")
        for field in (
            "caller_uid",
            "caller_gid",
            "caller_pid",
            "snapshot_device",
            "snapshot_inode",
        ):
            value = document.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise SnapshotBrokerError(
                    "Snapshot broker lease record identity is invalid"
                )
        for field, length in (
            ("snapshot_sha256", 64),
            ("acquire_attestation_sha256", 64),
            ("validation_contract_sha256", 64),
        ):
            value = document.get(field)
            if (
                not isinstance(value, str)
                or len(value) != length
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise SnapshotBrokerError("Snapshot broker lease digest is invalid")
        for field in ("task_id", "actor"):
            value = document.get(field)
            try:
                encoded = value.encode("ascii") if isinstance(value, str) else b""
            except UnicodeEncodeError:
                encoded = b""
            if (
                not isinstance(value, str)
                or not value
                or not encoded
                or len(encoded) != len(value)
                or len(value) > 256
                or any(
                    not (character.isalnum() or character in "-_.")
                    for character in value
                )
            ):
                raise SnapshotBrokerError("Snapshot broker lease binding is invalid")
        run_id = document.get("run_id")
        if (
            not isinstance(run_id, str)
            or len(run_id) != 32
            or any(character not in "0123456789abcdef" for character in run_id)
        ):
            raise SnapshotBrokerError("Snapshot broker lease run id is invalid")
        return _ServerLease(
            lease_id=document["lease_id"],
            caller_uid=document["caller_uid"],
            caller_gid=document["caller_gid"],
            caller_pid=document["caller_pid"],
            snapshot_path=Path(document["snapshot_path"]),
            snapshot={"sha256": document["snapshot_sha256"]},
            snapshot_device=document["snapshot_device"],
            snapshot_inode=document["snapshot_inode"],
            acquire_attestation_sha256=document["acquire_attestation_sha256"],
            expires_at=document["expires_at"],
            task_id=document["task_id"],
            attempt=document["attempt"],
            actor=document["actor"],
            run_id=document["run_id"],
            validation_contract_sha256=document["validation_contract_sha256"],
        )

    @staticmethod
    def _lease_namespace_identity(lease: _ServerLease) -> os.stat_result:
        metadata = lease.snapshot_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o555
            or metadata.st_dev != lease.snapshot_device
            or metadata.st_ino != lease.snapshot_inode
        ):
            raise SnapshotBrokerError("Snapshot broker lease pathname identity changed")
        return metadata

    def _remove_lease_namespace(self, lease: _ServerLease) -> None:
        self._lease_namespace_identity(lease)
        _remove_committed_snapshot(lease.snapshot_path)
        if lease.snapshot_path.exists():
            raise SnapshotBrokerError(
                "Snapshot broker cleanup did not remove the lease"
            )

    def _recover_persisted_leases(self) -> None:
        """Load live leases and remove expired records or unrecorded namespaces."""

        now = int(time.time())
        with self._lease_lock:
            self._leases.clear()
            with os.scandir(self.paths.lease_root) as iterator:
                records = sorted(iterator, key=lambda entry: entry.name)
            if len(records) > MAX_PERSISTED_LEASE_FILES:
                raise SnapshotBrokerError(
                    "Snapshot broker lease store exceeds its bound"
                )
            for entry in records:
                if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(
                    ".json"
                ):
                    raise SnapshotBrokerError(
                        "Snapshot broker lease store contains an unsafe entry"
                    )
                lease = self._decode_lease_record(Path(entry.path))
                if lease.expires_at < now:
                    if lease.snapshot_path.exists():
                        self._remove_lease_namespace(lease)
                    self._delete_lease_record(lease.lease_id)
                    continue
                # A committed record without its namespace is an interrupted
                # acquire, not a live lease.  Roll it back during startup so a
                # daemon restart cannot permanently consume the bounded store.
                if not lease.snapshot_path.exists():
                    self._delete_lease_record(lease.lease_id)
                    continue
                self._lease_namespace_identity(lease)
                self._leases[lease.lease_id] = lease
            with os.scandir(self.paths.store_root) as iterator:
                namespaces = sorted(iterator, key=lambda entry: entry.name)
            if len(namespaces) > MAX_PERSISTED_LEASE_FILES:
                raise SnapshotBrokerError(
                    "Snapshot broker snapshot store exceeds its bound"
                )
            for entry in namespaces:
                if not entry.is_dir(follow_symlinks=False) or not entry.name.startswith(
                    "lease-"
                ):
                    raise SnapshotBrokerError(
                        "Snapshot broker store contains an unsafe entry"
                    )
                if entry.name not in self._leases:
                    orphan = Path(entry.path)
                    metadata = orphan.stat(follow_symlinks=False)
                    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o555:
                        raise SnapshotBrokerError(
                            "Snapshot broker orphan is not root protected"
                        )
                    _remove_committed_snapshot(orphan)

    def _evict_expired_leases(self, *, now: int) -> None:
        with self._lease_lock:
            expired = [
                lease for lease in self._leases.values() if lease.expires_at < now
            ]
            for lease in expired:
                if lease.snapshot_path.exists():
                    self._remove_lease_namespace(lease)
                self._delete_lease_record(lease.lease_id)
                del self._leases[lease.lease_id]

    def _remove_stale_socket(self) -> None:
        try:
            metadata = self.paths.socket_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 0:
            raise SnapshotBrokerError("Refusing to replace an unsafe broker socket")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(str(self.paths.socket_path))
        except OSError as exc:
            if exc.errno not in {errno.ECONNREFUSED, errno.ENOENT}:
                raise SnapshotBrokerError(
                    "Cannot classify existing broker socket"
                ) from exc
        else:
            raise SnapshotBrokerError("Another snapshot broker is already listening")
        finally:
            probe.close()
        parent = _open_posix_directory_nofollow(self.paths.socket_path.parent)
        try:
            os.unlink(self.paths.socket_path.name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)

    def handle_connection(self, connection: socket.socket) -> None:
        operation = "error"
        request_id = "unknown"
        received_descriptors: list[int] = []
        try:
            pid, uid, gid = _peer_credentials(connection)
            _require_authorized_peer(uid=uid, gid=gid)
            self._evict_expired_leases(now=int(time.time()))
            request, received_descriptors = _receive_framed_json_with_fds(
                connection,
                maximum_descriptors=1,
                label="request",
            )
            operation = validate_request(request)
            request_id = request["request_id"]
            expected_descriptors = 1 if operation == "acquire" else 0
            if len(received_descriptors) != expected_descriptors:
                raise SnapshotBrokerError(
                    "Snapshot broker source descriptor count does not match the request"
                )
            if operation == "release":
                cached = self._cached_cleanup_response(
                    request,
                    uid=uid,
                    gid=gid,
                )
                if cached is not None:
                    _send_response(connection, cached)
                    return
            self._nonces.consume(
                uid=uid, nonce=request["nonce"], expires_at=request["expires_at"]
            )
            if operation == "acquire":
                response, descriptor = self._acquire(
                    request,
                    pid=pid,
                    uid=uid,
                    gid=gid,
                    source_descriptor=received_descriptors[0],
                )
                try:
                    try:
                        _send_response(connection, response, descriptor)
                    except BaseException:
                        self._rollback_acquire_response(
                            response["attestation"]["payload"]["lease_id"]
                        )
                        raise
                finally:
                    os.close(descriptor)
            else:
                response = self._release(request, pid=pid, uid=uid, gid=gid)
                _send_response(connection, response)
        except (
            EvidenceError,
            KeyError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            try:
                _send_response(connection, _error_response(operation, request_id, exc))
            except (OSError, SnapshotBrokerError):
                pass
        finally:
            for descriptor in received_descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _rollback_acquire_response(self, lease_id: str) -> None:
        """Remove a lease whose FD/proof did not reach the authenticated peer."""

        with self._lease_lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                return
            if lease.snapshot_path.exists():
                self._remove_lease_namespace(lease)
            self._delete_lease_record(lease_id)
            del self._leases[lease_id]

    def _cached_cleanup_response(
        self,
        request: dict[str, Any],
        *,
        uid: int,
        gid: int,
    ) -> dict[str, Any] | None:
        """Return one bounded idempotent cleanup result for an exact retry."""

        now = int(time.time())
        with self._lease_lock:
            expired = [
                lease_id
                for lease_id, tombstone in self._cleanup_tombstones.items()
                if tombstone.expires_at < now
            ]
            for lease_id in expired:
                del self._cleanup_tombstones[lease_id]
            tombstone = self._cleanup_tombstones.get(str(request.get("lease_id")))
            if tombstone is None:
                return None
            if (
                tombstone.caller_uid != uid
                or tombstone.caller_gid != gid
                or tombstone.request_sha256 != canonical_json_sha256(request)
            ):
                raise SnapshotBrokerError(
                    "Snapshot broker cleanup retry does not match the original"
                )
            return tombstone.response

    def _remember_cleanup_response(
        self,
        request: dict[str, Any],
        *,
        uid: int,
        gid: int,
        response: dict[str, Any],
    ) -> None:
        while len(self._cleanup_tombstones) >= MAX_CLEANUP_TOMBSTONES:
            del self._cleanup_tombstones[next(iter(self._cleanup_tombstones))]
        self._cleanup_tombstones[request["lease_id"]] = _CleanupTombstone(
            caller_uid=uid,
            caller_gid=gid,
            request_sha256=canonical_json_sha256(request),
            expires_at=request["expires_at"],
            response=response,
        )

    def _acquire(
        self,
        request: dict[str, Any],
        *,
        pid: int,
        uid: int,
        gid: int,
        source_descriptor: int,
    ) -> tuple[dict[str, Any], int]:
        with self._lease_lock:
            if len(self._leases) >= MAX_ACTIVE_BROKER_LEASES:
                raise SnapshotBrokerError(
                    "Snapshot broker active lease limit was reached"
                )
            if request["materialization_policy"] != SNAPSHOT_MATERIALIZATION_POLICY_ID:
                raise SnapshotBrokerError(
                    "Snapshot materialization policy is unsupported"
                )
            if self._runtime_binding is None:
                raise SnapshotBrokerError(
                    "Snapshot broker runtime provenance is unavailable"
                )
            _require_sealed_source_descriptor(
                source_descriptor,
                caller_uid=uid,
            )
            lease_id = "lease-" + secrets.token_hex(16)
            snapshot_path = self.paths.store_root / lease_id
            descriptor = -1
            record_persisted = False
            try:
                snapshot = _copy_sealed_source_descriptor(
                    source_descriptor,
                    snapshot_path,
                    caller_uid=uid,
                    source_commit=request["source_commit"],
                    tree_oid=request["tree_oid"],
                )
                flags = (
                    os.O_PATH
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0)
                )
                descriptor = os.open(snapshot_path, flags)
                metadata = os.fstat(descriptor)
                if (
                    metadata.st_uid != 0
                    or stat.S_IMODE(metadata.st_mode) != 0o555
                    or not stat.S_ISDIR(metadata.st_mode)
                ):
                    raise SnapshotBrokerError(
                        "Broker materialized an unsafe snapshot root"
                    )
                if snapshot["sha256"] != request["expected_snapshot_sha256"]:
                    raise SnapshotBrokerError(
                        "Broker snapshot does not match the requested manifest"
                    )
                issued_at = int(time.time())
                expires_at = issued_at + BROKER_LEASE_TTL_SECONDS
                payload = {
                    "schema_version": BROKER_SCHEMA_VERSION,
                    "protocol_id": BROKER_PROTOCOL_ID,
                    "kind": "snapshot-acquired",
                    "request_sha256": canonical_json_sha256(request),
                    "request_id": request["request_id"],
                    "request_nonce": request["nonce"],
                    "caller_pid": pid,
                    "caller_uid": uid,
                    "caller_gid": gid,
                    "lease_id": lease_id,
                    "source_commit": snapshot["source_commit"],
                    "tree_oid": snapshot["tree_oid"],
                    "snapshot_sha256": snapshot["sha256"],
                    "snapshot_device": metadata.st_dev,
                    "snapshot_inode": metadata.st_ino,
                    "snapshot_owner_uid": metadata.st_uid,
                    "descriptor_type": BROKER_DESCRIPTOR_TYPE,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "broker_nonce": secrets.token_hex(32),
                    "materialization_policy": snapshot["materialization_policy"],
                    "task_id": request["task_id"],
                    "attempt": request["attempt"],
                    "actor": request["actor"],
                    "run_id": request["run_id"],
                    "validation_contract_sha256": request["validation_contract_sha256"],
                    "broker_runtime_manifest_sha256": self._runtime_binding[
                        "manifest_sha256"
                    ],
                }
                attestation = sign_payload(payload)
                attestation_sha256 = canonical_json_sha256(attestation)
                lease = _ServerLease(
                    lease_id=lease_id,
                    caller_uid=uid,
                    caller_gid=gid,
                    caller_pid=pid,
                    snapshot_path=snapshot_path,
                    snapshot=snapshot,
                    snapshot_device=metadata.st_dev,
                    snapshot_inode=metadata.st_ino,
                    acquire_attestation_sha256=attestation_sha256,
                    expires_at=expires_at,
                    task_id=request["task_id"],
                    attempt=request["attempt"],
                    actor=request["actor"],
                    run_id=request["run_id"],
                    validation_contract_sha256=request["validation_contract_sha256"],
                )
                self._persist_lease(lease)
                record_persisted = True
                self._leases[lease_id] = lease
                response = {
                    "schema_version": BROKER_SCHEMA_VERSION,
                    "protocol_id": BROKER_PROTOCOL_ID,
                    "operation": "acquire",
                    "request_id": request["request_id"],
                    "ok": True,
                    "snapshot": snapshot,
                    "attestation": attestation,
                }
                return response, descriptor
            except BaseException:
                if descriptor >= 0:
                    os.close(descriptor)
                if record_persisted:
                    self._delete_lease_record(lease_id)
                self._leases.pop(lease_id, None)
                if snapshot_path.exists():
                    _remove_committed_snapshot(snapshot_path)
                raise

    def _release(
        self,
        request: dict[str, Any],
        *,
        pid: int,
        uid: int,
        gid: int,
    ) -> dict[str, Any]:
        with self._lease_lock:
            lease = self._leases.get(request["lease_id"])
            if lease is None:
                raise SnapshotBrokerError("Snapshot broker lease does not exist")
            if lease.caller_uid != uid or lease.caller_gid != gid:
                raise SnapshotBrokerError(
                    "Snapshot broker lease belongs to another caller"
                )
            if (
                request["acquire_attestation_sha256"]
                != lease.acquire_attestation_sha256
            ):
                raise SnapshotBrokerError(
                    "Snapshot broker release proof does not match acquisition"
                )
            if (
                request["task_id"] != lease.task_id
                or request["attempt"] != lease.attempt
                or request["actor"] != lease.actor
                or request["run_id"] != lease.run_id
                or request["validation_contract_sha256"]
                != lease.validation_contract_sha256
            ):
                raise SnapshotBrokerError(
                    "Snapshot broker release execution binding changed"
                )
            if self._runtime_binding is None:
                raise SnapshotBrokerError(
                    "Snapshot broker runtime provenance is unavailable"
                )
            payload = {
                "schema_version": BROKER_SCHEMA_VERSION,
                "protocol_id": BROKER_PROTOCOL_ID,
                "kind": "snapshot-cleaned",
                "request_sha256": canonical_json_sha256(request),
                "request_id": request["request_id"],
                "request_nonce": request["nonce"],
                "caller_pid": pid,
                "caller_uid": uid,
                "caller_gid": gid,
                "lease_id": lease.lease_id,
                "acquire_attestation_sha256": lease.acquire_attestation_sha256,
                "snapshot_sha256": lease.snapshot["sha256"],
                "snapshot_device": lease.snapshot_device,
                "snapshot_inode": lease.snapshot_inode,
                "namespace_removed": True,
                "issued_at": int(time.time()),
                "broker_nonce": secrets.token_hex(32),
                "task_id": lease.task_id,
                "attempt": lease.attempt,
                "actor": lease.actor,
                "run_id": lease.run_id,
                "validation_contract_sha256": lease.validation_contract_sha256,
                "receipt_preimage_sha256": request["receipt_preimage_sha256"],
                "broker_runtime_manifest_sha256": self._runtime_binding[
                    "manifest_sha256"
                ],
            }
            cleanup = sign_payload(payload)
            self._remove_lease_namespace(lease)
            response = {
                "schema_version": BROKER_SCHEMA_VERSION,
                "protocol_id": BROKER_PROTOCOL_ID,
                "operation": "release",
                "request_id": request["request_id"],
                "ok": True,
                "cleanup_attestation": cleanup,
            }
            self._remember_cleanup_response(
                request,
                uid=uid,
                gid=gid,
                response=response,
            )
            self._delete_lease_record(lease.lease_id)
            del self._leases[lease.lease_id]
            return response


def _require_socket_trust(path: Path) -> None:
    _require_linux()
    if path != BROKER_SOCKET_PATH:
        raise SnapshotBrokerError("Production broker socket path is not fixed")
    try:
        metadata = path.stat(follow_symlinks=False)
        parent = path.parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise SnapshotBrokerError(
            "Privileged snapshot broker socket is unavailable"
        ) from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != _broker_group().gr_gid
        or stat.S_IMODE(metadata.st_mode) != 0o660
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise SnapshotBrokerError("Privileged snapshot broker socket path is unsafe")


def _open_sealed_source_for_send(path: Path) -> int:
    """Open the caller materialization as a non-inheritable directory FD."""

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        _require_sealed_source_descriptor(
            descriptor,
            caller_uid=os.geteuid(),
        )
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise


def _receive_framed_json_with_fds(
    connection: socket.socket,
    *,
    maximum_descriptors: int,
    label: str,
) -> tuple[dict[str, Any], list[int]]:
    """Receive one frame and close every delivered FD on every error path."""

    itemsize = array.array("i").itemsize
    ancillary_size = socket.CMSG_SPACE(itemsize * (maximum_descriptors + 1))
    received: list[int] = []
    try:
        first, ancillary, flags, _ = connection.recvmsg(
            MAX_BROKER_FRAME_BYTES + 4,
            ancillary_size,
            getattr(socket, "MSG_CMSG_CLOEXEC", 0),
        )
        ancillary_error: str | None = None
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                complete_size = len(data) - (len(data) % itemsize)
                if complete_size:
                    values = array.array("i")
                    values.frombytes(data[:complete_size])
                    received.extend(values.tolist())
                if len(data) == 0 or complete_size != len(data):
                    ancillary_error = (
                        f"Snapshot broker {label} descriptor data is malformed"
                    )
            else:
                ancillary_error = (
                    f"Snapshot broker {label} carried unsupported ancillary data"
                )
        if ancillary_error is not None:
            raise SnapshotBrokerError(ancillary_error)
        if flags & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)):
            raise SnapshotBrokerError(
                f"Snapshot broker {label} or descriptor was truncated"
            )
        if len(received) > maximum_descriptors:
            raise SnapshotBrokerError(
                f"Snapshot broker {label} delivered too many descriptors"
            )
        if any(os.get_inheritable(descriptor) for descriptor in received):
            raise SnapshotBrokerError(
                f"Snapshot broker {label} descriptor was not close-on-exec"
            )
        if len(first) < 4:
            first += connection.recv(4 - len(first))
        if len(first) < 4:
            raise SnapshotBrokerError(f"Snapshot broker {label} was truncated")
        length = struct.unpack("!I", first[:4])[0]
        if length < 2 or length > MAX_BROKER_FRAME_BYTES:
            raise SnapshotBrokerError(f"Snapshot broker {label} length is invalid")
        payload = bytearray(first[4:])
        while len(payload) < length:
            chunk = connection.recv(length - len(payload))
            if not chunk:
                raise SnapshotBrokerError(f"Snapshot broker {label} was truncated")
            payload.extend(chunk)
        if len(payload) != length:
            raise SnapshotBrokerError(f"Snapshot broker {label} has trailing bytes")
        try:
            document = json.loads(bytes(payload).decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise SnapshotBrokerError(f"Snapshot broker {label} is not JSON") from exc
        if not isinstance(document, dict) or encode_frame(document)[4:] != bytes(
            payload
        ):
            raise SnapshotBrokerError(f"Snapshot broker {label} is not canonical JSON")
        return document, received
    except BaseException:
        for descriptor in received:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _receive_response_with_fd(
    connection: socket.socket,
) -> tuple[dict[str, Any], int | None]:
    response, received = _receive_framed_json_with_fds(
        connection,
        maximum_descriptors=1,
        label="response",
    )
    is_success = isinstance(response, dict) and response.get("ok") is True
    expected_descriptors = 1 if is_success else 0
    if len(received) != expected_descriptors:
        for descriptor in received:
            os.close(descriptor)
        raise SnapshotBrokerError(
            "Snapshot broker descriptor count does not match the response"
        )
    return response, received[0] if received else None


class SnapshotBrokerClient:
    def __init__(self, *, socket_path: Path = BROKER_SOCKET_PATH) -> None:
        _require_linux()
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            raise SnapshotBrokerError(
                "Snapshot broker client must run unprivileged; root collapses separation"
            )
        if socket_path != BROKER_SOCKET_PATH:
            raise SnapshotBrokerError(
                "Production broker client refuses a variable socket path"
            )
        self.socket_path = socket_path
        self.runtime_binding: dict[str, str] | None = None

    def preflight(self) -> None:
        _require_socket_trust(self.socket_path)
        if self.runtime_binding is None:
            self.runtime_binding = trusted_broker_runtime_binding(
                require_current_interpreter=False,
            )

    def _connect(self) -> socket.socket:
        self.preflight()
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(BROKER_CONNECTION_TIMEOUT_SECONDS)
            connection.connect(str(self.socket_path))
            _, uid, _ = _peer_credentials(connection)
            if uid != 0:
                raise SnapshotBrokerError("Snapshot broker peer is not uid 0")
            return connection
        except BaseException:
            connection.close()
            raise

    @staticmethod
    def _request(operation: str, **bindings: Any) -> dict[str, Any]:
        now = int(time.time())
        request = {
            "schema_version": BROKER_SCHEMA_VERSION,
            "protocol_id": BROKER_PROTOCOL_ID,
            "operation": operation,
            "request_id": secrets.token_hex(16),
            "nonce": secrets.token_hex(32),
            "issued_at": now,
            "expires_at": now + 60,
            **bindings,
        }
        validate_request(request)
        return request

    def acquire(
        self,
        *,
        source_root: Path,
        source_commit: str,
        tree_oid: str,
        task_id: str,
        attempt: int,
        actor: str,
        run_id: str,
        validation_contract_sha256: str,
        expected_snapshot_sha256: str,
        materialization_policy: str = SNAPSHOT_MATERIALIZATION_POLICY_ID,
    ) -> BrokerLease:
        request = self._request(
            "acquire",
            source_descriptor_type=BROKER_SOURCE_DESCRIPTOR_TYPE,
            source_commit=source_commit,
            tree_oid=tree_oid,
            materialization_policy=materialization_policy,
            task_id=task_id,
            attempt=attempt,
            actor=actor,
            run_id=run_id,
            validation_contract_sha256=validation_contract_sha256,
            expected_snapshot_sha256=expected_snapshot_sha256,
        )
        source_descriptor = _open_sealed_source_for_send(source_root)
        try:
            with self._connect() as connection:
                _send_frame_with_descriptor(
                    connection,
                    request,
                    source_descriptor,
                )
                response, descriptor = _receive_response_with_fd(connection)
        finally:
            os.close(source_descriptor)
        try:
            if not isinstance(response, dict):
                raise SnapshotBrokerError(
                    "Snapshot broker acquisition response is invalid"
                )
            if response.get("ok") is not True:
                if set(response) != ERROR_RESPONSE_KEYS:
                    raise SnapshotBrokerError(
                        "Snapshot broker error response schema is not exact"
                    )
                raise SnapshotBrokerError(
                    "Snapshot broker rejected acquisition: "
                    + str(response.get("message"))
                )
            if descriptor is None:
                raise SnapshotBrokerError(
                    "Snapshot broker success response omitted the lease descriptor"
                )
            if (
                set(response) != ACQUIRE_RESPONSE_KEYS
                or response.get("schema_version") != BROKER_SCHEMA_VERSION
                or response.get("protocol_id") != BROKER_PROTOCOL_ID
                or response.get("operation") != "acquire"
                or response.get("request_id") != request["request_id"]
            ):
                raise SnapshotBrokerError(
                    "Snapshot broker acquisition response schema is not exact"
                )
            payload = verify_signed_envelope(
                response["attestation"], kind="snapshot-acquired"
            )
            if self.runtime_binding is None:
                raise SnapshotBrokerError(
                    "Snapshot broker runtime provenance was not checked"
                )
            expected_request_sha = canonical_json_sha256(request)
            if (
                payload["request_sha256"] != expected_request_sha
                or payload["request_nonce"] != request["nonce"]
                or payload["source_commit"] != source_commit
                or payload["tree_oid"] != tree_oid
                or payload["materialization_policy"] != materialization_policy
                or payload["task_id"] != task_id
                or payload["attempt"] != attempt
                or payload["actor"] != actor
                or payload["run_id"] != run_id
                or payload["validation_contract_sha256"] != validation_contract_sha256
                or payload["snapshot_sha256"] != expected_snapshot_sha256
                or payload["broker_runtime_manifest_sha256"]
                != self.runtime_binding["manifest_sha256"]
                or payload["expires_at"] < int(time.time())
            ):
                raise SnapshotBrokerError(
                    "Snapshot broker acquisition proof does not match the request"
                )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o555
                or metadata.st_dev != payload["snapshot_device"]
                or metadata.st_ino != payload["snapshot_inode"]
            ):
                raise SnapshotBrokerError(
                    "Received snapshot descriptor identity is invalid"
                )
            snapshot = response.get("snapshot")
            if (
                not isinstance(snapshot, dict)
                or snapshot.get("source_commit") != source_commit
                or snapshot.get("tree_oid") != tree_oid
                or snapshot.get("sha256") != payload["snapshot_sha256"]
            ):
                raise SnapshotBrokerError(
                    "Broker snapshot manifest does not match its signature"
                )
            attestation_sha = canonical_json_sha256(response["attestation"])
            return BrokerLease(
                client=self,
                lease_id=payload["lease_id"],
                descriptor=descriptor,
                snapshot_root=Path(f"/proc/self/fd/{descriptor}"),
                snapshot=snapshot,
                acquire_attestation=response["attestation"],
                acquire_attestation_sha256=attestation_sha,
                task_id=task_id,
                attempt=attempt,
                actor=actor,
                run_id=run_id,
                validation_contract_sha256=validation_contract_sha256,
            )
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise

    def release(
        self,
        lease: BrokerLease,
        *,
        receipt_preimage_sha256: str,
    ) -> dict[str, Any]:
        if lease.release_request is None:
            lease.release_request = self._request(
                "release",
                lease_id=lease.lease_id,
                acquire_attestation_sha256=lease.acquire_attestation_sha256,
                task_id=lease.task_id,
                attempt=lease.attempt,
                actor=lease.actor,
                run_id=lease.run_id,
                validation_contract_sha256=lease.validation_contract_sha256,
                receipt_preimage_sha256=receipt_preimage_sha256,
            )
        request = lease.release_request
        if request["receipt_preimage_sha256"] != receipt_preimage_sha256:
            raise SnapshotBrokerError(
                "Snapshot broker cleanup retry changed the receipt preimage"
            )
        with self._connect() as connection:
            connection.sendall(encode_frame(request))
            response = decode_frame_from_stream(connection.makefile("rb", buffering=0))
        if response.get("ok") is not True:
            if set(response) != ERROR_RESPONSE_KEYS:
                raise SnapshotBrokerError(
                    "Snapshot broker cleanup error schema is not exact"
                )
            raise SnapshotBrokerError(
                "Snapshot broker refused cleanup: " + str(response.get("message"))
            )
        if (
            set(response) != RELEASE_RESPONSE_KEYS
            or response.get("schema_version") != BROKER_SCHEMA_VERSION
            or response.get("protocol_id") != BROKER_PROTOCOL_ID
            or response.get("operation") != "release"
            or response.get("request_id") != request["request_id"]
        ):
            raise SnapshotBrokerError(
                "Snapshot broker cleanup response schema is not exact"
            )
        cleanup = response["cleanup_attestation"]
        payload = verify_signed_envelope(cleanup, kind="snapshot-cleaned")
        if self.runtime_binding is None:
            raise SnapshotBrokerError(
                "Snapshot broker runtime provenance was not checked"
            )
        acquire_payload = lease.acquire_attestation["payload"]
        if (
            payload["request_sha256"] != canonical_json_sha256(request)
            or payload["request_nonce"] != request["nonce"]
            or payload["lease_id"] != lease.lease_id
            or payload["acquire_attestation_sha256"] != lease.acquire_attestation_sha256
            or payload["snapshot_sha256"] != lease.snapshot["sha256"]
            or payload["snapshot_device"] != acquire_payload["snapshot_device"]
            or payload["snapshot_inode"] != acquire_payload["snapshot_inode"]
            or payload["task_id"] != lease.task_id
            or payload["attempt"] != lease.attempt
            or payload["actor"] != lease.actor
            or payload["run_id"] != lease.run_id
            or payload["validation_contract_sha256"] != lease.validation_contract_sha256
            or payload["receipt_preimage_sha256"] != receipt_preimage_sha256
            or payload["broker_runtime_manifest_sha256"]
            != self.runtime_binding["manifest_sha256"]
            or payload["namespace_removed"] is not True
        ):
            raise SnapshotBrokerError(
                "Snapshot broker cleanup proof does not match the lease"
            )
        return cleanup


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cogni-snapshot-broker")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("serve", help="run the fixed-path root snapshot daemon")
    subcommands.add_parser("contract", help="print the fixed production contract")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    if arguments.command == "contract":
        print(
            json.dumps(
                {
                    "schema_version": BROKER_SCHEMA_VERSION,
                    "protocol_id": BROKER_PROTOCOL_ID,
                    "socket_path": str(BROKER_SOCKET_PATH),
                    "store_root": str(BROKER_STORE_ROOT),
                    "nonce_root": str(BROKER_NONCE_ROOT),
                    "transport": (
                        "AF_UNIX-SO_PEERCRED-SCM_RIGHTS-"
                        "sealed-source-to-O_PATH-snapshot"
                    ),
                    "source_authenticity": "not-attested-by-broker",
                    "signature": "Ed25519 detached via fixed SHA-bound OpenSSL",
                    "cleanup": "broker-only-signed-ack",
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    SnapshotBrokerDaemon().serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
