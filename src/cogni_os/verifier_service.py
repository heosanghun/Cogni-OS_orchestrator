"""Minimal durable coordinator for the dedicated verifier protocol.

This contribution deliberately does not execute validation commands, verify a
Ledger Authority Ed25519 signature, operate the privileged snapshot broker, or
append a terminal ledger event.  It provides the smallest durable service
unit: exact dispatch/wakeup binding, one-time journal claim, verified receipt
persistence, and the ``CLEANUP_ACKED -> RECEIPT_PERSISTED`` transition.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Final

from .verifier_journal import (
    CLEANUP_ACKED,
    RECEIPT_PERSISTED,
    VerifierJournal,
    VerifierJournalClaim,
    VerifierJournalError,
    VerifierJournalRecord,
)
from .verifier_protocol import (
    VerifierProtocolError,
    canonical_json_bytes,
    validate_dispatch,
    validate_wakeup,
)
from .verifier_receipt import verify_verification_receipt

SERVICE_ASSURANCE_SCOPE: Final = (
    "protocol-receipt-journal-only-ledger-ed25519-unimplemented"
)
SERVICE_RELEASE_BLOCKERS: Final = (
    "ledger_authority_ed25519_verification_unimplemented",
    "retained_source_execution_unimplemented",
    "ubuntu_root_systemd_bwrap_e2e_unverified",
    "linux_posix_root_dirfd_e2e_unverified",
)
MAX_RECEIPT_STORE_ENTRIES: Final = 4096


class VerifierServiceError(VerifierProtocolError):
    """The minimal verifier service state link failed closed."""


def _validate_posix_receipt_root_policy(
    metadata: Any,
    ancestor_metadata: tuple[Any, ...],
    *,
    euid: int,
    egid: int,
) -> None:
    """Validate the POSIX ownership policy without performing syscalls."""

    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != euid
        or metadata.st_gid != egid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise VerifierServiceError("Verifier receipt store must be euid/egid 0700")
    if any(
        not stat.S_ISDIR(ancestor.st_mode)
        or stat.S_ISLNK(ancestor.st_mode)
        or ancestor.st_uid not in {0, euid}
        or ancestor.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        for ancestor in ancestor_metadata
    ):
        raise VerifierServiceError(
            "Verifier receipt ancestry is not owner-protected"
        )


def _validate_posix_receipt_root_identity(
    metadata: Any,
    *,
    expected_identity: tuple[int, int],
    euid: int,
    egid: int,
) -> None:
    """Validate a path/fd stat result against the pinned directory identity."""

    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != expected_identity
        or metadata.st_uid != euid
        or metadata.st_gid != egid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise VerifierServiceError(
            "Verifier receipt root identity or protection changed"
        )


@dataclass(frozen=True)
class PersistedVerifierReceipt:
    record: VerifierJournalRecord
    path: Path
    sha256: str
    idempotent: bool


class DedicatedVerifierService:
    """Bind exact protocol documents to the crash-safe verifier journal."""

    def __init__(
        self,
        *,
        journal: VerifierJournal,
        receipt_root: Path,
        clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        self.journal = journal
        self.receipt_root = Path(os.path.abspath(os.fspath(receipt_root)))
        self._clock = clock
        self._receipt_dir_fd: int | None = None
        self._receipt_dir_identity: tuple[int, int] | None = None
        self._prepare_receipt_root()

    def close(self) -> None:
        descriptor = self._receipt_dir_fd
        self._receipt_dir_fd = None
        if descriptor is not None:
            os.close(descriptor)

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    @property
    def assurance(self) -> dict[str, Any]:
        return {
            "scope": SERVICE_ASSURANCE_SCOPE,
            "release_ready": False,
            "release_blockers": list(SERVICE_RELEASE_BLOCKERS),
            "journal_scope": self.journal.assurance_scope,
        }

    def claim_dispatch(
        self,
        dispatch: dict[str, Any],
        wakeup: dict[str, Any],
    ) -> VerifierJournalClaim:
        """Consume one exact wakeup only when it matches the full dispatch.

        The socket packet conveys no authority.  Matching it to the full
        dispatch prevents a caller from substituting task/run/nonce while the
        journal's exclusive marker prevents duplicate execution ownership.
        Ledger Authority Ed25519 verification remains an explicit release
        blocker and must precede this method in the future full service.
        """

        request = validate_dispatch(dispatch, now=self._clock())
        signal = validate_wakeup(wakeup)
        for key in ("dispatch_event_hash", "task_id", "run_id", "nonce"):
            if request[key] != signal[key]:
                raise VerifierServiceError(
                    f"Verifier wakeup does not match dispatch field {key}"
                )
        try:
            return self.journal.claim_dispatch(
                request["dispatch_event_hash"],
                task_id=request["task_id"],
                attempt=request["attempt"],
                actor=request["actor"],
                run_id=request["run_id"],
            )
        except VerifierJournalError as exc:
            raise VerifierServiceError("Verifier dispatch journal claim failed") from exc

    def persist_receipt(
        self,
        dispatch: dict[str, Any],
        receipt: dict[str, Any],
    ) -> PersistedVerifierReceipt:
        """Persist one verified receipt, then advance the durable journal.

        A crash after the exclusive receipt write but before the journal
        transition is recoverable: the retry accepts only byte-identical
        canonical content and then performs the pending transition.
        """

        request = validate_dispatch(dispatch, now=dispatch["issued_at"])
        try:
            document = verify_verification_receipt(receipt, dispatch=request)
        except Exception as exc:
            raise VerifierServiceError("Verifier receipt verification failed") from exc
        dispatch_hash = request["dispatch_event_hash"]
        try:
            record = self.journal.load(dispatch_hash)
        except (FileNotFoundError, VerifierJournalError) as exc:
            raise VerifierServiceError("Verifier receipt has no claimed dispatch") from exc
        expected_identity = (
            request["task_id"],
            request["attempt"],
            request["actor"],
            request["run_id"],
        )
        actual_identity = (
            record.task_id,
            record.attempt,
            record.actor,
            record.run_id,
        )
        if actual_identity != expected_identity:
            raise VerifierServiceError("Verifier receipt and journal identity disagree")
        if record.state not in {CLEANUP_ACKED, RECEIPT_PERSISTED}:
            raise VerifierServiceError(
                "Verifier receipt may persist only after cleanup acknowledgement"
            )

        encoded = canonical_json_bytes(document)
        receipt_path = self.receipt_root / f"{dispatch_hash}.receipt.json"
        idempotent = self._persist_exact(receipt_path, encoded)
        digest = hashlib.sha256(encoded).hexdigest()
        if record.state == CLEANUP_ACKED:
            try:
                record = self.journal.transition(
                    dispatch_hash,
                    RECEIPT_PERSISTED,
                    expected_revision=record.revision,
                )
            except VerifierJournalError as exc:
                raise VerifierServiceError(
                    "Verifier receipt journal transition failed"
                ) from exc
        return PersistedVerifierReceipt(
            record=record,
            path=receipt_path,
            sha256=digest,
            idempotent=idempotent,
        )

    def _prepare_receipt_root(self) -> None:
        self.receipt_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            metadata = self.receipt_root.stat(follow_symlinks=False)
        except OSError as exc:
            raise VerifierServiceError("Verifier receipt store is unavailable") from exc
        attributes = getattr(metadata, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or bool(attributes & reparse)
        ):
            raise VerifierServiceError("Verifier receipt store is not a plain directory")
        if os.name != "posix":
            return
        ancestors: list[Any] = []
        for ancestor in self.receipt_root.parents:
            try:
                ancestors.append(ancestor.stat(follow_symlinks=False))
            except OSError as exc:
                raise VerifierServiceError(
                    "Verifier receipt ancestry is unavailable"
                ) from exc
        _validate_posix_receipt_root_policy(
            metadata,
            tuple(ancestors),
            euid=os.geteuid(),
            egid=os.getegid(),
        )
        flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(self.receipt_root, flags)
            opened = os.fstat(descriptor)
        except OSError as exc:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise VerifierServiceError("Verifier receipt dirfd open failed") from exc
        try:
            _validate_posix_receipt_root_identity(
                opened,
                expected_identity=(metadata.st_dev, metadata.st_ino),
                euid=os.geteuid(),
                egid=os.getegid(),
            )
        except VerifierServiceError:
            os.close(descriptor)
            raise
        self._receipt_dir_fd = descriptor
        self._receipt_dir_identity = (opened.st_dev, opened.st_ino)

    def _persist_exact(self, path: Path, encoded: bytes) -> bool:
        self._require_receipt_root_identity()
        if self._receipt_dir_fd is not None:
            names = os.listdir(self._receipt_dir_fd)
        else:
            names = [entry.name for entry in self.receipt_root.iterdir()]
        if path.name not in set(names) and len(names) >= MAX_RECEIPT_STORE_ENTRIES:
            raise VerifierServiceError("Verifier receipt store exceeds its entry limit")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if self._receipt_dir_fd is not None and hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            if self._receipt_dir_fd is None:
                descriptor = os.open(path, flags, 0o600)
            else:
                descriptor = os.open(
                    path.name,
                    flags,
                    0o600,
                    dir_fd=self._receipt_dir_fd,
                )
        except FileExistsError:
            existing_descriptor: int | None = None
            try:
                read_flags = os.O_RDONLY
                if hasattr(os, "O_BINARY"):
                    read_flags |= os.O_BINARY
                if self._receipt_dir_fd is not None and hasattr(os, "O_NOFOLLOW"):
                    read_flags |= os.O_NOFOLLOW
                if self._receipt_dir_fd is None:
                    path_metadata = path.stat(follow_symlinks=False)
                    path_attributes = getattr(path_metadata, "st_file_attributes", 0)
                    path_reparse = getattr(
                        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                    )
                    if stat.S_ISLNK(path_metadata.st_mode) or bool(
                        path_attributes & path_reparse
                    ):
                        raise OSError("existing verifier receipt path is unsafe")
                    existing_descriptor = os.open(path, read_flags)
                else:
                    existing_descriptor = os.open(
                        path.name,
                        read_flags,
                        dir_fd=self._receipt_dir_fd,
                    )
                metadata = os.fstat(existing_descriptor)
                attributes = getattr(metadata, "st_file_attributes", 0)
                reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            except OSError as exc:
                if existing_descriptor is not None:
                    try:
                        os.close(existing_descriptor)
                    except OSError:
                        pass
                raise VerifierServiceError(
                    "Existing verifier receipt is unreadable"
                ) from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or bool(attributes & reparse)
                or metadata.st_nlink != 1
                or metadata.st_size != len(encoded)
            ):
                os.close(existing_descriptor)
                raise VerifierServiceError(
                    "Existing verifier receipt differs or is unsafe"
                )
            try:
                os.lseek(existing_descriptor, 0, os.SEEK_SET)
                existing = bytearray()
                remaining = len(encoded)
                while remaining:
                    chunk = os.read(existing_descriptor, min(remaining, 64 * 1024))
                    if not chunk:
                        raise OSError("existing verifier receipt is truncated")
                    existing.extend(chunk)
                    remaining -= len(chunk)
                if os.read(existing_descriptor, 1):
                    raise OSError("existing verifier receipt exceeds its bound")
            except OSError as exc:
                raise VerifierServiceError(
                    "Existing verifier receipt is unreadable"
                ) from exc
            finally:
                os.close(existing_descriptor)
            if bytes(existing) != encoded:
                raise VerifierServiceError(
                    "Existing verifier receipt differs or is unsafe"
                )
            self._require_receipt_root_identity()
            self._fsync_receipt_root()
            return True
        except OSError as exc:
            raise VerifierServiceError("Verifier receipt create failed") from exc
        write_error: OSError | None = None
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short verifier receipt write")
                view = view[written:]
            os.fsync(descriptor)
            self._verify_new_receipt_descriptor(descriptor, encoded)
        except OSError as exc:
            write_error = exc
        finally:
            try:
                os.close(descriptor)
            except OSError as exc:
                if write_error is None:
                    write_error = exc
        if write_error is not None:
            try:
                if self._receipt_dir_fd is None:
                    path.unlink(missing_ok=True)
                else:
                    try:
                        os.unlink(path.name, dir_fd=self._receipt_dir_fd)
                    except FileNotFoundError:
                        pass
                self._fsync_receipt_root()
            except OSError as cleanup_error:
                raise VerifierServiceError(
                    "Verifier receipt failed validation and cleanup failed"
                ) from cleanup_error
            raise VerifierServiceError(
                "Verifier receipt durable write failed"
            ) from write_error
        self._require_receipt_root_identity()
        self._fsync_receipt_root()
        return False

    def _require_receipt_root_identity(self) -> None:
        if os.name != "posix":
            return
        if self._receipt_dir_identity is None:
            raise VerifierServiceError("Verifier receipt dirfd identity is unavailable")
        try:
            metadata = self.receipt_root.stat(follow_symlinks=False)
        except OSError as exc:
            raise VerifierServiceError("Verifier receipt root path is unavailable") from exc
        _validate_posix_receipt_root_identity(
            metadata,
            expected_identity=self._receipt_dir_identity,
            euid=os.geteuid(),
            egid=os.getegid(),
        )

    def _verify_new_receipt_descriptor(self, descriptor: int, encoded: bytes) -> None:
        metadata = os.fstat(descriptor)
        attributes = getattr(metadata, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or bool(attributes & reparse)
            or metadata.st_nlink != 1
            or metadata.st_size != len(encoded)
        ):
            raise OSError("new verifier receipt identity is unsafe")
        if os.name == "posix" and (
            metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OSError("new verifier receipt ownership or mode is unsafe")

        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = hashlib.sha256()
        remaining = len(encoded)
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise OSError("new verifier receipt readback was truncated")
            observed.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("new verifier receipt readback exceeded its bound")
        expected_digest = hashlib.sha256(encoded).digest()
        if not hmac.compare_digest(observed.digest(), expected_digest):
            raise OSError("new verifier receipt readback digest mismatch")

    def _fsync_receipt_root(self) -> None:
        if os.name != "posix":
            return
        if self._receipt_dir_fd is None or self._receipt_dir_identity is None:
            raise OSError("Verifier receipt dirfd is unavailable")
        metadata = os.fstat(self._receipt_dir_fd)
        try:
            _validate_posix_receipt_root_identity(
                metadata,
                expected_identity=self._receipt_dir_identity,
                euid=os.geteuid(),
                egid=os.getegid(),
            )
        except VerifierServiceError as exc:
            raise OSError("Verifier receipt dirfd identity or protection changed") from exc
        os.fsync(self._receipt_dir_fd)
