"""Crash-safe state journal for the dedicated Cogni-OS verifier.

This module records *control-plane state only*.  It does not authenticate a
dispatch, execute a validation command, sign a receipt, append to the ledger,
or prove that the privileged Linux verifier service is correctly installed.
Those trust boundaries deliberately live in separate components.

The production verifier is a single writer.  This journal nevertheless uses
an ``O_CREAT|O_EXCL`` claim marker so that duplicate wake-ups for the same
signed dispatch event cannot reset a run or create a second execution.  Every
mutable record update is written to a same-directory temporary file, fsynced,
atomically replaced, and followed by a parent-directory fsync on POSIX.
Portable Windows operation exists for unit testing only because Python cannot
provide the same directory-fsync/openat guarantees there.
"""

from __future__ import annotations

import json
import os
import re
import stat
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

JOURNAL_ID: Final = "cogni-os.verifier-journal.v1"
JOURNAL_SCHEMA_VERSION: Final = 1
MAX_JOURNAL_RECORD_BYTES: Final = 4096
MAX_JOURNAL_RECORDS: Final = 4096
MAX_DIRECTORY_ENTRIES_SCANNED: Final = (MAX_JOURNAL_RECORDS * 3) + 32
MAX_TASK_ID_BYTES: Final = 80
MAX_ACTOR_BYTES: Final = 50
MAX_FAILURE_CODE_BYTES: Final = 64
MAX_QUARANTINE_REASON_BYTES: Final = 512
MAX_ATTEMPT: Final = 1_000_000

_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_ACTOR_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,49}$")
_FAILURE_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

REQUESTED: Final = "REQUESTED"
CLAIMED: Final = "CLAIMED"
SOURCE_VERIFIED: Final = "SOURCE_VERIFIED"
SNAPSHOT_ACQUIRED: Final = "SNAPSHOT_ACQUIRED"
EXECUTING: Final = "EXECUTING"
EXECUTION_SEALED: Final = "EXECUTION_SEALED"
RELEASE_PENDING: Final = "RELEASE_PENDING"
CLEANUP_ACKED: Final = "CLEANUP_ACKED"
RECEIPT_PERSISTED: Final = "RECEIPT_PERSISTED"
TERMINAL_APPENDED: Final = "TERMINAL_APPENDED"
DONE: Final = "DONE"
FAILED: Final = "FAILED"
QUARANTINED: Final = "QUARANTINED"
CRASH_ABORTED: Final = "CRASH_ABORTED"
FAILED_CLEANUP_REQUIRED: Final = "FAILED_CLEANUP_REQUIRED"

NORMAL_STATES: Final = frozenset(
    {
        REQUESTED,
        CLAIMED,
        SOURCE_VERIFIED,
        SNAPSHOT_ACQUIRED,
        EXECUTING,
        EXECUTION_SEALED,
        RELEASE_PENDING,
        CLEANUP_ACKED,
        RECEIPT_PERSISTED,
        TERMINAL_APPENDED,
        DONE,
    }
)
FAILURE_STATES: Final = frozenset(
    {FAILED, QUARANTINED, CRASH_ABORTED, FAILED_CLEANUP_REQUIRED}
)
ALL_STATES: Final = NORMAL_STATES | FAILURE_STATES
TERMINAL_STATES: Final = frozenset({DONE, FAILED, QUARANTINED})

# FAILED is only safe before a snapshot lease exists.  Once a snapshot is
# acquired, failures must be sealed and cleanup must run, or the record must be
# quarantined for operator handling.  CRASH_ABORTED is reachable only through
# recover(), never through the public transition method.
ALLOWED_TRANSITIONS: Final[Mapping[str, frozenset[str]]] = {
    REQUESTED: frozenset({CLAIMED, FAILED, QUARANTINED}),
    CLAIMED: frozenset({SOURCE_VERIFIED, FAILED, QUARANTINED}),
    SOURCE_VERIFIED: frozenset({SNAPSHOT_ACQUIRED, FAILED, QUARANTINED}),
    SNAPSHOT_ACQUIRED: frozenset({EXECUTING}),
    EXECUTING: frozenset({EXECUTION_SEALED}),
    EXECUTION_SEALED: frozenset({RELEASE_PENDING}),
    CRASH_ABORTED: frozenset({RELEASE_PENDING}),
    FAILED_CLEANUP_REQUIRED: frozenset({RELEASE_PENDING}),
    RELEASE_PENDING: frozenset({CLEANUP_ACKED}),
    CLEANUP_ACKED: frozenset({RECEIPT_PERSISTED, QUARANTINED}),
    RECEIPT_PERSISTED: frozenset({TERMINAL_APPENDED, QUARANTINED}),
    TERMINAL_APPENDED: frozenset({DONE, QUARANTINED}),
    DONE: frozenset(),
    FAILED: frozenset(),
    QUARANTINED: frozenset(),
}

_RECORD_KEYS: Final = frozenset(
    {
        "schema_version",
        "journal_id",
        "dispatch_event_hash",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "state",
        "previous_state",
        "revision",
        "created_at_ns",
        "updated_at_ns",
        "failure_code",
        "quarantine_reason",
    }
)
_CLAIM_KEYS: Final = frozenset(
    {
        "schema_version",
        "journal_id",
        "dispatch_event_hash",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "claimed_at_ns",
    }
)


class VerifierJournalError(RuntimeError):
    """Raised when a verifier journal operation must fail closed."""


@dataclass(frozen=True)
class VerifierJournalRecord:
    schema_version: int
    journal_id: str
    dispatch_event_hash: str
    task_id: str
    attempt: int
    actor: str
    run_id: str
    state: str
    previous_state: str | None
    revision: int
    created_at_ns: int
    updated_at_ns: int
    failure_code: str | None
    quarantine_reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "journal_id": self.journal_id,
            "dispatch_event_hash": self.dispatch_event_hash,
            "task_id": self.task_id,
            "attempt": self.attempt,
            "actor": self.actor,
            "run_id": self.run_id,
            "state": self.state,
            "previous_state": self.previous_state,
            "revision": self.revision,
            "created_at_ns": self.created_at_ns,
            "updated_at_ns": self.updated_at_ns,
            "failure_code": self.failure_code,
            "quarantine_reason": self.quarantine_reason,
        }

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def release_retry_required(self) -> bool:
        return self.state in {
            CRASH_ABORTED,
            FAILED_CLEANUP_REQUIRED,
            RELEASE_PENDING,
        }


@dataclass(frozen=True)
class VerifierJournalClaim:
    """Result of a dispatch claim.

    ``claim_acquired`` is true only for the process that created the exclusive
    claim marker.  A duplicate always receives the existing record with this
    flag false and therefore has no permission to start another execution.
    """

    record: VerifierJournalRecord
    new_dispatch: bool
    claim_acquired: bool


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
        raise VerifierJournalError("Journal value is not canonical JSON") from exc
    if len(encoded) > MAX_JOURNAL_RECORD_BYTES:
        raise VerifierJournalError("Journal record exceeds the fixed size limit")
    return encoded


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _validate_utf8_identifier(
    value: object,
    *,
    name: str,
    maximum_bytes: int,
    pattern: re.Pattern[str],
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise VerifierJournalError(f"Invalid {name}")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise VerifierJournalError(f"{name} exceeds its fixed size limit")
    return value


def _validate_optional_text(
    value: object, *, name: str, maximum_bytes: int
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise VerifierJournalError(f"Invalid {name}")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise VerifierJournalError(f"{name} exceeds its fixed size limit")
    if any(ord(character) < 0x20 for character in value):
        raise VerifierJournalError(f"{name} contains a control character")
    return value


def _validate_dispatch_hash(value: object) -> str:
    if not isinstance(value, str) or not _HEX_64_RE.fullmatch(value):
        raise VerifierJournalError(
            "dispatch_event_hash must be 64 lowercase hexadecimal characters"
        )
    return value


def _validate_record(value: object) -> VerifierJournalRecord:
    if not isinstance(value, dict) or frozenset(value) != _RECORD_KEYS:
        raise VerifierJournalError("Verifier journal record schema is not exact")
    if value["schema_version"] != JOURNAL_SCHEMA_VERSION:
        raise VerifierJournalError("Unsupported verifier journal schema version")
    if value["journal_id"] != JOURNAL_ID:
        raise VerifierJournalError("Unexpected verifier journal identifier")

    dispatch_hash = _validate_dispatch_hash(value["dispatch_event_hash"])
    task_id = _validate_utf8_identifier(
        value["task_id"],
        name="task_id",
        maximum_bytes=MAX_TASK_ID_BYTES,
        pattern=_TASK_ID_RE,
    )
    actor = _validate_utf8_identifier(
        value["actor"],
        name="actor",
        maximum_bytes=MAX_ACTOR_BYTES,
        pattern=_ACTOR_RE,
    )
    run_id = _validate_utf8_identifier(
        value["run_id"],
        name="run_id",
        maximum_bytes=32,
        pattern=_RUN_ID_RE,
    )
    attempt = value["attempt"]
    if isinstance(attempt, bool) or not isinstance(attempt, int):
        raise VerifierJournalError("attempt must be an integer")
    if attempt < 1 or attempt > MAX_ATTEMPT:
        raise VerifierJournalError("attempt is outside the fixed range")

    state = value["state"]
    if not isinstance(state, str) or state not in ALL_STATES:
        raise VerifierJournalError("Unknown verifier journal state")
    previous_state = value["previous_state"]
    if previous_state is not None and (
        not isinstance(previous_state, str) or previous_state not in ALL_STATES
    ):
        raise VerifierJournalError("Unknown previous verifier journal state")

    revision = value["revision"]
    created_at_ns = value["created_at_ns"]
    updated_at_ns = value["updated_at_ns"]
    for number, name in (
        (revision, "revision"),
        (created_at_ns, "created_at_ns"),
        (updated_at_ns, "updated_at_ns"),
    ):
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise VerifierJournalError(f"{name} must be a non-negative integer")
        if number > (2**63) - 1:
            raise VerifierJournalError(f"{name} exceeds its fixed range")
    if updated_at_ns < created_at_ns:
        raise VerifierJournalError("Journal timestamps are not monotonic")
    if revision == 0 and previous_state is not None:
        raise VerifierJournalError("Initial journal record has a previous state")
    if revision > 0 and previous_state is None:
        raise VerifierJournalError("Updated journal record lacks a previous state")

    failure_code = _validate_optional_text(
        value["failure_code"],
        name="failure_code",
        maximum_bytes=MAX_FAILURE_CODE_BYTES,
    )
    if failure_code is not None and not _FAILURE_CODE_RE.fullmatch(failure_code):
        raise VerifierJournalError("Invalid failure_code")
    quarantine_reason = _validate_optional_text(
        value["quarantine_reason"],
        name="quarantine_reason",
        maximum_bytes=MAX_QUARANTINE_REASON_BYTES,
    )
    if (
        state in {FAILED, CRASH_ABORTED, FAILED_CLEANUP_REQUIRED}
        and failure_code is None
    ):
        raise VerifierJournalError("Failure state requires failure_code")
    if state == QUARANTINED and (failure_code is None or quarantine_reason is None):
        raise VerifierJournalError(
            "QUARANTINED requires failure_code and quarantine_reason"
        )
    failure_carry_states = {
        RELEASE_PENDING,
        CLEANUP_ACKED,
        RECEIPT_PERSISTED,
        TERMINAL_APPENDED,
        DONE,
    }
    if state not in FAILURE_STATES | failure_carry_states and failure_code is not None:
        raise VerifierJournalError("State cannot carry failure metadata")
    if state != QUARANTINED and quarantine_reason is not None:
        raise VerifierJournalError("Non-quarantine failure carries a reason")

    return VerifierJournalRecord(
        schema_version=JOURNAL_SCHEMA_VERSION,
        journal_id=JOURNAL_ID,
        dispatch_event_hash=dispatch_hash,
        task_id=task_id,
        attempt=attempt,
        actor=actor,
        run_id=run_id,
        state=state,
        previous_state=previous_state,
        revision=revision,
        created_at_ns=created_at_ns,
        updated_at_ns=updated_at_ns,
        failure_code=failure_code,
        quarantine_reason=quarantine_reason,
    )


class VerifierJournal:
    """Bounded, single-writer verifier state journal."""

    def __init__(
        self,
        root: Path,
        *,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        self._clock_ns = clock_ns
        self._lock = threading.RLock()
        self._prepare_root()

    @property
    def assurance_scope(self) -> str:
        if os.name == "posix":
            return "filesystem-durability-only-not-root-e2e"
        return "portable-semantics-only"

    def claim_dispatch(
        self,
        dispatch_event_hash: str,
        *,
        task_id: str,
        attempt: int,
        actor: str,
        run_id: str,
    ) -> VerifierJournalClaim:
        """Record and exclusively claim a dispatch without resetting duplicates."""

        identity = self._validated_identity(
            dispatch_event_hash,
            task_id=task_id,
            attempt=attempt,
            actor=actor,
            run_id=run_id,
        )
        with self._lock:
            new_dispatch = False
            try:
                record = self.load(dispatch_event_hash)
            except FileNotFoundError:
                self._ensure_capacity_for_new_record()
                now = self._now_ns()
                requested = VerifierJournalRecord(
                    schema_version=JOURNAL_SCHEMA_VERSION,
                    journal_id=JOURNAL_ID,
                    dispatch_event_hash=dispatch_event_hash,
                    task_id=task_id,
                    attempt=attempt,
                    actor=actor,
                    run_id=run_id,
                    state=REQUESTED,
                    previous_state=None,
                    revision=0,
                    created_at_ns=now,
                    updated_at_ns=now,
                    failure_code=None,
                    quarantine_reason=None,
                )
                try:
                    self._write_exclusive(
                        self._record_name(dispatch_event_hash),
                        _canonical_json_bytes(requested.as_dict()),
                    )
                    record = requested
                    new_dispatch = True
                except FileExistsError:
                    record = self.load(dispatch_event_hash)

            self._require_same_identity(record, identity)
            marker = {
                "schema_version": JOURNAL_SCHEMA_VERSION,
                "journal_id": JOURNAL_ID,
                "dispatch_event_hash": dispatch_event_hash,
                "task_id": task_id,
                "attempt": attempt,
                "actor": actor,
                "run_id": run_id,
                "claimed_at_ns": self._now_ns(),
            }
            claim_acquired = False
            try:
                self._write_exclusive(
                    self._claim_name(dispatch_event_hash),
                    _canonical_json_bytes(marker),
                )
                claim_acquired = True
            except FileExistsError:
                stored_marker = self._read_json_exact(
                    self._claim_name(dispatch_event_hash), _CLAIM_KEYS
                )
                self._validate_claim_marker(stored_marker, identity)

            # A crash can occur after the exclusive marker is durable but before
            # the state replace.  A later wake-up may complete this harmless
            # REQUESTED -> CLAIMED transition, but it does not acquire execution
            # ownership and returns claim_acquired=False.
            record = self.load(dispatch_event_hash)
            if record.state == REQUESTED:
                record = self.transition(
                    dispatch_event_hash,
                    CLAIMED,
                    expected_revision=record.revision,
                )
            return VerifierJournalClaim(
                record=record,
                new_dispatch=new_dispatch,
                claim_acquired=claim_acquired,
            )

    def load(self, dispatch_event_hash: str) -> VerifierJournalRecord:
        dispatch_event_hash = _validate_dispatch_hash(dispatch_event_hash)
        value = self._read_json_exact(
            self._record_name(dispatch_event_hash), _RECORD_KEYS
        )
        record = _validate_record(value)
        if record.dispatch_event_hash != dispatch_event_hash:
            raise VerifierJournalError("Journal filename and dispatch hash disagree")
        return record

    def list_records(self) -> tuple[VerifierJournalRecord, ...]:
        with self._lock:
            names = self._bounded_directory_names()
            record_names = sorted(
                name
                for name in names
                if name.endswith(".json") and _HEX_64_RE.fullmatch(name[:-5])
            )
            if len(record_names) > MAX_JOURNAL_RECORDS:
                raise VerifierJournalError("Journal record count exceeds its limit")
            return tuple(self.load(name[:-5]) for name in record_names)

    def transition(
        self,
        dispatch_event_hash: str,
        new_state: str,
        *,
        expected_revision: int | None = None,
        failure_code: str | None = None,
        quarantine_reason: str | None = None,
    ) -> VerifierJournalRecord:
        dispatch_event_hash = _validate_dispatch_hash(dispatch_event_hash)
        if new_state in {CRASH_ABORTED, FAILED_CLEANUP_REQUIRED}:
            raise VerifierJournalError(f"{new_state} may only be written by recover()")
        with self._lock:
            current = self.load(dispatch_event_hash)
            if expected_revision is not None and current.revision != expected_revision:
                raise VerifierJournalError("Journal revision changed concurrently")
            if new_state not in ALLOWED_TRANSITIONS[current.state]:
                raise VerifierJournalError(
                    f"Illegal verifier journal transition: {current.state} -> {new_state}"
                )
            updated = self._next_record(
                current,
                new_state,
                failure_code=failure_code,
                quarantine_reason=quarantine_reason,
            )
            self._replace_record(updated)
            return updated

    def mark_failed(
        self, dispatch_event_hash: str, *, failure_code: str
    ) -> VerifierJournalRecord:
        return self.transition(dispatch_event_hash, FAILED, failure_code=failure_code)

    def quarantine(
        self,
        dispatch_event_hash: str,
        *,
        failure_code: str,
        reason: str,
    ) -> VerifierJournalRecord:
        return self.transition(
            dispatch_event_hash,
            QUARANTINED,
            failure_code=failure_code,
            quarantine_reason=reason,
        )

    def recover(self, dispatch_event_hash: str) -> VerifierJournalRecord:
        """Apply the fail-closed restart policy for one durable record."""

        dispatch_event_hash = _validate_dispatch_hash(dispatch_event_hash)
        with self._lock:
            current = self.load(dispatch_event_hash)
            if current.state not in {EXECUTING, SNAPSHOT_ACQUIRED}:
                # RELEASE_PENDING intentionally remains unchanged and retryable.
                return current
            if current.state == EXECUTING:
                recovery_state = CRASH_ABORTED
                failure_code = "verifier_crash_during_execution"
            else:
                recovery_state = FAILED_CLEANUP_REQUIRED
                failure_code = "verifier_restart_after_snapshot"
            aborted = self._next_record(
                current,
                recovery_state,
                failure_code=failure_code,
                quarantine_reason=None,
            )
            self._replace_record(aborted)
            return aborted

    def recover_all(self) -> tuple[VerifierJournalRecord, ...]:
        with self._lock:
            return tuple(
                self.recover(record.dispatch_event_hash)
                for record in self.list_records()
            )

    def _next_record(
        self,
        current: VerifierJournalRecord,
        new_state: str,
        *,
        failure_code: str | None,
        quarantine_reason: str | None,
    ) -> VerifierJournalRecord:
        updated = VerifierJournalRecord(
            schema_version=JOURNAL_SCHEMA_VERSION,
            journal_id=JOURNAL_ID,
            dispatch_event_hash=current.dispatch_event_hash,
            task_id=current.task_id,
            attempt=current.attempt,
            actor=current.actor,
            run_id=current.run_id,
            state=new_state,
            previous_state=current.state,
            revision=current.revision + 1,
            created_at_ns=current.created_at_ns,
            updated_at_ns=max(current.updated_at_ns, self._now_ns()),
            failure_code=(
                current.failure_code if failure_code is None else failure_code
            ),
            quarantine_reason=quarantine_reason,
        )
        return _validate_record(updated.as_dict())

    def _replace_record(self, record: VerifierJournalRecord) -> None:
        self._replace(
            self._record_name(record.dispatch_event_hash),
            _canonical_json_bytes(record.as_dict()),
        )

    def _validated_identity(
        self,
        dispatch_event_hash: str,
        *,
        task_id: str,
        attempt: int,
        actor: str,
        run_id: str,
    ) -> tuple[str, str, int, str, str]:
        value = {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "journal_id": JOURNAL_ID,
            "dispatch_event_hash": dispatch_event_hash,
            "task_id": task_id,
            "attempt": attempt,
            "actor": actor,
            "run_id": run_id,
            "state": REQUESTED,
            "previous_state": None,
            "revision": 0,
            "created_at_ns": 0,
            "updated_at_ns": 0,
            "failure_code": None,
            "quarantine_reason": None,
        }
        record = _validate_record(value)
        return (
            record.dispatch_event_hash,
            record.task_id,
            record.attempt,
            record.actor,
            record.run_id,
        )

    @staticmethod
    def _require_same_identity(
        record: VerifierJournalRecord,
        identity: tuple[str, str, int, str, str],
    ) -> None:
        actual = (
            record.dispatch_event_hash,
            record.task_id,
            record.attempt,
            record.actor,
            record.run_id,
        )
        if actual != identity:
            raise VerifierJournalError(
                "Duplicate dispatch hash has different bounded identifiers"
            )

    @staticmethod
    def _validate_claim_marker(
        marker: Mapping[str, Any],
        identity: tuple[str, str, int, str, str],
    ) -> None:
        if marker["schema_version"] != JOURNAL_SCHEMA_VERSION:
            raise VerifierJournalError("Unsupported claim marker schema version")
        if marker["journal_id"] != JOURNAL_ID:
            raise VerifierJournalError("Unexpected claim marker identifier")
        claimed_at_ns = marker["claimed_at_ns"]
        if (
            isinstance(claimed_at_ns, bool)
            or not isinstance(claimed_at_ns, int)
            or claimed_at_ns < 0
            or claimed_at_ns > (2**63) - 1
        ):
            raise VerifierJournalError("Invalid claim marker timestamp")
        marker_identity = (
            _validate_dispatch_hash(marker["dispatch_event_hash"]),
            _validate_utf8_identifier(
                marker["task_id"],
                name="task_id",
                maximum_bytes=MAX_TASK_ID_BYTES,
                pattern=_TASK_ID_RE,
            ),
            marker["attempt"],
            _validate_utf8_identifier(
                marker["actor"],
                name="actor",
                maximum_bytes=MAX_ACTOR_BYTES,
                pattern=_ACTOR_RE,
            ),
            _validate_utf8_identifier(
                marker["run_id"],
                name="run_id",
                maximum_bytes=32,
                pattern=_RUN_ID_RE,
            ),
        )
        if (
            isinstance(marker["attempt"], bool)
            or not isinstance(marker["attempt"], int)
            or marker["attempt"] < 1
            or marker["attempt"] > MAX_ATTEMPT
        ):
            raise VerifierJournalError("Invalid claim marker attempt")
        if marker_identity != identity:
            raise VerifierJournalError("Claim marker identity does not match dispatch")

    def _read_json_exact(
        self, name: str, expected_keys: frozenset[str]
    ) -> dict[str, Any]:
        raw = self._read_bounded(name)
        if not raw.endswith(b"\n"):
            raise VerifierJournalError("Journal JSON lacks its canonical newline")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VerifierJournalError("Journal file is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict) or frozenset(value) != expected_keys:
            raise VerifierJournalError("Journal file schema is not exact")
        if _canonical_json_bytes(value) != raw:
            raise VerifierJournalError("Journal file is not canonical JSON")
        return value

    def _prepare_root(self) -> None:
        parent = self.root.parent
        self._assert_safe_ancestry(parent, require_final_directory=True)
        try:
            self.root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        self._assert_safe_ancestry(self.root, require_final_directory=True)
        if os.name == "posix":
            os.chmod(self.root, 0o700)

    @staticmethod
    def _assert_safe_ancestry(path: Path, *, require_final_directory: bool) -> None:
        absolute = Path(os.path.abspath(os.fspath(path)))
        chain = list(reversed(absolute.parents)) + [absolute]
        for index, component in enumerate(chain):
            try:
                metadata = os.lstat(component)
            except FileNotFoundError as exc:
                raise VerifierJournalError(
                    f"Journal ancestry does not exist: {component}"
                ) from exc
            if _is_link_or_reparse(metadata):
                raise VerifierJournalError(
                    f"Journal ancestry contains a symlink/reparse point: {component}"
                )
            if (
                index == len(chain) - 1
                and require_final_directory
                and not stat.S_ISDIR(metadata.st_mode)
            ):
                raise VerifierJournalError(
                    f"Journal path is not a directory: {component}"
                )

    def _open_root_fd(self) -> int:
        self._assert_safe_ancestry(self.root, require_final_directory=True)
        flags = os.O_RDONLY
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.root, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise VerifierJournalError("Journal root descriptor is not a directory")
        return descriptor

    def _read_bounded(self, name: str) -> bytes:
        if os.name == "posix":
            root_fd = self._open_root_fd()
            descriptor = -1
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_fd,
                )
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise VerifierJournalError("Journal entry is not a regular file")
                if metadata.st_size > MAX_JOURNAL_RECORD_BYTES:
                    raise VerifierJournalError("Journal entry exceeds the size limit")
                chunks: list[bytes] = []
                remaining = MAX_JOURNAL_RECORD_BYTES + 1
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 64 * 1024))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                if len(raw) > MAX_JOURNAL_RECORD_BYTES:
                    raise VerifierJournalError("Journal entry exceeds the size limit")
                return raw
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(root_fd)

        self._assert_safe_ancestry(self.root, require_final_directory=True)
        path = self.root / name
        metadata = os.lstat(path)
        if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise VerifierJournalError("Journal entry is not a safe regular file")
        if metadata.st_size > MAX_JOURNAL_RECORD_BYTES:
            raise VerifierJournalError("Journal entry exceeds the size limit")
        with path.open("rb") as handle:
            raw = handle.read(MAX_JOURNAL_RECORD_BYTES + 1)
        if len(raw) > MAX_JOURNAL_RECORD_BYTES:
            raise VerifierJournalError("Journal entry exceeds the size limit")
        return raw

    def _write_exclusive(self, name: str, payload: bytes) -> None:
        root_fd = self._open_root_fd() if os.name == "posix" else None
        descriptor = -1
        created = False
        path = self.root / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            if root_fd is not None:
                descriptor = os.open(name, flags, 0o600, dir_fd=root_fd)
            else:
                self._assert_safe_ancestry(self.root, require_final_directory=True)
                descriptor = os.open(path, flags, 0o600)
            created = True
            self._write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            self._fsync_parent(root_fd)
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            if created:
                try:
                    if root_fd is not None:
                        os.unlink(name, dir_fd=root_fd)
                    elif path.exists():
                        path.unlink()
                except OSError:
                    pass
            raise
        finally:
            if root_fd is not None:
                os.close(root_fd)

    def _replace(self, name: str, payload: bytes) -> None:
        root_fd = self._open_root_fd() if os.name == "posix" else None
        temp_name = f".{name}.{uuid.uuid4().hex}.tmp"
        temp_path = self.root / temp_name
        descriptor = -1
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            if root_fd is not None:
                descriptor = os.open(temp_name, flags, 0o600, dir_fd=root_fd)
            else:
                self._assert_safe_ancestry(self.root, require_final_directory=True)
                descriptor = os.open(temp_path, flags, 0o600)
            self._write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            if root_fd is not None:
                os.replace(
                    temp_name,
                    name,
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                )
            else:
                os.replace(temp_path, self.root / name)
            self._fsync_parent(root_fd)
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                if root_fd is not None:
                    os.unlink(temp_name, dir_fd=root_fd)
                elif temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass
            raise
        finally:
            if root_fd is not None:
                os.close(root_fd)

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise VerifierJournalError("Short write to verifier journal")
            view = view[written:]

    def _fsync_parent(self, root_fd: int | None) -> None:
        if root_fd is not None:
            os.fsync(root_fd)
            return
        # Portable semantics are intentionally not promoted to production
        # durability.  Some Windows filesystems allow a directory handle here,
        # but Python's os.open generally does not.  File fsync and atomic replace
        # are still exercised by unit tests; assurance_scope remains explicit.

    def _bounded_directory_names(self) -> tuple[str, ...]:
        self._assert_safe_ancestry(self.root, require_final_directory=True)
        names: list[str] = []
        with os.scandir(self.root) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > MAX_DIRECTORY_ENTRIES_SCANNED:
                    raise VerifierJournalError(
                        "Journal directory scan exceeds its fixed limit"
                    )
        return tuple(names)

    def _ensure_capacity_for_new_record(self) -> None:
        count = sum(
            1
            for name in self._bounded_directory_names()
            if name.endswith(".json") and _HEX_64_RE.fullmatch(name[:-5])
        )
        if count >= MAX_JOURNAL_RECORDS:
            raise VerifierJournalError("Journal record count reached its limit")

    def _now_ns(self) -> int:
        value = self._clock_ns()
        if isinstance(value, bool) or not isinstance(value, int):
            raise VerifierJournalError("Journal clock did not return an integer")
        if value < 0 or value > (2**63) - 1:
            raise VerifierJournalError("Journal clock is outside its fixed range")
        return value

    @staticmethod
    def _record_name(dispatch_event_hash: str) -> str:
        return f"{dispatch_event_hash}.json"

    @staticmethod
    def _claim_name(dispatch_event_hash: str) -> str:
        return f"{dispatch_event_hash}.claim"
