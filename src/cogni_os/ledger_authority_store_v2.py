"""Fail-closed durable store for the independent Ed25519 v2 authority ledger.

The v2 event log and its PREPARE/COMMIT journal are append-only.  This module
never opens, migrates, truncates, or repairs the legacy HMAC ledger.  Any torn,
non-canonical, unresolved, or mutually inconsistent state blocks authority
reads until an explicit transaction reconciliation can prove one exact result.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from .ledger_authority_v2 import (
    LEDGER_V2_PROTOCOL_ID,
    LEDGER_V2_SCHEMA_VERSION,
    LEDGER_V2_SIGNATURE_ALGORITHM,
    LEGACY_HMAC_V1_EVENT_KEYS,
    MAX_LEDGER_V2_DOCUMENT_BYTES,
    LedgerAuthorityV2Error,
    _openssl_ed25519,
    canonical_json_bytes,
    trusted_ledger_signing_binding,
    trusted_ledger_verification_binding,
    validate_v2_envelope,
    verify_v2_chain,
)

LEDGER_V2_LOG_NAME: Final = "events.v2.jsonl"
LEDGER_V2_JOURNAL_NAME: Final = "append-journal.v2.jsonl"
LEDGER_V2_LOCK_NAME: Final = ".events.v2.lock"
LEDGER_V2_CHECKPOINT_DOMAIN: Final = "cogni-os.ledger-checkpoint.v2"
LEDGER_V2_JOURNAL_DOMAIN: Final = "cogni-os.ledger-append-journal.v2"
LEDGER_V2_JOURNAL_GENESIS_HASH: Final = "0" * 64

MAX_STORE_LINE_BYTES: Final = MAX_LEDGER_V2_DOCUMENT_BYTES
MAX_STORE_BYTES: Final = 128 * 1024 * 1024
MAX_STORE_EVENTS: Final = 100_000
MAX_JOURNAL_LINE_BYTES: Final = MAX_LEDGER_V2_DOCUMENT_BYTES + 16 * 1024
MAX_JOURNAL_BYTES: Final = 256 * 1024 * 1024
MAX_JOURNAL_ENTRIES: Final = MAX_STORE_EVENTS * 2

PREPARE_KEYS: Final = frozenset(
    {
        "schema_version",
        "protocol_id",
        "domain",
        "kind",
        "journal_sequence",
        "previous_journal_hash",
        "tx_id",
        "ledger_id",
        "expected_sequence",
        "expected_head",
        "pre_log_sha256",
        "pre_log_size_bytes",
        "post_log_sha256",
        "post_log_size_bytes",
        "event_hash",
        "envelope_sha256",
        "envelope",
        "journal_hash",
    }
)
COMMIT_KEYS: Final = frozenset(
    {
        "schema_version",
        "protocol_id",
        "domain",
        "kind",
        "journal_sequence",
        "previous_journal_hash",
        "tx_id",
        "prepare_hash",
        "ledger_id",
        "expected_sequence",
        "event_hash",
        "post_log_sha256",
        "post_log_size_bytes",
        "journal_hash",
    }
)
CHECKPOINT_KEYS: Final = frozenset(
    {
        "schema_version",
        "protocol_id",
        "domain",
        "kind",
        "algorithm",
        "key_id",
        "ledger_id",
        "event_count",
        "head_hash",
        "log_sha256",
        "log_size_bytes",
        "journal_entry_count",
        "journal_head_hash",
        "journal_sha256",
        "journal_size_bytes",
        "issued_at",
        "signature_b64",
    }
)
CHECKPOINT_PREIMAGE_KEYS: Final = frozenset(CHECKPOINT_KEYS - {"signature_b64"})

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")


class LedgerAuthorityStoreV2Error(LedgerAuthorityV2Error):
    """The standalone v2 store failed an integrity or durability boundary."""


class IndeterminateCommit(LedgerAuthorityStoreV2Error):
    """A transaction was started but its durable outcome requires reconciliation."""

    def __init__(self, tx_id: str, phase: str) -> None:
        self.tx_id = tx_id
        self.transaction_id = tx_id
        self.phase = phase
        super().__init__(
            f"Ledger v2 transaction {tx_id} is indeterminate at {phase}; "
            "call reconcile_transaction with the same tx_id"
        )


class RetryableAppendNotApplied(LedgerAuthorityStoreV2Error):
    """PREPARE failed and a locked reread proved that no state changed."""

    def __init__(self, tx_id: str) -> None:
        self.tx_id = tx_id
        self.transaction_id = tx_id
        super().__init__(
            f"Ledger v2 transaction {tx_id} was not applied; retry is safe"
        )


# Compatibility name for the first review draft.
LedgerAuthorityCommitIndeterminateV2Error = IndeterminateCommit


class _DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedV2StoreSnapshot:
    envelopes: tuple[dict[str, Any], ...]
    event_count: int
    head_hash: str
    ledger_id: str | None
    log_sha256: str
    log_size_bytes: int
    journal_entry_count: int
    journal_head_hash: str
    journal_sha256: str
    journal_size_bytes: int


@dataclass(frozen=True)
class DurableV2Append:
    tx_id: str
    envelope: dict[str, Any]
    snapshot: VerifiedV2StoreSnapshot


@dataclass(frozen=True)
class V2TransactionState:
    tx_id: str
    status: str
    prepare: dict[str, Any] | None
    commit: dict[str, Any] | None


@dataclass(frozen=True)
class _JournalSnapshot:
    entries: tuple[dict[str, Any], ...]
    transactions: dict[str, V2TransactionState]
    entry_count: int
    head_hash: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class _CombinedAudit:
    ledger: VerifiedV2StoreSnapshot
    journal: _JournalSnapshot


class DurableV2DescriptorLock:
    """Persistent-path advisory lock whose ownership is its live descriptor."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._descriptor: int | None = None

    def acquire(self) -> None:
        if self._descriptor is not None:
            raise LedgerAuthorityStoreV2Error("Ledger v2 lock is not reentrant")
        descriptor = -1
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            before = _optional_safe_regular_lstat(self.path, "Ledger v2 lock")
            descriptor = os.open(self.path, flags, 0o600)
            opened = os.fstat(descriptor)
            _require_safe_regular(opened, "Ledger v2 lock descriptor")
            after = _safe_regular_lstat(self.path, "Ledger v2 lock")
            if before is not None and not _same_file_identity(before, opened):
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 lock changed between lstat and open"
                )
            if not _same_file_identity(opened, after):
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 lock path does not identify its open descriptor"
                )
            if opened.st_size == 0:
                if os.write(descriptor, b"\x00") != 1:
                    raise OSError("partial Ledger v2 lock marker write")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            self._os_lock(descriptor)
        except Exception as exc:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise LedgerAuthorityStoreV2Error("Ledger v2 advisory lock failed") from exc
        self._descriptor = descriptor

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        failure: OSError | None = None
        try:
            self._os_unlock(descriptor)
        except OSError as exc:
            failure = exc
        try:
            os.close(descriptor)
        except OSError as exc:
            failure = failure or exc
        if failure is not None:
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 advisory unlock failed"
            ) from failure

    @staticmethod
    def _os_lock(descriptor: int) -> None:
        if os.name == "posix":
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            return
        raise OSError("No supported descriptor advisory lock primitive")

    @staticmethod
    def _os_unlock(descriptor: int) -> None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "posix":
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            return
        raise OSError("No supported descriptor advisory lock primitive")

    def __enter__(self) -> "DurableV2DescriptorLock":
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


class LedgerAuthorityV2Store:
    """Bounded v2 event store plus append-only transaction intent journal."""

    def __init__(self, root: Path, *, forbidden_legacy_root: Path) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.forbidden_legacy_root = Path(
            os.path.abspath(os.fspath(forbidden_legacy_root))
        )
        _reject_root_overlap(self.root, self.forbidden_legacy_root)
        self.path = self.root / LEDGER_V2_LOG_NAME
        self.journal_path = self.root / LEDGER_V2_JOURNAL_NAME
        self.lock_path = self.root / LEDGER_V2_LOCK_NAME
        self._indeterminate_tx_ids: set[str] = set()
        self._prepare_store_files()

    @property
    def assurance(self) -> dict[str, Any]:
        return {
            "scope": "portable-v2-ledger-and-intent-journal-semantics-only",
            "release_ready": False,
            "legacy_ledger": "separate-and-never-opened",
            "automatic_repair": False,
            "release_blockers": [
                "root_protected_v2_store_installation_unverified",
                "linux_descriptor_lock_multiprocess_e2e_unverified",
                "ledger_authority_private_key_daemon_systemd_not_deployed",
                "signed_checkpoint_registry_and_rotation_not_deployed",
                "cross_process_crash_powerloss_e2e_unverified",
                "workspace_projection_release_gate_not_v2_integrated",
            ],
        }

    def read_verified(self) -> VerifiedV2StoreSnapshot:
        with DurableV2DescriptorLock(self.lock_path):
            audit = self._read_combined_unlocked(require_clean=True)
            return audit.ledger

    def get_transaction(self, tx_id: str) -> V2TransactionState:
        _identifier(tx_id, "tx_id")
        with DurableV2DescriptorLock(self.lock_path):
            audit = self._read_combined_unlocked(require_clean=False)
            state = audit.journal.transactions.get(tx_id)
            if state is None:
                return V2TransactionState(tx_id, "missing", None, None)
            if tx_id in self._indeterminate_tx_ids:
                return V2TransactionState(
                    tx_id, "indeterminate", state.prepare, state.commit
                )
            return state

    def append(
        self,
        envelope: dict[str, Any],
        *,
        tx_id: str,
        expected_head: str,
        expected_sequence: int,
    ) -> DurableV2Append:
        _identifier(tx_id, "tx_id")
        _sha256(expected_head, "expected_head")
        _positive_bounded_int(expected_sequence, MAX_STORE_EVENTS, "expected_sequence")
        encoded_body = canonical_json_bytes(envelope)
        document = validate_v2_envelope(json.loads(encoded_body.decode("utf-8")))

        with DurableV2DescriptorLock(self.lock_path):
            audit = self._read_combined_unlocked(require_clean=False)
            existing = audit.journal.transactions.get(tx_id)
            if existing is not None:
                self._require_same_intent(
                    existing,
                    document,
                    expected_head=expected_head,
                    expected_sequence=expected_sequence,
                )
            if tx_id in self._indeterminate_tx_ids:
                raise IndeterminateCommit(tx_id, "existing-indeterminate")
            if self._indeterminate_tx_ids:
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 has an in-process indeterminate transaction"
                )
            unresolved = [
                state
                for state in audit.journal.transactions.values()
                if state.status != "committed"
            ]
            if existing is not None and existing.status != "committed":
                raise IndeterminateCommit(tx_id, "existing-prepare")
            if unresolved:
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 journal has an unresolved transaction"
                )
            if existing is not None:
                assert existing.prepare is not None
                return DurableV2Append(
                    tx_id, existing.prepare["envelope"], audit.ledger
                )

            before = audit.ledger
            if before.head_hash != expected_head:
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 expected head changed before append"
                )
            if before.event_count + 1 != expected_sequence:
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 expected sequence changed before append"
                )
            event = document["event"]
            if (
                event["sequence"] != expected_sequence
                or event["previous_hash"] != expected_head
            ):
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 candidate position does not match compare-and-append"
                )
            verify_v2_chain([*before.envelopes, document])
            record = encoded_body + b"\n"
            if len(encoded_body) > MAX_STORE_LINE_BYTES:
                raise LedgerAuthorityStoreV2Error("Ledger v2 record exceeds line limit")
            if before.log_size_bytes + len(record) > MAX_STORE_BYTES:
                raise LedgerAuthorityStoreV2Error("Ledger v2 store exceeds byte limit")
            post_hash = _hash_envelope_lines((*before.envelopes, document))
            prepare = _make_prepare(
                tx_id=tx_id,
                journal_sequence=audit.journal.entry_count + 1,
                previous_journal_hash=audit.journal.head_hash,
                envelope=document,
                pre=before,
                post_log_sha256=post_hash,
                post_log_size_bytes=before.log_size_bytes + len(record),
            )
            try:
                self._append_record(
                    self.journal_path,
                    canonical_json_bytes(prepare) + b"\n",
                    maximum=MAX_JOURNAL_BYTES,
                    label="Ledger v2 journal PREPARE",
                )
            except Exception as exc:
                try:
                    observed = self._read_combined_unlocked(require_clean=True)
                except (OSError, LedgerAuthorityV2Error):
                    observed = None
                if observed == audit:
                    self._indeterminate_tx_ids.discard(tx_id)
                    raise RetryableAppendNotApplied(tx_id) from exc
                self._indeterminate_tx_ids.add(tx_id)
                raise IndeterminateCommit(tx_id, "prepare") from exc

            try:
                self._append_record(
                    self.path,
                    record,
                    maximum=MAX_STORE_BYTES,
                    label="Ledger v2 event append",
                )
                after_event = self._read_ledger_unlocked()
                _require_snapshot_matches_prepare(after_event, prepare, applied=True)
            except Exception as exc:
                self._indeterminate_tx_ids.add(tx_id)
                raise IndeterminateCommit(tx_id, "event") from exc

            journal_after_prepare = self._read_journal_unlocked()
            commit = _make_commit(prepare, journal_after_prepare)
            try:
                self._append_record(
                    self.journal_path,
                    canonical_json_bytes(commit) + b"\n",
                    maximum=MAX_JOURNAL_BYTES,
                    label="Ledger v2 journal COMMIT",
                )
            except Exception as exc:
                self._indeterminate_tx_ids.add(tx_id)
                raise IndeterminateCommit(tx_id, "commit") from exc

            try:
                final = self._read_combined_unlocked(require_clean=True)
            except Exception as exc:
                self._indeterminate_tx_ids.add(tx_id)
                raise IndeterminateCommit(tx_id, "postcheck") from exc
            self._indeterminate_tx_ids.discard(tx_id)
            return DurableV2Append(tx_id, document, final.ledger)

    def reconcile_transaction(self, tx_id: str) -> DurableV2Append:
        _identifier(tx_id, "tx_id")
        with DurableV2DescriptorLock(self.lock_path):
            audit = self._read_combined_unlocked(require_clean=False)
            state = audit.journal.transactions.get(tx_id)
            if state is None or state.prepare is None:
                raise LedgerAuthorityStoreV2Error(
                    f"Ledger v2 transaction {tx_id} does not exist"
                )
            prepare = state.prepare
            other_unresolved = [
                item.tx_id
                for item in audit.journal.transactions.values()
                if item.status != "committed" and item.tx_id != tx_id
            ]
            if other_unresolved:
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 has another unresolved transaction"
                )
            if self._indeterminate_tx_ids - {tx_id}:
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 has another in-process indeterminate transaction"
                )
            self._indeterminate_tx_ids.add(tx_id)
            if state.commit is not None:
                try:
                    self._sync_existing(self.path, "Ledger v2 event log")
                    self._sync_existing(self.journal_path, "Ledger v2 journal")
                    self._fsync_parent()
                except Exception as exc:
                    self._indeterminate_tx_ids.add(tx_id)
                    raise IndeterminateCommit(tx_id, "reconcile-sync") from exc
                try:
                    clean = self._read_combined_unlocked(
                        require_clean=True,
                        allow_indeterminate_tx_id=tx_id,
                    )
                except Exception as exc:
                    raise IndeterminateCommit(tx_id, "reconcile-postcheck") from exc
                self._indeterminate_tx_ids.discard(tx_id)
                return DurableV2Append(tx_id, prepare["envelope"], clean.ledger)

            try:
                _require_snapshot_matches_prepare(audit.ledger, prepare, applied=False)
            except LedgerAuthorityStoreV2Error:
                _require_snapshot_matches_prepare(audit.ledger, prepare, applied=True)
            else:
                record = canonical_json_bytes(prepare["envelope"]) + b"\n"
                try:
                    self._append_record(
                        self.path,
                        record,
                        maximum=MAX_STORE_BYTES,
                        label="Ledger v2 reconciled event append",
                    )
                except Exception as exc:
                    self._indeterminate_tx_ids.add(tx_id)
                    raise IndeterminateCommit(tx_id, "reconcile-event") from exc
                ledger_after = self._read_ledger_unlocked()
                _require_snapshot_matches_prepare(ledger_after, prepare, applied=True)

            journal_now = self._read_journal_unlocked()
            commit = _make_commit(prepare, journal_now)
            try:
                self._append_record(
                    self.journal_path,
                    canonical_json_bytes(commit) + b"\n",
                    maximum=MAX_JOURNAL_BYTES,
                    label="Ledger v2 reconciled COMMIT",
                )
            except Exception as exc:
                self._indeterminate_tx_ids.add(tx_id)
                raise IndeterminateCommit(tx_id, "reconcile-commit") from exc
            try:
                clean = self._read_combined_unlocked(
                    require_clean=True,
                    allow_indeterminate_tx_id=tx_id,
                )
            except Exception as exc:
                raise IndeterminateCommit(tx_id, "reconcile-postcheck") from exc
            self._indeterminate_tx_ids.discard(tx_id)
            return DurableV2Append(tx_id, prepare["envelope"], clean.ledger)

    def sign_checkpoint(self, *, issued_at: str) -> dict[str, Any]:
        snapshot = self.read_verified()
        if snapshot.event_count < 1 or snapshot.ledger_id is None:
            raise LedgerAuthorityStoreV2Error(
                "An empty Ledger v2 store cannot produce a checkpoint"
            )
        _timestamp(issued_at)
        binding = trusted_ledger_signing_binding()
        unsigned = {
            "schema_version": LEDGER_V2_SCHEMA_VERSION,
            "protocol_id": LEDGER_V2_PROTOCOL_ID,
            "domain": LEDGER_V2_CHECKPOINT_DOMAIN,
            "kind": "ledger-checkpoint",
            "algorithm": LEDGER_V2_SIGNATURE_ALGORITHM,
            "key_id": binding["key_id"],
            "ledger_id": snapshot.ledger_id,
            "event_count": snapshot.event_count,
            "head_hash": snapshot.head_hash,
            "log_sha256": snapshot.log_sha256,
            "log_size_bytes": snapshot.log_size_bytes,
            "journal_entry_count": snapshot.journal_entry_count,
            "journal_head_hash": snapshot.journal_head_hash,
            "journal_sha256": snapshot.journal_sha256,
            "journal_size_bytes": snapshot.journal_size_bytes,
            "issued_at": issued_at,
        }
        preimage = _validate_checkpoint_preimage(unsigned)
        signature = _openssl_ed25519(
            canonical_json_bytes(preimage),
            openssl_path=Path(binding["openssl_path"]),
            key_path=Path(binding["private_key_path"]),
            signature=None,
        )
        assert isinstance(signature, bytes)
        checkpoint = {
            **preimage,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        if (
            _openssl_ed25519(
                canonical_json_bytes(preimage),
                openssl_path=Path(binding["openssl_path"]),
                key_path=Path(binding["public_key_path"]),
                signature=signature,
            )
            is not True
        ):
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 checkpoint public/private key pair does not match"
            )
        return validate_signed_checkpoint(checkpoint)

    def verify_pinned_checkpoint(
        self, checkpoint: dict[str, Any]
    ) -> VerifiedV2StoreSnapshot:
        with DurableV2DescriptorLock(self.lock_path):
            snapshot = self._read_combined_unlocked(require_clean=True).ledger
            document = verify_signed_checkpoint(checkpoint)
            expected = {
                "ledger_id": snapshot.ledger_id,
                "event_count": snapshot.event_count,
                "head_hash": snapshot.head_hash,
                "log_sha256": snapshot.log_sha256,
                "log_size_bytes": snapshot.log_size_bytes,
                "journal_entry_count": snapshot.journal_entry_count,
                "journal_head_hash": snapshot.journal_head_hash,
                "journal_sha256": snapshot.journal_sha256,
                "journal_size_bytes": snapshot.journal_size_bytes,
            }
            if any(document[key] != value for key, value in expected.items()):
                raise LedgerAuthorityStoreV2Error(
                    "Signed checkpoint is not pinned to the current v2 ledger and journal"
                )
            return snapshot

    def _prepare_store_files(self) -> None:
        if (self.root / "events.jsonl").exists():
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 root must be separate from the legacy HMAC ledger"
            )
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            root_metadata = os.lstat(self.root)
        except OSError as exc:
            raise LedgerAuthorityStoreV2Error("Ledger v2 root is unavailable") from exc
        if _is_link_or_reparse(root_metadata) or not stat.S_ISDIR(
            root_metadata.st_mode
        ):
            raise LedgerAuthorityStoreV2Error("Ledger v2 root is not a safe directory")
        log_metadata = _optional_safe_regular_lstat(self.path, "Ledger v2 log")
        journal_metadata = _optional_safe_regular_lstat(
            self.journal_path, "Ledger v2 journal"
        )
        if (log_metadata is None) != (journal_metadata is None):
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 log and journal must either both exist or both be absent"
            )
        if log_metadata is not None:
            return
        self._create_empty_file(self.path, "Ledger v2 log")
        # If this fails, the first file deliberately remains: no repair/delete.
        self._create_empty_file(self.journal_path, "Ledger v2 journal")
        self._fsync_parent()

    def _create_empty_file(self, path: Path, label: str) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(path, flags, 0o600)
            opened = os.fstat(descriptor)
            _require_safe_regular(opened, f"{label} descriptor")
            after = _safe_regular_lstat(path, label)
            if not _same_file_identity(opened, after):
                raise LedgerAuthorityStoreV2Error(
                    f"{label} path does not identify its descriptor"
                )
            self._fsync_file(descriptor)
        except Exception as exc:
            raise LedgerAuthorityStoreV2Error(f"{label} creation failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _read_combined_unlocked(
        self,
        *,
        require_clean: bool,
        allow_indeterminate_tx_id: str | None = None,
    ) -> _CombinedAudit:
        ledger = self._read_ledger_unlocked()
        journal = self._read_journal_unlocked()
        _validate_combined(ledger, journal, require_clean=require_clean)
        allowed = (
            {allow_indeterminate_tx_id}
            if allow_indeterminate_tx_id is not None
            else set()
        )
        if require_clean and self._indeterminate_tx_ids - allowed:
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 has an in-process indeterminate transaction"
            )
        ledger = replace(
            ledger,
            journal_entry_count=journal.entry_count,
            journal_head_hash=journal.head_hash,
            journal_sha256=journal.sha256,
            journal_size_bytes=journal.size_bytes,
        )
        return _CombinedAudit(ledger, journal)

    def _read_ledger_unlocked(self) -> VerifiedV2StoreSnapshot:
        envelopes, digest, total = self._read_jsonl(
            self.path,
            label="Ledger v2 log",
            maximum_line=MAX_STORE_LINE_BYTES,
            maximum_bytes=MAX_STORE_BYTES,
            maximum_entries=MAX_STORE_EVENTS,
            decoder=_decode_ledger_line,
        )
        summary = verify_v2_chain(envelopes)
        return VerifiedV2StoreSnapshot(
            envelopes=tuple(envelopes),
            event_count=len(envelopes),
            head_hash=summary["head"],
            ledger_id=summary["ledger_id"],
            log_sha256=digest,
            log_size_bytes=total,
            journal_entry_count=0,
            journal_head_hash=LEDGER_V2_JOURNAL_GENESIS_HASH,
            journal_sha256=hashlib.sha256().hexdigest(),
            journal_size_bytes=0,
        )

    def _read_journal_unlocked(self) -> _JournalSnapshot:
        entries, digest, total = self._read_jsonl(
            self.journal_path,
            label="Ledger v2 journal",
            maximum_line=MAX_JOURNAL_LINE_BYTES,
            maximum_bytes=MAX_JOURNAL_BYTES,
            maximum_entries=MAX_JOURNAL_ENTRIES,
            decoder=_decode_journal_line,
        )
        transactions = _validate_journal_chain(entries)
        head = (
            entries[-1]["journal_hash"] if entries else LEDGER_V2_JOURNAL_GENESIS_HASH
        )
        return _JournalSnapshot(
            tuple(entries), transactions, len(entries), head, digest, total
        )

    def _read_jsonl(
        self,
        path: Path,
        *,
        label: str,
        maximum_line: int,
        maximum_bytes: int,
        maximum_entries: int,
        decoder: Any,
    ) -> tuple[list[dict[str, Any]], str, int]:
        descriptor = self._open_regular(path, os.O_RDONLY, label)
        documents: list[dict[str, Any]] = []
        total = 0
        digest = hashlib.sha256()
        try:
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                descriptor = -1
                while True:
                    read_limit = min(maximum_line + 2, maximum_bytes - total + 1)
                    line = handle.readline(read_limit)
                    if not line:
                        break
                    total += len(line)
                    if total > maximum_bytes:
                        raise LedgerAuthorityStoreV2Error(f"{label} exceeds byte limit")
                    if len(documents) >= maximum_entries:
                        raise LedgerAuthorityStoreV2Error(
                            f"{label} exceeds entry limit"
                        )
                    if not line.endswith(b"\n"):
                        if len(line) > maximum_line:
                            raise LedgerAuthorityStoreV2Error(
                                f"{label} line exceeds its limit"
                            )
                        raise LedgerAuthorityStoreV2Error(
                            f"{label} non-empty file lacks terminal LF"
                        )
                    body = line[:-1]
                    if len(body) > maximum_line:
                        raise LedgerAuthorityStoreV2Error(
                            f"{label} line exceeds its limit"
                        )
                    digest.update(line)
                    documents.append(decoder(body, len(documents) + 1))
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return documents, digest.hexdigest(), total

    def _require_same_intent(
        self,
        state: V2TransactionState,
        envelope: dict[str, Any],
        *,
        expected_head: str,
        expected_sequence: int,
    ) -> None:
        prepare = state.prepare
        if prepare is None or (
            prepare["envelope"] != envelope
            or prepare["expected_head"] != expected_head
            or prepare["expected_sequence"] != expected_sequence
        ):
            raise LedgerAuthorityStoreV2Error(
                f"Ledger v2 tx_id {state.tx_id} was reused with a different intent"
            )

    def _append_record(
        self, path: Path, record: bytes, *, maximum: int, label: str
    ) -> None:
        before = _safe_regular_lstat(path, label)
        if before.st_size + len(record) > maximum:
            raise LedgerAuthorityStoreV2Error(f"{label} exceeds byte limit")
        descriptor = self._open_regular(path, os.O_WRONLY | os.O_APPEND, label)
        failure: Exception | None = None
        try:
            self._write_all(descriptor, record)
            self._fsync_file(descriptor)
        except (OSError, LedgerAuthorityStoreV2Error) as exc:
            failure = exc
        try:
            os.close(descriptor)
        except OSError as exc:
            failure = failure or exc
        if failure is not None:
            raise LedgerAuthorityStoreV2Error(
                f"{label} did not durably complete"
            ) from failure
        self._fsync_parent()

    def _sync_existing(self, path: Path, label: str) -> None:
        descriptor = self._open_regular(path, os.O_RDWR, label)
        try:
            self._fsync_file(descriptor)
        finally:
            os.close(descriptor)

    def _open_regular(self, path: Path, flags: int, label: str) -> int:
        before = _safe_regular_lstat(path, label)
        open_flags = flags | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(path, open_flags)
            opened = os.fstat(descriptor)
            _require_safe_regular(opened, f"{label} descriptor")
            after = _safe_regular_lstat(path, label)
            if not _same_file_identity(before, opened) or not _same_file_identity(
                opened, after
            ):
                raise LedgerAuthorityStoreV2Error(
                    f"{label} changed between lstat and open"
                )
            return descriptor
        except Exception as exc:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise LedgerAuthorityStoreV2Error(f"{label} open failed") from exc

    @staticmethod
    def _write_all(descriptor: int, record: bytes) -> None:
        view = memoryview(record)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 append stopped after a non-positive write"
                )
            view = view[written:]

    @staticmethod
    def _fsync_file(descriptor: int) -> None:
        os.fsync(descriptor)

    def _fsync_parent(self) -> None:
        if os.name != "posix":
            return
        descriptor = os.open(
            self.root,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _decode_json_object(body: bytes, *, label: str, line_number: int) -> dict[str, Any]:
    if not body:
        raise LedgerAuthorityStoreV2Error(f"{label} contains blank line {line_number}")
    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKey as exc:
        raise LedgerAuthorityStoreV2Error(
            f"{label} has duplicate JSON key at line {line_number}"
        ) from exc
    except LedgerAuthorityStoreV2Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerAuthorityStoreV2Error(
            f"{label} line {line_number} is not UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise LedgerAuthorityStoreV2Error(
            f"{label} line {line_number} is not an object"
        )
    if canonical_json_bytes(value) != body:
        raise LedgerAuthorityStoreV2Error(
            f"{label} line {line_number} is not canonical JSON"
        )
    return value


def _decode_ledger_line(body: bytes, line_number: int) -> dict[str, Any]:
    value = _decode_json_object(body, label="Ledger v2 log", line_number=line_number)
    if set(value) == LEGACY_HMAC_V1_EVENT_KEYS:
        raise LedgerAuthorityStoreV2Error(
            "HMAC v1 event must not be mixed into the Ed25519 v2 store"
        )
    return validate_v2_envelope(value)


def _decode_journal_line(body: bytes, line_number: int) -> dict[str, Any]:
    value = _decode_json_object(
        body, label="Ledger v2 journal", line_number=line_number
    )
    return _validate_journal_record(value)


def _make_prepare(
    *,
    tx_id: str,
    journal_sequence: int,
    previous_journal_hash: str,
    envelope: dict[str, Any],
    pre: VerifiedV2StoreSnapshot,
    post_log_sha256: str,
    post_log_size_bytes: int,
) -> dict[str, Any]:
    event = envelope["event"]
    unsigned = {
        "schema_version": LEDGER_V2_SCHEMA_VERSION,
        "protocol_id": LEDGER_V2_PROTOCOL_ID,
        "domain": LEDGER_V2_JOURNAL_DOMAIN,
        "kind": "PREPARE",
        "journal_sequence": journal_sequence,
        "previous_journal_hash": previous_journal_hash,
        "tx_id": tx_id,
        "ledger_id": event["ledger_id"],
        "expected_sequence": event["sequence"],
        "expected_head": event["previous_hash"],
        "pre_log_sha256": pre.log_sha256,
        "pre_log_size_bytes": pre.log_size_bytes,
        "post_log_sha256": post_log_sha256,
        "post_log_size_bytes": post_log_size_bytes,
        "event_hash": envelope["event_hash"],
        "envelope_sha256": hashlib.sha256(canonical_json_bytes(envelope)).hexdigest(),
        "envelope": envelope,
    }
    return _with_journal_hash(unsigned)


def _make_commit(prepare: dict[str, Any], journal: _JournalSnapshot) -> dict[str, Any]:
    if journal.head_hash != prepare["journal_hash"]:
        raise LedgerAuthorityStoreV2Error(
            "Ledger v2 PREPARE is not the current journal head"
        )
    unsigned = {
        "schema_version": LEDGER_V2_SCHEMA_VERSION,
        "protocol_id": LEDGER_V2_PROTOCOL_ID,
        "domain": LEDGER_V2_JOURNAL_DOMAIN,
        "kind": "COMMIT",
        "journal_sequence": journal.entry_count + 1,
        "previous_journal_hash": journal.head_hash,
        "tx_id": prepare["tx_id"],
        "prepare_hash": prepare["journal_hash"],
        "ledger_id": prepare["ledger_id"],
        "expected_sequence": prepare["expected_sequence"],
        "event_hash": prepare["event_hash"],
        "post_log_sha256": prepare["post_log_sha256"],
        "post_log_size_bytes": prepare["post_log_size_bytes"],
    }
    return _with_journal_hash(unsigned)


def _with_journal_hash(unsigned: dict[str, Any]) -> dict[str, Any]:
    return {
        **unsigned,
        "journal_hash": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def _validate_journal_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LedgerAuthorityStoreV2Error("Ledger v2 journal record is not an object")
    kind = value.get("kind")
    keys = (
        PREPARE_KEYS if kind == "PREPARE" else COMMIT_KEYS if kind == "COMMIT" else None
    )
    if keys is None or set(value) != keys:
        raise LedgerAuthorityStoreV2Error("Ledger v2 journal schema is not exact")
    if (
        value["schema_version"] != LEDGER_V2_SCHEMA_VERSION
        or value["protocol_id"] != LEDGER_V2_PROTOCOL_ID
        or value["domain"] != LEDGER_V2_JOURNAL_DOMAIN
    ):
        raise LedgerAuthorityStoreV2Error("Ledger v2 journal identity is invalid")
    _positive_bounded_int(
        value["journal_sequence"], MAX_JOURNAL_ENTRIES, "journal_sequence"
    )
    _sha256(value["previous_journal_hash"], "previous_journal_hash")
    _identifier(value["tx_id"], "tx_id")
    _identifier(value["ledger_id"], "journal ledger_id")
    _positive_bounded_int(
        value["expected_sequence"], MAX_STORE_EVENTS, "expected_sequence"
    )
    _sha256(value["event_hash"], "journal event_hash")
    _sha256(value["post_log_sha256"], "post_log_sha256")
    _bounded_nonnegative_int(
        value["post_log_size_bytes"], MAX_STORE_BYTES, "post_log_size_bytes"
    )
    if kind == "PREPARE":
        _sha256(value["expected_head"], "expected_head")
        _sha256(value["pre_log_sha256"], "pre_log_sha256")
        _bounded_nonnegative_int(
            value["pre_log_size_bytes"], MAX_STORE_BYTES, "pre_log_size_bytes"
        )
        _sha256(value["envelope_sha256"], "envelope_sha256")
        envelope = validate_v2_envelope(value["envelope"])
        event = envelope["event"]
        encoded = canonical_json_bytes(envelope)
        if (
            hashlib.sha256(encoded).hexdigest() != value["envelope_sha256"]
            or envelope["event_hash"] != value["event_hash"]
            or event["ledger_id"] != value["ledger_id"]
            or event["sequence"] != value["expected_sequence"]
            or event["previous_hash"] != value["expected_head"]
            or value["post_log_size_bytes"]
            != value["pre_log_size_bytes"] + len(encoded) + 1
        ):
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 PREPARE does not bind its exact envelope transition"
            )
    else:
        _sha256(value["prepare_hash"], "prepare_hash")
    claimed = value["journal_hash"]
    _sha256(claimed, "journal_hash")
    unsigned = {key: item for key, item in value.items() if key != "journal_hash"}
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != claimed:
        raise LedgerAuthorityStoreV2Error("Ledger v2 journal record hash is invalid")
    return value


def _validate_journal_chain(
    entries: list[dict[str, Any]],
) -> dict[str, V2TransactionState]:
    previous = LEDGER_V2_JOURNAL_GENESIS_HASH
    transactions: dict[str, V2TransactionState] = {}
    unresolved: str | None = None
    for index, entry in enumerate(entries, start=1):
        if (
            entry["journal_sequence"] != index
            or entry["previous_journal_hash"] != previous
        ):
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 journal chain is discontinuous"
            )
        tx_id = entry["tx_id"]
        if entry["kind"] == "PREPARE":
            if unresolved is not None or tx_id in transactions:
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 journal contains overlapping or reused tx_id"
                )
            transactions[tx_id] = V2TransactionState(tx_id, "prepared", entry, None)
            unresolved = tx_id
        else:
            state = transactions.get(tx_id)
            if state is None or unresolved != tx_id or state.prepare is None:
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 COMMIT has no immediately pending PREPARE"
                )
            prepare = state.prepare
            if (
                entry["prepare_hash"] != prepare["journal_hash"]
                or entry["previous_journal_hash"] != prepare["journal_hash"]
                or any(
                    entry[key] != prepare[key]
                    for key in (
                        "ledger_id",
                        "expected_sequence",
                        "event_hash",
                        "post_log_sha256",
                        "post_log_size_bytes",
                    )
                )
            ):
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 COMMIT does not bind its PREPARE"
                )
            transactions[tx_id] = V2TransactionState(tx_id, "committed", prepare, entry)
            unresolved = None
        previous = entry["journal_hash"]
    return transactions


def _validate_combined(
    ledger: VerifiedV2StoreSnapshot,
    journal: _JournalSnapshot,
    *,
    require_clean: bool,
) -> None:
    prefixes = _ledger_prefixes(ledger.envelopes)
    prepares = [entry for entry in journal.entries if entry["kind"] == "PREPARE"]
    commits = [entry for entry in journal.entries if entry["kind"] == "COMMIT"]
    if len(prepares) > ledger.event_count + 1 or len(commits) > ledger.event_count:
        raise LedgerAuthorityStoreV2Error(
            "Ledger v2 journal cardinality is inconsistent with the event log"
        )
    for ordinal, prepare in enumerate(prepares, start=1):
        if prepare["expected_sequence"] != ordinal:
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 journal event sequence is not contiguous"
            )
        pre_hash, pre_size = prefixes[ordinal - 1]
        if (
            prepare["pre_log_sha256"] != pre_hash
            or prepare["pre_log_size_bytes"] != pre_size
        ):
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 PREPARE pre-state does not match the event log"
            )
        if ordinal <= ledger.event_count:
            post_hash, post_size = prefixes[ordinal]
            if (
                prepare["envelope"] != ledger.envelopes[ordinal - 1]
                or prepare["post_log_sha256"] != post_hash
                or prepare["post_log_size_bytes"] != post_size
            ):
                raise LedgerAuthorityStoreV2Error(
                    "Ledger v2 PREPARE post-state does not match the event log"
                )
    unresolved = [
        state for state in journal.transactions.values() if state.status != "committed"
    ]
    if not unresolved and len(commits) != ledger.event_count:
        raise LedgerAuthorityStoreV2Error(
            "Ledger v2 contains an event without a committed journal transaction"
        )
    if unresolved:
        prepare = unresolved[0].prepare
        if prepare is None or prepare["expected_sequence"] not in {
            ledger.event_count,
            ledger.event_count + 1,
        }:
            raise LedgerAuthorityStoreV2Error(
                "Ledger v2 unresolved transaction has an indeterminate log position"
            )
        if require_clean:
            raise LedgerAuthorityStoreV2Error(
                f"Ledger v2 transaction {unresolved[0].tx_id} is unresolved"
            )


def _require_snapshot_matches_prepare(
    snapshot: VerifiedV2StoreSnapshot,
    prepare: dict[str, Any],
    *,
    applied: bool,
) -> None:
    if applied:
        matches = (
            snapshot.event_count == prepare["expected_sequence"]
            and snapshot.head_hash == prepare["event_hash"]
            and snapshot.log_sha256 == prepare["post_log_sha256"]
            and snapshot.log_size_bytes == prepare["post_log_size_bytes"]
            and snapshot.envelopes[-1] == prepare["envelope"]
        )
    else:
        matches = (
            snapshot.event_count + 1 == prepare["expected_sequence"]
            and snapshot.head_hash == prepare["expected_head"]
            and snapshot.log_sha256 == prepare["pre_log_sha256"]
            and snapshot.log_size_bytes == prepare["pre_log_size_bytes"]
        )
    if not matches:
        raise LedgerAuthorityStoreV2Error(
            "Ledger v2 state matches neither the PREPARE pre-state nor requested state"
        )


def _ledger_prefixes(
    envelopes: tuple[dict[str, Any], ...],
) -> list[tuple[str, int]]:
    digest = hashlib.sha256()
    size = 0
    result = [(digest.hexdigest(), size)]
    for envelope in envelopes:
        record = canonical_json_bytes(envelope) + b"\n"
        digest.update(record)
        size += len(record)
        result.append((digest.hexdigest(), size))
    return result


def _hash_envelope_lines(envelopes: tuple[dict[str, Any], ...]) -> str:
    return _ledger_prefixes(envelopes)[-1][0]


def _exact_object(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LedgerAuthorityStoreV2Error(f"{label} schema is not exact")
    canonical_json_bytes(value)
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise LedgerAuthorityStoreV2Error(f"{label} must be a lowercase SHA-256")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise LedgerAuthorityStoreV2Error(f"{label} is invalid")
    return value


def _positive_bounded_int(value: Any, maximum: int, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > maximum
    ):
        raise LedgerAuthorityStoreV2Error(f"{label} is invalid")
    return value


def _bounded_nonnegative_int(value: Any, maximum: int, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > maximum
    ):
        raise LedgerAuthorityStoreV2Error(f"{label} is invalid")
    return value


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise LedgerAuthorityStoreV2Error("Checkpoint timestamp is invalid")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise LedgerAuthorityStoreV2Error("Checkpoint timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LedgerAuthorityStoreV2Error("Checkpoint timestamp has no timezone")
    return value


def _reject_json_constant(value: str) -> Any:
    raise LedgerAuthorityStoreV2Error(f"JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0) or 0
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _require_safe_regular(metadata: os.stat_result, label: str) -> None:
    if (
        _is_link_or_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise LedgerAuthorityStoreV2Error(f"{label} is not a safe regular file")


def _safe_regular_lstat(path: Path, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise LedgerAuthorityStoreV2Error(f"{label} is unavailable") from exc
    _require_safe_regular(metadata, label)
    return metadata


def _optional_safe_regular_lstat(path: Path, label: str) -> os.stat_result | None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise LedgerAuthorityStoreV2Error(f"{label} is unavailable") from exc
    _require_safe_regular(metadata, label)
    return metadata


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_nlink,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_nlink,
    )


def _reject_root_overlap(root: Path, forbidden_legacy_root: Path) -> None:
    try:
        canonical_root = os.path.normcase(str(root.resolve(strict=False)))
        canonical_legacy = os.path.normcase(
            str(forbidden_legacy_root.resolve(strict=False))
        )
        common = os.path.commonpath((canonical_root, canonical_legacy))
    except (OSError, ValueError) as exc:
        raise LedgerAuthorityStoreV2Error(
            "Ledger v2 and legacy roots could not be compared safely"
        ) from exc
    if common in {canonical_root, canonical_legacy}:
        raise LedgerAuthorityStoreV2Error(
            "Ledger v2 root overlaps the forbidden legacy root"
        )


def _validate_checkpoint_preimage(value: Any) -> dict[str, Any]:
    document = _exact_object(value, CHECKPOINT_PREIMAGE_KEYS, "Checkpoint preimage")
    if (
        document["schema_version"] != LEDGER_V2_SCHEMA_VERSION
        or document["protocol_id"] != LEDGER_V2_PROTOCOL_ID
        or document["domain"] != LEDGER_V2_CHECKPOINT_DOMAIN
        or document["kind"] != "ledger-checkpoint"
        or document["algorithm"] != LEDGER_V2_SIGNATURE_ALGORITHM
    ):
        raise LedgerAuthorityStoreV2Error("Checkpoint identity is invalid")
    _sha256(document["key_id"], "Checkpoint key_id")
    _identifier(document["ledger_id"], "Checkpoint ledger_id")
    _positive_bounded_int(document["event_count"], MAX_STORE_EVENTS, "event_count")
    _positive_bounded_int(
        document["journal_entry_count"], MAX_JOURNAL_ENTRIES, "journal_entry_count"
    )
    _bounded_nonnegative_int(
        document["log_size_bytes"], MAX_STORE_BYTES, "log_size_bytes"
    )
    _bounded_nonnegative_int(
        document["journal_size_bytes"], MAX_JOURNAL_BYTES, "journal_size_bytes"
    )
    _sha256(document["head_hash"], "Checkpoint head_hash")
    _sha256(document["log_sha256"], "Checkpoint log_sha256")
    _sha256(document["journal_head_hash"], "Checkpoint journal_head_hash")
    _sha256(document["journal_sha256"], "Checkpoint journal_sha256")
    _timestamp(document["issued_at"])
    return document


def validate_signed_checkpoint(value: Any) -> dict[str, Any]:
    document = _exact_object(value, CHECKPOINT_KEYS, "Signed checkpoint")
    unsigned = {key: document[key] for key in CHECKPOINT_PREIMAGE_KEYS}
    _validate_checkpoint_preimage(unsigned)
    signature = document["signature_b64"]
    if not isinstance(signature, str) or len(signature) > 1024:
        raise LedgerAuthorityStoreV2Error("Checkpoint signature encoding is invalid")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise LedgerAuthorityStoreV2Error(
            "Checkpoint signature encoding is invalid"
        ) from exc
    if len(decoded) != 64:
        raise LedgerAuthorityStoreV2Error("Checkpoint signature length is invalid")
    return document


def verify_signed_checkpoint(value: dict[str, Any]) -> dict[str, Any]:
    document = validate_signed_checkpoint(value)
    binding = trusted_ledger_verification_binding()
    if document["key_id"] != binding["key_id"]:
        raise LedgerAuthorityStoreV2Error("Checkpoint names another authority key")
    unsigned = {key: document[key] for key in CHECKPOINT_PREIMAGE_KEYS}
    if (
        _openssl_ed25519(
            canonical_json_bytes(unsigned),
            openssl_path=Path(binding["openssl_path"]),
            key_path=Path(binding["public_key_path"]),
            signature=base64.b64decode(document["signature_b64"], validate=True),
        )
        is not True
    ):
        raise LedgerAuthorityStoreV2Error("Checkpoint signature is invalid")
    return document
