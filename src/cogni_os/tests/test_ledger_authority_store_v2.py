from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import cogni_os.ledger_authority_store_v2 as store_module
from cogni_os.ledger_authority_store_v2 import (
    DurableV2DescriptorLock,
    IndeterminateCommit,
    LedgerAuthorityStoreV2Error,
    LedgerAuthorityV2Store,
    RetryableAppendNotApplied,
    canonical_json_bytes,
)
from cogni_os.ledger_authority_v2 import (
    LEDGER_V2_GENESIS_HASH,
    _public_key_spki_sha256,
    sign_v2_event,
)
from cogni_os.util import sha256_file


def _openssl_path() -> Path:
    discovered = shutil.which("openssl")
    candidates = (
        Path(discovered) if discovered else None,
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
    )
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise AssertionError("OpenSSL is required for Ledger v2 store tests")


def _event(sequence: int, previous_hash: str) -> dict[str, object]:
    return {
        "sequence": sequence,
        "ledger_id": "workspace-p01",
        "timestamp": "2027-01-15T08:00:00Z",
        "actor": "ledger-authority",
        "action": "task.recorded",
        "task_id": "P01-TRUTH",
        "payload": {"sequence": sequence},
        "previous_hash": previous_hash,
    }


class LedgerAuthorityV2StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.root = Path(self.temporary.name)
        self.openssl = _openssl_path()
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        subprocess.run(
            [
                str(self.openssl),
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(self.private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                str(self.openssl),
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            check=True,
            capture_output=True,
        )
        key_id = _public_key_spki_sha256(
            public_key_path=self.public_key, openssl_path=self.openssl
        )
        signing = {
            "private_key_path": str(self.private_key),
            "public_key_path": str(self.public_key),
            "key_id": key_id,
            "openssl_path": str(self.openssl),
            "openssl_sha256": sha256_file(self.openssl),
        }
        verification = {
            key: value for key, value in signing.items() if key != "private_key_path"
        }
        self.patchers = tuple(
            patch(target, return_value=value)
            for target, value in (
                (
                    "cogni_os.ledger_authority_v2.trusted_ledger_signing_binding",
                    signing,
                ),
                (
                    "cogni_os.ledger_authority_v2.trusted_ledger_verification_binding",
                    verification,
                ),
                (
                    "cogni_os.ledger_authority_store_v2.trusted_ledger_signing_binding",
                    signing,
                ),
                (
                    "cogni_os.ledger_authority_store_v2.trusted_ledger_verification_binding",
                    verification,
                ),
            )
        )
        for patcher in self.patchers:
            patcher.start()
        self.legacy_root = self.root / "legacy"
        self.legacy_root.mkdir()
        self.store = self._new_store("v2")

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    def _new_store(self, name: str) -> LedgerAuthorityV2Store:
        return LedgerAuthorityV2Store(
            self.root / name, forbidden_legacy_root=self.legacy_root
        )

    def _signed(self, sequence: int, previous_hash: str) -> dict[str, object]:
        return sign_v2_event(_event(sequence, previous_hash))

    def _append(
        self,
        store: LedgerAuthorityV2Store,
        envelope: dict[str, object],
        *,
        tx_id: str,
        sequence: int,
        head: str,
    ):
        return store.append(
            envelope,
            tx_id=tx_id,
            expected_head=head,
            expected_sequence=sequence,
        )

    def test_store_001_append_only_journal_and_idempotent_tx(self) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        result = self._append(
            self.store,
            first,
            tx_id="tx-001",
            sequence=1,
            head=LEDGER_V2_GENESIS_HASH,
        )
        self.assertEqual(result.tx_id, "tx-001")
        self.assertEqual(result.snapshot.event_count, 1)
        self.assertEqual(result.snapshot.journal_entry_count, 2)
        self.assertEqual(
            self.store.path.read_bytes(), canonical_json_bytes(first) + b"\n"
        )

        journal_before = self.store.journal_path.read_bytes()
        entries = [json.loads(line) for line in journal_before.splitlines()]
        self.assertEqual([item["kind"] for item in entries], ["PREPARE", "COMMIT"])
        self.assertEqual(entries[0]["previous_journal_hash"], "0" * 64)
        self.assertEqual(
            entries[1]["previous_journal_hash"], entries[0]["journal_hash"]
        )
        for entry in entries:
            unsigned = {
                key: value for key, value in entry.items() if key != "journal_hash"
            }
            self.assertEqual(
                entry["journal_hash"],
                hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
            )

        repeated = self._append(
            self.store,
            first,
            tx_id="tx-001",
            sequence=1,
            head=LEDGER_V2_GENESIS_HASH,
        )
        self.assertEqual(repeated.snapshot.event_count, 1)
        self.assertEqual(self.store.journal_path.read_bytes(), journal_before)
        self.assertEqual(self.store.get_transaction("tx-001").status, "committed")
        self.assertEqual(self.store.get_transaction("tx-missing").status, "missing")

        second = self._signed(2, first["event_hash"])
        real_write = os.write

        def positive_short_write(descriptor: int, value: object) -> int:
            raw = bytes(value)
            return real_write(descriptor, raw[: max(1, len(raw) // 2)])

        with patch(
            "cogni_os.ledger_authority_store_v2.os.write",
            side_effect=positive_short_write,
        ):
            second_result = self._append(
                self.store,
                second,
                tx_id="tx-002",
                sequence=2,
                head=first["event_hash"],
            )
        self.assertEqual(second_result.snapshot.event_count, 2)
        self.assertEqual(second_result.snapshot.journal_entry_count, 4)
        self.assertTrue(self.store.path.read_bytes().endswith(b"\n"))

    def test_store_002_event_fsync_ambiguity_blocks_until_explicit_reconcile(
        self,
    ) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        real_fsync = self.store._fsync_file

        def fail_after_event_fsync(descriptor: int) -> None:
            real_fsync(descriptor)
            if os.fstat(descriptor).st_ino == self.store.path.stat().st_ino:
                raise OSError("ambiguous event fsync")

        with (
            patch.object(self.store, "_fsync_file", side_effect=fail_after_event_fsync),
            self.assertRaises(IndeterminateCommit) as caught,
        ):
            self._append(
                self.store,
                first,
                tx_id="tx-event-fsync",
                sequence=1,
                head=LEDGER_V2_GENESIS_HASH,
            )
        self.assertEqual(caught.exception.tx_id, "tx-event-fsync")
        journal_before = self.store.journal_path.read_bytes()
        log_before = self.store.path.read_bytes()
        self.assertEqual(len(journal_before.splitlines()), 1)
        self.assertTrue(log_before.endswith(b"\n"))
        with self.assertRaisesRegex(LedgerAuthorityStoreV2Error, "unresolved"):
            self.store.read_verified()
        self.assertEqual(
            self.store.get_transaction("tx-event-fsync").status, "indeterminate"
        )

        reopened = LedgerAuthorityV2Store(
            self.store.root, forbidden_legacy_root=self.legacy_root
        )
        self.assertEqual(self.store.path.read_bytes(), log_before)
        self.assertEqual(self.store.journal_path.read_bytes(), journal_before)
        self.assertEqual(reopened.get_transaction("tx-event-fsync").status, "prepared")
        reconciled = reopened.reconcile_transaction("tx-event-fsync")
        self.assertEqual(reconciled.snapshot.event_count, 1)
        self.assertEqual(reconciled.snapshot.journal_entry_count, 2)
        self.assertEqual(reopened.read_verified(), reconciled.snapshot)

    def test_store_003_commit_fsync_error_is_indeterminate_with_tx_id(self) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        real_fsync = self.store._fsync_file
        journal_fsyncs = 0

        def fail_after_commit_fsync(descriptor: int) -> None:
            nonlocal journal_fsyncs
            real_fsync(descriptor)
            if os.fstat(descriptor).st_ino == self.store.journal_path.stat().st_ino:
                journal_fsyncs += 1
                if journal_fsyncs == 2:
                    raise OSError("ambiguous COMMIT fsync")

        with (
            patch.object(
                self.store, "_fsync_file", side_effect=fail_after_commit_fsync
            ),
            self.assertRaises(IndeterminateCommit) as caught,
        ):
            self._append(
                self.store,
                first,
                tx_id="tx-commit-fsync",
                sequence=1,
                head=LEDGER_V2_GENESIS_HASH,
            )
        self.assertEqual(caught.exception.tx_id, "tx-commit-fsync")
        self.assertEqual(caught.exception.phase, "commit")
        self.assertEqual(
            self.store.get_transaction("tx-commit-fsync").status, "indeterminate"
        )
        with self.assertRaisesRegex(LedgerAuthorityStoreV2Error, "indeterminate"):
            self.store.sign_checkpoint(issued_at="2027-01-15T08:00:01Z")
        reconciled = self.store.reconcile_transaction("tx-commit-fsync")
        self.assertEqual(reconciled.snapshot.event_count, 1)
        self.assertEqual(
            self.store.get_transaction("tx-commit-fsync").status, "committed"
        )

    def test_store_004_tx_id_reuse_with_different_intent_is_rejected(self) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        self._append(
            self.store,
            first,
            tx_id="tx-reuse",
            sequence=1,
            head=LEDGER_V2_GENESIS_HASH,
        )
        second = self._signed(2, first["event_hash"])
        with self.assertRaisesRegex(LedgerAuthorityStoreV2Error, "different intent"):
            self._append(
                self.store,
                second,
                tx_id="tx-reuse",
                sequence=2,
                head=first["event_hash"],
            )

    def test_store_005_strict_parsers_reject_torn_noncanonical_and_tampered(
        self,
    ) -> None:
        cases = (
            (b"\n", "blank"),
            (b'{"x":1,"x":2}\n', "duplicate"),
            (b'{"x":"\xff"}\n', "UTF-8"),
            (b'{"x":1}', "terminal LF"),
            (b'{ "x":1}\n', "canonical"),
        )
        for index, (raw, message) in enumerate(cases):
            with self.subTest(index=index):
                store = self._new_store(f"malformed-{index}")
                store.journal_path.write_bytes(raw)
                before = raw
                with self.assertRaisesRegex(LedgerAuthorityStoreV2Error, message):
                    store.read_verified()
                self.assertEqual(store.journal_path.read_bytes(), before)

        legacy_event = {
            "sequence": 1,
            "timestamp": "2027-01-15T08:00:00Z",
            "actor": "codex",
            "action": "task.created",
            "task_id": "P01-TRUTH",
            "payload": {},
            "previous_hash": "0" * 64,
            "event_hash": "a" * 64,
            "signature": "b" * 64,
        }
        legacy_store = self._new_store("legacy-line")
        legacy_store.path.write_bytes(canonical_json_bytes(legacy_event) + b"\n")
        with self.assertRaisesRegex(LedgerAuthorityStoreV2Error, "HMAC v1"):
            legacy_store.read_verified()

        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        self._append(
            self.store,
            first,
            tx_id="tx-tamper",
            sequence=1,
            head=LEDGER_V2_GENESIS_HASH,
        )
        lines = self.store.journal_path.read_bytes().splitlines()
        commit = json.loads(lines[1])
        commit["post_log_sha256"] = "f" * 64
        self.store.journal_path.write_bytes(
            lines[0] + b"\n" + canonical_json_bytes(commit) + b"\n"
        )
        with self.assertRaisesRegex(LedgerAuthorityStoreV2Error, "hash is invalid"):
            self.store.read_verified()

    def test_store_006_bounded_reader_consumes_at_most_total_limit_plus_one(
        self,
    ) -> None:
        class BoundedReader:
            def __init__(self) -> None:
                self.position = 0
                self.requests: list[int] = []

            def __enter__(self):
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def readline(self, limit: int) -> bytes:
                self.requests.append(limit)
                self.position += limit
                return b"x" * limit

        reader = BoundedReader()
        with (
            patch.object(self.store, "_open_regular", return_value=12345),
            patch("cogni_os.ledger_authority_store_v2.os.fdopen", return_value=reader),
            self.assertRaisesRegex(LedgerAuthorityStoreV2Error, "byte limit"),
        ):
            self.store._read_jsonl(
                self.store.path,
                label="bounded fixture",
                maximum_line=4096,
                maximum_bytes=32,
                maximum_entries=10,
                decoder=lambda body, line: {},
            )
        self.assertEqual(reader.requests, [33])
        self.assertLessEqual(reader.position, 33)

    def test_store_007_forbidden_legacy_root_rejects_both_overlap_directions(
        self,
    ) -> None:
        boundary = self.root / "boundary"
        legacy = boundary / "legacy"
        legacy.mkdir(parents=True)
        marker = legacy / "events.jsonl"
        marker.write_bytes(b"legacy-fixture\n")
        before = marker.read_bytes()
        for candidate in (legacy / "v2-child", boundary):
            with (
                self.subTest(candidate=candidate),
                self.assertRaisesRegex(LedgerAuthorityStoreV2Error, "overlaps"),
            ):
                LedgerAuthorityV2Store(candidate, forbidden_legacy_root=legacy)
        self.assertEqual(marker.read_bytes(), before)
        self.assertFalse((legacy / "v2-child").exists())

    def test_store_008_lock_is_descriptor_owned_and_never_unlinked(self) -> None:
        self.assertNotIn("FileLock", inspect.getsource(store_module))
        first = DurableV2DescriptorLock(self.store.lock_path)
        first.acquire()
        identity = self.store.lock_path.stat().st_ino
        first.release()
        second = DurableV2DescriptorLock(self.store.lock_path)
        second.acquire()
        self.assertEqual(self.store.lock_path.stat().st_ino, identity)
        second.release()
        self.assertTrue(self.store.lock_path.is_file())

    def test_store_009_checkpoint_pins_both_ledger_and_journal(self) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        result = self._append(
            self.store,
            first,
            tx_id="tx-checkpoint-1",
            sequence=1,
            head=LEDGER_V2_GENESIS_HASH,
        )
        checkpoint = self.store.sign_checkpoint(issued_at="2027-01-15T08:00:01Z")
        self.assertEqual(
            checkpoint["journal_head_hash"], result.snapshot.journal_head_hash
        )
        self.assertEqual(
            self.store.verify_pinned_checkpoint(checkpoint), result.snapshot
        )
        second = self._signed(2, first["event_hash"])
        self._append(
            self.store,
            second,
            tx_id="tx-checkpoint-2",
            sequence=2,
            head=first["event_hash"],
        )
        with self.assertRaisesRegex(LedgerAuthorityStoreV2Error, "not pinned"):
            self.store.verify_pinned_checkpoint(checkpoint)
        self.assertFalse(self.store.assurance["release_ready"])

    def test_store_010_no_truncate_or_repair_after_partial_event_write(self) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        real_write = os.write
        real_write_all = self.store._write_all

        def partial_event(descriptor: int, record: bytes) -> None:
            if os.fstat(descriptor).st_ino != self.store.path.stat().st_ino:
                real_write_all(descriptor, record)
                return
            raw = bytes(record)
            real_write(descriptor, raw[: len(raw) // 2])
            raise OSError("partial event")

        with (
            patch.object(self.store, "_write_all", side_effect=partial_event),
            self.assertRaises(IndeterminateCommit),
        ):
            self._append(
                self.store,
                first,
                tx_id="tx-partial",
                sequence=1,
                head=LEDGER_V2_GENESIS_HASH,
            )
        torn = self.store.path.read_bytes()
        journal = self.store.journal_path.read_bytes()
        self.assertFalse(torn.endswith(b"\n"))
        with self.assertRaises(LedgerAuthorityStoreV2Error):
            self.store.read_verified()
        LedgerAuthorityV2Store(self.store.root, forbidden_legacy_root=self.legacy_root)
        self.assertEqual(self.store.path.read_bytes(), torn)
        self.assertEqual(self.store.journal_path.read_bytes(), journal)

    def test_store_011_reconcile_prepared_not_applied_is_exact_and_idempotent(
        self,
    ) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        real_append_record = self.store._append_record

        def stop_before_event(
            path: Path, record: bytes, *, maximum: int, label: str
        ) -> None:
            if path == self.store.path:
                raise OSError("event append was not attempted")
            real_append_record(path, record, maximum=maximum, label=label)

        with (
            patch.object(self.store, "_append_record", side_effect=stop_before_event),
            self.assertRaises(IndeterminateCommit),
        ):
            self._append(
                self.store,
                first,
                tx_id="tx-not-applied",
                sequence=1,
                head=LEDGER_V2_GENESIS_HASH,
            )
        self.assertEqual(self.store.path.read_bytes(), b"")
        self.assertEqual(len(self.store.journal_path.read_bytes().splitlines()), 1)

        reopened = LedgerAuthorityV2Store(
            self.store.root, forbidden_legacy_root=self.legacy_root
        )
        first_result = reopened.reconcile_transaction("tx-not-applied")
        journal_after = reopened.journal_path.read_bytes()
        log_after = reopened.path.read_bytes()
        second_result = reopened.reconcile_transaction("tx-not-applied")
        self.assertEqual(second_result, first_result)
        self.assertEqual(reopened.journal_path.read_bytes(), journal_after)
        self.assertEqual(reopened.path.read_bytes(), log_after)

    def test_store_012_reconcile_postcheck_failure_remains_indeterminate(self) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        real_append_record = self.store._append_record

        def stop_before_event(
            path: Path, record: bytes, *, maximum: int, label: str
        ) -> None:
            if path == self.store.path:
                raise OSError("leave durable PREPARE without event")
            real_append_record(path, record, maximum=maximum, label=label)

        with (
            patch.object(self.store, "_append_record", side_effect=stop_before_event),
            self.assertRaises(IndeterminateCommit),
        ):
            self._append(
                self.store,
                first,
                tx_id="tx-postcheck",
                sequence=1,
                head=LEDGER_V2_GENESIS_HASH,
            )

        real_read_combined = self.store._read_combined_unlocked
        combined_reads = 0

        def fail_reconcile_postcheck(
            *,
            require_clean: bool,
            allow_indeterminate_tx_id: str | None = None,
        ):
            nonlocal combined_reads
            combined_reads += 1
            if combined_reads == 2:
                self.assertEqual(allow_indeterminate_tx_id, "tx-postcheck")
                self.assertIn("tx-postcheck", self.store._indeterminate_tx_ids)
                raise OSError("injected combined postcheck failure")
            return real_read_combined(
                require_clean=require_clean,
                allow_indeterminate_tx_id=allow_indeterminate_tx_id,
            )

        with (
            patch.object(
                self.store,
                "_read_combined_unlocked",
                side_effect=fail_reconcile_postcheck,
            ),
            self.assertRaises(IndeterminateCommit) as caught,
        ):
            self.store.reconcile_transaction("tx-postcheck")
        self.assertEqual(caught.exception.phase, "reconcile-postcheck")
        self.assertIn("tx-postcheck", self.store._indeterminate_tx_ids)
        self.assertEqual(
            self.store.get_transaction("tx-postcheck").status, "indeterminate"
        )

        reconciled = self.store.reconcile_transaction("tx-postcheck")
        self.assertEqual(reconciled.snapshot.event_count, 1)
        self.assertNotIn("tx-postcheck", self.store._indeterminate_tx_ids)

    def test_store_013_checkpoint_pin_holds_lock_across_signature_verification(
        self,
    ) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        self._append(
            self.store,
            first,
            tx_id="tx-race-1",
            sequence=1,
            head=LEDGER_V2_GENESIS_HASH,
        )
        checkpoint = self.store.sign_checkpoint(issued_at="2027-01-15T08:00:01Z")
        second = self._signed(2, first["event_hash"])
        peer = LedgerAuthorityV2Store(
            self.store.root, forbidden_legacy_root=self.legacy_root
        )
        started = threading.Event()
        completed = threading.Event()
        worker_errors: list[BaseException] = []
        worker: list[threading.Thread] = []
        real_verify = store_module.verify_signed_checkpoint

        def concurrent_append() -> None:
            started.set()
            try:
                self._append(
                    peer,
                    second,
                    tx_id="tx-race-2",
                    sequence=2,
                    head=first["event_hash"],
                )
            except Exception as exc:  # noqa: BLE001 - cross-thread test boundary
                worker_errors.append(exc)
            finally:
                completed.set()

        def verify_while_contended(value: dict[str, object]):
            contender = threading.Thread(target=concurrent_append, daemon=True)
            worker.append(contender)
            contender.start()
            self.assertTrue(started.wait(1.0))
            self.assertFalse(completed.wait(0.1))
            return real_verify(value)

        with patch.object(
            store_module,
            "verify_signed_checkpoint",
            side_effect=verify_while_contended,
        ):
            pinned = self.store.verify_pinned_checkpoint(checkpoint)

        self.assertTrue(completed.wait(5.0))
        worker[0].join(timeout=1.0)
        self.assertEqual(worker_errors, [])
        self.assertEqual(pinned.event_count, 1)
        self.assertEqual(pinned.journal_head_hash, checkpoint["journal_head_hash"])
        self.assertEqual(self.store.read_verified().event_count, 2)

    def test_store_014_prepare_failure_before_bytes_is_retryable_not_applied(
        self,
    ) -> None:
        first = self._signed(1, LEDGER_V2_GENESIS_HASH)
        real_append_record = self.store._append_record

        def fail_before_prepare(
            path: Path, record: bytes, *, maximum: int, label: str
        ) -> None:
            if path == self.store.journal_path and label.endswith("PREPARE"):
                raise OSError("PREPARE open failed before any bytes")
            real_append_record(path, record, maximum=maximum, label=label)

        with (
            patch.object(self.store, "_append_record", side_effect=fail_before_prepare),
            self.assertRaises(RetryableAppendNotApplied) as caught,
        ):
            self._append(
                self.store,
                first,
                tx_id="tx-retryable",
                sequence=1,
                head=LEDGER_V2_GENESIS_HASH,
            )
        self.assertEqual(caught.exception.tx_id, "tx-retryable")
        self.assertEqual(self.store.get_transaction("tx-retryable").status, "missing")
        self.assertNotIn("tx-retryable", self.store._indeterminate_tx_ids)
        self.assertEqual(self.store.read_verified().event_count, 0)
        self.assertEqual(self.store.path.read_bytes(), b"")
        self.assertEqual(self.store.journal_path.read_bytes(), b"")

        retried = self._append(
            self.store,
            first,
            tx_id="tx-retryable",
            sequence=1,
            head=LEDGER_V2_GENESIS_HASH,
        )
        self.assertEqual(retried.snapshot.event_count, 1)
        self.assertEqual(self.store.get_transaction("tx-retryable").status, "committed")


if __name__ == "__main__":
    unittest.main()
