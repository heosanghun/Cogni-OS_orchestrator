from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cogni_os.verifier_journal import (
    CLAIMED,
    CLEANUP_ACKED,
    CRASH_ABORTED,
    DONE,
    EXECUTING,
    EXECUTION_SEALED,
    FAILED,
    FAILED_CLEANUP_REQUIRED,
    JOURNAL_ID,
    JOURNAL_SCHEMA_VERSION,
    MAX_JOURNAL_RECORD_BYTES,
    QUARANTINED,
    RECEIPT_PERSISTED,
    RELEASE_PENDING,
    SNAPSHOT_ACQUIRED,
    SOURCE_VERIFIED,
    TERMINAL_APPENDED,
    VerifierJournal,
    VerifierJournalError,
    _canonical_json_bytes,
    _is_link_or_reparse,
)

DISPATCH_HASH = "a" * 64
SECOND_DISPATCH_HASH = "b" * 64
RUN_ID = "1" * 32


class _Clock:
    def __init__(self) -> None:
        self.value = 1_000_000

    def __call__(self) -> int:
        self.value += 1
        return self.value


class VerifierJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "journal"
        self.journal = VerifierJournal(self.root, clock_ns=_Clock())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def claim(self, dispatch_hash: str = DISPATCH_HASH):
        return self.journal.claim_dispatch(
            dispatch_hash,
            task_id="P01",
            attempt=2,
            actor="antigravity-verifier",
            run_id=RUN_ID,
        )

    def test_exclusive_claim_is_canonical_and_duplicate_does_not_reset(self) -> None:
        first = self.claim()
        self.assertTrue(first.new_dispatch)
        self.assertTrue(first.claim_acquired)
        self.assertEqual(first.record.state, CLAIMED)

        advanced = self.journal.transition(DISPATCH_HASH, SOURCE_VERIFIED)
        duplicate = self.claim()
        self.assertFalse(duplicate.new_dispatch)
        self.assertFalse(duplicate.claim_acquired)
        self.assertEqual(duplicate.record, advanced)

        record_path = self.root / f"{DISPATCH_HASH}.json"
        raw = record_path.read_bytes()
        self.assertEqual(raw, _canonical_json_bytes(advanced.as_dict()))
        self.assertEqual(json.loads(raw), advanced.as_dict())

    def test_happy_path_has_only_the_strict_state_sequence(self) -> None:
        record = self.claim().record
        states = (
            SOURCE_VERIFIED,
            SNAPSHOT_ACQUIRED,
            EXECUTING,
            EXECUTION_SEALED,
            RELEASE_PENDING,
            CLEANUP_ACKED,
            RECEIPT_PERSISTED,
            TERMINAL_APPENDED,
            DONE,
        )
        for revision, state_name in enumerate(states, start=2):
            record = self.journal.transition(
                DISPATCH_HASH,
                state_name,
                expected_revision=record.revision,
            )
            self.assertEqual(record.state, state_name)
            self.assertEqual(record.revision, revision)
        self.assertTrue(record.terminal)
        with self.assertRaisesRegex(VerifierJournalError, "Illegal"):
            self.journal.transition(DISPATCH_HASH, SOURCE_VERIFIED)

    def test_illegal_transition_and_stale_revision_fail_closed(self) -> None:
        record = self.claim().record
        with self.assertRaisesRegex(VerifierJournalError, "Illegal"):
            self.journal.transition(DISPATCH_HASH, EXECUTING)
        with self.assertRaisesRegex(VerifierJournalError, "revision changed"):
            self.journal.transition(
                DISPATCH_HASH, SOURCE_VERIFIED, expected_revision=record.revision - 1
            )

    def test_executing_recovery_never_reexecutes_and_preserves_failure_through_cleanup(
        self,
    ) -> None:
        self.claim()
        self.journal.transition(DISPATCH_HASH, SOURCE_VERIFIED)
        self.journal.transition(DISPATCH_HASH, SNAPSHOT_ACQUIRED)
        self.journal.transition(DISPATCH_HASH, EXECUTING)

        recovered = self.journal.recover(DISPATCH_HASH)
        self.assertEqual(recovered.state, CRASH_ABORTED)
        self.assertEqual(recovered.failure_code, "verifier_crash_during_execution")
        self.assertFalse(recovered.terminal)
        self.assertTrue(recovered.release_retry_required)
        self.assertEqual(self.journal.recover(DISPATCH_HASH), recovered)
        with self.assertRaisesRegex(VerifierJournalError, "Illegal"):
            self.journal.transition(DISPATCH_HASH, EXECUTION_SEALED)

        duplicate = self.claim()
        self.assertFalse(duplicate.claim_acquired)
        self.assertEqual(duplicate.record.state, CRASH_ABORTED)
        release_pending = self.journal.transition(DISPATCH_HASH, RELEASE_PENDING)
        self.assertEqual(
            release_pending.failure_code, "verifier_crash_during_execution"
        )
        cleanup = self.journal.transition(DISPATCH_HASH, CLEANUP_ACKED)
        self.assertEqual(cleanup.failure_code, "verifier_crash_during_execution")

    def test_snapshot_acquired_recovery_skips_execution_and_requires_cleanup(
        self,
    ) -> None:
        self.claim()
        self.journal.transition(DISPATCH_HASH, SOURCE_VERIFIED)
        self.journal.transition(DISPATCH_HASH, SNAPSHOT_ACQUIRED)
        recovered = self.journal.recover(DISPATCH_HASH)
        self.assertEqual(recovered.state, FAILED_CLEANUP_REQUIRED)
        self.assertTrue(recovered.release_retry_required)
        duplicate = self.claim()
        self.assertFalse(duplicate.claim_acquired)
        self.assertEqual(duplicate.record.state, FAILED_CLEANUP_REQUIRED)
        with self.assertRaisesRegex(VerifierJournalError, "Illegal"):
            self.journal.transition(DISPATCH_HASH, EXECUTING)
        pending = self.journal.transition(DISPATCH_HASH, RELEASE_PENDING)
        self.assertEqual(pending.failure_code, "verifier_restart_after_snapshot")

    def test_release_pending_survives_recovery_and_remains_retryable(self) -> None:
        self.claim()
        for state_name in (
            SOURCE_VERIFIED,
            SNAPSHOT_ACQUIRED,
            EXECUTING,
            EXECUTION_SEALED,
            RELEASE_PENDING,
        ):
            self.journal.transition(DISPATCH_HASH, state_name)
        before = self.journal.load(DISPATCH_HASH)
        after = self.journal.recover(DISPATCH_HASH)
        self.assertEqual(after, before)
        self.assertTrue(after.release_retry_required)
        self.assertEqual(self.journal.recover_all(), (after,))

    def test_failure_and_quarantine_metadata_are_bounded_and_exact(self) -> None:
        self.claim()
        failed = self.journal.mark_failed(
            DISPATCH_HASH, failure_code="source_manifest_invalid"
        )
        self.assertEqual(failed.state, FAILED)
        self.assertTrue(failed.terminal)

        self.claim(SECOND_DISPATCH_HASH)
        quarantined = self.journal.quarantine(
            SECOND_DISPATCH_HASH,
            failure_code="policy_mismatch",
            reason="Operator review is required.",
        )
        self.assertEqual(quarantined.state, QUARANTINED)
        self.assertEqual(quarantined.quarantine_reason, "Operator review is required.")
        with self.assertRaisesRegex(VerifierJournalError, "Illegal"):
            self.journal.transition(SECOND_DISPATCH_HASH, SOURCE_VERIFIED)

    def test_crash_aborted_cannot_be_requested_by_a_caller(self) -> None:
        self.claim()
        with self.assertRaisesRegex(VerifierJournalError, "only be written by recover"):
            self.journal.transition(DISPATCH_HASH, CRASH_ABORTED)

    def test_post_snapshot_quarantine_cannot_bypass_cleanup(self) -> None:
        self.claim()
        self.journal.transition(DISPATCH_HASH, SOURCE_VERIFIED)
        self.journal.transition(DISPATCH_HASH, SNAPSHOT_ACQUIRED)
        with self.assertRaisesRegex(VerifierJournalError, "Illegal"):
            self.journal.quarantine(
                DISPATCH_HASH,
                failure_code="post_snapshot_anomaly",
                reason="cleanup must happen first",
            )
        recovered = self.journal.recover(DISPATCH_HASH)
        self.journal.transition(DISPATCH_HASH, RELEASE_PENDING)
        cleaned = self.journal.transition(DISPATCH_HASH, CLEANUP_ACKED)
        self.assertEqual(cleaned.failure_code, recovered.failure_code)
        quarantined = self.journal.quarantine(
            DISPATCH_HASH,
            failure_code="post_cleanup_review",
            reason="safe to quarantine after cleanup",
        )
        self.assertEqual(quarantined.state, QUARANTINED)

    def test_duplicate_hash_with_different_identity_is_rejected(self) -> None:
        self.claim()
        with self.assertRaisesRegex(
            VerifierJournalError, "different bounded identifiers"
        ):
            self.journal.claim_dispatch(
                DISPATCH_HASH,
                task_id="P02",
                attempt=2,
                actor="antigravity-verifier",
                run_id=RUN_ID,
            )

    def test_identifiers_and_record_size_are_bounded(self) -> None:
        with self.assertRaisesRegex(VerifierJournalError, "dispatch_event_hash"):
            self.claim("A" * 64)
        with self.assertRaisesRegex(VerifierJournalError, "task_id"):
            self.journal.claim_dispatch(
                DISPATCH_HASH,
                task_id="x" * 81,
                attempt=2,
                actor="antigravity-verifier",
                run_id=RUN_ID,
            )
        with self.assertRaisesRegex(VerifierJournalError, "attempt"):
            self.journal.claim_dispatch(
                DISPATCH_HASH,
                task_id="P01",
                attempt=True,
                actor="antigravity-verifier",
                run_id=RUN_ID,
            )
        with self.assertRaisesRegex(VerifierJournalError, "size limit"):
            _canonical_json_bytes({"value": "x" * MAX_JOURNAL_RECORD_BYTES})

    def test_record_count_and_directory_scan_are_bounded(self) -> None:
        self.claim()
        with (
            patch("cogni_os.verifier_journal.MAX_JOURNAL_RECORDS", 1),
            self.assertRaisesRegex(VerifierJournalError, "reached its limit"),
        ):
            self.claim(SECOND_DISPATCH_HASH)

    def test_unknown_fields_and_noncanonical_json_are_rejected(self) -> None:
        record = self.claim().record
        record_path = self.root / f"{DISPATCH_HASH}.json"
        value = record.as_dict()
        value["unknown"] = True
        record_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(VerifierJournalError, "schema is not exact"):
            self.journal.load(DISPATCH_HASH)

        value.pop("unknown")
        record_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(VerifierJournalError, "not canonical"):
            self.journal.load(DISPATCH_HASH)

    def test_non_regular_entry_and_symlink_or_reparse_are_rejected(self) -> None:
        unsafe_root = Path(self.temporary.name) / "regular-file"
        unsafe_root.write_text("not a directory", encoding="utf-8")
        with self.assertRaisesRegex(VerifierJournalError, "not a directory"):
            VerifierJournal(unsafe_root)

        target = Path(self.temporary.name) / "target"
        target.mkdir()
        link = Path(self.temporary.name) / "link"
        try:
            os.symlink(target, link, target_is_directory=True)
        except OSError:
            # Creating symlinks may require a Windows developer-mode privilege;
            # the metadata predicate is still tested without weakening the suite.
            fake = os.stat_result((stat.S_IFLNK, 0, 0, 0, 0, 0, 0, 0, 0, 0))
            self.assertTrue(_is_link_or_reparse(fake))
        else:
            with self.assertRaisesRegex(VerifierJournalError, "symlink/reparse"):
                VerifierJournal(link)

    def test_replace_failure_preserves_previous_durable_record(self) -> None:
        before = self.claim().record
        with (
            patch("cogni_os.verifier_journal.os.replace", side_effect=OSError("boom")),
            self.assertRaisesRegex(OSError, "boom"),
        ):
            self.journal.transition(DISPATCH_HASH, SOURCE_VERIFIED)
        self.assertEqual(self.journal.load(DISPATCH_HASH), before)
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_schema_and_assurance_do_not_claim_execution_or_root_e2e(self) -> None:
        self.assertEqual(JOURNAL_ID, "cogni-os.verifier-journal.v1")
        self.assertEqual(JOURNAL_SCHEMA_VERSION, 1)
        self.assertIn(
            self.journal.assurance_scope,
            {
                "portable-semantics-only",
                "filesystem-durability-only-not-root-e2e",
            },
        )
        self.assertNotIn("verified", self.journal.assurance_scope)
        self.assertNotIn("release-go", self.journal.assurance_scope)


if __name__ == "__main__":
    unittest.main()
