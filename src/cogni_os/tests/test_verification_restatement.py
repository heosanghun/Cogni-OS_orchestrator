"""Append-only correction tests for historical verification claims."""

from __future__ import annotations

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from cogni_os.doctor import audit_workspace
from cogni_os.errors import AuthorizationError, TransitionError
from cogni_os.independence import audit_verification_events, identity_snapshot
from cogni_os.model import transition
from cogni_os.tests._actor_capability_test_support import (
    install_legacy_capability_fixture,
)
from cogni_os.util import atomic_write_json, utc_now
from cogni_os.workspace import Workspace

from cogni_os.cli import build_parser


class VerificationRestatementTests(unittest.TestCase):
    def setUp(self) -> None:
        install_legacy_capability_fixture(self)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = Workspace.initialize(
            self.root,
            name="Restatement Test",
            orchestrator="codex",
            orchestrator_control_principal="codex-conductor",
            orchestrator_model_family="openai-codex",
            preset="cogni-codex-antigravity",
        )
        self.verified_sequence = self._record_same_family_verification()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _record_same_family_verification(self) -> int:
        pending = self.workspace.add_task(
            actor="codex",
            task_id="T-001",
            title="Historical release truth claim",
            description="Preserve and correct this historical claim.",
            owner="antigravity",
        )
        submitted = transition(
            pending,
            "submitted",
            attempt=1,
            result={"submitted_at": utc_now(), "submitted_by": "antigravity"},
        )
        worker = self.workspace.get_agent("antigravity")
        worker_identity = identity_snapshot("antigravity", worker["identity"])
        self.workspace.ledger.append(
            actor="antigravity",
            action="task.submitted",
            task_id="T-001",
            payload={"task": submitted, "worker_identity": worker_identity},
        )

        verifier = self.workspace.get_agent("antigravity-verifier")
        verifier_identity = identity_snapshot(
            "antigravity-verifier",
            verifier["identity"],
        )
        verification = {
            "verified_at": utc_now(),
            "verified_by": "antigravity-verifier",
            "decision": "accept",
            "note": "Historical self-verification claim.",
            "independence": {"independent": True, "reasons": []},
        }
        verified = transition(
            submitted,
            "verified",
            verification=verification,
        )
        event = self.workspace.ledger.append(
            actor="antigravity-verifier",
            action="task.verified",
            task_id="T-001",
            payload={
                "task": verified,
                "verifier_identity": verifier_identity,
                "independence": verification["independence"],
            },
        )
        atomic_write_json(self.root / "tasks" / "T-001.json", verified)
        return int(event["sequence"])

    def test_restatement_preserves_task_and_original_event(self) -> None:
        task_path = self.root / "tasks" / "T-001.json"
        task_before = task_path.read_bytes()
        events_before = self.workspace.ledger.read()
        target_before = deepcopy(events_before[self.verified_sequence - 1])

        restatement = self.workspace.restate_verification(
            actor="codex",
            task_id="T-001",
            effective_status="verification_disputed",
            reason="Worker and verifier resolve to the same model family.",
        )

        self.assertEqual(task_path.read_bytes(), task_before)
        events_after = self.workspace.ledger.read()
        self.assertEqual(
            events_after[self.verified_sequence - 1],
            target_before,
        )
        self.assertEqual(restatement["action"], "verification.restatement")
        self.assertEqual(
            restatement["payload"]["target_verification_sequence"],
            self.verified_sequence,
        )
        self.assertEqual(
            restatement["payload"]["target_verification_hash"],
            target_before["event_hash"],
        )

        audit = audit_verification_events(
            events_after,
            {agent["id"]: agent for agent in self.workspace.list_agents()},
            orchestrator="codex",
        )
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["unresolved_untrusted_verifications"], [])
        self.assertEqual(
            audit["verifications"][0]["effective_status"],
            "verification_disputed",
        )

    def test_restatement_is_idempotent_for_same_correction(self) -> None:
        first = self.workspace.restate_verification(
            actor="codex",
            task_id="T-001",
            effective_status="verification_disputed",
            reason="Same-family verifier is not independent.",
        )
        count = len(self.workspace.ledger.read())
        second = self.workspace.restate_verification(
            actor="codex",
            task_id="T-001",
            effective_status="verification_disputed",
            reason="Same-family verifier is not independent.",
        )

        self.assertEqual(first["event_hash"], second["event_hash"])
        self.assertEqual(len(self.workspace.ledger.read()), count)

    def test_audit_rejects_restatement_that_is_not_hash_bound(self) -> None:
        self.workspace.restate_verification(
            actor="codex",
            task_id="T-001",
            effective_status="verification_disputed",
            reason="Same-family verifier is not independent.",
        )
        events = deepcopy(self.workspace.ledger.read())
        events[-1]["payload"]["target_verification_hash"] = "0" * 64

        audit = audit_verification_events(
            events,
            {agent["id"]: agent for agent in self.workspace.list_agents()},
            orchestrator="codex",
        )

        self.assertFalse(audit["valid"])
        self.assertIn(
            "target_hash_mismatch",
            audit["invalid_restatements"][0]["reasons"],
        )

    def test_only_orchestrator_can_restate_and_revocation_is_monotonic(self) -> None:
        with self.assertRaises(AuthorizationError):
            self.workspace.restate_verification(
                actor="antigravity",
                task_id="T-001",
                effective_status="verification_disputed",
                reason="Unauthorized correction.",
            )

        self.workspace.restate_verification(
            actor="codex",
            task_id="T-001",
            effective_status="verification_revoked",
            reason="Historical acceptance is revoked.",
        )
        with self.assertRaises(TransitionError):
            self.workspace.restate_verification(
                actor="codex",
                task_id="T-001",
                effective_status="verification_disputed",
                reason="Attempt to weaken a final revocation.",
            )

    def test_doctor_distinguishes_health_from_release_readiness(self) -> None:
        before = audit_workspace(self.root)
        self.assertFalse(before["healthy"])
        self.assertFalse(before["release_ready"])
        self.assertEqual(
            before["checks"]["verification_semantics"][
                "unresolved_untrusted_verifications"
            ][0]["task_id"],
            "T-001",
        )

        self.workspace.restate_verification(
            actor="codex",
            task_id="T-001",
            effective_status="verification_disputed",
            reason="Same-family verification cannot satisfy the release gate.",
        )
        after = audit_workspace(self.root)

        self.assertTrue(after["healthy"])
        self.assertFalse(after["release_ready"])
        claims = after["checks"]["current_verification_claims"]
        self.assertTrue(claims["valid"])
        self.assertEqual(claims["release_blockers"], ["T-001"])
        self.assertEqual(
            claims["claims"][0]["historical_state"],
            "verification_disputed",
        )
        self.assertEqual(
            claims["claims"][0]["current_release_state"],
            "verification_disputed",
        )

    def test_cli_exposes_explicit_restatement_command(self) -> None:
        args = build_parser().parse_args(
            [
                "task",
                "restate-verification",
                str(self.root),
                "--actor",
                "codex",
                "--id",
                "T-001",
                "--status",
                "verification_disputed",
                "--reason",
                "Known historical trust defect.",
                "--target-sequence",
                str(self.verified_sequence),
            ]
        )

        self.assertEqual(args.id, "T-001")
        self.assertEqual(args.target_sequence, self.verified_sequence)


if __name__ == "__main__":
    unittest.main()
