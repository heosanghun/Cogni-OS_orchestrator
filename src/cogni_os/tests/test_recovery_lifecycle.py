"""Crash-recovery and lease-recovery security regressions."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cogni_os.actor_capability import (
    CAPABILITY_HOME_ENV,
    ActorCapabilityAuthority,
    authority_for_workspace,
)
from cogni_os.doctor import audit_workspace
from cogni_os.errors import (
    AuthorizationError,
    ConfigurationError,
    IntegrityError,
    LeaseError,
)
from cogni_os.model import transition
from cogni_os.util import atomic_write_json
from cogni_os.verification_lifecycle import audit_verification_runs
from cogni_os.workspace import Workspace


class RecoveryLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.root = base / "workspace"
        self.capability_home = base / "capability-home"
        self.secret = b"codex-recovery-test-secret-32-bytes-minimum"
        self.environment = patch.dict(
            os.environ,
            {CAPABILITY_HOME_ENV: str(self.capability_home)},
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.workspace = Workspace.initialize(
            self.root,
            name="Recovery lifecycle test",
            orchestrator="codex",
            preset="cogni-codex-antigravity",
        )
        authority = authority_for_workspace(self.workspace)
        authority.provision_guard(actor="codex", bootstrap_secret=self.secret)
        authority.bootstrap(actor="codex", bootstrap_secret=self.secret)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _add_task(self, task_id: str) -> dict:
        return self.workspace.add_task(
            actor="codex",
            capability_secret=self.secret,
            task_id=task_id,
            title="Recover an interrupted operation",
            description="Test fixture",
            owner="antigravity",
        )

    def _submitted(self, task_id: str) -> dict:
        pending = self._add_task(task_id)
        submitted = transition(
            pending,
            "submitted",
            attempt=1,
            result={"submitted_by": "antigravity"},
        )
        self.workspace.ledger.append(
            actor="antigravity",
            action="task.submitted",
            task_id=task_id,
            payload={"task": submitted},
        )
        atomic_write_json(self.workspace._task_path(task_id), submitted)
        return submitted

    def _start_run(self, task_id: str, run_id: str) -> dict:
        with self._isolated_actor_posture():
            receipt = self.workspace.authorize_actor_capability(
                actor="codex",
                operation="task.verify",
                capability_secret=self.secret,
                require_actor_os_isolation=True,
                task_id=task_id,
                run_id=run_id,
                task_attempt=1,
            )
        return self.workspace.ledger.append(
            actor="codex",
            action="verification.started",
            task_id=task_id,
            payload={
                "schema_version": 1,
                "run_id": run_id,
                "task_attempt": 1,
                "verifier_identity": {"fixture": "independent-verifier"},
                "verifier_manifest_sha256": "d" * 64,
                "worker_manifest_sha256": None,
                "verification_contract_inputs_sha256": "c" * 64,
                "capability_receipt": receipt,
            },
        )

    def _isolated_actor_posture(self):
        """Attest the synthetic test principal without weakening production code."""

        return patch.object(
            ActorCapabilityAuthority,
            "status",
            return_value={
                "state": "provisioned",
                "actor_os_isolation_proven": True,
                "independent_trust_root": True,
            },
        )

    def test_orphans_after_each_preterminal_crash_are_closed_once(self) -> None:
        for index, crash_point in enumerate(("started", "receipt", "archive"), 1):
            task_id = f"T-CRASH-{index}"
            run_id = f"{index:032x}"
            self._submitted(task_id)
            self._start_run(task_id, run_id)
            if crash_point == "receipt":
                (self.workspace.runs_dir / f"{run_id}.receipt").write_text(
                    "unbound receipt\n", encoding="utf-8"
                )
            elif crash_point == "archive":
                (self.workspace.submissions_dir / f"{run_id}.archive").write_text(
                    "unbound archive\n", encoding="utf-8"
                )

            before = audit_verification_runs(self.workspace.ledger.read_verified())
            self.assertEqual(
                [item["run_id"] for item in before["orphaned_runs"]], [run_id]
            )
            with (
                patch(
                    "cogni_os.workspace.run_trusted_validations",
                    side_effect=AssertionError("reconciliation reran validation"),
                ),
                self._isolated_actor_posture(),
            ):
                first = self.workspace.reconcile_verification(
                    actor="codex",
                    capability_secret=self.secret,
                    task_id=task_id,
                    run_id=run_id,
                )
                second = self.workspace.reconcile_verification(
                    actor="codex",
                    capability_secret=self.secret,
                    task_id=task_id,
                    run_id=run_id,
                )
            self.assertTrue(first["terminal_appended"])
            self.assertFalse(second["terminal_appended"])
            self.assertEqual(first["terminal_sequence"], second["terminal_sequence"])
            lifecycle = [
                event
                for event in self.workspace.ledger.read_verified()
                if event.get("task_id") == task_id
                and event.get("payload", {}).get("run_id") == run_id
            ]
            self.assertEqual(
                [event["action"] for event in lifecycle],
                ["verification.started", "verification.failed"],
            )
            self.assertEqual(lifecycle[-1]["payload"]["stage"], "recovery")
            self.assertEqual(
                lifecycle[-1]["payload"]["error_type"], "interrupted_error"
            )
            self.assertEqual(
                lifecycle[-1]["payload"]["capability_receipt"]["operation"],
                "task.reconcile_verification",
            )

    def test_terminal_event_rebuilds_projection_without_rerun(self) -> None:
        task_id = "T-TERMINAL"
        run_id = "a" * 32
        submitted = self._submitted(task_id)
        started = self._start_run(task_id, run_id)
        started_payload = started["payload"]
        trusted_validation = {"validation_contract_sha256": "e" * 64}
        verified = transition(
            submitted,
            "verified",
            verification={
                "run_id": run_id,
                "decision": "accept",
                "verifier_identity": started_payload["verifier_identity"],
                "verifier_evidence": {
                    "manifest_sha256": started_payload["verifier_manifest_sha256"],
                    "executor_attestation": {
                        "schema_version": 0,
                        "test_only": True,
                    },
                },
                "worker_manifest_sha256": started_payload["worker_manifest_sha256"],
                "verification_contract_inputs_sha256": started_payload[
                    "verification_contract_inputs_sha256"
                ],
                "capability_receipt": started_payload["capability_receipt"],
                "trusted_validation": trusted_validation,
            },
        )
        terminal = self.workspace.ledger.append(
            actor="codex",
            action="task.verified",
            task_id=task_id,
            payload={
                "run_id": run_id,
                "task_attempt": 1,
                "task": verified,
                "verifier_identity": started_payload["verifier_identity"],
                "verifier_evidence": verified["verification"]["verifier_evidence"],
                "worker_manifest_sha256": started_payload["worker_manifest_sha256"],
                "verification_contract_inputs_sha256": started_payload[
                    "verification_contract_inputs_sha256"
                ],
                "capability_receipt": started_payload["capability_receipt"],
                "trusted_validation": trusted_validation,
            },
        )
        self.assertEqual(self.workspace.get_task(task_id)["state"], "submitted")

        with (
            patch(
                "cogni_os.workspace.run_trusted_validations",
                side_effect=AssertionError("reconciliation reran validation"),
            ),
            self._isolated_actor_posture(),
        ):
            first = self.workspace.reconcile_verification(
                actor="codex",
                capability_secret=self.secret,
                task_id=task_id,
                run_id=run_id,
            )
            second = self.workspace.reconcile_verification(
                actor="codex",
                capability_secret=self.secret,
                task_id=task_id,
                run_id=run_id,
            )
        self.assertFalse(first["terminal_appended"])
        self.assertTrue(first["projection_rebuilt"])
        self.assertFalse(second["projection_rebuilt"])
        self.assertEqual(first["terminal_sequence"], terminal["sequence"])
        self.assertEqual(self.workspace.get_task(task_id), verified)
        terminals = [
            event
            for event in self.workspace.ledger.read_verified()
            if event.get("payload", {}).get("run_id") == run_id
            and event.get("action")
            in {"verification.failed", "task.verified", "task.rejected"}
        ]
        self.assertEqual(len(terminals), 1)

    def test_doctor_flags_orphan_and_conflicting_terminal_runs(self) -> None:
        task_id = "T-DOCTOR"
        run_id = "b" * 32
        submitted = self._submitted(task_id)
        self._start_run(task_id, run_id)
        diagnosed = audit_workspace(self.root)
        self.assertFalse(diagnosed["healthy"])
        self.assertEqual(
            diagnosed["checks"]["verification_lifecycle"]["orphaned_runs"][0]["run_id"],
            run_id,
        )

        failed = self.workspace.ledger.append(
            actor="codex",
            action="verification.failed",
            task_id=task_id,
            payload={
                "schema_version": 1,
                "run_id": run_id,
                "task_attempt": 1,
                "stage": "recovery",
                "error_type": "interrupted_error",
            },
        )
        self.assertIsInstance(failed["sequence"], int)
        verified = transition(
            submitted,
            "verified",
            verification={"run_id": run_id, "decision": "accept"},
        )
        self.workspace.ledger.append(
            actor="codex",
            action="task.verified",
            task_id=task_id,
            payload={"run_id": run_id, "task": verified},
        )
        with self.assertRaises(IntegrityError):
            self.workspace.reconcile_verification(
                actor="codex",
                capability_secret=self.secret,
                task_id=task_id,
                run_id=run_id,
            )
        lifecycle = audit_verification_runs(self.workspace.ledger.read_verified())
        self.assertFalse(lifecycle["valid"])
        self.assertIn(
            "multiple_terminal_events", lifecycle["invalid_runs"][0]["reasons"]
        )

    def test_healthy_lease_is_not_preempted_and_invalid_id_creates_no_lock(
        self,
    ) -> None:
        self._add_task("T-HEALTHY")
        claimed = self.workspace.claim(actor="antigravity", task_id="T-HEALTHY")
        before_events = len(self.workspace.ledger.read_verified())
        with self.assertRaises(LeaseError):
            self.workspace.recover_lease(
                actor="codex",
                task_id="T-HEALTHY",
                reason="Must not preempt a healthy worker",
            )
        self.assertEqual(len(self.workspace.ledger.read_verified()), before_events)
        self.assertEqual(self.workspace.get_task("T-HEALTHY"), claimed["task"])

        with self.assertRaises(ConfigurationError):
            self.workspace.recover_lease(
                actor="codex",
                task_id="../outside",
                reason="Invalid path",
            )
        self.assertFalse(
            (self.workspace.control_dir / "locks" / "outside.lock").exists()
        )

    def test_expired_lease_uses_signed_session_evidence_and_preserves_attempt(
        self,
    ) -> None:
        self._add_task("T-EXPIRED")
        with patch(
            "cogni_os.workspace.lease_expiry",
            return_value="2000-01-01T00:00:00Z",
        ):
            claimed = self.workspace.claim(actor="antigravity", task_id="T-EXPIRED")
        recovered = self.workspace.recover_lease(
            actor="codex",
            task_id="T-EXPIRED",
            reason="Signed worker session expired without heartbeat",
        )
        self.assertEqual(recovered["state"], "pending")
        self.assertEqual(recovered["attempt"], claimed["task"]["attempt"])
        event = self.workspace.ledger.read_verified()[-1]
        self.assertEqual(event["action"], "task.lease_recovered")
        self.assertEqual(event["payload"]["recovery_mode"], "expired_lease")
        evidence = event["payload"]["liveness_evidence"]
        self.assertEqual(evidence["session_id"], claimed["task"]["lease"]["session_id"])
        self.assertTrue(evidence["lease_expired"])
        self.assertIsNone(event["payload"]["capability_receipt"])
        self.assertNotIn(claimed["lease_token"], str(event))
        self.assertNotIn("token_hash", str(event))

    def test_forced_recovery_is_capability_gated_and_separately_audited(self) -> None:
        self._add_task("T-FORCE")
        claimed = self.workspace.claim(actor="antigravity", task_id="T-FORCE")
        before_events = len(self.workspace.ledger.read_verified())
        with self.assertRaises(AuthorizationError):
            self.workspace.recover_lease(
                actor="codex",
                task_id="T-FORCE",
                reason="Emergency override",
                force=True,
            )
        self.assertEqual(len(self.workspace.ledger.read_verified()), before_events)

        with self._isolated_actor_posture():
            recovered = self.workspace.recover_lease(
                actor="codex",
                task_id="T-FORCE",
                reason="Emergency override with an isolated actor capability",
                force=True,
                capability_secret=self.secret,
            )
        self.assertEqual(recovered["state"], "pending")
        self.assertEqual(recovered["attempt"], claimed["task"]["attempt"])
        event = self.workspace.ledger.read_verified()[-1]
        self.assertEqual(event["action"], "task.lease_force_recovered")
        self.assertEqual(event["payload"]["recovery_mode"], "forced")
        receipt = event["payload"]["capability_receipt"]
        self.assertEqual(receipt["operation"], "task.recover_lease.force")
        self.assertFalse(receipt["actor_os_isolation_proven"])
        self.assertNotIn(claimed["lease_token"], str(event))


if __name__ == "__main__":
    unittest.main()
