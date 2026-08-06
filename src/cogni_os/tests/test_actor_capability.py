"""Security regressions for isolated, one-time actor capabilities."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cogni_os.actor_capability import (
    CAPABILITY_BOOTSTRAP_ENV,
    CAPABILITY_SECRET_ENV,
    ActorCapabilityAuthority,
    authority_for_workspace,
    platform_security_posture,
    scrub_capability_environment,
)
from cogni_os.doctor import audit_workspace
from cogni_os.errors import AuthorizationError, ConfigurationError, EvidenceError
from cogni_os.release_evidence import collect_p01_production_evidence
from cogni_os.release_gate import (
    _secure_archive_primitives_available,
    issue_release_gate,
)
from cogni_os.workspace import Workspace

from cogni_os.cli import main as cli_main


class ActorCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.workspace = base / "workspace"
        self.workspace.mkdir()
        self.home = base / "capability-home"
        self.secret = b"codex-conductor-root-secret-32-bytes-minimum"
        self.executant_secret = b"antigravity-executant-secret-32-bytes-minimum"
        self.authority = ActorCapabilityAuthority(
            workspace_root=self.workspace,
            workspace_id="workspace-a",
            home=self.home,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _bootstrap(self, authority=None, *, actor="codex", secret=None):
        target = authority or self.authority
        selected = secret or self.secret
        target.provision_guard(actor=actor, bootstrap_secret=selected)
        return target.bootstrap(actor=actor, bootstrap_secret=selected)

    def test_unprovisioned_and_wrong_bootstrap_fail_closed(self) -> None:
        with self.assertRaises(AuthorizationError):
            self.authority.mint(
                actor="codex",
                operation="task.add",
                credential_secret=self.secret,
            )
        self.authority.provision_guard(
            actor="codex",
            bootstrap_secret=self.secret,
        )
        with self.assertRaises(AuthorizationError):
            self.authority.bootstrap(
                actor="codex",
                bootstrap_secret=self.executant_secret,
            )
        self.assertEqual(self.authority.status(actor="codex")["state"], "guard_pending")
        status = self.authority.bootstrap(
            actor="codex",
            bootstrap_secret=self.secret,
        )
        self.assertEqual(status["state"], "provisioned")
        self.assertFalse(status["actor_os_isolation_proven"])
        self.assertFalse((self.workspace / ".cogni" / "capabilities").exists())

    def test_actor_operation_workspace_and_replay_scopes_are_enforced(self) -> None:
        self._bootstrap()
        task_id = "P01-RECEIPT-BINDING"
        run_id = "a" * 32
        token = self.authority.mint(
            actor="codex",
            operation="task.add",
            credential_secret=self.secret,
            now=10_000,
            nonce="a" * 48,
            task_id=task_id,
            run_id=run_id,
            task_attempt=1,
        )
        with self.assertRaises(AuthorizationError):
            self.authority.verify_and_consume(
                expected_actor="codex",
                expected_operation="task.recover_lease",
                token=token,
                now=10_001,
            )
        with self.assertRaises(AuthorizationError):
            self.authority.verify_and_consume(
                expected_actor="antigravity",
                expected_operation="task.add",
                token=token,
                now=10_001,
            )
        other = ActorCapabilityAuthority(
            workspace_root=self.workspace,
            workspace_id="workspace-b",
            home=self.home,
        )
        self._bootstrap(other)
        with self.assertRaises(AuthorizationError):
            other.verify_and_consume(
                expected_actor="codex",
                expected_operation="task.add",
                token=token,
                now=10_001,
            )
        consumed = self.authority.verify_and_consume(
            expected_actor="codex",
            expected_operation="task.add",
            token=token,
            now=10_001,
            expected_task_id=task_id,
            expected_run_id=run_id,
            expected_task_attempt=1,
        )
        self.assertEqual(consumed["operation"], "task.add")
        validated = self.authority.validate_receipt(
            consumed,
            expected_actor="codex",
            expected_operation="task.add",
            expected_task_id=task_id,
            expected_run_id=run_id,
            expected_task_attempt=1,
        )
        self.assertEqual(validated, consumed)
        self.assertEqual(consumed["schema_version"], 2)
        self.assertEqual(consumed["task_id"], task_id)
        self.assertEqual(consumed["run_id"], run_id)
        self.assertEqual(consumed["task_attempt"], 1)
        with self.assertRaisesRegex(AuthorizationError, "CAPABILITY_UNATTESTED"):
            self.authority.validate_receipt(
                consumed,
                expected_actor="codex",
                expected_operation="task.add",
                expected_task_id=task_id,
                expected_run_id=run_id,
                expected_task_attempt=1,
                require_independent_trust_root=True,
            )
        for mismatch in (
            {"expected_task_id": "P01-OTHER"},
            {"expected_run_id": "b" * 32},
            {"expected_task_attempt": 2},
        ):
            expected = {
                "expected_actor": "codex",
                "expected_operation": "task.add",
                "expected_task_id": task_id,
                "expected_run_id": run_id,
                "expected_task_attempt": 1,
                **mismatch,
            }
            with self.assertRaises(AuthorizationError):
                self.authority.validate_receipt(consumed, **expected)

        tampered = dict(consumed)
        tampered["consumed_at_epoch"] += 1
        with self.assertRaises(AuthorizationError):
            self.authority.validate_receipt(
                tampered,
                expected_actor="codex",
                expected_operation="task.add",
                expected_task_id=task_id,
                expected_run_id=run_id,
                expected_task_attempt=1,
            )
        with self.assertRaises(AuthorizationError):
            self.authority.validate_receipt(
                {
                    "workspace_id": "workspace-a",
                    "actor": "codex",
                    "operation": "task.add",
                },
                expected_actor="codex",
                expected_operation="task.add",
                expected_task_id=task_id,
                expected_run_id=run_id,
                expected_task_attempt=1,
            )
        with self.assertRaises(AuthorizationError):
            self.authority.verify_and_consume(
                expected_actor="codex",
                expected_operation="task.add",
                token=token,
                now=10_001,
                expected_task_id=task_id,
                expected_run_id=run_id,
                expected_task_attempt=1,
            )

    def test_executant_secret_cannot_mint_or_impersonate_conductor(self) -> None:
        self._bootstrap()
        self._bootstrap(actor="antigravity", secret=self.executant_secret)
        with self.assertRaises(AuthorizationError):
            self.authority.mint(
                actor="codex",
                operation="release.gate.issue",
                credential_secret=self.executant_secret,
            )
        executant_token = self.authority.mint(
            actor="antigravity",
            operation="release.gate.issue",
            credential_secret=self.executant_secret,
        )
        with self.assertRaises(AuthorizationError):
            self.authority.verify_and_consume(
                expected_actor="codex",
                expected_operation="release.gate.issue",
                token=executant_token,
            )

    def test_rotation_consumes_old_proof_and_invalidates_old_secret(self) -> None:
        self._bootstrap()
        old_operation_token = self.authority.mint(
            actor="codex",
            operation="task.add",
            credential_secret=self.secret,
        )
        rotation = self.authority.mint(
            actor="codex",
            operation="capability.rotate",
            credential_secret=self.secret,
        )
        new_secret = b"rotated-codex-conductor-secret-32-bytes-minimum"
        status = self.authority.rotate(
            actor="codex",
            rotation_token=rotation,
            new_secret=new_secret,
        )
        self.assertEqual(status["key_version"], 2)
        with self.assertRaises(AuthorizationError):
            self.authority.mint(
                actor="codex",
                operation="task.add",
                credential_secret=self.secret,
            )
        with self.assertRaises(AuthorizationError):
            self.authority.verify_and_consume(
                expected_actor="codex",
                expected_operation="task.add",
                token=old_operation_token,
            )
        new_token = self.authority.mint(
            actor="codex",
            operation="task.add",
            credential_secret=new_secret,
        )
        self.authority.verify_and_consume(
            expected_actor="codex",
            expected_operation="task.add",
            token=new_token,
        )

    def test_rotation_preserves_historical_receipts_and_is_compare_and_swap_safe(
        self,
    ) -> None:
        self._bootstrap()
        historical_token = self.authority.mint(
            actor="codex",
            operation="task.add",
            credential_secret=self.secret,
            task_id="P01-HISTORY",
            task_attempt=1,
        )
        historical_receipt = self.authority.verify_and_consume(
            expected_actor="codex",
            expected_operation="task.add",
            expected_task_id="P01-HISTORY",
            expected_run_id=None,
            expected_task_attempt=1,
            token=historical_token,
        )
        rotations = [
            self.authority.mint(
                actor="codex",
                operation="capability.rotate",
                credential_secret=self.secret,
            )
            for _ in range(2)
        ]
        new_secrets = [b"r" * 32, b"s" * 32]

        def rotate(index: int) -> tuple[str, object]:
            try:
                return (
                    "ok",
                    self.authority.rotate(
                        actor="codex",
                        rotation_token=rotations[index],
                        new_secret=new_secrets[index],
                    ),
                )
            except AuthorizationError as exc:
                return ("error", exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(rotate, range(2)))
        self.assertEqual([state for state, _ in outcomes].count("ok"), 1)
        self.assertEqual([state for state, _ in outcomes].count("error"), 1)
        self.assertEqual(self.authority.status(actor="codex")["key_version"], 2)
        self.authority.validate_receipt(
            historical_receipt,
            expected_actor="codex",
            expected_operation="task.add",
            expected_task_id="P01-HISTORY",
            expected_run_id=None,
            expected_task_attempt=1,
        )

    def test_secret_environment_is_removed_from_child_environment(self) -> None:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            CAPABILITY_SECRET_ENV: "do-not-inherit",
            CAPABILITY_BOOTSTRAP_ENV: "do-not-inherit-either",
        }
        clean = scrub_capability_environment(environment)
        self.assertIn("PATH", clean)
        self.assertNotIn(CAPABILITY_SECRET_ENV, clean)
        self.assertNotIn(CAPABILITY_BOOTSTRAP_ENV, clean)

    def test_same_user_process_isolation_is_never_overclaimed(self) -> None:
        posture = platform_security_posture()
        self.assertFalse(posture["same_os_user_actor_isolation_proven"])
        self.assertFalse(
            posture["workspace_process_impersonation_blocked_without_credential"]
        )
        self.assertTrue(posture["actor_label_only_authorization_rejected"])
        self.assertTrue(posture["operation_scoped_credential_check_enabled"])

    def test_capability_home_inside_workspace_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            ActorCapabilityAuthority(
                workspace_root=self.workspace,
                workspace_id="workspace-a",
                home=self.workspace / ".cogni" / "capabilities",
            )

    def test_conductor_label_cannot_mutate_workspace_without_correct_capability(
        self,
    ) -> None:
        root = self.workspace / "runtime"
        with patch.dict(os.environ, {"COGNI_CAPABILITY_HOME": str(self.home)}):
            workspace = Workspace.initialize(
                root,
                name="capability integration",
                orchestrator="codex",
                preset="cogni-codex-antigravity",
            )
            before_ledger = workspace.ledger.path.read_bytes()
            before_tasks = sorted(workspace.tasks_dir.glob("*.json"))
            with self.assertRaises(AuthorizationError):
                workspace.add_task(
                    actor="codex",
                    task_id="P01-NO-CAP",
                    title="must not exist",
                    description="actor labels are not authorization",
                    owner="antigravity",
                )
            self.assertEqual(workspace.ledger.path.read_bytes(), before_ledger)
            self.assertEqual(sorted(workspace.tasks_dir.glob("*.json")), before_tasks)

            authority = authority_for_workspace(workspace)
            authority.provision_guard(
                actor="codex",
                bootstrap_secret=self.secret,
            )
            authority.bootstrap(actor="codex", bootstrap_secret=self.secret)
            authority.provision_guard(
                actor="antigravity",
                bootstrap_secret=self.executant_secret,
            )
            authority.bootstrap(
                actor="antigravity",
                bootstrap_secret=self.executant_secret,
            )
            for wrong in (b"x" * 32, self.executant_secret):
                with self.assertRaises(AuthorizationError):
                    workspace.add_task(
                        actor="codex",
                        capability_secret=wrong,
                        task_id="P01-WRONG-CAP",
                        title="must not exist",
                        description="executant cannot impersonate conductor",
                        owner="antigravity",
                    )
                self.assertEqual(workspace.ledger.path.read_bytes(), before_ledger)
                self.assertEqual(
                    sorted(workspace.tasks_dir.glob("*.json")), before_tasks
                )

            created = workspace.add_task(
                actor="codex",
                capability_secret=self.secret,
                task_id="P01-AUTHORIZED",
                title="authorized",
                description="correct isolated capability",
                owner="antigravity",
            )
            self.assertEqual(created["state"], "pending")

    def test_workspace_init_remains_compatible_but_public_agent_add_is_guarded(
        self,
    ) -> None:
        root = self.workspace / "initialization-runtime"
        with patch.dict(os.environ, {"COGNI_CAPABILITY_HOME": str(self.home)}):
            workspace = Workspace.initialize(
                root,
                name="initialization compatibility",
                orchestrator="codex",
                preset="cogni-codex-antigravity",
            )
            self.assertEqual(
                {agent["id"] for agent in workspace.list_agents()},
                {"codex", "antigravity", "antigravity-verifier"},
            )
            self.assertFalse(self.home.exists())
            baseline = workspace.ledger.path.read_bytes()
            with self.assertRaisesRegex(AuthorizationError, "credential is required"):
                workspace.add_agent(
                    actor="codex",
                    agent_id="reviewer",
                    role="advisor",
                )
            self.assertEqual(workspace.ledger.path.read_bytes(), baseline)
            self.assertFalse((workspace.agents_dir / "reviewer.json").exists())

            authority = authority_for_workspace(workspace)
            authority.provision_guard(actor="codex", bootstrap_secret=self.secret)
            authority.bootstrap(actor="codex", bootstrap_secret=self.secret)
            reviewer = workspace.add_agent(
                actor="codex",
                capability_secret=self.secret,
                agent_id="reviewer",
                role="advisor",
            )
            self.assertEqual(reviewer["id"], "reviewer")
            self.assertTrue((workspace.agents_dir / "reviewer.json").is_file())

    def test_release_gate_is_no_go_when_capability_posture_is_unattested(self) -> None:
        root = self.workspace / "release-runtime"
        with patch.dict(os.environ, {"COGNI_CAPABILITY_HOME": str(self.home)}):
            workspace = Workspace.initialize(
                root,
                name="release gate capability posture",
                orchestrator="codex",
                preset="cogni-codex-antigravity",
            )
            before = workspace.ledger.path.read_bytes()
            if not _secure_archive_primitives_available():
                with self.assertRaisesRegex(EvidenceError, "descriptor-relative"):
                    issue_release_gate(
                        workspace,
                        actor="codex",
                        attesting_agent_id="antigravity",
                    )
                self.assertEqual(workspace.ledger.path.read_bytes(), before)
                self.assertFalse((workspace.archive_dir / "release-gates").exists())
                return
            with self.assertRaisesRegex(
                AuthorizationError,
                "CAPABILITY_UNPROVISIONED|credential is required",
            ):
                issue_release_gate(
                    workspace,
                    actor="codex",
                    attesting_agent_id="antigravity",
                )
            self.assertEqual(workspace.ledger.path.read_bytes(), before)

            authority = authority_for_workspace(workspace)
            authority.provision_guard(
                actor="codex",
                bootstrap_secret=self.secret,
            )
            authority.bootstrap(actor="codex", bootstrap_secret=self.secret)
            with self.assertRaisesRegex(AuthorizationError, "CAPABILITY_UNATTESTED"):
                issue_release_gate(
                    workspace,
                    actor="codex",
                    capability_secret=self.secret,
                    attesting_agent_id="antigravity",
                )
            self.assertEqual(workspace.ledger.path.read_bytes(), before)
            self.assertFalse((workspace.archive_dir / "release-gates").exists())

    def test_release_evidence_is_denied_before_git_network_or_archive_access(
        self,
    ) -> None:
        root = self.workspace / "release-evidence-runtime"
        with patch.dict(os.environ, {"COGNI_CAPABILITY_HOME": str(self.home)}):
            workspace = Workspace.initialize(
                root,
                name="release evidence capability posture",
                orchestrator="codex",
                preset="cogni-codex-antigravity",
            )
            baseline = workspace.ledger.path.read_bytes()
            arguments = {
                "workspace": workspace,
                "actor": "codex",
                "cloudflare_account_id": "1" * 32,
                "deployment_id": "current-deployment",
                "deployment_source_commit": "a" * 40,
                "rollback_deployment_id": "prior-deployment",
                "rollback_source_commit": "b" * 40,
            }
            with self.assertRaisesRegex(
                AuthorizationError,
                "credential is required",
            ):
                collect_p01_production_evidence(**arguments)
            self.assertEqual(workspace.ledger.path.read_bytes(), baseline)
            self.assertFalse((workspace.archive_dir / "release-evidence").exists())

            authority = authority_for_workspace(workspace)
            authority.provision_guard(actor="codex", bootstrap_secret=self.secret)
            authority.bootstrap(actor="codex", bootstrap_secret=self.secret)
            with self.assertRaisesRegex(AuthorizationError, "CAPABILITY_UNATTESTED"):
                collect_p01_production_evidence(
                    **arguments,
                    capability_secret=self.secret,
                )
            self.assertEqual(workspace.ledger.path.read_bytes(), baseline)
            self.assertFalse((workspace.archive_dir / "release-evidence").exists())

    def test_doctor_exposes_unprovisioned_capability_release_blocker(self) -> None:
        root = self.workspace / "doctor-runtime"
        with patch.dict(os.environ, {"COGNI_CAPABILITY_HOME": str(self.home)}):
            Workspace.initialize(
                root,
                name="capability doctor posture",
                orchestrator="codex",
                preset="cogni-codex-antigravity",
            )
            result = audit_workspace(root)
        self.assertEqual(
            result["checks"]["actor_capability"]["state"],
            "unprovisioned",
        )
        self.assertIn(
            "CAPABILITY_UNPROVISIONED",
            result["checks"]["current_verification_claims"]["release_blockers"],
        )
        self.assertFalse(result["release_ready"])

    def test_cli_actor_label_with_missing_or_executant_secret_cannot_mutate(
        self,
    ) -> None:
        root = self.workspace / "cli-runtime"
        capability_environment = {"COGNI_CAPABILITY_HOME": str(self.home)}
        with patch.dict(os.environ, capability_environment, clear=False):
            workspace = Workspace.initialize(
                root,
                name="CLI capability boundary",
                orchestrator="codex",
                preset="cogni-codex-antigravity",
            )
            authority = authority_for_workspace(workspace)
            for actor, secret in (
                ("codex", self.secret),
                ("antigravity", self.executant_secret),
            ):
                authority.provision_guard(actor=actor, bootstrap_secret=secret)
                authority.bootstrap(actor=actor, bootstrap_secret=secret)
            baseline = workspace.ledger.path.read_bytes()

            command = [
                "task",
                "add",
                str(root),
                "--actor",
                "codex",
                "--id",
                "P01-CLI-DENIED",
                "--owner",
                "antigravity",
                "--title",
                "must not exist",
                "--description",
                "actor label cannot authorize mutation",
            ]
            for supplied in (None, self.executant_secret.decode("utf-8")):
                environment = dict(capability_environment)
                if supplied is not None:
                    environment[CAPABILITY_SECRET_ENV] = supplied
                with (
                    patch.dict(os.environ, environment, clear=True),
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as stopped,
                ):
                    cli_main(command)
                self.assertEqual(stopped.exception.code, 1)
                self.assertEqual(workspace.ledger.path.read_bytes(), baseline)
                self.assertFalse((workspace.tasks_dir / "P01-CLI-DENIED.json").exists())


if __name__ == "__main__":
    unittest.main()
