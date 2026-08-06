"""Unit tests for Cogni-OS Workspace & CLI."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cogni_os.errors import (
    AuthorizationError,
    EvidenceError,
    IntegrityError,
    TransitionError,
)
from cogni_os.tests._actor_capability_test_support import (
    install_legacy_capability_fixture,
)
from cogni_os.tests._isolation_test_support import install_direct_isolation_fixture
from cogni_os.util import atomic_write_json
from cogni_os.workspace import Workspace

from cogni_os.cli import build_parser


class TestCogniOSWorkspace(unittest.TestCase):
    def setUp(self):
        install_legacy_capability_fixture(self)
        install_direct_isolation_fixture(self)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _commit_fixture(self) -> None:
        self.validation_helper = self.root / "trusted_validation_helper.py"
        self.validation_helper.write_text(
            "import sys\nsys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init"], cwd=self.root, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "core.autocrlf", "false"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "tests@cogni.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Cogni Tests"],
            cwd=self.root,
            check=True,
        )
        # Keep the fixture deterministic even when the host has a global
        # excludes rule for Python files.
        subprocess.run(
            ["git", "add", "-f", "trusted_validation_helper.py"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(
            ["git", "commit", "-m", "test fixture"],
            cwd=self.root,
            check=True,
            capture_output=True,
        )

    def test_initialize_workspace(self):
        ws = Workspace.initialize(
            self.root,
            name="Test Cogni-OS Workspace",
            orchestrator="codex",
            preset="cogni-codex-antigravity",
        )
        self._commit_fixture()
        self.assertEqual(ws.orchestrator, "codex")
        status = ws.status()
        self.assertEqual(status["total_tasks"], 0)
        self.assertTrue(status["ledger"]["valid"])

        agents = ws.list_agents()
        agent_ids = [a["id"] for a in agents]
        self.assertIn("codex", agent_ids)
        self.assertIn("antigravity", agent_ids)
        self.assertIn("antigravity-verifier", agent_ids)

    def test_task_lifecycle(self):
        ws = Workspace.initialize(
            self.root,
            name="Lifecycle Test",
            orchestrator="codex",
            preset="cogni-codex-antigravity",
        )
        self._commit_fixture()

        # 1. Add Task
        task = ws.add_task(
            actor="codex",
            task_id="T1",
            title="Implement Core Module",
            description="Build core algorithm",
            owner="antigravity",
        )
        self.assertEqual(task["state"], "pending")

        # 2. Claim Task
        claimed = ws.claim(actor="antigravity", task_id="T1")
        self.assertEqual(claimed["task"]["state"], "claimed")
        token = claimed["lease_token"]

        # 3. Start Task
        started = ws.start(actor="antigravity", task_id="T1", lease_token=token)
        self.assertEqual(started["state"], "running")

        # 4. Prepare Report & Evidence Manifest
        report_dir = ws.reports_dir / "antigravity"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_file = report_dir / "T1.md"
        report_file.write_text(
            "## 1. Overview\nDone\n"
            "## 2. Approach\nBuilt algorithm\n"
            "## 3. Evidence\nTests passed\n"
            "## 4. Risks\nNone\n"
            "## 5. Security\nAudited\n"
            "## 6. Conclusion\nReady\n",
            encoding="utf-8",
        )

        artifact_file = report_dir / "out.txt"
        art_bytes = b"hello world\n"
        artifact_file.write_bytes(art_bytes)
        import hashlib

        art_sha = hashlib.sha256(art_bytes).hexdigest()
        worker_raw = report_dir / "worker-test.log"
        worker_raw_bytes = b"1 passed\n"
        worker_raw.write_bytes(worker_raw_bytes)
        worker_raw_sha = hashlib.sha256(worker_raw_bytes).hexdigest()

        manifest_file = report_dir / "T1.evidence.json"
        import json

        manifest_data = {
            "schema_version": 1,
            "artifacts": [{"path": "out.txt", "sha256": art_sha}],
            "validations": [
                {
                    "command": "python -m unittest discover",
                    "exit_code": 0,
                    "passed": 1,
                    "failed": 0,
                    "skipped": 0,
                    "raw_output_path": "worker-test.log",
                    "raw_output_sha256": worker_raw_sha,
                }
            ],
            "known_answer_checks": [
                {"name": "check1", "expected": 10, "observed": 10, "passed": True}
            ],
            "claims": [],
        }
        manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

        # 5. Submit Task
        submitted = ws.submit(
            actor="antigravity",
            task_id="T1",
            lease_token=token,
            report_path=report_file,
            evidence_path=manifest_file,
        )
        self.assertEqual(submitted["state"], "submitted")

        verifier_dir = ws.reports_dir / "codex"
        verifier_raw = verifier_dir / "T1-verifier.log"
        verifier_raw_bytes = b"known-answer independently reproduced\n"
        verifier_raw.write_bytes(verifier_raw_bytes)
        verifier_manifest = verifier_dir / "T1.verifier.evidence.json"
        verifier_manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "artifacts": [],
                    "validations": [
                        {
                            "command": "python -m unittest discover --independent",
                            "command_argv": [
                                sys.executable,
                                str(self.validation_helper),
                                verifier_raw_bytes.hex(),
                            ],
                            "exit_code": 0,
                            "passed": 1,
                            "failed": 0,
                            "skipped": 0,
                            "raw_output_path": "T1-verifier.log",
                            "raw_output_sha256": hashlib.sha256(
                                verifier_raw_bytes
                            ).hexdigest(),
                        }
                    ],
                    "known_answer_checks": [
                        {
                            "name": "check1-independent",
                            "expected": 10,
                            "observed": 10,
                            "passed": True,
                        }
                    ],
                    "claims": [],
                }
            ),
            encoding="utf-8",
        )

        # 6. Verify Task with the independent Codex family, not an
        # Antigravity role-labelled alias.
        verified = ws.verify(
            actor="codex",
            task_id="T1",
            decision="accept",
            note="Verified clean.",
            evidence_path=verifier_manifest,
        )
        self.assertEqual(verified["state"], "verified")

    def test_conductor_recovers_lost_claimed_and_running_leases(self):
        ws = Workspace.initialize(
            self.root,
            name="Lease recovery test",
            orchestrator="codex",
            preset="cogni-codex-antigravity",
        )

        for task_id, should_start in (("T-CLAIMED", False), ("T-RUNNING", True)):
            with self.subTest(task_id=task_id):
                ws.add_task(
                    actor="codex",
                    task_id=task_id,
                    title="Recover interrupted work",
                    description="Requeue without reconstructing a lost token.",
                    owner="antigravity",
                )
                claimed = ws.claim(actor="antigravity", task_id=task_id)
                token = claimed["lease_token"]
                active = claimed["task"]
                if should_start:
                    active = ws.start(
                        actor="antigravity",
                        task_id=task_id,
                        lease_token=token,
                    )
                active = json.loads(json.dumps(active))
                active["lease"]["expires_at"] = "2000-01-01T00:00:00Z"
                ws.ledger.append(
                    actor="antigravity",
                    action="task.heartbeat",
                    task_id=task_id,
                    payload={"task": active},
                )
                atomic_write_json(ws._task_path(task_id), active)
                previous_revision = active["revision"]
                previous_expiration = active["lease"]["expires_at"]

                recovered = ws.recover_lease(
                    actor="codex",
                    task_id=task_id,
                    reason="Host restarted before the worker token was retained.",
                )

                self.assertEqual(recovered["state"], "pending")
                self.assertIsNone(recovered["lease"])
                self.assertEqual(recovered["attempt"], 1)
                self.assertEqual(recovered["revision"], previous_revision + 2)
                event = ws.ledger.read()[-1]
                self.assertEqual(event["action"], "task.lease_recovered")
                self.assertEqual(event["actor"], "codex")
                self.assertEqual(event["payload"]["previous_state"], active["state"])
                self.assertEqual(
                    event["payload"]["previous_holder"],
                    "antigravity",
                )
                self.assertEqual(
                    event["payload"]["previous_expires_at"],
                    previous_expiration,
                )
                self.assertEqual(event["payload"]["previous_attempt"], 1)
                self.assertEqual(
                    event["payload"]["transition"],
                    {
                        "from": active["state"],
                        "via": "blocked",
                        "to": "pending",
                    },
                )
                self.assertNotIn("token_hash", str(event))
                self.assertNotIn(token, str(event))
                self.assertEqual(ws.ledger.projected_tasks()[task_id], recovered)
                self.assertEqual(ws.get_task(task_id), recovered)
                self.assertTrue(ws.audit_projections()["valid"])

                reclaimed = ws.claim(actor="antigravity", task_id=task_id)
                self.assertEqual(reclaimed["task"]["attempt"], 2)
                restarted = ws.start(
                    actor="antigravity",
                    task_id=task_id,
                    lease_token=reclaimed["lease_token"],
                )
                self.assertEqual(restarted["state"], "running")

    def test_lease_recovery_rejects_non_conductor_empty_reason_and_idle_task(self):
        ws = Workspace.initialize(
            self.root,
            name="Lease recovery authorization",
            orchestrator="codex",
            preset="cogni-codex-antigravity",
        )
        ws.add_task(
            actor="codex",
            task_id="T-RECOVER",
            title="Recover safely",
            description="Only the conductor can recover active work.",
            owner="antigravity",
        )
        claimed = ws.claim(actor="antigravity", task_id="T-RECOVER")
        original = json.loads(json.dumps(claimed["task"]))
        original["lease"]["expires_at"] = "2000-01-01T00:00:00Z"
        ws.ledger.append(
            actor="antigravity",
            action="task.heartbeat",
            task_id="T-RECOVER",
            payload={"task": original},
        )
        atomic_write_json(ws._task_path("T-RECOVER"), original)

        with self.assertRaises(AuthorizationError):
            ws.recover_lease(
                actor="antigravity",
                task_id="T-RECOVER",
                reason="Try to reclaim my own lease.",
            )
        with self.assertRaises(EvidenceError):
            ws.recover_lease(
                actor="codex",
                task_id="T-RECOVER",
                reason="   ",
            )
        self.assertEqual(ws.get_task("T-RECOVER"), original)
        self.assertFalse(
            any(event["action"] == "task.lease_recovered" for event in ws.ledger.read())
        )

        tampered = ws.get_task("T-RECOVER")
        tampered["lease"]["holder"] = "forged-holder"
        (ws.tasks_dir / "T-RECOVER.json").write_text(
            json.dumps(tampered),
            encoding="utf-8",
        )
        with self.assertRaises(IntegrityError):
            ws.recover_lease(
                actor="codex",
                task_id="T-RECOVER",
                reason="A mutable task file cannot authorize recovery.",
            )
        (ws.tasks_dir / "T-RECOVER.json").write_text(
            json.dumps(original),
            encoding="utf-8",
        )

        recovered = ws.recover_lease(
            actor="codex",
            task_id="T-RECOVER",
            reason="Confirmed worker interruption.",
        )
        self.assertEqual(recovered["state"], "pending")
        with self.assertRaises(TransitionError):
            ws.recover_lease(
                actor="codex",
                task_id="T-RECOVER",
                reason="A pending task has no active lease.",
            )

    def test_recover_lease_cli_has_no_bearer_token_argument(self):
        args = build_parser().parse_args(
            [
                "task",
                "recover-lease",
                str(self.root),
                "--actor",
                "codex",
                "--id",
                "T-RECOVER",
                "--reason",
                "Host interruption",
            ]
        )
        self.assertEqual(args.task_command, "recover-lease")
        self.assertFalse(hasattr(args, "lease_token"))


if __name__ == "__main__":
    unittest.main()
