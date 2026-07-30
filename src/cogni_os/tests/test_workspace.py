"""Unit tests for Cogni-OS Workspace & CLI."""

import tempfile
import unittest
from pathlib import Path

from cogni_os.workspace import Workspace
from cogni_os.errors import ConfigurationError, LeaseError, AuthorizationError


class TestCogniOSWorkspace(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_initialize_workspace(self):
        ws = Workspace.initialize(
            self.root,
            name="Test Cogni-OS Workspace",
            orchestrator="codex",
            preset="cogni-codex-antigravity",
        )
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
            encoding="utf-8"
        )

        artifact_file = report_dir / "out.txt"
        art_bytes = b"hello world\n"
        artifact_file.write_bytes(art_bytes)
        import hashlib
        art_sha = hashlib.sha256(art_bytes).hexdigest()

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
                }
            ],
            "known_answer_checks": [
                {"name": "check1", "expected": 10, "observed": 10, "passed": True}
            ],
            "claims": []
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

        # 6. Verify Task with Independent Verifier
        verified = ws.verify(
            actor="antigravity-verifier",
            task_id="T1",
            decision="accept",
            note="Verified clean.",
        )
        self.assertEqual(verified["state"], "verified")


if __name__ == "__main__":
    unittest.main()
