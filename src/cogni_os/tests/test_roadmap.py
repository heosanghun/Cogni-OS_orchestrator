"""Tests for the evidence-gated Phase 1-11 roadmap."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cogni_os.errors import ConfigurationError
from cogni_os.roadmap import (
    ROADMAP_PHASES,
    bootstrap_roadmap,
    roadmap_snapshot,
    roadmap_status,
)
from cogni_os.workspace import Workspace


class RoadmapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = Workspace.initialize(
            self.root,
            name="Roadmap Test",
            orchestrator="codex",
            orchestrator_control_principal="codex-conductor",
            orchestrator_model_family="openai-codex",
            preset="cogni-codex-antigravity",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_bootstrap_registers_strict_sequential_graph(self) -> None:
        result = bootstrap_roadmap(self.workspace, actor="codex")

        self.assertEqual(len(result["created"]), 11)
        self.assertEqual(result["existing"], [])
        self.assertEqual(result["status"]["trusted_complete"], 0)
        self.assertEqual(result["status"]["progress_percent"], 0.0)

        tasks = {task["id"]: task for task in self.workspace.list_tasks()}
        self.assertEqual(set(tasks), {item["id"] for item in ROADMAP_PHASES})
        previous = None
        for contract in ROADMAP_PHASES:
            task = tasks[contract["id"]]
            self.assertEqual(
                task["prerequisites"],
                [] if previous is None else [previous],
            )
            self.assertTrue(task["gates"]["require_validation"])
            self.assertTrue(task["gates"]["require_known_answer_check"])
            self.assertTrue(task["gates"]["require_independent_verification"])
            self.assertFalse(task["gates"]["allow_skips"])
            previous = task["id"]

        self.assertTrue(tasks["P08-CORE"]["permissions"]["gpu"])
        self.assertTrue(tasks["P11-RELEASE"]["permissions"]["gpu"])
        self.assertFalse(tasks["P10-COGNIBOARD"]["permissions"]["gpu"])
        self.assertFalse(tasks["P02-ORCHESTRATION"]["permissions"]["network"])
        self.assertFalse(tasks["P10-COGNIBOARD"]["permissions"]["network"])
        self.assertIn(
            "preemptive filesystem confinement",
            tasks["P02-ORCHESTRATION"]["description"],
        )
        self.assertIn(
            "OS-level deny-by-default network isolation",
            tasks["P02-ORCHESTRATION"]["description"],
        )
        self.assertIn(
            "conductor-only",
            tasks["P10-COGNIBOARD"]["description"],
        )
        immutable_evidence_roots = {
            "tasks",
            "reports",
            "submissions",
            "ledger",
        }
        self.assertTrue(
            immutable_evidence_roots.isdisjoint(
                tasks["P01-TRUTH"]["allowed_write_roots"]
            )
        )
        self.assertIn(
            "verification.restatement",
            tasks["P01-TRUTH"]["description"],
        )
        for task in tasks.values():
            if task["permissions"]["gpu"]:
                self.assertIn(
                    "GPU",
                    task["description"].upper(),
                )

    def test_bootstrap_is_idempotent(self) -> None:
        bootstrap_roadmap(self.workspace, actor="codex")
        second = bootstrap_roadmap(self.workspace, actor="codex")

        self.assertEqual(second["created"], [])
        self.assertEqual(len(second["existing"]), 11)
        self.assertEqual(self.workspace.status()["total_tasks"], 11)

    def test_bootstrap_rejects_drifted_contract(self) -> None:
        bootstrap_roadmap(self.workspace, actor="codex")
        path = self.root / "tasks" / "P04-WORLD.json"
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace(
                "Phase 4 - ESTC world kernel",
                "drifted title",
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ConfigurationError, "different contract"):
            bootstrap_roadmap(self.workspace, actor="codex")

    def test_status_rejects_forged_verified_task(self) -> None:
        bootstrap_roadmap(self.workspace, actor="codex")
        task = self.workspace.get_task("P01-TRUTH")
        task["state"] = "verified"
        task["verification"] = {"decision": "accept"}
        (self.root / "tasks" / "P01-TRUTH.json").write_text(
            __import__("json").dumps(task),
            encoding="utf-8",
        )
        status = roadmap_status(self.workspace)

        self.assertEqual(status["trusted_complete"], 0)
        self.assertEqual(status["progress_percent"], 0.0)
        self.assertEqual(
            status["phases"][0]["state"],
            "verification_disputed",
        )
        self.assertEqual(
            status["progress_basis"],
            "trusted-roadmap-task-states",
        )

    def test_snapshot_counts_only_canonical_trusted_phase_states(self) -> None:
        status = roadmap_snapshot(
            [
                {"id": "P01-TRUTH", "state": "verified"},
                {"id": "P02-ORCHESTRATION", "state": "verification_disputed"},
                {"id": "T-UNRELATED", "state": "verified"},
            ]
        )

        self.assertEqual(status["total"], 11)
        self.assertEqual(status["trusted_complete"], 1)
        self.assertEqual(status["progress_percent"], 9.1)
        self.assertEqual(status["phases"][0]["state"], "verified")
        self.assertEqual(
            status["phases"][1]["state"],
            "verification_disputed",
        )
        self.assertEqual(status["phases"][2]["state"], "missing")


if __name__ == "__main__":
    unittest.main()
