"""Focused tests for evidence-safe external-agent prompts."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cogni_os.adapter import render_task_prompt
from cogni_os.tests._actor_capability_test_support import (
    install_legacy_capability_fixture,
)
from cogni_os.workspace import Workspace


class AdapterPromptTests(unittest.TestCase):
    def setUp(self) -> None:
        install_legacy_capability_fixture(self)

    def test_unmeasured_claims_are_omitted_and_recorded_as_no_go(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = Workspace.initialize(
                root,
                name="Adapter Prompt Test",
                orchestrator="codex",
                orchestrator_control_principal="codex-conductor",
                orchestrator_model_family="openai-codex",
                preset="cogni-codex-antigravity",
            )
            workspace.add_task(
                actor="codex",
                task_id="T-PROMPT",
                title="Prompt contract",
                description="Verify prompt evidence rules.",
                owner="antigravity",
            )
            task = workspace.get_task("T-PROMPT")

            prompt = render_task_prompt(
                workspace=workspace,
                task=task,
                report_path=root / "reports" / "T-PROMPT.md",
                evidence_path=root / "reports" / "T-PROMPT.evidence.json",
            )

        self.assertIn(
            "Omit unmeasured claims from the evidence manifest",
            prompt,
        )
        self.assertIn("explicit NO_GO limitation", prompt)
        self.assertIn(
            "Never place [FILL] or any unresolved placeholder",
            prompt,
        )
        self.assertNotIn("Unmeasured values must be [FILL]", prompt)


if __name__ == "__main__":
    unittest.main()
