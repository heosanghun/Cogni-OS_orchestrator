"""Independent fail-closed regressions found during the Phase 11 release audit."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for import_root in (ROOT, SRC):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from cogni_os.errors import EvidenceError  # noqa: E402
from cogni_os.trusted_runner import (  # noqa: E402
    _trusted_environment,
    _validate_command_argv,
    run_trusted_validations,
)
from cogni_os.workspace import Workspace  # noqa: E402
from scripts.publish_monitor_snapshot import (  # noqa: E402
    export_tasks,
    task_summary,
    task_trust_state,
)


class ReleaseAuditRegressionTests(unittest.TestCase):
    def test_trusted_gpu_visibility_is_bounded_to_physical_zero_through_five(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary) / "scratch"
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            with patch.dict(os.environ, {}, clear=True):
                enabled = _trusted_environment(
                    workspace_root=workspace,
                    scratch_root=scratch / "enabled",
                    gpu_allowed=True,
                    network_allowed=False,
                )
                disabled = _trusted_environment(
                    workspace_root=workspace,
                    scratch_root=scratch / "disabled",
                    gpu_allowed=False,
                    network_allowed=False,
                )
            self.assertEqual(
                enabled["CUDA_VISIBLE_DEVICES"],
                "0,1,2,3,4,5",
            )
            self.assertEqual(disabled["CUDA_VISIBLE_DEVICES"], "")

            with patch.dict(
                os.environ,
                {"CUDA_VISIBLE_DEVICES": "1,3,6,7"},
                clear=True,
            ):
                narrowed = _trusted_environment(
                    workspace_root=workspace,
                    scratch_root=scratch / "narrowed",
                    gpu_allowed=True,
                    network_allowed=False,
                )
            self.assertEqual(narrowed["CUDA_VISIBLE_DEVICES"], "1,3")

    def test_trusted_gpu_visibility_rejects_uuid_mig_and_remap_ambiguity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            scratch = Path(temporary) / "scratch"
            ambiguous_environments = (
                {"CUDA_VISIBLE_DEVICES": "GPU-01234567"},
                {"CUDA_VISIBLE_DEVICES": "MIG-GPU-01234567/1/0"},
                {"CUDA_VISIBLE_DEVICES": "1,1"},
                {"NVIDIA_VISIBLE_DEVICES": "GPU-01234567"},
                {"NVIDIA_VISIBLE_DEVICES": "2,4"},
                {"NVIDIA_VISIBLE_DEVICES": "0,1,2,3,4,5,6"},
            )
            for environment in ambiguous_environments:
                with self.subTest(environment=environment), patch.dict(
                    os.environ,
                    environment,
                    clear=True,
                ), self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(GPU|device|remap|numeric|duplicate)",
                ):
                    _trusted_environment(
                        workspace_root=workspace,
                        scratch_root=scratch,
                        gpu_allowed=True,
                        network_allowed=False,
                    )

    def test_trusted_runner_rejects_dirty_executed_source(self) -> None:
        """A receipt must not bind dirty executed bytes to the clean HEAD SHA."""
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            script_path = workspace / "verify_source.py"
            script_path.write_text(
                "import sys\nsys.stdout.buffer.write(b'clean\\n')\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["git", "init"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "audit@cogni.invalid"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Cogni Release Audit"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "add", "verify_source.py"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "trusted source fixture"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )

            dirty_output = b"dirty\n"
            script_path.write_text(
                "import sys\nsys.stdout.buffer.write(b'dirty\\n')\n",
                encoding="utf-8",
            )
            manifest = {
                "validations": [
                    {
                        "command_argv": [sys.executable, str(script_path)],
                        "exit_code": 0,
                        "raw_output": {
                            "sha256": hashlib.sha256(dirty_output).hexdigest(),
                        },
                    }
                ]
            }

            with self.assertRaisesRegex(
                EvidenceError,
                r"(?i)(dirty|uncommitted|source|worktree)",
            ):
                run_trusted_validations(
                    workspace_root=workspace,
                    runs_root=workspace / "runs",
                    task_id="T-DIRTY-SOURCE",
                    attempt=1,
                    actor="codex",
                    manifest=manifest,
                    gpu_allowed=False,
                    network_allowed=False,
                )

    def test_trusted_runner_rejects_source_mutation_during_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source_path = workspace / "source.txt"
            source_path.write_text("trusted\n", encoding="utf-8")
            mutator = workspace / "mutating_validation.py"
            mutator.write_text(
                "from pathlib import Path\n"
                "import sys\n"
                "Path('source.txt').write_text('tampered\\n', encoding='utf-8')\n"
                "sys.stdout.buffer.write(b'validation passed\\n')\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["git", "init"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "audit@cogni.invalid"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Cogni Release Audit"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(["git", "add", "."], cwd=workspace, check=True)
            subprocess.run(
                ["git", "commit", "-m", "source mutation fixture"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            output = b"validation passed\n"
            with self.assertRaisesRegex(
                EvidenceError,
                r"(?i)(postcheck|dirty|changed|source)",
            ):
                run_trusted_validations(
                    workspace_root=workspace,
                    runs_root=workspace / "runs",
                    task_id="T-SOURCE-MUTATION",
                    attempt=1,
                    actor="codex",
                    manifest={
                        "validations": [
                            {
                                "command_argv": [
                                    sys.executable,
                                    str(mutator),
                                ],
                                "exit_code": 0,
                                "raw_output": {
                                    "sha256": hashlib.sha256(output).hexdigest(),
                                },
                            }
                        ]
                    },
                    gpu_allowed=False,
                    network_allowed=False,
                )

    def test_trusted_runner_rejects_untracked_code_in_operational_directory(
        self,
    ) -> None:
        """Operational output exclusions must not become executable-code hiding."""
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(
                ["git", "init"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "audit@cogni.invalid"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Cogni Release Audit"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(["git", "add", "README.md"], cwd=workspace, check=True)
            subprocess.run(
                ["git", "commit", "-m", "trusted source fixture"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )

            operational_script = workspace / "reports" / "verifier.py"
            operational_script.parent.mkdir()
            output = b"untracked verifier passed\n"
            operational_script.write_text(
                "import sys\n"
                "sys.stdout.buffer.write(b'untracked verifier passed\\n')\n",
                encoding="utf-8",
            )
            manifest = {
                "validations": [
                    {
                        "command_argv": [
                            sys.executable,
                            str(operational_script),
                        ],
                        "exit_code": 0,
                        "raw_output": {
                            "sha256": hashlib.sha256(output).hexdigest(),
                        },
                    }
                ]
            }

            with self.assertRaisesRegex(
                EvidenceError,
                r"(?i)(untracked|source|executable|operational|provenance)",
            ):
                run_trusted_validations(
                    workspace_root=workspace,
                    runs_root=workspace / "runs",
                    task_id="T-UNTRACKED-EXECUTABLE",
                    attempt=1,
                    actor="codex",
                    manifest=manifest,
                    gpu_allowed=False,
                    network_allowed=False,
                )

    def test_allowlisted_test_module_cannot_load_untracked_operational_code(
        self,
    ) -> None:
        """The pytest module allowlist must also constrain its test/config paths."""
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(
                ["git", "init"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "audit@cogni.invalid"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Cogni Release Audit"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(["git", "add", "README.md"], cwd=workspace, check=True)
            subprocess.run(
                ["git", "commit", "-m", "trusted source fixture"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            untracked_test = workspace / "reports" / "test_untracked.py"
            untracked_test.parent.mkdir()
            untracked_test.write_text(
                "def test_untracked():\n    assert True\n",
                encoding="utf-8",
            )
            for argv in (
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    str(untracked_test),
                ],
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "--rootdir=reports",
                ],
                [
                    sys.executable,
                    "-m",
                    "unittest",
                    "reports.test_untracked",
                ],
            ):
                with self.subTest(argv=argv), self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(tracked|source|path|pytest|operational)",
                ):
                    _validate_command_argv(workspace, argv)

    def test_trusted_runner_rejects_actor_selected_interpreter_binary(
        self,
    ) -> None:
        """An executable basename and post-hoc hash are not a toolchain allowlist."""
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            actor_binary = workspace / "python.exe"
            actor_binary.write_bytes(b"not the configured trusted interpreter")
            with self.assertRaisesRegex(
                EvidenceError,
                r"(?i)(executable|interpreter|allowlist|toolchain|trusted)",
            ):
                _validate_command_argv(
                    workspace,
                    [
                        str(actor_binary),
                        "-m",
                        "unittest",
                        "cogni_os.tests.test_workspace",
                    ],
                )

    def test_trusted_node_rejects_preload_and_loader_injection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            fake_node = workspace / "node.exe"
            fake_node.write_bytes(b"configured test-only node fixture")
            committed_test = workspace / "tests" / "safe.test.mjs"
            committed_test.parent.mkdir()
            committed_test.write_text(
                "import test from 'node:test';\n"
                "test('safe', () => {});\n",
                encoding="utf-8",
            )
            preload = workspace / "reports" / "preload.cjs"
            preload.parent.mkdir()
            preload.write_text("throw new Error('must not load');\n", encoding="utf-8")
            subprocess.run(
                ["git", "init"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "audit@cogni.invalid"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Cogni Release Audit"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "add", "tests/safe.test.mjs"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "trusted Node fixture"],
                cwd=workspace,
                check=True,
                capture_output=True,
            )
            for option in (
                f"--require={preload}",
                f"--import={preload}",
                f"--loader={preload}",
            ):
                with self.subTest(option=option), self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(node option|allowlist|preload|loader)",
                ):
                    _validate_command_argv(
                        workspace,
                        [
                            str(fake_node),
                            option,
                            "--test",
                            str(committed_test),
                        ],
                    )

    def test_monitor_rejects_malformed_or_failed_trusted_validation(self) -> None:
        base_verification = {
            "independence": {"independent": True},
            "verifier_evidence": {"manifest_sha256": "a" * 64},
        }
        malformed_values = (
            "yes",
            {
                "schema_version": 1,
                "passed": False,
                "source_commit": "b" * 40,
                "receipt_sha256": "c" * 64,
                "validations": [{"exit_code": 1}],
            },
            {
                "schema_version": 1,
                "passed": True,
                "source_commit": "b" * 40,
                "receipt_sha256": "c" * 64,
                "validations": [],
            },
        )
        for trusted_validation in malformed_values:
            with self.subTest(trusted_validation=trusted_validation):
                task = {
                    "id": "T-MALFORMED-TRUST",
                    "state": "verified",
                    "verification": {
                        **base_verification,
                        "trusted_validation": trusted_validation,
                    },
                }
                self.assertEqual(
                    task_trust_state(task),
                    "verification_disputed",
                )

    def test_monitor_binds_trusted_receipt_to_task_and_manifest(self) -> None:
        manifest_sha256 = "a" * 64
        receipt_sha256 = "b" * 64
        output_sha256 = "c" * 64
        trusted_validation = {
            "schema_version": 1,
            "runner": "cogni-os-trusted-runner-v1",
            "task_id": "T-OTHER",
            "attempt": 99,
            "actor": "other-verifier",
            "passed": True,
            "failure": None,
            "source_clean": True,
            "source_commit": "d" * 40,
            "operational_paths_sha256": "e" * 64,
            "environment_sha256": "f" * 64,
            "gpu_allowed": False,
            "network_allowed": False,
            "max_output_bytes": 4 * 1024 * 1024,
            "receipt_sha256": receipt_sha256,
            "validations": [
                {
                    "exit_code": 0,
                    "timed_out": False,
                    "output_truncated": False,
                    "command_argv": ["python", "-m", "unittest"],
                    "output_sha256": output_sha256,
                    "output_size_bytes": 1,
                }
            ],
        }
        verification = {
            "verified_by": "codex",
            "independence": {"independent": True},
            "verifier_evidence": {
                "manifest_sha256": manifest_sha256,
                "bundle": {
                    "manifest_sha256": "1" * 64,
                    "files": [
                        {
                            "kind": "trusted_runner_receipt",
                            "retained": True,
                            "archive_path": "receipt.json",
                            "sha256": receipt_sha256,
                        },
                        {
                            "kind": "trusted_runner_output",
                            "retained": True,
                            "archive_path": "validation.log",
                            "sha256": output_sha256,
                        },
                    ],
                },
            },
            "trusted_validation": trusted_validation,
        }
        task = {
            "id": "T-EXPECTED",
            "attempt": 2,
            "state": "verified",
            "verification": verification,
        }
        self.assertEqual(task_trust_state(task), "verification_disputed")

        trusted_validation["task_id"] = task["id"]
        trusted_validation["attempt"] = task["attempt"]
        trusted_validation["actor"] = verification["verified_by"]
        self.assertEqual(
            task_trust_state(task),
            "verification_disputed",
            "The verifier source manifest itself must be retained and hash-bound",
        )

    def test_untrusted_archived_task_is_not_counted_as_verified(self) -> None:
        exported = export_tasks(
            [
                {
                    "id": "T-ARCHIVED-WITHOUT-TRUST",
                    "title": "Archived without trusted evidence",
                    "owner": "codex",
                    "state": "archived",
                    "updated_at": "2026-07-31T00:00:00Z",
                }
            ]
        )
        self.assertEqual(exported[0]["state"], "verification_disputed")
        summary = task_summary(exported)
        self.assertEqual(summary["trusted_verified"], 0)
        self.assertEqual(summary["verification_disputed"], 1)

    def test_submission_rejects_artifact_outside_workspace(self) -> None:
        """A manifest must not turn an arbitrary host file into bundled evidence."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            workspace_root = temporary_root / "workspace"
            workspace = Workspace.initialize(
                workspace_root,
                name="Evidence confinement audit",
                orchestrator="codex",
                preset="cogni-codex-antigravity",
            )
            task_id = "T-EVIDENCE-ESCAPE"
            workspace.add_task(
                actor="codex",
                task_id=task_id,
                title="Reject evidence path escape",
                description="Evidence must remain inside the workspace.",
                owner="antigravity",
            )
            claimed = workspace.claim(actor="antigravity", task_id=task_id)
            workspace.start(
                actor="antigravity",
                task_id=task_id,
                lease_token=claimed["lease_token"],
            )

            report_directory = workspace.reports_dir / "antigravity"
            report_directory.mkdir(parents=True, exist_ok=True)
            report_path = report_directory / f"{task_id}.md"
            report_path.write_text(
                "".join(
                    f"## {number}. Section {number}\nMeasured evidence {number}\n"
                    for number in range(1, 7)
                ),
                encoding="utf-8",
            )
            raw_output = report_directory / "validation.log"
            raw_bytes = b"1 passed\n"
            raw_output.write_bytes(raw_bytes)

            outside_artifact = temporary_root / "host-secret.txt"
            outside_bytes = b"must never enter an evidence bundle\n"
            outside_artifact.write_bytes(outside_bytes)
            manifest_path = report_directory / f"{task_id}.evidence.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "artifacts": [
                            {
                                "path": str(outside_artifact),
                                "sha256": hashlib.sha256(
                                    outside_bytes
                                ).hexdigest(),
                            }
                        ],
                        "validations": [
                            {
                                "command": "python -m unittest",
                                "exit_code": 0,
                                "passed": 1,
                                "failed": 0,
                                "skipped": 0,
                                "raw_output_path": raw_output.name,
                                "raw_output_sha256": hashlib.sha256(
                                    raw_bytes
                                ).hexdigest(),
                            }
                        ],
                        "known_answer_checks": [
                            {
                                "name": "confinement",
                                "expected": True,
                                "observed": True,
                                "passed": True,
                            }
                        ],
                        "claims": [],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                EvidenceError,
                r"(?i)(outside|escape|workspace|root|confine|allowed)",
            ):
                workspace.submit(
                    actor="antigravity",
                    task_id=task_id,
                    lease_token=claimed["lease_token"],
                    report_path=report_path,
                    evidence_path=manifest_path,
                )


if __name__ == "__main__":
    unittest.main()
