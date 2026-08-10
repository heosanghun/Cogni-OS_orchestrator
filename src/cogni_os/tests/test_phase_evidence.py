"""Fail-closed tests for Phase 1-11 semantic evidence coverage."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cogni_os.evidence import EvidenceError, validate_manifest
from cogni_os.phase_evidence import (
    PHASE_EVIDENCE_REQUIREMENTS,
    PHASE_REQUIREMENT_TEST_SELECTORS,
    audit_phase_task,
    audit_phase_tasks,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class PhaseEvidenceTests(unittest.TestCase):
    commit = "a" * 40

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self.temporary_directory.name)
        self.trust_projection = patch(
            "cogni_os.phase_evidence.task_trust_projection",
            return_value={
                "historical_trusted": True,
                "current_release_validated": True,
                "verified_source_commit": self.commit,
                "current_release_state": "verified",
            },
        )
        self.trust_projection.start()

    def tearDown(self) -> None:
        self.trust_projection.stop()
        self.temporary_directory.cleanup()

    def phase_task(self, phase_id: str) -> dict:
        artifacts = []
        validations = []
        bindings = []
        runtime_sha256 = _digest(f"{phase_id}:runtime")
        runtime_path = str(Path(sys.executable).resolve())
        for requirement_id in PHASE_EVIDENCE_REQUIREMENTS[phase_id]:
            artifact_sha256 = _digest(f"{phase_id}:{requirement_id}:artifact")
            output_sha256 = _digest(f"{phase_id}:{requirement_id}:output")
            selector = PHASE_REQUIREMENT_TEST_SELECTORS[phase_id][requirement_id]
            executed_argv = [runtime_path, "-m", "unittest", selector]
            test_module_path = str(
                self.workspace_root
                / Path("src").joinpath(*selector.split(".")[:-2]).with_suffix(".py")
            )
            test_module_sha256 = _digest(f"{phase_id}:test-module")
            artifacts.append(
                {"path": f"{requirement_id}.json", "sha256": artifact_sha256}
            )
            validations.append(
                {
                    "command_argv": [sys.executable, "-m", "unittest", selector],
                    "executed_argv": executed_argv,
                    "command_policy": {
                        "kind": "python",
                        "executable_path": runtime_path,
                        "executable_sha256": runtime_sha256,
                        "executable_binding": {
                            "policy_id": "fixed-admin-runtime-readonly-v1",
                            "kind": "python",
                            "path": runtime_path,
                            "sha256": runtime_sha256,
                            "provenance": "fixed-admin-path-chain",
                        },
                        "executed_argv": executed_argv,
                        "code_paths": [
                            {
                                "path": test_module_path,
                                "sha256": test_module_sha256,
                            }
                        ],
                    },
                    "exit_code": 0,
                    "timed_out": False,
                    "output_truncated": False,
                    "output_size_bytes": 64,
                    "output_sha256": output_sha256,
                    "executable_sha256_after": runtime_sha256,
                }
            )
            bindings.append(
                {
                    "requirement_id": requirement_id,
                    "artifact_sha256": artifact_sha256,
                    "trusted_output_sha256": output_sha256,
                }
            )
        return {
            "id": phase_id,
            "state": "verified",
            "verification": {
                "trusted_validation": {
                    "runner": "cogni-os-trusted-runner-v3",
                    "passed": True,
                    "source_clean": True,
                    "source_postcheck_passed": True,
                    "source_commit": self.commit,
                    "receipt_sha256": _digest(f"{phase_id}:receipt"),
                    "receipt_preimage_sha256": _digest(f"{phase_id}:preimage"),
                    "verifier_manifest_sha256": _digest(f"{phase_id}:manifest"),
                    "validation_contract_sha256": _digest(f"{phase_id}:contract"),
                    "environment_sha256": _digest(f"{phase_id}:environment"),
                    "sandbox_environment_sha256": _digest(
                        f"{phase_id}:sandbox-environment"
                    ),
                    "isolation_attested": True,
                    "snapshot_precheck_passed": True,
                    "snapshot_postcheck_passed": True,
                    "operational_change_count": 0,
                    "network_allowed": False,
                    "validations": validations,
                }
            },
            "result": {
                "manifest": {
                    "artifacts": artifacts,
                    "known_answer_checks": [
                        {
                            "name": "worker-self-declaration-is-not-authority",
                            "expected": "anything",
                            "observed": "anything",
                            "passed": True,
                        }
                    ],
                    "phase_evidence": {
                        "schema": "cogni.phase-evidence.v1",
                        "phase_id": phase_id,
                        "source_commit": self.commit,
                        "requirements": bindings,
                    },
                }
            },
        }

    def audit(self, task: dict) -> dict:
        return audit_phase_task(
            task,
            current_source_commit=self.commit,
            workspace_root=self.workspace_root,
        )

    def test_exact_current_trusted_coverage_passes_without_release_authority(
        self,
    ) -> None:
        result = self.audit(self.phase_task("P01-TRUTH"))
        self.assertEqual(result["coverage_status"], "SEMANTIC_COVERAGE_PASS")
        self.assertFalse(result["release_authority"])

    def test_self_declared_known_answer_cannot_replace_trusted_selector(self) -> None:
        task = self.phase_task("P08-CORE")
        task["verification"]["trusted_validation"]["validations"].pop()
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertTrue(
            any("TRUSTED_OUTPUT_NOT_BOUND" in reason for reason in result["reasons"])
        )

    def test_script_prefix_cannot_impersonate_canonical_unittest(self) -> None:
        task = self.phase_task("P08-CORE")
        validation = task["verification"]["trusted_validation"]["validations"][0]
        selector = validation["command_argv"][-1]
        validation["command_argv"] = [
            sys.executable,
            "forged_helper.py",
            "-m",
            "unittest",
            selector,
        ]
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertTrue(
            any("COMMAND_NOT_PINNED" in reason for reason in result["reasons"])
        )

    def test_unpinned_runtime_and_missing_code_provenance_fail_closed(self) -> None:
        task = self.phase_task("P08-CORE")
        validation = task["verification"]["trusted_validation"]["validations"][0]
        validation["executed_argv"][0] = "not-a-python-runtime"
        validation["command_policy"]["code_paths"] = []
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertTrue(
            any("PROVENANCE_INVALID" in reason for reason in result["reasons"])
        )

    def test_declared_runtime_must_equal_the_attested_executable(self) -> None:
        task = self.phase_task("P08-CORE")
        validation = task["verification"]["trusted_validation"]["validations"][0]
        validation["command_argv"][0] = "not-a-python-runtime"
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertTrue(
            any("PROVENANCE_INVALID" in reason for reason in result["reasons"])
        )

    def test_missing_runner_environment_binding_fails_closed(self) -> None:
        task = self.phase_task("P03-EVIDENCE")
        trusted = task["verification"]["trusted_validation"]
        trusted["environment_sha256"] = None
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertIn("TRUSTED_RUNNER_PROVENANCE_INVALID", result["reasons"])

    def test_wrong_commit_and_missing_requirement_fail(self) -> None:
        task = self.phase_task("P08-CORE")
        envelope = task["result"]["manifest"]["phase_evidence"]
        envelope["source_commit"] = "d" * 40
        envelope["requirements"].pop()
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertIn("PHASE_SOURCE_COMMIT_MISMATCH", result["reasons"])
        self.assertIn("PHASE_REQUIREMENT_COVERAGE_MISMATCH", result["reasons"])

    def test_unverified_or_failed_trusted_validation_fails(self) -> None:
        task = self.phase_task("P03-EVIDENCE")
        task["state"] = "submitted"
        task["verification"]["trusted_validation"]["passed"] = False
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertIn("TASK_NOT_VERIFIED", result["reasons"])
        self.assertIn("TRUSTED_VALIDATION_NOT_PASSED", result["reasons"])

    def test_same_phase_output_reuse_fails_closed(self) -> None:
        task = self.phase_task("P02-ORCHESTRATION")
        validations = task["verification"]["trusted_validation"]["validations"]
        requirements = task["result"]["manifest"]["phase_evidence"]["requirements"]
        validations[1]["output_sha256"] = validations[0]["output_sha256"]
        requirements[1]["trusted_output_sha256"] = validations[0]["output_sha256"]
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertIn("TRUSTED_VALIDATION_OUTPUT_REUSED", result["reasons"])

    def test_artifact_cannot_reuse_its_trusted_output_digest(self) -> None:
        task = self.phase_task("P01-TRUTH")
        validation = task["verification"]["trusted_validation"]["validations"][0]
        artifact = task["result"]["manifest"]["artifacts"][0]
        requirement = task["result"]["manifest"]["phase_evidence"]["requirements"][0]
        artifact["sha256"] = validation["output_sha256"]
        requirement["artifact_sha256"] = validation["output_sha256"]
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertTrue(
            any("ARTIFACT_OUTPUT_DIGEST_COLLISION" in value for value in result["reasons"])
        )

    def test_cross_phase_reuse_invalidates_every_owner(self) -> None:
        first = self.phase_task("P01-TRUTH")
        second = self.phase_task("P02-ORCHESTRATION")
        reused = first["verification"]["trusted_validation"]["validations"][0][
            "output_sha256"
        ]
        second["verification"]["trusted_validation"]["validations"][0][
            "output_sha256"
        ] = reused
        second["result"]["manifest"]["phase_evidence"]["requirements"][0][
            "trusted_output_sha256"
        ] = reused
        report = audit_phase_tasks(
            [first, second],
            current_source_commit=self.commit,
            workspace_root=self.workspace_root,
        )
        by_id = {phase["phase_id"]: phase for phase in report["phases"]}
        for phase_id in ("P01-TRUTH", "P02-ORCHESTRATION"):
            self.assertEqual(by_id[phase_id]["coverage_status"], "NO_GO")
            self.assertTrue(
                any(
                    reason.startswith("CROSS_PHASE_TRUSTED_OUTPUT_REUSE:")
                    for reason in by_id[phase_id]["reasons"]
                )
            )
        self.assertEqual(report["validated_phases"], 0)

    def test_cross_phase_artifact_output_collision_invalidates_both(self) -> None:
        first = self.phase_task("P01-TRUTH")
        second = self.phase_task("P02-ORCHESTRATION")
        reused = first["result"]["manifest"]["artifacts"][0]["sha256"]
        second["verification"]["trusted_validation"]["validations"][0][
            "output_sha256"
        ] = reused
        second["result"]["manifest"]["phase_evidence"]["requirements"][0][
            "trusted_output_sha256"
        ] = reused
        report = audit_phase_tasks(
            [first, second],
            current_source_commit=self.commit,
            workspace_root=self.workspace_root,
        )
        by_id = {phase["phase_id"]: phase for phase in report["phases"]}
        for phase_id in ("P01-TRUTH", "P02-ORCHESTRATION"):
            self.assertEqual(by_id[phase_id]["coverage_status"], "NO_GO")
            self.assertTrue(
                any(
                    reason.startswith("CROSS_DOMAIN_DIGEST_REUSE:")
                    for reason in by_id[phase_id]["reasons"]
                )
            )

    def test_malformed_normalized_manifest_is_no_go_not_crash(self) -> None:
        task = self.phase_task("P07-WORKSPACE")
        task["result"]["manifest"] = []
        result = self.audit(task)
        self.assertEqual(result["coverage_status"], "NO_GO")
        self.assertIn("NORMALIZED_MANIFEST_MISSING", result["reasons"])


class PhaseEvidenceManifestTests(unittest.TestCase):
    def _write_manifest(self, root: Path) -> tuple[Path, dict]:
        artifact = root / "artifact.json"
        artifact.write_text('{"measured":true}\n', encoding="utf-8")
        raw_output = root / "validation.log"
        raw_output.write_text(
            "one canonical acceptance test passed\n", encoding="utf-8"
        )
        phase_evidence = {
            "schema": "cogni.phase-evidence.v1",
            "phase_id": "P01-TRUTH",
            "source_commit": "a" * 40,
            "requirements": [
                {
                    "requirement_id": "authoritative_source_commit",
                    "artifact_sha256": hashlib.sha256(
                        artifact.read_bytes()
                    ).hexdigest(),
                    "trusted_output_sha256": hashlib.sha256(
                        raw_output.read_bytes()
                    ).hexdigest(),
                }
            ],
        }
        manifest = {
            "schema_version": 1,
            "artifacts": [
                {
                    "path": artifact.name,
                    "sha256": phase_evidence["requirements"][0]["artifact_sha256"],
                }
            ],
            "validations": [
                {
                    "command": "python -m unittest canonical.selector",
                    "command_argv": [
                        sys.executable,
                        "-m",
                        "unittest",
                        "canonical.selector",
                    ],
                    "exit_code": 0,
                    "passed": 1,
                    "failed": 0,
                    "skipped": 0,
                    "skip_reasons": [],
                    "raw_output_path": raw_output.name,
                    "raw_output_sha256": phase_evidence["requirements"][0][
                        "trusted_output_sha256"
                    ],
                }
            ],
            "known_answer_checks": [
                {"name": "format-only", "expected": 1, "observed": 1, "passed": True}
            ],
            "claims": [],
            "phase_evidence": phase_evidence,
        }
        path = root / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path, phase_evidence

    def test_normalizer_preserves_phase_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest_path, phase_evidence = self._write_manifest(root)
            result = validate_manifest(
                manifest_path,
                permissions={"gpu": False, "performance_metrics": False},
                gates={
                    "require_validation": True,
                    "require_known_answer_check": True,
                    "allow_skips": False,
                },
                require_command_argv=True,
                allowed_root=root,
            )
            self.assertEqual(result["phase_evidence"], phase_evidence)

    def test_duplicate_json_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "manifest.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(EvidenceError, "duplicate JSON member"):
                validate_manifest(
                    path,
                    permissions={},
                    gates={},
                    allowed_root=path.parent,
                )

    def test_non_standard_nan_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "manifest.json"
            path.write_text('{"schema_version":1,"value":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(EvidenceError, "non-finite JSON constant"):
                validate_manifest(
                    path,
                    permissions={},
                    gates={},
                    allowed_root=path.parent,
                )


class PhaseEvidenceCliInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        script_path = (
            Path(__file__).resolve().parents[3]
            / "scripts"
            / ("audit_phase_evidence.py")
        )
        spec = importlib.util.spec_from_file_location(
            "audit_phase_evidence", script_path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("phase evidence audit script could not be imported")
        cls.audit_script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.audit_script)

    def _write_inventory(self, root: Path) -> Path:
        tasks = root / "tasks"
        tasks.mkdir()
        for phase_id in PHASE_EVIDENCE_REQUIREMENTS:
            (tasks / f"{phase_id}.json").write_text(
                json.dumps({"id": phase_id, "state": "pending"}),
                encoding="utf-8",
            )
        return tasks

    def test_exact_canonical_inventory_loads_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._write_inventory(root)
            tasks = self.audit_script._load_tasks(root)
            self.assertEqual(len(tasks), len(PHASE_EVIDENCE_REQUIREMENTS))
            self.assertEqual(
                {task["id"] for task in tasks}, set(PHASE_EVIDENCE_REQUIREMENTS)
            )

    def test_missing_or_unexpected_phase_filename_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            tasks = self._write_inventory(root)
            (tasks / "P01-TRUTH.json").unlink()
            (tasks / "P99-UNEXPECTED.json").write_text(
                '{"id":"P99-UNEXPECTED"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "inventory mismatch"):
                self.audit_script._load_tasks(root)

    def test_filename_and_payload_id_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            tasks = self._write_inventory(root)
            (tasks / "P01-TRUTH.json").write_text(
                '{"id":"P02-ORCHESTRATION"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "id does not match filename"):
                self.audit_script._load_tasks(root)

    def test_duplicate_task_json_member_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            tasks = self._write_inventory(root)
            (tasks / "P01-TRUTH.json").write_text(
                '{"id":"P01-TRUTH","id":"P01-TRUTH"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON member"):
                self.audit_script._load_tasks(root)

    def test_non_standard_task_json_number_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            tasks = self._write_inventory(root)
            (tasks / "P01-TRUTH.json").write_text(
                '{"id":"P01-TRUTH","value":NaN}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "non-standard JSON constant"):
                self.audit_script._load_tasks(root)


if __name__ == "__main__":
    unittest.main()
