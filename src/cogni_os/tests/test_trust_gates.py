"""Fail-closed release-truth gates for Cogni-OS task transitions."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cogni_os.errors import (
    AuthorizationError,
    ConfigurationError,
    EvidenceError,
    LeaseError,
)
from cogni_os.evidence import validate_manifest, validate_report
from cogni_os.independence import (
    canonical_model_family,
    evaluate_independence,
)
from cogni_os.workspace import Workspace


class TrustGateTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.workspace = Workspace.initialize(
            self.root,
            name="Trust gate test",
            orchestrator="codex",
            preset="cogni-codex-antigravity",
        )
        self.validation_helper = self.root / "trusted_validation_helper.py"
        self.validation_helper.write_text(
            "import sys\n"
            "mode = sys.argv[1]\n"
            "payload = bytes.fromhex(sys.argv[2])\n"
            "sys.stdout.buffer.write(payload)\n"
            "if mode == 'exit':\n"
            "    raise SystemExit(int(sys.argv[3]))\n",
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
        # The developer workstation may define a global excludes file that
        # ignores Python files. Force-add the verifier helper so the fixture
        # always models committed executable evidence.
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

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _manifest(
        self,
        directory: Path,
        stem: str,
        *,
        passed: int = 1,
        raw_bytes: bytes = b"1 passed\n",
        expected: object = "expected",
        observed: object = "expected",
        command_argv: list[str] | None = None,
    ) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        raw_path = directory / f"{stem}.log"
        raw_path.write_bytes(raw_bytes)
        manifest_path = directory / f"{stem}.evidence.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "artifacts": [],
                    "validations": [
                        {
                            "command": f"verify {stem}",
                            "command_argv": [
                                sys.executable,
                                str(self.validation_helper),
                                "emit",
                                raw_bytes.hex(),
                            ]
                            if command_argv is None
                            else command_argv,
                            "exit_code": 0,
                            "passed": passed,
                            "failed": 0,
                            "skipped": 0,
                            "raw_output_path": raw_path.name,
                            "raw_output_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                        }
                    ],
                    "known_answer_checks": [
                        {
                            "name": stem,
                            "expected": expected,
                            "observed": observed,
                            "passed": True,
                        }
                    ],
                    "claims": [],
                }
            ),
            encoding="utf-8",
        )
        return manifest_path

    def _report(self, directory: Path, stem: str) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{stem}.md"
        path.write_text(
            "".join(
                f"## {number}. Section {number}\nMeasured evidence {number}\n"
                for number in range(1, 7)
            ),
            encoding="utf-8",
        )
        return path

    def _submit(self, task_id: str = "T-WORK") -> Path:
        self.workspace.add_task(
            actor="codex",
            task_id=task_id,
            title="Measured work",
            description="Produce reproducible evidence",
            owner="antigravity",
        )
        claim = self.workspace.claim(actor="antigravity", task_id=task_id)
        self.workspace.start(
            actor="antigravity",
            task_id=task_id,
            lease_token=claim["lease_token"],
        )
        worker_dir = self.workspace.reports_dir / "antigravity"
        manifest = self._manifest(worker_dir, f"{task_id}-worker")
        self.workspace.submit(
            actor="antigravity",
            task_id=task_id,
            lease_token=claim["lease_token"],
            report_path=self._report(worker_dir, task_id),
            evidence_path=manifest,
        )
        return manifest

    def _verify_with_codex(self, task_id: str) -> None:
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            f"{task_id}-independent",
            raw_bytes=b"independent reproduction passed\n",
        )
        self.workspace.verify(
            actor="codex",
            task_id=task_id,
            decision="accept",
            note="Independent evidence reproduced.",
            evidence_path=verifier_manifest,
        )

    def test_prerequisite_must_exist_and_be_verified_before_claim(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "do not exist"):
            self.workspace.add_task(
                actor="codex",
                task_id="T-UNKNOWN-DEPENDENCY",
                title="Blocked",
                description="Missing prerequisite",
                owner="antigravity",
                prerequisites=["T-MISSING"],
            )

        self._submit("T-BASE")
        self.workspace.add_task(
            actor="codex",
            task_id="T-DEPENDENT",
            title="Dependent task",
            description="Must wait for verified base",
            owner="antigravity",
            prerequisites=["T-BASE"],
        )
        with self.assertRaisesRegex(LeaseError, "T-BASE:submitted"):
            self.workspace.claim(actor="antigravity", task_id="T-DEPENDENT")

        self._verify_with_codex("T-BASE")
        claimed = self.workspace.claim(
            actor="antigravity",
            task_id="T-DEPENDENT",
        )
        self.assertEqual(claimed["task"]["state"], "claimed")

    def test_role_label_does_not_create_independent_model_family(self) -> None:
        self.assertEqual(
            canonical_model_family("google-antigravity-verifier"),
            "google-antigravity",
        )
        result = evaluate_independence(
            {
                "actor": "antigravity",
                "control_principal": "worker-control",
                "model_family": "google-antigravity",
                "alias_chain": [],
            },
            {
                "actor": "antigravity-verifier",
                "control_principal": "verifier-control",
                "model_family": "google-antigravity-verifier",
                "alias_chain": [],
            },
        )
        self.assertFalse(result["independent"])
        self.assertIn("same_model_family", result["reasons"])

    def test_antigravity_family_cannot_verify_antigravity_submission(self) -> None:
        self._submit()
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "antigravity-verifier",
            "T-WORK-verifier",
            raw_bytes=b"claimed reproduction\n",
        )
        with self.assertRaisesRegex(AuthorizationError, "same_model_family"):
            self.workspace.verify(
                actor="antigravity-verifier",
                task_id="T-WORK",
                decision="accept",
                note="Should be rejected as same family.",
                evidence_path=verifier_manifest,
            )

    def test_verification_requires_distinct_hashed_raw_evidence(self) -> None:
        worker_manifest = self._submit()
        with self.assertRaisesRegex(EvidenceError, "manifest is required"):
            self.workspace.verify(
                actor="codex",
                task_id="T-WORK",
                decision="accept",
                note="No evidence supplied.",
            )
        with self.assertRaisesRegex(EvidenceError, "independently produced"):
            verifier_root = self.workspace.reports_dir / "codex"
            verifier_root.mkdir(parents=True, exist_ok=True)
            copied_manifest = verifier_root / worker_manifest.name
            copied_manifest.write_bytes(worker_manifest.read_bytes())
            worker_payload = json.loads(worker_manifest.read_text(encoding="utf-8"))
            worker_raw_name = worker_payload["validations"][0]["raw_output_path"]
            (verifier_root / worker_raw_name).write_bytes(
                (worker_manifest.parent / worker_raw_name).read_bytes()
            )
            self.workspace.verify(
                actor="codex",
                task_id="T-WORK",
                decision="accept",
                note="Worker evidence reused.",
                evidence_path=copied_manifest,
            )

    def test_empty_metrics_missing_raw_and_placeholders_fail_closed(self) -> None:
        evidence_dir = self.workspace.reports_dir / "antigravity"
        no_checks = self._manifest(evidence_dir, "zero-checks", passed=0)
        with self.assertRaisesRegex(EvidenceError, "no measured checks"):
            validate_manifest(
                no_checks,
                permissions={"gpu": False, "performance_metrics": False},
                gates={
                    "require_validation": True,
                    "allow_skips": False,
                    "require_known_answer_check": True,
                },
            )

        missing_raw = self._manifest(evidence_dir, "missing-raw")
        payload = json.loads(missing_raw.read_text(encoding="utf-8"))
        payload["validations"][0].pop("raw_output_path")
        payload["validations"][0].pop("raw_output_sha256")
        missing_raw.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "raw_output_path"):
            validate_manifest(
                missing_raw,
                permissions={"gpu": False, "performance_metrics": False},
                gates={
                    "require_validation": True,
                    "allow_skips": False,
                    "require_known_answer_check": True,
                },
            )

        placeholder = self._manifest(
            evidence_dir,
            "placeholder",
            expected="[FILL]",
            observed="[FILL]",
        )
        with self.assertRaisesRegex(EvidenceError, "placeholder"):
            validate_manifest(
                placeholder,
                permissions={"gpu": False, "performance_metrics": False},
                gates={
                    "require_validation": True,
                    "allow_skips": False,
                    "require_known_answer_check": True,
                },
            )

        report = self._report(evidence_dir, "placeholder-report")
        report.write_text(
            report.read_text(encoding="utf-8") + "\n[FILL]\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(EvidenceError, r"\[FILL\]"):
            validate_report(report)

    def test_trusted_runner_receipt_is_saved_and_bound_to_verification(self) -> None:
        self._submit()
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            "T-WORK-trusted",
            raw_bytes=b"trusted reproduction passed\n",
        )
        verified = self.workspace.verify(
            actor="codex",
            task_id="T-WORK",
            decision="accept",
            note="Executed by trusted runner.",
            evidence_path=verifier_manifest,
        )
        trusted = verified["verification"]["trusted_validation"]
        self.assertTrue(trusted["passed"])
        self.assertEqual(len(trusted["source_commit"]), 40)
        self.assertEqual(len(trusted["receipt_sha256"]), 64)
        self.assertTrue(Path(trusted["receipt_path"]).is_file())
        self.assertTrue(Path(trusted["validations"][0]["output_path"]).is_file())
        self.assertEqual(
            trusted["validations"][0]["output_sha256"],
            hashlib.sha256(b"trusted reproduction passed\n").hexdigest(),
        )

    def test_trusted_runner_rejects_forged_output(self) -> None:
        self._submit()
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            "T-WORK-forged",
            raw_bytes=b"claimed output\n",
            command_argv=[
                sys.executable,
                str(self.validation_helper),
                "emit",
                b"actual output\n".hex(),
            ],
        )
        with self.assertRaisesRegex(EvidenceError, "output was forged"):
            self.workspace.verify(
                actor="codex",
                task_id="T-WORK",
                decision="accept",
                note="Forged result must fail.",
                evidence_path=verifier_manifest,
            )
        self.assertEqual(self.workspace.get_task("T-WORK")["state"], "submitted")

    def test_trusted_runner_rejects_failing_command(self) -> None:
        self._submit()
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            "T-WORK-failure",
            raw_bytes=b"failure\n",
            command_argv=[
                sys.executable,
                str(self.validation_helper),
                "exit",
                b"failure\n".hex(),
                "7",
            ],
        )
        with self.assertRaisesRegex(EvidenceError, "exit code 7"):
            self.workspace.verify(
                actor="codex",
                task_id="T-WORK",
                decision="accept",
                note="Nonzero command must fail.",
                evidence_path=verifier_manifest,
            )

    def test_shell_metacharacters_are_literal_arguments(self) -> None:
        self._submit()
        marker = self.root / "must-not-exist.txt"
        literal = f"; echo compromised > {marker}"
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            "T-WORK-no-shell",
            raw_bytes=literal.encode("utf-8"),
            command_argv=[
                sys.executable,
                str(self.validation_helper),
                "emit",
                literal.encode("utf-8").hex(),
            ],
        )
        verified = self.workspace.verify(
            actor="codex",
            task_id="T-WORK",
            decision="accept",
            note="Metacharacters stayed literal.",
            evidence_path=verifier_manifest,
        )
        self.assertEqual(verified["state"], "verified")
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
