"""Fail-closed release-truth gates for Cogni-OS task transitions."""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import cogni_os.release_gate as release_gate_module
from cogni_os.errors import (
    AuthorizationError,
    ConfigurationError,
    EvidenceError,
    LeaseError,
    StateError,
)
from cogni_os.evidence import validate_manifest, validate_report
from cogni_os.independence import (
    canonical_model_family,
    evaluate_independence,
)
from cogni_os.ledger import GENESIS_HASH
from cogni_os.tests._actor_capability_test_support import (
    install_legacy_capability_fixture,
)
from cogni_os.tests._isolation_test_support import install_direct_isolation_fixture
from cogni_os.trusted_runner import TRUSTED_RECEIPT_RESULT_KEYS
from cogni_os.trust_projection import task_trust_projection, task_trust_state
from cogni_os.util import canonical_json
from cogni_os.verifier_attestation_protocol import VerifierAttestationError
from cogni_os.workspace import Workspace


class TrustGateTestCase(unittest.TestCase):
    def setUp(self) -> None:
        install_legacy_capability_fixture(self)
        install_direct_isolation_fixture(self)
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

    def _append_conflicting_verification_failure(self, task_id: str) -> None:
        events = self.workspace.ledger.read_verified()
        started = next(
            event
            for event in events
            if event.get("action") == "verification.started"
            and event.get("task_id") == task_id
        )
        payload = started["payload"]
        self.workspace.ledger.append(
            actor=str(started["actor"]),
            action="verification.failed",
            task_id=task_id,
            payload={
                "schema_version": 1,
                "run_id": payload["run_id"],
                "task_attempt": payload["task_attempt"],
                "stage": "trusted_runner",
                "error_type": "evidence_error",
                "verifier_identity": payload["verifier_identity"],
                "verifier_manifest_sha256": payload["verifier_manifest_sha256"],
                "worker_manifest_sha256": payload["worker_manifest_sha256"],
                "verification_contract_inputs_sha256": payload[
                    "verification_contract_inputs_sha256"
                ],
                "capability_receipt": payload["capability_receipt"],
            },
        )

    def _move_failure_before_verified_and_resign(self, task_id: str) -> None:
        events = self.workspace.ledger.read_verified()
        verified_index = next(
            index
            for index, event in enumerate(events)
            if event.get("action") == "task.verified"
            and event.get("task_id") == task_id
        )
        failed_index = next(
            index
            for index, event in enumerate(events)
            if event.get("action") == "verification.failed"
            and event.get("task_id") == task_id
        )
        failed = events.pop(failed_index)
        events.insert(verified_index, failed)

        previous_hash = GENESIS_HASH
        key = self.workspace.ledger._key()
        rewritten = []
        for sequence, event in enumerate(events, start=1):
            core = {
                "sequence": sequence,
                "timestamp": event["timestamp"],
                "actor": event["actor"],
                "action": event["action"],
                "task_id": event["task_id"],
                "payload": event["payload"],
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(canonical_json(core)).hexdigest()
            signature = hmac.new(
                key,
                event_hash.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            rewritten.append({**core, "event_hash": event_hash, "signature": signature})
            previous_hash = event_hash
        self.workspace.ledger.path.write_text(
            "".join(
                json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
                for event in rewritten
            ),
            encoding="utf-8",
        )
        self.workspace.ledger.read_verified()

    def _assert_conflicting_terminals_fail_closed(
        self, *, failure_before_verified: bool
    ) -> None:
        task_id = "T-CONFLICT"
        self._submit(task_id)
        self._verify_with_codex(task_id)
        self._append_conflicting_verification_failure(task_id)
        if failure_before_verified:
            self._move_failure_before_verified_and_resign(task_id)

        task = self.workspace.get_task(task_id)
        source_commit = task["verification"]["trusted_validation"]["source_commit"]
        projection = task_trust_projection(
            task,
            current_commit=source_commit,
            workspace_root=self.root,
        )
        self.assertEqual(projection["historical_state"], "verification_disputed")
        self.assertFalse(projection["historical_trusted"])
        self.assertFalse(projection["current_release_validated"])
        with self.assertRaisesRegex(StateError, "not trusted"):
            release_gate_module._task_bindings(
                self.workspace,
                source_commit,
                self.workspace.ledger.read_verified(),
            )

    def test_verified_then_failed_same_run_is_never_trusted(self) -> None:
        self._assert_conflicting_terminals_fail_closed(failure_before_verified=False)

    def test_failed_then_verified_same_run_is_never_trusted(self) -> None:
        self._assert_conflicting_terminals_fail_closed(failure_before_verified=True)

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

    def test_manifest_is_hashed_and_parsed_from_one_bounded_read(self) -> None:
        evidence_dir = self.workspace.reports_dir / "antigravity"
        manifest = self._manifest(evidence_dir, "single-read")
        original_open = Path.open
        reads = 0

        def tracked_open(path: Path, *args: object, **kwargs: object):
            nonlocal reads
            if path.resolve() == manifest.resolve() and args and args[0] == "rb":
                reads += 1
            return original_open(path, *args, **kwargs)

        with patch("pathlib.Path.open", new=tracked_open):
            result = validate_manifest(
                manifest,
                permissions={"gpu": False, "performance_metrics": False},
                gates={
                    "require_validation": True,
                    "allow_skips": False,
                    "require_known_answer_check": True,
                },
            )

        self.assertEqual(reads, 1)
        self.assertEqual(
            result["manifest_sha256"],
            hashlib.sha256(manifest.read_bytes()).hexdigest(),
        )

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
        started_events = [
            event
            for event in self.workspace.ledger.read()
            if event["action"] == "verification.started"
            and event["task_id"] == "T-WORK"
        ]
        self.assertEqual(len(started_events), 1)
        run_id = started_events[0]["payload"]["run_id"]
        self.assertRegex(run_id, r"^[0-9a-f]{32}$")
        self.assertEqual(
            started_events[0]["payload"]["verifier_manifest_sha256"],
            verified["verification"]["verifier_evidence"]["manifest_sha256"],
        )
        verified_event = next(
            event
            for event in reversed(self.workspace.ledger.read())
            if event["action"] == "task.verified" and event["task_id"] == "T-WORK"
        )
        self.assertEqual(verified_event["payload"]["run_id"], run_id)
        self.assertEqual(verified["verification"]["run_id"], run_id)
        trusted = verified["verification"]["trusted_validation"]
        self.assertTrue(trusted["passed"])
        self.assertEqual(len(trusted["source_commit"]), 40)
        self.assertEqual(len(trusted["receipt_sha256"]), 64)
        self.assertEqual(len(trusted["verifier_manifest_sha256"]), 64)
        self.assertEqual(len(trusted["validation_contract_sha256"]), 64)
        self.assertEqual(
            trusted["verifier_manifest_sha256"],
            verified["verification"]["verifier_evidence"]["manifest_sha256"],
        )
        self.assertEqual(
            verified["verification"]["verifier_evidence"][
                "executor_attestation"
            ],
            {"schema_version": 0, "test_only": True},
        )
        self.assertTrue(Path(trusted["receipt_path"]).is_file())
        self.assertTrue(Path(trusted["validations"][0]["output_path"]).is_file())
        self.assertEqual(
            trusted["validations"][0]["output_sha256"],
            hashlib.sha256(b"trusted reproduction passed\n").hexdigest(),
        )

        archived_receipt = next(
            item
            for item in verified["verification"]["verifier_evidence"]["bundle"]["files"]
            if item["kind"] == "trusted_runner_receipt"
        )
        receipt_document = json.loads(
            Path(archived_receipt["archive_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(
            receipt_document["validation_contract_sha256"],
            trusted["validation_contract_sha256"],
        )

        current_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(
            task_trust_state(
                verified,
                current_commit=current_commit,
                workspace_root=self.root,
            ),
            "verified",
        )
        next_release = task_trust_projection(
            verified,
            current_commit="f" * 40,
            workspace_root=self.root,
        )
        self.assertEqual(next_release["historical_state"], "verified")
        self.assertTrue(next_release["historical_trusted"])
        self.assertEqual(next_release["verified_source_commit"], current_commit.lower())
        self.assertEqual(next_release["current_release_state"], "verification_disputed")
        self.assertFalse(next_release["current_release_validated"])

        trusted["validation_contract_sha256"] = "0" * 64
        self.assertEqual(
            task_trust_state(
                verified,
                current_commit=current_commit,
                workspace_root=self.root,
            ),
            "verification_disputed",
        )
        trusted["validation_contract_sha256"] = receipt_document[
            "validation_contract_sha256"
        ]

        receipt_path = Path(archived_receipt["archive_path"])
        original_receipt = receipt_path.read_bytes()
        receipt_path.write_bytes(original_receipt + b"\n")
        self.assertEqual(
            task_trust_state(
                verified,
                current_commit=current_commit,
                workspace_root=self.root,
            ),
            "verification_disputed",
        )
        receipt_path.write_bytes(original_receipt)

        # A mutable task JSON projection cannot replace the signed event's
        # verifier bundle, even when the forged inline values are well formed.
        forged_projection = deepcopy(verified)
        forged_projection["verification"]["verifier_evidence"]["bundle"][
            "manifest_sha256"
        ] = "f" * 64
        self.assertEqual(
            task_trust_state(
                forged_projection,
                current_commit=current_commit,
                workspace_root=self.root,
            ),
            "verification_disputed",
        )

        # The signed event binds the immutable bundle.json bytes.  Retained
        # files are never trusted only because they appear in an inline list.
        bundle_path = Path(
            verified["verification"]["verifier_evidence"]["bundle"]["manifest_path"]
        )
        original_bundle = bundle_path.read_bytes()
        bundle_path.write_bytes(original_bundle + b"\n")
        self.assertEqual(
            task_trust_state(
                verified,
                current_commit=current_commit,
                workspace_root=self.root,
            ),
            "verification_disputed",
        )
        bundle_path.write_bytes(original_bundle)

        ledger_path = self.workspace.ledger.path
        original_ledger = ledger_path.read_bytes()
        tampered_ledger = original_ledger.replace(
            b'"task.verified"',
            b'"task.verifieD"',
            1,
        )
        self.assertNotEqual(tampered_ledger, original_ledger)
        ledger_path.write_bytes(tampered_ledger)
        self.assertEqual(
            task_trust_state(
                verified,
                current_commit=current_commit,
                workspace_root=self.root,
            ),
            "verification_disputed",
        )
        ledger_path.write_bytes(original_ledger)

        malformed_attempt = deepcopy(verified)
        malformed_attempt["attempt"] = {"not": "an integer"}
        self.assertEqual(
            task_trust_state(
                malformed_attempt,
                current_commit=current_commit,
                workspace_root=self.root,
            ),
            "verification_disputed",
        )

        with patch(
            "cogni_os.trust_projection._bounded_file_snapshot",
            side_effect=PermissionError("simulated archive race"),
        ):
            self.assertEqual(
                task_trust_state(
                    verified,
                    current_commit=current_commit,
                    workspace_root=self.root,
                ),
                "verification_disputed",
            )

    def test_restatement_removes_valid_proof_from_both_trust_axes(self) -> None:
        for task_id, effective_status in (
            ("T-RESTATED-DISPUTED", "verification_disputed"),
            ("T-RESTATED-REVOKED", "verification_revoked"),
        ):
            with self.subTest(effective_status=effective_status):
                self._submit(task_id)
                self._verify_with_codex(task_id)
                task = self.workspace.get_task(task_id)
                current_commit = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=self.root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                before = task_trust_projection(
                    task,
                    current_commit=current_commit,
                    workspace_root=self.root,
                )
                self.assertTrue(before["historical_trusted"])
                self.assertTrue(before["current_release_validated"])

                self.workspace.restate_verification(
                    actor="codex",
                    task_id=task_id,
                    effective_status=effective_status,
                    reason="Signed correction removes this proof from release trust.",
                )
                after = task_trust_projection(
                    task,
                    current_commit=current_commit,
                    workspace_root=self.root,
                )
                self.assertEqual(after["recorded_state"], "verified")
                self.assertEqual(after["historical_state"], effective_status)
                self.assertFalse(after["historical_trusted"])
                self.assertIsNone(after["verified_source_commit"])
                self.assertEqual(after["current_release_state"], effective_status)
                self.assertFalse(after["current_release_validated"])

    def test_malformed_signed_restatement_fails_projection_closed(self) -> None:
        task_id = "T-MALFORMED-RESTATEMENT"
        self._submit(task_id)
        self._verify_with_codex(task_id)
        task = self.workspace.get_task(task_id)
        verification_event = next(
            event
            for event in reversed(self.workspace.ledger.read_verified())
            if event.get("action") == "task.verified"
            and event.get("task_id") == task_id
        )
        self.workspace.ledger.append(
            actor="codex",
            action="verification.restatement",
            task_id=task_id,
            payload={
                "schema_version": 1,
                "target_verification_sequence": verification_event["sequence"],
                "target_verification_hash": "0" * 64,
                "original_verifier": verification_event["actor"],
                "effective_status": "verification_disputed",
                "reason": "Deliberately malformed hash binding.",
            },
        )
        current_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        projection = task_trust_projection(
            task,
            current_commit=current_commit,
            workspace_root=self.root,
        )
        self.assertEqual(projection["historical_state"], "verification_disputed")
        self.assertFalse(projection["historical_trusted"])
        self.assertFalse(projection["current_release_validated"])

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
        lifecycle = [
            event
            for event in self.workspace.ledger.read()
            if event["task_id"] == "T-WORK"
            and event["action"]
            in {
                "verification.started",
                "verification.failed",
                "task.verified",
                "task.rejected",
            }
        ]
        self.assertEqual(
            [event["action"] for event in lifecycle],
            ["verification.started", "verification.failed"],
        )
        started, failed = lifecycle
        self.assertEqual(failed["payload"]["schema_version"], 1)
        self.assertEqual(failed["payload"]["run_id"], started["payload"]["run_id"])
        self.assertEqual(failed["payload"]["task_attempt"], 1)
        self.assertEqual(failed["payload"]["stage"], "trusted_runner")
        self.assertEqual(failed["payload"]["error_type"], "evidence_error")
        self.assertEqual(
            failed["payload"]["capability_receipt"],
            started["payload"]["capability_receipt"],
        )
        self.assertEqual(
            failed["payload"]["verification_contract_inputs_sha256"],
            started["payload"]["verification_contract_inputs_sha256"],
        )
        self.assertNotIn("output was forged", json.dumps(failed))

    def test_legacy_runner_cannot_write_accept_or_reject_terminal(self) -> None:
        legacy_result = {key: None for key in TRUSTED_RECEIPT_RESULT_KEYS}
        for decision in ("accept", "reject"):
            task_id = f"T-LEGACY-{decision.upper()}"
            with self.subTest(decision=decision):
                self._submit(task_id)
                verifier_manifest = self._manifest(
                    self.workspace.reports_dir / "codex",
                    f"{task_id}-independent",
                    raw_bytes=f"{decision} reproduction\n".encode(),
                )
                with (
                    patch(
                        "cogni_os.workspace.run_trusted_validations",
                        return_value=legacy_result,
                    ),
                    patch("cogni_os.workspace.archive_evidence_bundle") as archive,
                    self.assertRaisesRegex(
                        VerifierAttestationError,
                        "Trusted runner validations must be a list",
                    ),
                ):
                    self.workspace.verify(
                        actor="codex",
                        task_id=task_id,
                        decision=decision,
                        note="Legacy execution evidence must stay submitted.",
                        evidence_path=verifier_manifest,
                    )

                archive.assert_not_called()
                self.assertEqual(
                    self.workspace.get_task(task_id)["state"],
                    "submitted",
                )
                lifecycle = [
                    event
                    for event in self.workspace.ledger.read_verified()
                    if event.get("task_id") == task_id
                    and event.get("action")
                    in {
                        "verification.started",
                        "verification.failed",
                        "task.verified",
                        "task.rejected",
                    }
                ]
                self.assertEqual(
                    [event["action"] for event in lifecycle],
                    ["verification.started", "verification.failed"],
                )
                self.assertEqual(
                    lifecycle[1]["payload"]["stage"],
                    "executor_attestation",
                )
                self.assertEqual(
                    lifecycle[1]["payload"]["run_id"],
                    lifecycle[0]["payload"]["run_id"],
                )

    def test_legacy_runner_none_validations_fails_closed_before_attestation(
        self,
    ) -> None:
        task_id = "T-LEGACY-NONE-VALIDATIONS"
        self._submit(task_id)
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            f"{task_id}-independent",
            raw_bytes=b"legacy none validations\n",
        )
        legacy_result = {key: None for key in TRUSTED_RECEIPT_RESULT_KEYS}

        with (
            patch(
                "cogni_os.workspace.run_trusted_validations",
                return_value=legacy_result,
            ),
            patch("cogni_os.workspace.request_executor_attestation") as request,
            patch("cogni_os.workspace.verify_executor_attestation") as verify,
            patch("cogni_os.workspace.archive_evidence_bundle") as archive,
            self.assertRaisesRegex(
                VerifierAttestationError,
                "Trusted runner validations must be a list",
            ),
        ):
            self.workspace.verify(
                actor="codex",
                task_id=task_id,
                decision="accept",
                note="Malformed legacy validations must fail closed.",
                evidence_path=verifier_manifest,
            )

        request.assert_not_called()
        verify.assert_not_called()
        archive.assert_not_called()
        self.assertEqual(self.workspace.get_task(task_id)["state"], "submitted")
        lifecycle = [
            event
            for event in self.workspace.ledger.read_verified()
            if event.get("task_id") == task_id
            and event.get("action")
            in {"verification.started", "verification.failed"}
        ]
        self.assertEqual(
            [event["action"] for event in lifecycle],
            ["verification.started", "verification.failed"],
        )
        self.assertEqual(
            lifecycle[1]["payload"]["stage"],
            "executor_attestation",
        )

    def test_invalid_executor_attestation_cannot_reach_archive(self) -> None:
        task_id = "T-INVALID-ATTESTATION"
        self._submit(task_id)
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            f"{task_id}-independent",
            raw_bytes=b"invalid attestation reproduction\n",
        )
        with (
            patch(
                "cogni_os.workspace.request_executor_attestation",
                return_value={"malformed": True},
            ),
            patch(
                "cogni_os.workspace.verify_executor_attestation",
                side_effect=VerifierAttestationError(
                    "Independent executor proof does not match receipt"
                ),
            ),
            patch("cogni_os.workspace.archive_evidence_bundle") as archive,
            self.assertRaisesRegex(VerifierAttestationError, "does not match"),
        ):
            self.workspace.verify(
                actor="codex",
                task_id=task_id,
                decision="accept",
                note="Malformed executor proof must fail closed.",
                evidence_path=verifier_manifest,
            )

        archive.assert_not_called()
        self.assertEqual(self.workspace.get_task(task_id)["state"], "submitted")
        lifecycle = [
            event
            for event in self.workspace.ledger.read_verified()
            if event.get("task_id") == task_id
            and event.get("action")
            in {
                "verification.started",
                "verification.failed",
                "task.verified",
                "task.rejected",
            }
        ]
        self.assertEqual(
            [event["action"] for event in lifecycle],
            ["verification.started", "verification.failed"],
        )
        self.assertEqual(
            lifecycle[1]["payload"]["stage"],
            "executor_attestation",
        )

    def test_archive_failure_is_redacted_and_terminates_started_run(self) -> None:
        self._submit()
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            "T-WORK-archive-failure",
            raw_bytes=b"independent archive reproduction\n",
        )
        sensitive_detail = r"C:\private\token=do-not-record"
        with (
            patch(
                "cogni_os.workspace.archive_evidence_bundle",
                side_effect=OSError(sensitive_detail),
            ),
            self.assertRaisesRegex(OSError, "do-not-record"),
        ):
            self.workspace.verify(
                actor="codex",
                task_id="T-WORK",
                decision="accept",
                note="Archive failure must be classified without details.",
                evidence_path=verifier_manifest,
            )

        lifecycle = [
            event
            for event in self.workspace.ledger.read()
            if event["task_id"] == "T-WORK"
            and event["action"]
            in {
                "verification.started",
                "verification.failed",
                "task.verified",
            }
        ]
        self.assertEqual(
            [event["action"] for event in lifecycle],
            ["verification.started", "verification.failed"],
        )
        failed_payload = lifecycle[1]["payload"]
        started_payload = lifecycle[0]["payload"]
        self.assertEqual(failed_payload["schema_version"], 1)
        self.assertEqual(failed_payload["run_id"], started_payload["run_id"])
        self.assertEqual(failed_payload["task_attempt"], 1)
        self.assertEqual(failed_payload["stage"], "archive")
        self.assertEqual(failed_payload["error_type"], "io_error")
        self.assertEqual(
            failed_payload["capability_receipt"],
            started_payload["capability_receipt"],
        )
        self.assertEqual(
            failed_payload["verification_contract_inputs_sha256"],
            started_payload["verification_contract_inputs_sha256"],
        )
        serialized = json.dumps(lifecycle[1], ensure_ascii=False)
        self.assertNotIn("do-not-record", serialized)
        self.assertNotIn("private", serialized)
        self.assertEqual(self.workspace.get_task("T-WORK")["state"], "submitted")

    def test_projection_write_failure_after_terminal_event_is_not_misclassified(
        self,
    ) -> None:
        self._submit()
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            "T-WORK-projection-failure",
            raw_bytes=b"independent projection reproduction\n",
        )
        with (
            patch(
                "cogni_os.workspace.atomic_write_json",
                side_effect=OSError("projection write failed"),
            ),
            self.assertRaisesRegex(OSError, "projection write failed"),
        ):
            self.workspace.verify(
                actor="codex",
                task_id="T-WORK",
                decision="accept",
                note="Terminal ledger event precedes the task projection.",
                evidence_path=verifier_manifest,
            )

        lifecycle = [
            event
            for event in self.workspace.ledger.read()
            if event["task_id"] == "T-WORK"
            and event["action"]
            in {
                "verification.started",
                "verification.failed",
                "task.verified",
            }
        ]
        self.assertEqual(
            [event["action"] for event in lifecycle],
            ["verification.started", "task.verified"],
        )
        self.assertEqual(
            lifecycle[0]["payload"]["run_id"],
            lifecycle[1]["payload"]["run_id"],
        )
        self.assertFalse(
            any(event["action"] == "verification.failed" for event in lifecycle)
        )
        self.assertEqual(self.workspace.get_task("T-WORK")["state"], "submitted")
        self.assertFalse(self.workspace.audit_projections()["valid"])

        with patch(
            "cogni_os.workspace.run_trusted_validations",
            side_effect=AssertionError("reconciliation reran validation"),
        ):
            repaired = self.workspace.reconcile_verification(
                actor="codex",
                task_id="T-WORK",
                run_id=lifecycle[0]["payload"]["run_id"],
            )
            replayed = self.workspace.reconcile_verification(
                actor="codex",
                task_id="T-WORK",
                run_id=lifecycle[0]["payload"]["run_id"],
            )
        self.assertTrue(repaired["projection_rebuilt"])
        self.assertFalse(replayed["projection_rebuilt"])
        self.assertFalse(repaired["terminal_appended"])
        self.assertEqual(self.workspace.get_task("T-WORK")["state"], "verified")
        self.assertTrue(self.workspace.audit_projections()["valid"])
        self.assertEqual(
            len(
                [
                    event
                    for event in self.workspace.ledger.read_verified()
                    if event.get("payload", {}).get("run_id")
                    == lifecycle[0]["payload"]["run_id"]
                    and event.get("action")
                    in {"verification.failed", "task.verified", "task.rejected"}
                ]
            ),
            1,
        )

    def test_hard_crashes_before_terminal_are_reconciled_without_rerun(self) -> None:
        self._submit()
        crash_cases = (
            ("after-started", "cogni_os.workspace.run_trusted_validations"),
            ("after-receipt", "cogni_os.workspace.archive_evidence_bundle"),
            ("after-archive", "cogni_os.workspace.transition"),
        )
        for index, (crash_point, target) in enumerate(crash_cases, 1):
            with self.subTest(crash_point=crash_point):
                verifier_manifest = self._manifest(
                    self.workspace.reports_dir / "codex",
                    f"T-WORK-{crash_point}",
                    raw_bytes=f"{crash_point}\n".encode(),
                )
                with (
                    patch(target, side_effect=SystemExit(crash_point)),
                    self.assertRaises(SystemExit),
                ):
                    self.workspace.verify(
                        actor="codex",
                        task_id="T-WORK",
                        decision="accept",
                        note=f"Crash injection {index}",
                        evidence_path=verifier_manifest,
                    )

                lifecycle = [
                    event
                    for event in self.workspace.ledger.read_verified()
                    if event.get("task_id") == "T-WORK"
                    and event.get("action")
                    in {"verification.started", "verification.failed"}
                ]
                started = lifecycle[-1]
                self.assertEqual(started["action"], "verification.started")
                run_id = started["payload"]["run_id"]
                self.assertFalse(
                    any(
                        event.get("action") == "verification.failed"
                        and event.get("payload", {}).get("run_id") == run_id
                        for event in lifecycle
                    )
                )
                with patch(
                    "cogni_os.workspace.run_trusted_validations",
                    side_effect=AssertionError("reconciliation reran validation"),
                ):
                    reconciled = self.workspace.reconcile_verification(
                        actor="codex",
                        task_id="T-WORK",
                        run_id=run_id,
                    )
                    replayed = self.workspace.reconcile_verification(
                        actor="codex",
                        task_id="T-WORK",
                        run_id=run_id,
                    )
                self.assertTrue(reconciled["terminal_appended"])
                self.assertFalse(replayed["terminal_appended"])
                terminals = [
                    event
                    for event in self.workspace.ledger.read_verified()
                    if event.get("payload", {}).get("run_id") == run_id
                    and event.get("action")
                    in {"verification.failed", "task.verified", "task.rejected"}
                ]
                self.assertEqual(len(terminals), 1)
                self.assertEqual(terminals[0]["payload"]["stage"], "recovery")
                self.assertEqual(
                    self.workspace.get_task("T-WORK")["state"], "submitted"
                )

    def test_completed_verification_reconciliation_is_a_noop(self) -> None:
        self._submit()
        verifier_manifest = self._manifest(
            self.workspace.reports_dir / "codex",
            "T-WORK-completed-reconcile",
            raw_bytes=b"completed verification\n",
        )
        verified = self.workspace.verify(
            actor="codex",
            task_id="T-WORK",
            decision="accept",
            note="Complete before reconciliation",
            evidence_path=verifier_manifest,
        )
        run_id = verified["verification"]["run_id"]
        before_count = len(self.workspace.ledger.read_verified())
        with patch(
            "cogni_os.workspace.run_trusted_validations",
            side_effect=AssertionError("reconciliation reran validation"),
        ):
            reconciled = self.workspace.reconcile_verification(
                actor="codex",
                task_id="T-WORK",
                run_id=run_id,
            )
        self.assertFalse(reconciled["terminal_appended"])
        self.assertFalse(reconciled["projection_rebuilt"])
        self.assertEqual(len(self.workspace.ledger.read_verified()), before_count)
        self.assertEqual(reconciled["task"], verified)

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
