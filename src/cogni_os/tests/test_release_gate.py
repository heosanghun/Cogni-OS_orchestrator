"""Regression tests for immutable, signed release gate contracts."""

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

import cogni_os.release_gate as release_gate_module
from cogni_os.errors import (
    AuthorizationError,
    EvidenceError,
    IntegrityError,
    StateError,
)
from cogni_os.independence import identity_snapshot
from cogni_os.release_gate import (
    P01_TASK_ID,
    issue_release_gate,
    release_gate_status,
    validate_release_gate,
)
from cogni_os.tests._actor_capability_test_support import (
    install_legacy_capability_fixture,
)
from cogni_os.tests._isolation_test_support import install_direct_isolation_fixture
from cogni_os.util import atomic_write_json, canonical_json, utc_now
from cogni_os.workspace import Workspace

from cogni_os.cli import build_parser


class ReleaseGateTestCase(unittest.TestCase):
    def setUp(self) -> None:
        install_legacy_capability_fixture(self)
        install_direct_isolation_fixture(self)
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.workspace = Workspace.initialize(
            self.root,
            name="Release gate test",
            orchestrator="codex",
            preset="cogni-codex-antigravity",
        )
        self.validation_helper = self.root / "validation_helper.py"
        self.validation_helper.write_text(
            "import sys\nsys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))\n",
            encoding="utf-8",
        )
        self._git("init")
        self._git("config", "core.autocrlf", "false")
        self._git("config", "user.email", "tests@cogni.invalid")
        self._git("config", "user.name", "Cogni Tests")
        self._git("add", "-f", "validation_helper.py")
        self._git("add", ".")
        self._git("commit", "-m", "release gate fixture")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip().lower()

        self._submit_task(P01_TASK_ID)
        self._write_production_evidence()
        self._accept_task(P01_TASK_ID)
        self._write_agent_attestation()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )

    def _manifest(self, directory: Path, stem: str, raw: bytes) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        output_path = directory / f"{stem}.log"
        output_path.write_bytes(raw)
        manifest = directory / f"{stem}.evidence.json"
        manifest.write_text(
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
                                raw.hex(),
                            ],
                            "exit_code": 0,
                            "passed": 1,
                            "failed": 0,
                            "skipped": 0,
                            "raw_output_path": output_path.name,
                            "raw_output_sha256": hashlib.sha256(raw).hexdigest(),
                        }
                    ],
                    "known_answer_checks": [
                        {
                            "name": stem,
                            "expected": "pass",
                            "observed": "pass",
                            "passed": True,
                        }
                    ],
                    "claims": [],
                }
            ),
            encoding="utf-8",
        )
        return manifest

    @staticmethod
    def _report(directory: Path, stem: str) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        report = directory / f"{stem}.md"
        report.write_text(
            "".join(
                f"## {number}. Section {number}\nMeasured evidence {number}\n"
                for number in range(1, 7)
            ),
            encoding="utf-8",
        )
        return report

    def _submit_task(self, task_id: str) -> None:
        self.workspace.add_task(
            actor="codex",
            task_id=task_id,
            title=f"Verified {task_id}",
            description="Produce independently reproducible evidence",
            owner="antigravity",
        )
        claim = self.workspace.claim(actor="antigravity", task_id=task_id)
        self.workspace.start(
            actor="antigravity",
            task_id=task_id,
            lease_token=claim["lease_token"],
        )
        worker_directory = self.workspace.reports_dir / "antigravity"
        self.workspace.submit(
            actor="antigravity",
            task_id=task_id,
            lease_token=claim["lease_token"],
            report_path=self._report(worker_directory, f"{task_id}-worker"),
            evidence_path=self._manifest(
                worker_directory,
                f"{task_id}-worker",
                b"worker passed\n",
            ),
        )

    def _accept_task(self, task_id: str) -> None:
        verifier_directory = self.workspace.reports_dir / "codex"
        self.workspace.verify(
            actor="codex",
            task_id=task_id,
            decision="accept",
            note="Independent known-answer reproduction passed.",
            evidence_path=self._manifest(
                verifier_directory,
                f"{task_id}-verifier",
                b"verifier passed\n",
            ),
        )

    def _write_production_evidence(self) -> None:
        task = self.workspace.get_task(P01_TASK_ID)
        attempt = task["attempt"]
        codex = self.workspace.get_agent("codex")
        producer = {
            **identity_snapshot("codex", codex["identity"]),
            "role": "orchestrator",
        }
        capability_receipt = self.workspace.authorize_actor_capability(
            actor="codex",
            operation="release.evidence.collect",
            capability_secret=None,
            require_actor_os_isolation=True,
        )
        values = {
            "production-health-body": ("production_health.body.json", {"ok": True}),
            "production-health-capture": (
                "production_health.capture.json",
                {"status": 200},
            ),
            "production-snapshot-body": (
                "production_snapshot.body.json",
                {"schema_version": "1.1"},
            ),
            "production-snapshot-capture": (
                "production_snapshot.capture.json",
                {"status": 200},
            ),
            "cloudflare-deployment-evidence": (
                "cloudflare_deployment.json",
                {"attestation_level": "CLOUDFLARE_API_VERIFIED"},
            ),
            "cloudflare-rollback-target-evidence": (
                "cloudflare_rollback_target.json",
                {"attestation_level": "CLOUDFLARE_API_VERIFIED"},
            ),
            "cloudflare-rollback-dry-run-receipt": (
                "cloudflare_rollback_dry_run.json",
                {"mutation_performed": False},
            ),
        }
        artifacts: list[dict[str, object]] = []
        artifact_bytes: dict[str, bytes] = {}
        for kind, (filename, value) in values.items():
            content = canonical_json(value)
            artifact_bytes[filename] = content
            artifacts.append(
                {
                    "kind": kind,
                    "filename": filename,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                }
            )
        bundle = {
            "schema_version": 1,
            "kind": "production-release-evidence",
            "task_id": P01_TASK_ID,
            "task_attempt": attempt,
            "producer": producer,
            "actor_capability": capability_receipt,
            "source_commit": self.commit,
            "deployment_attestation": "CLOUDFLARE_API_VERIFIED",
            "rollback_mutation_performed": False,
            "artifacts": artifacts,
        }
        bundle_bytes = canonical_json(bundle)
        bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
        relative_directory = Path(
            "archive",
            "release-evidence",
            P01_TASK_ID,
            f"attempt-{attempt}",
            bundle_sha256,
        )
        directory = self.root / relative_directory
        directory.mkdir(parents=True)
        for filename, content in artifact_bytes.items():
            (directory / filename).write_bytes(content)
        (directory / "bundle.json").write_bytes(bundle_bytes)
        event_artifacts = [
            {
                "kind": item["kind"],
                "archive_path": (relative_directory / str(item["filename"])).as_posix(),
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
            }
            for item in artifacts
        ]
        self.workspace.ledger.append(
            actor="codex",
            action="release.evidence_collected",
            task_id=P01_TASK_ID,
            payload={
                "schema_version": 1,
                "producer": producer,
                "actor_capability": capability_receipt,
                "source_commit": self.commit,
                "task_attempt": attempt,
                "collection": {
                    "kind": "production-release-evidence",
                    "bundle_path": (relative_directory / "bundle.json").as_posix(),
                    "bundle_sha256": bundle_sha256,
                    "artifacts": event_artifacts,
                },
            },
        )

    def _write_agent_attestation(self) -> None:
        observed_at = utc_now()
        document = {
            "schema_version": 1,
            "kind": "cogni-agent-runtime-attestation",
            "agent_id": "antigravity",
            "ready": True,
            "source_commit": self.commit,
            "observed_at": observed_at,
        }
        relative = Path("reports", "antigravity", "runtime-attestation.json")
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json(document))
        agent_path = self.workspace.agents_dir / "antigravity.json"
        agent = json.loads(agent_path.read_text(encoding="utf-8"))
        agent["runtime_attestation"] = {
            "ready": True,
            "observed_at": observed_at,
            "source_commit": self.commit,
            "evidence_path": relative.as_posix(),
            "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        atomic_write_json(agent_path, agent)

    def _issue(self) -> dict[str, object]:
        return issue_release_gate(
            self.workspace,
            actor="codex",
            attesting_agent_id="antigravity",
        )

    def _archive_snapshot(self) -> list[tuple[str, str, str]]:
        archive = self.root / "archive"
        if not archive.exists():
            return []
        snapshot: list[tuple[str, str, str]] = []
        for candidate in sorted(archive.rglob("*")):
            relative = candidate.relative_to(archive).as_posix()
            if candidate.is_dir():
                snapshot.append((relative, "directory", ""))
            elif candidate.is_file():
                snapshot.append(
                    (
                        relative,
                        "file",
                        hashlib.sha256(candidate.read_bytes()).hexdigest(),
                    )
                )
            else:
                snapshot.append((relative, "other", ""))
        return snapshot

    def _assert_unsupported_platform_no_go(self) -> None:
        ledger_before = self.workspace.ledger.path.read_bytes()
        archive_before = self._archive_snapshot()
        with patch.object(
            Workspace,
            "authorize_actor_capability",
            side_effect=AssertionError("capability must not be consumed"),
        ):
            with self.assertRaisesRegex(EvidenceError, "descriptor-relative"):
                issue_release_gate(
                    self.workspace,
                    actor="codex",
                    attesting_agent_id="antigravity",
                )
        self.assertEqual(self.workspace.ledger.path.read_bytes(), ledger_before)
        self.assertEqual(self._archive_snapshot(), archive_before)
        self.assertFalse((self.root / "archive" / "release-gates").exists())

    def _positive_archive_or_assert_platform_no_go(self) -> bool:
        if release_gate_module._secure_archive_primitives_available():
            return True
        self._assert_unsupported_platform_no_go()
        return False

    def test_platform_archive_boundary_is_explicit(self) -> None:
        if release_gate_module._secure_archive_primitives_available():
            self.assertTrue(release_gate_module._secure_archive_primitives_available())
            return
        self._assert_unsupported_platform_no_go()

    def test_preexisting_release_archive_symlink_cannot_redirect_write(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        outside = self.root / "outside-preexisting"
        outside.mkdir()
        release_gates = self.root / "archive" / "release-gates"
        release_gates.symlink_to(outside, target_is_directory=True)
        ledger_before = self.workspace.ledger.path.read_bytes()
        with self.assertRaisesRegex(EvidenceError, "opened safely"):
            issue_release_gate(
                self.workspace,
                actor="codex",
                attesting_agent_id="antigravity",
            )
        self.assertEqual(self.workspace.ledger.path.read_bytes(), ledger_before)
        self.assertEqual(list(outside.iterdir()), [])

    def test_parent_swap_to_symlink_cannot_redirect_contract_write(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        outside = self.root / "outside-swap"
        outside.mkdir()
        real_mkdir = os.mkdir
        swapped = False

        def swap_after_create(
            component: str,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal swapped
            real_mkdir(component, mode=mode, dir_fd=dir_fd)
            if component == "release-gates" and dir_fd is not None and not swapped:
                swapped = True
                release_gates = self.root / "archive" / "release-gates"
                release_gates.rename(self.root / "archive" / "release-gates-original")
                release_gates.symlink_to(outside, target_is_directory=True)

        ledger_before = self.workspace.ledger.path.read_bytes()
        with patch("cogni_os.release_gate.os.mkdir", side_effect=swap_after_create):
            with self.assertRaisesRegex(EvidenceError, "opened safely"):
                issue_release_gate(
                    self.workspace,
                    actor="codex",
                    attesting_agent_id="antigravity",
                )
        self.assertTrue(swapped)
        self.assertEqual(self.workspace.ledger.path.read_bytes(), ledger_before)
        self.assertEqual(list(outside.iterdir()), [])

    def test_real_git_release_gate_is_reachable_and_allows_later_event(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        result = self._issue()
        self.assertEqual(result["status"], "PASS")
        self.assertFalse((self.root / "release" / "RELEASE_GATE.json").exists())
        contract_path = self.root / str(result["contract_path"])
        self.assertEqual(
            contract_path.parent.name,
            hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        )
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        event = self.workspace.ledger.read_verified()[-1]
        self.assertEqual(event["action"], "release.gate_issued")
        self.assertEqual(
            event["previous_hash"],
            contract["ledger_head_before_issue"],
        )
        self.workspace.ledger.append(
            actor="codex",
            action="monitor.heartbeat",
            task_id=None,
            payload={"status": "alive"},
        )
        validated = validate_release_gate(self.workspace)
        self.assertEqual(validated["event_hash"], result["event_hash"])
        self.assertEqual(release_gate_status(self.workspace)["status"], "PASS")

    def test_contract_mutation_fails_closed(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        result = self._issue()
        path = self.root / str(result["contract_path"])
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(EvidenceError, "contract bytes changed"):
            validate_release_gate(self.workspace)

    def test_unauthorized_actor_cannot_issue(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        with self.assertRaises(AuthorizationError):
            issue_release_gate(
                self.workspace,
                actor="antigravity",
                attesting_agent_id="antigravity",
            )
        self.assertFalse(
            any(
                event["action"] == "release.gate_issued"
                for event in self.workspace.ledger.read_verified()
            )
        )

    def test_wrong_commit_and_new_clean_commit_fail_closed(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        self._issue()
        with self.assertRaisesRegex(EvidenceError, "Expected release commit"):
            validate_release_gate(
                self.workspace,
                expected_source_commit="f" * 40,
            )
        (self.root / "new-source.txt").write_text("new commit\n", encoding="utf-8")
        self._git("add", "new-source.txt")
        self._git("commit", "-m", "different source")
        with self.assertRaisesRegex(EvidenceError, "gate event"):
            validate_release_gate(self.workspace)

    def test_dirty_source_fails_before_issuance_and_after_gate(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        self.validation_helper.write_text("raise SystemExit(1)\n", encoding="utf-8")
        with self.assertRaisesRegex(StateError, "dirty"):
            self._issue()
        self._git("checkout", "--", "validation_helper.py")
        self._issue()
        self.validation_helper.write_text("raise SystemExit(2)\n", encoding="utf-8")
        with self.assertRaisesRegex(StateError, "dirty"):
            validate_release_gate(self.workspace)

    def test_ledger_mismatch_fails_signature_validation(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        self._issue()
        lines = self.workspace.ledger.path.read_text(encoding="utf-8").splitlines()
        event = json.loads(lines[-1])
        event["previous_hash"] = "0" * 64
        lines[-1] = json.dumps(event, sort_keys=True)
        self.workspace.ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(IntegrityError):
            validate_release_gate(self.workspace)

    def test_p01_or_attestation_artifact_mutation_fails_closed(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        result = self._issue()
        contract = json.loads(
            (self.root / str(result["contract_path"])).read_text(encoding="utf-8")
        )
        p01_path = self.root / contract["p01_production_evidence"]["bundle_path"]
        p01_path.write_bytes(p01_path.read_bytes() + b" ")
        with self.assertRaisesRegex(EvidenceError, "bundle hash"):
            validate_release_gate(self.workspace)

        # Restore the exact immutable bytes, then prove the independent runtime
        # attestation anchor is also re-hashed at read time.
        p01_path.write_bytes(p01_path.read_bytes()[:-1])
        attestation_path = self.root / contract["agent_attestation"]["evidence_path"]
        attestation_path.write_bytes(b"{}")
        with self.assertRaisesRegex(EvidenceError, "attestation evidence changed"):
            validate_release_gate(self.workspace)

    def test_ads_style_attestation_path_is_rejected(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        agent_path = self.workspace.agents_dir / "antigravity.json"
        agent = json.loads(agent_path.read_text(encoding="utf-8"))
        agent["runtime_attestation"]["evidence_path"] = (
            "reports/antigravity/runtime-attestation.json:stream"
        )
        atomic_write_json(agent_path, agent)
        with self.assertRaisesRegex(EvidenceError, "unsafe component"):
            self._issue()

    def test_restatement_invalidates_an_already_issued_gate(self) -> None:
        if not self._positive_archive_or_assert_platform_no_go():
            return
        self._issue()
        self.workspace.restate_verification(
            actor="codex",
            task_id=P01_TASK_ID,
            effective_status="verification_revoked",
            reason="Independent review revoked this verification proof.",
        )
        with self.assertRaisesRegex(StateError, "not trusted"):
            validate_release_gate(self.workspace)
        status = release_gate_status(self.workspace)
        self.assertEqual(status["status"], "NO_GO")
        self.assertIn("not trusted", status["reason"])

    def test_cli_exposes_issue_and_fail_closed_status_commands(self) -> None:
        issue = build_parser().parse_args(
            [
                "release",
                "gate",
                "issue",
                str(self.root),
                "--actor",
                "codex",
                "--attesting-agent",
                "antigravity",
            ]
        )
        self.assertEqual(issue.actor, "codex")
        self.assertEqual(issue.attesting_agent, "antigravity")

        status = build_parser().parse_args(
            [
                "release",
                "gate",
                "status",
                str(self.root),
                "--expected-source-commit",
                "a" * 40,
            ]
        )
        self.assertEqual(status.expected_source_commit, "a" * 40)


if __name__ == "__main__":
    unittest.main()
