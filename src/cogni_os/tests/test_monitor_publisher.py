from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cogni_os.tests._actor_capability_test_support import (
    install_legacy_capability_fixture,
)
from cogni_os.tests._isolation_test_support import (
    install_direct_isolation_fixture,
)
from cogni_os.trust_projection import task_trust_state
from cogni_os.util import canonical_json
from cogni_os.workspace import Workspace
from scripts.publish_monitor_snapshot import (
    RELEASE_ARTIFACT_FILES,
    PublisherAlreadyRunning,
    PublisherInstanceLock,
    _run_capped_command,
    append_runtime_journal,
    audit_operational_evidence,
    build_snapshot,
    collect_gpus,
    collector_host_id,
    compute_backoff_seconds,
    export_agents,
    export_tasks,
    git_tree_status,
    hmac_signature,
    main,
    next_sequence,
    peek_next_sequence,
    process_is_alive,
    release_gate,
    sanitize_error,
    signature_message,
    validate_publish_endpoint,
    wait_for_supervisor,
)


class MonitorPublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        install_legacy_capability_fixture(self)

    def _gpu_boundary_environment(
        self,
        directory: Path,
        *,
        violating_ids: list[int] | None = None,
        container_claims: int = 0,
        scheduler_reservations: int = 0,
        inventory_complete: bool = True,
    ) -> dict[str, str]:
        secret = "boundary-test-secret-0123456789abcdef"
        now = datetime.now(timezone.utc)
        document = {
            "schema_version": 1,
            "document_type": "cogni-gpu-boundary-attestation",
            "workspace_id": "workspace-test",
            "issuer": "isolated-host-authority",
            "key_id": "host-boundary-test",
            "observed_at": (now - timedelta(seconds=1)).isoformat().replace(
                "+00:00", "Z"
            ),
            "expires_at": (now + timedelta(seconds=60)).isoformat().replace(
                "+00:00", "Z"
            ),
            "nonce": "boundary-nonce-0123456789abcdef",
            "scope": [
                "host-inventory",
                "host-processes",
                "containers",
                "scheduler",
            ],
            "allowed_ids": [0, 1, 2, 3, 4, 5],
            "denied_ids": [6, 7],
            "inventory_complete": inventory_complete,
            "violating_ids": violating_ids or [],
            "container_claims": container_claims,
            "scheduler_reservations": scheduler_reservations,
        }
        message = b"COGNI-GPU-BOUNDARY-V1\n" + canonical_json(document)
        document["signature"] = "sha256=" + hmac.new(
            secret.encode("utf-8"), message, hashlib.sha256
        ).hexdigest()
        path = directory / "gpu-boundary.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return {
            "COGNI_GPU_BOUNDARY_ATTESTATION_PATH": str(path),
            "COGNI_GPU_BOUNDARY_HMAC_KEYS": json.dumps(
                {"host-boundary-test": secret}
            ),
        }

    def _release_collection_fixture(
        self, root: Path
    ) -> tuple[dict[str, object], dict[str, object]]:
        workspace = Workspace.initialize(
            root,
            name="PRIVATE-CUSTOMER-NAME",
            preset=None,
        )
        producer = {
            "actor": "codex",
            **workspace.get_agent("codex")["identity"],
            "role": "orchestrator",
        }
        commit = "a" * 40
        attempt = 1
        bundle_bytes = b'{"schema_version":1}\n'
        bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
        relative_root = (
            f"archive/release-evidence/P01-TRUTH/attempt-{attempt}/{bundle_sha}"
        )
        bundle_path = root / relative_root / "bundle.json"
        bundle_path.parent.mkdir(parents=True)
        bundle_path.write_bytes(bundle_bytes)
        artifacts: list[dict[str, object]] = []
        for index, (kind, filename) in enumerate(RELEASE_ARTIFACT_FILES.items()):
            content = f"artifact-{index}\n".encode()
            path = root / relative_root / filename
            path.write_bytes(content)
            artifacts.append(
                {
                    "kind": kind,
                    "archive_path": f"{relative_root}/{filename}",
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                }
            )
        event: dict[str, object] = {
            "action": "release.evidence_collected",
            "actor": "codex",
            "task_id": "P01-TRUTH",
            "payload": {
                "schema_version": 1,
                "producer": producer,
                "source_commit": commit,
                "task_attempt": attempt,
                "collection": {
                    "kind": "production-release-evidence",
                    "bundle_path": f"{relative_root}/bundle.json",
                    "bundle_sha256": bundle_sha,
                    "artifacts": artifacts,
                },
            },
        }
        return event, {"operational_records": []}

    def test_release_collection_requires_registered_orchestrator_and_exact_contract(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event, tree = self._release_collection_fixture(root)
            valid = audit_operational_evidence(root, [event], tree)
            self.assertTrue(valid["valid"])
            self.assertEqual(
                valid["reference_count"], len(RELEASE_ARTIFACT_FILES) + 1
            )

            spoofed = deepcopy(event)
            spoofed["actor"] = "antigravity"
            spoofed["payload"]["producer"] = {
                **spoofed["payload"]["producer"],
                "actor": "antigravity",
            }
            self.assertFalse(audit_operational_evidence(root, [spoofed], tree)["valid"])

            missing = deepcopy(event)
            missing["payload"]["collection"]["artifacts"].pop()
            self.assertFalse(audit_operational_evidence(root, [missing], tree)["valid"])

            wrong_kind = deepcopy(event)
            wrong_kind["payload"]["collection"]["artifacts"][0]["kind"] = (
                "unexpected-kind"
            )
            self.assertFalse(
                audit_operational_evidence(root, [wrong_kind], tree)["valid"]
            )

            wrong_filename = deepcopy(event)
            wrong_filename["payload"]["collection"]["artifacts"][0]["archive_path"] = (
                wrong_filename["payload"]["collection"]["artifacts"][0][
                    "archive_path"
                ].replace("production_health.body.json", "renamed.json")
            )
            self.assertFalse(
                audit_operational_evidence(root, [wrong_filename], tree)["valid"]
            )

            wrong_size = deepcopy(event)
            wrong_size["payload"]["collection"]["artifacts"][0]["size_bytes"] += 1
            self.assertFalse(
                audit_operational_evidence(root, [wrong_size], tree)["valid"]
            )

    def test_git_tree_status_separates_operational_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "config",
                    "user.email",
                    "test@example.invalid",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Cogni Test"],
                check=True,
            )
            (root / "README.md").write_text("baseline\n", encoding="utf-8")
            (root / ".gitignore").write_text(
                "archive/\nreports/\nruns/\nsubmissions/\n", encoding="utf-8"
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "README.md", ".gitignore"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "baseline"],
                check=True,
            )

            (root / "ledger").mkdir()
            (root / "tasks").mkdir()
            (root / "ledger" / "events.jsonl").write_text("{}\n", encoding="utf-8")
            (root / "tasks" / "P01.json").write_text("{}\n", encoding="utf-8")
            operational = git_tree_status(root)
            self.assertTrue(operational["clean"])
            self.assertEqual(operational["change_count"], 0)
            self.assertEqual(operational["operational_change_count"], 2)
            operational_fingerprint = operational["operational_fingerprint"]

            (root / "tasks" / "P01.json").write_text(
                '{"state":"pending"}\n', encoding="utf-8"
            )
            operational_content_changed = git_tree_status(root)
            self.assertNotEqual(
                operational_content_changed["operational_fingerprint"],
                operational_fingerprint,
            )

            (root / "source-change.txt").write_text("changed\n", encoding="utf-8")
            source_dirty = git_tree_status(root)
            self.assertFalse(source_dirty["clean"])
            self.assertEqual(source_dirty["change_count"], 1)
            self.assertEqual(source_dirty["operational_change_count"], 2)
            source_fingerprint = source_dirty["fingerprint"]

            (root / "source-change.txt").write_text("changed again\n", encoding="utf-8")
            source_content_changed = git_tree_status(root)
            self.assertNotEqual(
                source_content_changed["fingerprint"], source_fingerprint
            )

            (root / "tasks" / "evil.py").write_text(
                "raise SystemExit\n", encoding="utf-8"
            )
            unclassified = git_tree_status(root)
            self.assertEqual(unclassified["unclassified_change_count"], 1)

            (root / "reports").mkdir()
            (root / "reports" / "orphan.md").write_text(
                "unbound evidence\n", encoding="utf-8"
            )
            orphaned = git_tree_status(root)
            evidence_audit = audit_operational_evidence(root, [], orphaned)
            self.assertTrue(evidence_audit["valid"])
            self.assertEqual(evidence_audit["unbound_count"], 0)
            self.assertEqual(evidence_audit["reference_count"], 0)

            # reports/ and runs/ are mutable staging, never release truth.  A
            # nested path/hash pair must not become trusted merely because it
            # appears somewhere in an actor-controlled payload.
            report_path = root / "reports" / "orphan.md"
            report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
            nested_event = {
                "action": "actor.note",
                "payload": {
                    "artifact": {"path": str(report_path), "sha256": report_sha}
                },
            }
            nested_audit = audit_operational_evidence(root, [nested_event], orphaned)
            self.assertTrue(nested_audit["valid"])
            self.assertEqual(nested_audit["reference_count"], 0)

            report_path.write_text("tampered evidence\n", encoding="utf-8")
            tampered = git_tree_status(root)
            staging_audit = audit_operational_evidence(root, [nested_event], tampered)
            self.assertTrue(staging_audit["valid"])
            self.assertEqual(staging_audit["hash_mismatch_count"], 0)

            # Only the exact archived task bundle schema under submissions/
            # establishes release truth; both directions are checked.
            task_id = "T-BOUND"
            attempt = 1
            manifest_bytes = b'{"schema_version":1}\n'
            archived_report_bytes = b"immutable report\n"
            manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
            archived_report_sha = hashlib.sha256(archived_report_bytes).hexdigest()
            bundle_id = f"worker-{manifest_sha[:16]}"
            bundle_root = (
                root / "submissions" / task_id / f"attempt-{attempt:03d}" / bundle_id
            )
            files_root = bundle_root / "files"
            files_root.mkdir(parents=True)
            archived_manifest = files_root / f"{manifest_sha}_manifest.json"
            archived_report = files_root / f"{archived_report_sha}_report.md"
            archived_manifest.write_bytes(manifest_bytes)
            archived_report.write_bytes(archived_report_bytes)
            bundle_manifest = bundle_root / "bundle.json"
            bundle_manifest.write_text('{"schema_version":1}\n', encoding="utf-8")
            bundle_manifest_sha = hashlib.sha256(
                bundle_manifest.read_bytes()
            ).hexdigest()
            bundle = {
                "task_id": task_id,
                "attempt": attempt,
                "label": "worker",
                "bundle_id": bundle_id,
                "path": str(bundle_root),
                "manifest_path": str(bundle_manifest),
                "manifest_sha256": bundle_manifest_sha,
                "retained": 2,
                "external": 0,
                "files": [
                    {
                        "kind": "manifest",
                        "sha256": manifest_sha,
                        "size_bytes": len(manifest_bytes),
                        "retained": True,
                        "archive_path": str(archived_manifest),
                    },
                    {
                        "kind": "report",
                        "sha256": archived_report_sha,
                        "size_bytes": len(archived_report_bytes),
                        "retained": True,
                        "archive_path": str(archived_report),
                    },
                ],
            }
            bound_event = {
                "action": "task.submitted",
                "actor": "antigravity",
                "task_id": task_id,
                "payload": {
                    "task": {
                        "id": task_id,
                        "attempt": attempt,
                        "owner": "antigravity",
                        "result": {"submitted_by": "antigravity"},
                    },
                    "worker_identity": {"actor": "antigravity"},
                    "bundle": bundle,
                    "nested_injection": {
                        "path": str(report_path),
                        "sha256": report_sha,
                    },
                },
            }
            archived_tree = git_tree_status(root)
            bound_audit = audit_operational_evidence(root, [bound_event], archived_tree)
            self.assertTrue(bound_audit["valid"])
            self.assertEqual(bound_audit["reference_count"], 3)

            archived_report.write_text("tampered archive\n", encoding="utf-8")
            archive_tampered = git_tree_status(root)
            tampered_audit = audit_operational_evidence(
                root,
                [bound_event],
                archive_tampered,
            )
            self.assertFalse(tampered_audit["valid"])
            self.assertEqual(tampered_audit["hash_mismatch_count"], 1)

            (root / "reports" / "evil.py").write_text(
                "raise SystemExit\n", encoding="utf-8"
            )
            executable_evidence = git_tree_status(root)
            self.assertGreaterEqual(executable_evidence["unclassified_change_count"], 2)

    def test_supervisor_watch_stops_orphaned_publisher(self) -> None:
        self.assertTrue(process_is_alive(os.getpid()))
        with (
            patch(
                "scripts.publish_monitor_snapshot.process_is_alive",
                side_effect=[True, False],
            ),
            patch("scripts.publish_monitor_snapshot.time.sleep") as sleep,
        ):
            self.assertFalse(
                wait_for_supervisor(10, 12345, check_interval=1),
            )
        sleep.assert_called_once_with(1)

    def test_process_lock_is_single_instance_and_recovers_after_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "publisher.instance.lock"
            first = PublisherInstanceLock(lock_path)
            second = PublisherInstanceLock(lock_path)
            first.acquire()
            with self.assertRaises(PublisherAlreadyRunning):
                second.acquire()
            first.release()
            second.acquire()
            second.release()

    def test_supervised_duplicate_returns_temporary_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = Workspace.initialize(
                root / "workspace",
                name="Duplicate Process Test",
                orchestrator="codex",
                orchestrator_control_principal="codex-conductor",
                orchestrator_model_family="openai-codex",
                preset="cogni-codex-antigravity",
            )
            state_dir = root / "state"
            lock = PublisherInstanceLock(
                state_dir / "locks" / "monitor-publisher.instance.lock"
            )
            with lock:
                exit_code = main(
                    [
                        str(workspace.root),
                        "--dry-run",
                        "--state-dir",
                        str(state_dir),
                    ]
                )
            self.assertEqual(exit_code, 75)

    def test_exponential_backoff_is_bounded(self) -> None:
        self.assertEqual(compute_backoff_seconds(15, 1, 300), 15)
        self.assertEqual(compute_backoff_seconds(15, 2, 300), 30)
        self.assertEqual(compute_backoff_seconds(15, 5, 120), 120)
        self.assertEqual(compute_backoff_seconds(15, 100, 120), 120)

    def test_subprocess_capture_and_timeout_are_bounded_in_flight(self) -> None:
        for stream_name in ("stdout", "stderr"):
            descriptor = "1" if stream_name == "stdout" else "2"
            command = [
                sys.executable,
                "-c",
                f"import os; os.write({descriptor}, b'x' * 8192)",
            ]
            with self.assertRaisesRegex(RuntimeError, stream_name):
                _run_capped_command(
                    command,
                    timeout=5,
                    text=False,
                    stdout_limit=1024,
                    stderr_limit=1024,
                )
        with self.assertRaises(subprocess.TimeoutExpired):
            _run_capped_command(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                timeout=1,
                text=True,
                stdout_limit=1024,
                stderr_limit=1024,
            )

    def test_runtime_journal_is_jsonl_and_error_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            secret = "a-secret-that-must-not-enter-the-journal"
            error = RuntimeError(f"failed with {secret}\non retry")
            append_runtime_journal(
                state_dir,
                "publish_failed",
                error=sanitize_error(error, secret=secret),
            )
            journal = state_dir / "monitor_publisher_journal.jsonl"
            content = journal.read_text(encoding="utf-8")
            record = json.loads(content)
            self.assertEqual(record["event"], "publish_failed")
            self.assertNotIn(secret, content)
            self.assertIn("[REDACTED]", content)

    def test_publisher_state_can_live_outside_read_only_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = Workspace.initialize(
                root / "workspace",
                name="Read-only Projection Test",
                orchestrator="codex",
                orchestrator_control_principal="codex-conductor",
                orchestrator_model_family="openai-codex",
                preset="cogni-codex-antigravity",
            )
            state_dir = root / "publisher-state"

            self.assertEqual(
                peek_next_sequence(workspace, state_dir=state_dir),
                1,
            )
            self.assertEqual(
                next_sequence(workspace, state_dir=state_dir),
                1,
            )
            self.assertEqual(
                peek_next_sequence(workspace, state_dir=state_dir),
                2,
            )
            self.assertTrue(
                (state_dir / "monitor_publish_state.json").is_file(),
            )
            self.assertFalse(
                (workspace.control_dir / "monitor_publish_state.json").exists(),
            )

    def test_snapshot_contains_evidence_derived_phase_roadmap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Workspace.initialize(
                Path(temporary),
                name="Publisher Roadmap Test",
                orchestrator="codex",
                orchestrator_control_principal="codex-conductor",
                orchestrator_model_family="openai-codex",
                preset="cogni-codex-antigravity",
            )
            snapshot = build_snapshot(
                workspace,
                sequence=1,
                include_gpu=False,
            )

        self.assertEqual(snapshot["roadmap"]["total"], 11)
        self.assertEqual(snapshot["roadmap"]["trusted_complete"], 0)
        self.assertEqual(snapshot["roadmap"]["progress_percent"], 0.0)
        self.assertEqual(len(snapshot["roadmap"]["phases"]), 11)
        self.assertTrue(
            all(phase["state"] == "missing" for phase in snapshot["roadmap"]["phases"])
        )

    def test_public_snapshot_excludes_customer_task_and_secret_canaries(self) -> None:
        customer_canary = "PII-CUSTOMER-ALPHA-99117"
        title_canary = "PRIVATE-TASK-TITLE-77221"
        secret_canary = "SECRET-TOKEN-DO-NOT-PUBLISH-66331"
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Workspace.initialize(
                Path(temporary),
                name=customer_canary,
                preset=None,
            )
            workspace.add_task(
                actor="codex",
                task_id="T-PRIVATE",
                title=title_canary,
                description=secret_canary,
                owner="codex",
            )
            snapshot = build_snapshot(
                workspace,
                sequence=1,
                include_gpu=False,
            )
        serialized = json.dumps(snapshot, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(customer_canary, serialized)
        self.assertNotIn(title_canary, serialized)
        self.assertNotIn(secret_canary, serialized)
        self.assertEqual(snapshot["workspace_name"], "Cogni-OS Evidence Operations")
        self.assertEqual(snapshot["tasks"][0]["title"], "Operational task")

    def test_publish_endpoint_is_exactly_pinned(self) -> None:
        production = "https://cogni-os-orchestrator.pages.dev/api/ingest"
        self.assertEqual(validate_publish_endpoint(production), production)
        rejected = (
            "http://cogni-os-orchestrator.pages.dev/api/ingest",
            "https://cogni-os-orchestrator.pages.dev:444/api/ingest",
            "https://cogni-os-orchestrator.pages.dev/api/ingest?next=evil",
            "https://user@cogni-os-orchestrator.pages.dev/api/ingest",
            "https://cogni-os-orchestrator.pages.dev.evil/api/ingest",
            "https://cogni-os-orchestrator.pages.dev/api/ingest/",
        )
        for endpoint in rejected:
            with self.subTest(endpoint=endpoint), self.assertRaises(RuntimeError):
                validate_publish_endpoint(endpoint)

    def test_custom_publish_host_requires_explicit_allowlist(self) -> None:
        endpoint = "https://monitor.example.invalid/api/ingest"
        with self.assertRaises(RuntimeError):
            validate_publish_endpoint(endpoint)
        self.assertEqual(
            validate_publish_endpoint(
                endpoint,
                allowed_hosts={"monitor.example.invalid"},
            ),
            endpoint,
        )

    @patch("scripts.publish_monitor_snapshot.socket.gethostname")
    def test_collector_host_is_pseudonymous(self, hostname) -> None:
        hostname.return_value = "sensitive-hostname"
        self.assertEqual(collector_host_id("workspace"), "host-redacted")
        value = collector_host_id("workspace", b"x" * 32)
        self.assertRegex(value, r"^host-[0-9a-f]{16}$")
        self.assertNotIn("sensitive-hostname", value)

    def test_unsubstantiated_verified_task_is_disputed(self) -> None:
        task = {
            "state": "verified",
            "verification": {
                "decision": "accept",
                "independence": {"independent": True},
            },
        }
        self.assertEqual(task_trust_state(task), "verification_disputed")

    def test_verified_requires_independence_evidence_hash_and_trusted_run(self) -> None:
        install_direct_isolation_fixture(self)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = Workspace.initialize(
                root,
                name="Publisher trust fixture",
                orchestrator="codex",
                preset="cogni-codex-antigravity",
            )
            helper = root / "trusted_validation_helper.py"
            helper.write_text(
                "import sys\nsys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "core.autocrlf", "false"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "tests@cogni.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Cogni Tests"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "add", "-f", helper.name],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "publisher trust fixture"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            workspace.add_task(
                actor="codex",
                task_id="T-1",
                title="Verify publisher trust",
                description="Exercise the signed trusted-runner path.",
                owner="antigravity",
            )
            claimed = workspace.claim(actor="antigravity", task_id="T-1")
            token = claimed["lease_token"]
            workspace.start(actor="antigravity", task_id="T-1", lease_token=token)

            worker_dir = workspace.reports_dir / "antigravity"
            worker_dir.mkdir(parents=True, exist_ok=True)
            report = worker_dir / "T-1.md"
            report.write_text(
                "## 1. Overview\nDone\n## 2. Approach\nReproduced\n"
                "## 3. Evidence\nRetained\n## 4. Risks\nBounded\n"
                "## 5. Security\nChecked\n## 6. Conclusion\nReady\n",
                encoding="utf-8",
            )
            worker_output = worker_dir / "worker.log"
            worker_output.write_bytes(b"worker pass\n")
            worker_manifest = worker_dir / "T-1.evidence.json"
            worker_manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "artifacts": [],
                        "validations": [
                            {
                                "command": "worker-check",
                                "exit_code": 0,
                                "passed": 1,
                                "failed": 0,
                                "skipped": 0,
                                "raw_output_path": worker_output.name,
                                "raw_output_sha256": hashlib.sha256(
                                    worker_output.read_bytes()
                                ).hexdigest(),
                            }
                        ],
                        "known_answer_checks": [
                            {
                                "name": "worker-known-answer",
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
            workspace.submit(
                actor="antigravity",
                task_id="T-1",
                lease_token=token,
                report_path=report,
                evidence_path=worker_manifest,
            )

            verifier_dir = workspace.reports_dir / "codex"
            verifier_output = verifier_dir / "verifier.log"
            verifier_output.write_bytes(b"independent pass\n")
            verifier_manifest = verifier_dir / "T-1.verifier.evidence.json"
            verifier_manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "artifacts": [],
                        "validations": [
                            {
                                "command": "trusted independent check",
                                "command_argv": [
                                    sys.executable,
                                    str(helper),
                                    verifier_output.read_bytes().hex(),
                                ],
                                "exit_code": 0,
                                "passed": 1,
                                "failed": 0,
                                "skipped": 0,
                                "raw_output_path": verifier_output.name,
                                "raw_output_sha256": hashlib.sha256(
                                    verifier_output.read_bytes()
                                ).hexdigest(),
                            }
                        ],
                        "known_answer_checks": [
                            {
                                "name": "independent-known-answer",
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
            task = workspace.verify(
                actor="codex",
                task_id="T-1",
                decision="accept",
                note="Trusted runner reproduced the result.",
                evidence_path=verifier_manifest,
            )
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(
                task_trust_state(
                    task,
                    current_commit=commit,
                    workspace_root=root,
                ),
                "verified",
            )

    def test_export_never_invents_running_progress(self) -> None:
        exported = export_tasks(
            [
                {
                    "id": "T-1",
                    "title": "Test",
                    "owner": "worker",
                    "state": "running",
                    "updated_at": "2026-07-30T00:00:00Z",
                    "attempt": 1,
                }
            ]
        )
        self.assertIsNone(exported[0]["progress"])

    def test_agent_ready_requires_fresh_file_backed_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            agents_dir = root / "agents"
            evidence_path = root / "reports" / "runtime.json"
            agents_dir.mkdir()
            evidence_path.parent.mkdir()
            evidence_path.write_text('{"ready":true}\n', encoding="utf-8")
            evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            (agents_dir / "worker.json").write_text(
                json.dumps(
                    {
                        "id": "worker",
                        "role": "executant",
                        "mode": "command",
                        "command": ["python", "-m", "worker"],
                        "runtime_attestation": {
                            "ready": True,
                            "observed_at": observed_at,
                            "source_commit": "abcdef0",
                            "evidence_path": "reports/runtime.json",
                            "evidence_sha256": evidence_sha256,
                        },
                    }
                ),
                encoding="utf-8",
            )
            workspace = SimpleNamespace(root=root, agents_dir=agents_dir)
            exported = export_agents(workspace, [], "abcdef0")
            self.assertEqual(exported[0]["status"], "READY")
            self.assertEqual(
                exported[0]["attestation_evidence_sha256"],
                evidence_sha256,
            )

            evidence_path.write_text('{"ready":false}\n', encoding="utf-8")
            exported = export_agents(workspace, [], "abcdef0")
            self.assertEqual(exported[0]["status"], "CONFIGURED")
            self.assertIsNone(exported[0]["attestation_evidence_sha256"])

    def test_publisher_release_gate_ignores_retired_tracked_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = Workspace.initialize(
                root, name="Release gate test", preset=None
            )
            contract_path = root / "release" / "RELEASE_GATE.json"
            contract_path.parent.mkdir()
            contract_path.write_text(
                json.dumps({"status": "PASS", "evidence_sha256": "a" * 64}),
                encoding="utf-8",
            )
            gate = release_gate(
                workspace,
                "a" * 40,
                [],
                {"valid": True, "signed": True, "head": "b" * 64},
                {"clean": True, "fingerprint": "c" * 64},
                {"valid": True},
                [],
                collector_commit="a" * 40,
                collector_tree={"clean": True},
                operational_state={"valid": True},
            )
            self.assertEqual(gate["status"], "NO_GO")
            self.assertIsNone(gate["evidence_sha256"])
            self.assertTrue(
                any("immutable release gate" in reason for reason in gate["reasons"])
            )

    def test_release_gate_rejects_collector_commit_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Workspace.initialize(
                Path(temporary), name="Collector mismatch", preset=None
            )
            gate = release_gate(
                workspace,
                "a" * 40,
                [],
                {"valid": True, "signed": True, "head": "a" * 64},
                {"clean": True, "fingerprint": "b" * 64},
                {"valid": True},
                [],
                collector_commit="b" * 40,
                collector_tree={"clean": True},
                operational_state={"valid": True},
            )
            self.assertEqual(gate["status"], "NO_GO")
            self.assertTrue(
                any("커밋이 다릅니다" in reason for reason in gate["reasons"])
            )

    def test_signature_protocol_is_stable(self) -> None:
        message = signature_message(
            key_id="publisher-2026-07",
            workspace_id="workspace",
            sequence=7,
            observed_at="2026-07-30T00:00:00Z",
            nonce="nonce_1234567890",
            body_sha256="a" * 64,
        )
        self.assertEqual(
            message.decode("utf-8"),
            "COGNI-SNAPSHOT-V2\npublisher-2026-07\nworkspace\n7\n"
            "2026-07-30T00:00:00Z\n"
            "nonce_1234567890\n" + "a" * 64,
        )

    def test_signature_matches_cloudflare_verifier_contract(self) -> None:
        message = signature_message(
            key_id="publisher-2026-07",
            workspace_id="workspace",
            sequence=7,
            observed_at="2026-07-30T00:00:00Z",
            nonce="nonce_1234567890abcdef",
            body_sha256="a" * 64,
        )
        self.assertEqual(
            hmac_signature(
                "0123456789abcdef0123456789abcdef",
                message,
            ),
            "e7e822dba04efc22745208c1a162c06ea712d4d2024427879d70c8e1801a478e",
        )

    @patch("scripts.publish_monitor_snapshot._run_capped_command")
    def test_gpu_collector_never_queries_denied_devices(self, run) -> None:
        wrapper_source = (ROOT / "scripts" / "run_monitor_publisher.ps1").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("-Name 'docker'", wrapper_source)
        self.assertNotIn(
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            wrapper_source,
        )
        self.assertIn("-Name 'nvidia-smi'", wrapper_source)
        self.assertIn(r"C:\Windows\System32\nvidia-smi.exe", wrapper_source)

        def command(arguments, **kwargs):
            if arguments[0] == "nvidia-smi":
                requested = int(
                    next(value for value in arguments if value.startswith("--id="))[5:]
                )
                self.assertIn(requested, range(6))
                if any(value.startswith("--query-gpu=") for value in arguments):
                    return SimpleNamespace(
                        stdout=(
                            f"{requested}, GPU-uuid{requested}, NVIDIA RTX A6000, "
                            "0, 19, 49152, 33, 20\n"
                        )
                    )
                return SimpleNamespace(stdout="")
            self.fail(f"unexpected command: {arguments}")
        run.side_effect = command
        with tempfile.TemporaryDirectory() as directory:
            environment = self._gpu_boundary_environment(
                Path(directory), violating_ids=[6]
            )
            with patch.dict(
                "scripts.publish_monitor_snapshot.os.environ",
                environment,
                clear=True,
            ):
                gpus, state, violations, evidence = collect_gpus(
                    True, workspace_id="workspace-test"
                )
        self.assertEqual(state, "POLICY_VIOLATION")
        self.assertEqual([gpu["id"] for gpu in gpus], list(range(6)))
        self.assertEqual(violations, [6])
        self.assertTrue(evidence["measurement_complete"])
        self.assertEqual(evidence["boundary_attestation"]["state"], "VERIFIED")
        for call in run.call_args_list:
            arguments = call.args[0]
            self.assertEqual(arguments[0], "nvidia-smi")
            self.assertTrue(any(value.startswith("--id=") for value in arguments))
            self.assertFalse(any(value in {"--id=6", "--id=7"} for value in arguments))

    @patch("scripts.publish_monitor_snapshot._run_capped_command")
    def test_gpu_collector_detects_docker_device_request(self, run) -> None:
        """A Docker claim is accepted only from signed boundary evidence."""

        def command(arguments, **kwargs):
            if arguments[0] == "nvidia-smi":
                requested = int(
                    next(value for value in arguments if value.startswith("--id="))[5:]
                )
                self.assertIn(requested, range(6))
                if any(value.startswith("--query-gpu=") for value in arguments):
                    return SimpleNamespace(
                        stdout=(
                            f"{requested}, GPU-uuid{requested}, NVIDIA RTX A6000, "
                            "0, 19, 49152, 33, 20\n"
                        )
                    )
                return SimpleNamespace(stdout="")
            self.fail(f"unexpected command: {arguments}")

        run.side_effect = command
        with tempfile.TemporaryDirectory() as directory:
            environment = self._gpu_boundary_environment(
                Path(directory),
                violating_ids=[6, 7],
                container_claims=1,
                scheduler_reservations=2,
            )
            with patch.dict(
                "scripts.publish_monitor_snapshot.os.environ",
                environment,
                clear=True,
            ):
                _, state, violations, evidence = collect_gpus(
                    True, workspace_id="workspace-test"
                )
        self.assertEqual(state, "POLICY_VIOLATION")
        self.assertEqual(violations, [6, 7])
        self.assertTrue(evidence["measurement_complete"])
        self.assertEqual(evidence["evidence_counts"]["container_claims"], 1)
        self.assertEqual(
            evidence["evidence_counts"]["scheduler_reservations"], 2
        )
        self.assertEqual(
            {call.args[0][0] for call in run.call_args_list}, {"nvidia-smi"}
        )

    @patch("scripts.publish_monitor_snapshot._run_capped_command")
    def test_gpu_collector_without_external_boundary_is_fail_closed(self, run) -> None:
        def command(arguments, **kwargs):
            if arguments[0] == "nvidia-smi":
                requested = int(
                    next(value for value in arguments if value.startswith("--id="))[5:]
                )
                if any(value.startswith("--query-gpu=") for value in arguments):
                    return SimpleNamespace(
                        stdout=(
                            f"{requested}, GPU-uuid{requested}, NVIDIA RTX A6000, "
                            "0, 19, 49152, 33, 20\n"
                        )
                    )
                return SimpleNamespace(stdout="")
            self.fail(f"unexpected command: {arguments}")

        run.side_effect = command
        with patch.dict("scripts.publish_monitor_snapshot.os.environ", {}, clear=True):
            _, state, violations, evidence = collect_gpus(
                True, workspace_id="workspace-test"
            )
        self.assertEqual(state, "UNMEASURED")
        self.assertEqual(violations, [])
        self.assertFalse(evidence["measurement_complete"])
        self.assertEqual(evidence["source_states"]["boundary"], "UNAVAILABLE")
        self.assertEqual(evidence["source_states"]["containers"], "UNAVAILABLE")
        self.assertEqual(evidence["source_states"]["scheduler"], "UNAVAILABLE")
        self.assertEqual(
            {call.args[0][0] for call in run.call_args_list}, {"nvidia-smi"}
        )

        # A signed but incomplete authority report cannot close the boundary.
        with tempfile.TemporaryDirectory() as directory:
            environment = self._gpu_boundary_environment(
                Path(directory), inventory_complete=False
            )
            with patch.dict(
                "scripts.publish_monitor_snapshot.os.environ",
                environment,
                clear=True,
            ):
                _, state, violations, evidence = collect_gpus(
                    True, workspace_id="workspace-test"
                )
            workspace = Workspace.initialize(
                Path(directory) / "gate", name="GPU boundary gate", preset=None
            )
            gate = release_gate(
                workspace,
                "a" * 40,
                [],
                {"valid": True, "signed": True},
                {"clean": True},
                {"valid": True},
                violations,
                gpu_telemetry_state=state,
                gpu_measurement=evidence,
                release_deployment={},
                collector_commit="a" * 40,
                collector_tree={"clean": True},
                operational_state={"valid": True},
            )
        self.assertEqual(state, "UNMEASURED")
        self.assertEqual(violations, [])
        self.assertFalse(evidence["measurement_complete"])
        self.assertEqual(evidence["boundary_attestation"]["state"], "INVALID")
        self.assertEqual(evidence["source_states"]["containers"], "UNAVAILABLE")
        self.assertEqual(evidence["source_states"]["scheduler"], "UNAVAILABLE")
        self.assertEqual(gate["status"], "NO_GO")
        self.assertTrue(any("GPU" in reason for reason in gate["reasons"]))
        self.assertEqual(
            {call.args[0][0] for call in run.call_args_list}, {"nvidia-smi"}
        )

    def test_disabled_gpu_collection_is_unmeasured_and_never_complete(self) -> None:
        gpus, state, violations, evidence = collect_gpus(False)
        self.assertEqual(gpus, [])
        self.assertEqual(state, "UNMEASURED")
        self.assertEqual(violations, [])
        self.assertFalse(evidence["measurement_complete"])
        self.assertEqual(
            set(evidence["source_states"].values()),
            {"DISABLED"},
        )


if __name__ == "__main__":
    unittest.main()
