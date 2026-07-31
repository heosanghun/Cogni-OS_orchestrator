from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.publish_monitor_snapshot import (  # noqa: E402
    build_snapshot,
    collector_host_id,
    collect_gpus,
    export_agents,
    export_tasks,
    hmac_signature,
    next_sequence,
    peek_next_sequence,
    release_gate,
    signature_message,
    task_trust_state,
    validate_publish_endpoint,
)
from cogni_os.workspace import Workspace  # noqa: E402


class MonitorPublisherTests(unittest.TestCase):
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
            all(
                phase["state"] == "missing"
                for phase in snapshot["roadmap"]["phases"]
            )
        )

    def test_publish_endpoint_is_exactly_pinned(self) -> None:
        production = (
            "https://cogni-os-orchestrator.pages.dev/api/ingest"
        )
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
        value = collector_host_id("workspace")
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
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "submissions" / "T-1"
            archive.mkdir(parents=True)
            manifest_path = archive / "manifest.json"
            receipt_path = archive / "receipt.json"
            output_path = archive / "validation.log"
            manifest_path.write_text('{"schema_version":1}\n', encoding="utf-8")
            receipt_path.write_text('{"passed":true}\n', encoding="utf-8")
            output_path.write_text("1 passed\n", encoding="utf-8")
            manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            receipt_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            output_sha = hashlib.sha256(output_path.read_bytes()).hexdigest()
            commit = "d" * 40
            task = {
                "id": "T-1",
                "attempt": 1,
                "state": "verified",
                "permissions": {"gpu": False, "network": False},
                "verification": {
                    "verified_by": "codex",
                    "independence": {"independent": True},
                    "verifier_evidence": {
                        "manifest_sha256": manifest_sha,
                        "bundle": {
                            "task_id": "T-1",
                            "attempt": 1,
                            "label": "verifier",
                            "manifest_sha256": "a" * 64,
                            "files": [
                                {
                                    "kind": "manifest",
                                    "retained": True,
                                    "archive_path": str(manifest_path),
                                    "sha256": manifest_sha,
                                },
                                {
                                    "kind": "trusted_runner_receipt",
                                    "retained": True,
                                    "archive_path": str(receipt_path),
                                    "sha256": receipt_sha,
                                },
                                {
                                    "kind": "trusted_runner_output",
                                    "retained": True,
                                    "archive_path": str(output_path),
                                    "sha256": output_sha,
                                },
                            ],
                        },
                    },
                    "trusted_validation": {
                        "runner": "cogni-os-trusted-runner-v1",
                        "task_id": "T-1",
                        "attempt": 1,
                        "actor": "codex",
                        "source_commit": commit,
                        "source_clean": True,
                        "source_postcheck_passed": True,
                        "source_postcheck_error": None,
                        "operational_change_count": 1,
                        "operational_paths_sha256": "b" * 64,
                        "environment_sha256": "c" * 64,
                        "gpu_allowed": False,
                        "cuda_visible_devices": "",
                        "network_allowed": False,
                        "max_output_bytes": 4 * 1024 * 1024,
                        "passed": True,
                        "failure": None,
                        "receipt_sha256": receipt_sha,
                        "validations": [
                            {
                                "command_argv": ["python", "-m", "unittest"],
                                "command_policy": {
                                    "kind": "python",
                                    "executable_path": "python",
                                    "executable_sha256": "e" * 64,
                                    "executable_binding": "current-python-runtime",
                                    "executed_argv": [
                                        "python",
                                        "-m",
                                        "unittest",
                                    ],
                                },
                                "executed_argv": [
                                    "python",
                                    "-m",
                                    "unittest",
                                ],
                                "executable_sha256_after": "e" * 64,
                                "exit_code": 0,
                                "timed_out": False,
                                "output_truncated": False,
                                "output_sha256": output_sha,
                                "output_size_bytes": output_path.stat().st_size,
                            }
                        ],
                    },
                },
            }
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
            observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
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

    def test_release_gate_rehashes_evidence_and_binds_attested_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence_path = root / "reports" / "release.evidence.json"
            contract_path = root / "release" / "RELEASE_GATE.json"
            evidence_path.parent.mkdir()
            contract_path.parent.mkdir()
            evidence_path.write_text('{"tests":"pass"}\n', encoding="utf-8")
            evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            ledger_head = "a" * 64
            tree_fingerprint = "b" * 64
            contract_path.write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "source_commit": "abcdef0",
                        "evidence_path": "reports/release.evidence.json",
                        "evidence_sha256": evidence_sha256,
                        "ledger_head": ledger_head,
                        "source_tree_sha256": tree_fingerprint,
                        "trusted_verified_task_ids": ["T-1"],
                    }
                ),
                encoding="utf-8",
            )
            gate = release_gate(
                root,
                "abcdef0",
                [{"id": "T-1", "state": "verified"}],
                [
                    {
                        "status": "READY",
                        "attestation_evidence_sha256": evidence_sha256,
                        "attested_source_commit": "abcdef0",
                    }
                ],
                {
                    "valid": True,
                    "signed": True,
                    "head": ledger_head,
                },
                {"clean": True, "fingerprint": tree_fingerprint},
                {"valid": True},
                [],
            )
            self.assertEqual(gate["status"], "PASS")

            evidence_path.write_text('{"tests":"tampered"}\n', encoding="utf-8")
            gate = release_gate(
                root,
                "abcdef0",
                [{"id": "T-1", "state": "verified"}],
                [
                    {
                        "status": "READY",
                        "attestation_evidence_sha256": evidence_sha256,
                        "attested_source_commit": "abcdef0",
                    }
                ],
                {
                    "valid": True,
                    "signed": True,
                    "head": ledger_head,
                },
                {"clean": True, "fingerprint": tree_fingerprint},
                {"valid": True},
                [],
            )
            self.assertEqual(gate["status"], "NO_GO")
            self.assertTrue(any("SHA-256" in reason for reason in gate["reasons"]))

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

    @patch("scripts.publish_monitor_snapshot.subprocess.run")
    def test_gpu_collector_filters_gpu_6_and_7(self, run) -> None:
        run.return_value = SimpleNamespace(
            stdout=(
                "0, GPU-uuid0, NVIDIA RTX A6000, 10, 1024, 49152, 40, 30\n"
                "5, GPU-uuid5, NVIDIA RTX A6000, 20, 2048, 49152, 42, 35\n"
                "6, GPU-uuid6, NVIDIA RTX A6000, 99, 40000, 49152, 80, 200\n"
                "7, GPU-uuid7, NVIDIA RTX A6000, 99, 40000, 49152, 80, 200\n"
            )
        )
        with patch.dict(
            "scripts.publish_monitor_snapshot.os.environ",
            {},
            clear=True,
        ):
            gpus, state, violations = collect_gpus(True)
        self.assertEqual(state, "POLICY_VIOLATION")
        self.assertEqual([gpu["id"] for gpu in gpus], [0, 5])
        self.assertEqual(violations, [6, 7])


if __name__ == "__main__":
    unittest.main()
