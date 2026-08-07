from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cogni_os.ledger import Ledger

ROOT = Path(__file__).resolve().parents[3]
VALIDATOR_PATH = ROOT / "scripts" / "validate_p01_python.py"
SPEC = importlib.util.spec_from_file_location("_p01_validator", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - repository invariant
    raise RuntimeError("Phase 1 validator could not be loaded")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


class PhaseOneValidatorTests(unittest.TestCase):
    commit = "a" * 40
    rollback_commit = "b" * 40
    workspace_id = "5988e0651ec1afcdeb87b58ccc8d68ea"
    account_id = "1" * 32
    current_deployment_id = "deployment-current"
    rollback_deployment_id = "deployment-previous"
    observed_at = "2026-08-01T00:00:00Z"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ledger = Ledger(
            self.root / "ledger" / "events.jsonl",
            self.root / ".cogni" / "locks" / "ledger.lock",
            self.root / ".cogni" / "ledger.key",
        )
        self.ledger.initialize()
        self.baseline = self.ledger.append(
            actor="codex",
            action="workspace.initialized",
            task_id=None,
            payload={"schema_version": 1},
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _build_deployment(commit: str) -> dict[str, Any]:
        return {
            "provider": "cloudflare-pages",
            "project": "cogni-os-orchestrator",
            "environment": "production",
            "source_commit": commit,
            "branch": "main",
            "url": "https://cogni-os-orchestrator.pages.dev",
            "deployment_url": (
                "https://deployment-current.cogni-os-orchestrator.pages.dev"
            ),
            "attribution": "BUILD_BOUND",
        }

    def _cloudflare(
        self,
        *,
        deployment_id: str,
        commit: str,
        created_on: str,
    ) -> dict[str, Any]:
        canonical_deployment_id = self.current_deployment_id
        canonical_commit = self.commit
        canonical_url = (
            f"https://{canonical_deployment_id}.cogni-os-orchestrator.pages.dev"
        )
        deployment_result = {
            "project_name": "cogni-os-orchestrator",
            "id": deployment_id,
            "short_id": deployment_id[-8:],
            "environment": "production",
            "url": f"https://{deployment_id}.cogni-os-orchestrator.pages.dev",
            "created_on": created_on,
            "modified_on": created_on,
            "is_skipped": False,
            "deployment_trigger": {
                "type": "github:push",
                "metadata": {
                    "branch": "main",
                    "commit_dirty": False,
                    "commit_hash": commit,
                },
            },
            "latest_stage": {
                "name": "deploy",
                "status": "success",
                "started_on": created_on,
                "ended_on": created_on,
            },
        }
        canonical = {
            "id": canonical_deployment_id,
            "environment": "production",
            "url": canonical_url,
            "is_skipped": False,
            "deployment_trigger": {
                "metadata": {
                    "branch": "main",
                    "commit_dirty": False,
                    "commit_hash": canonical_commit,
                }
            },
            "latest_stage": {
                "name": "deploy",
                "status": "success",
                "started_on": self.observed_at,
                "ended_on": self.observed_at,
            },
        }
        project_result = {
            "name": "cogni-os-orchestrator",
            "subdomain": "cogni-os-orchestrator.pages.dev",
            "canonical_deployment": canonical,
        }
        deployment_endpoint = (
            "https://api.cloudflare.com/client/v4/accounts/"
            f"{self.account_id}/pages/projects/cogni-os-orchestrator/deployments/"
            f"{deployment_id}"
        )
        project_endpoint = (
            "https://api.cloudflare.com/client/v4/accounts/"
            f"{self.account_id}/pages/projects/cogni-os-orchestrator"
        )
        deployment_body = _json_bytes(
            {"success": True, "result": deployment_result}
        )
        project_body = _json_bytes({"success": True, "result": project_result})

        def raw_capture(endpoint: str, resource: str, body: bytes) -> dict[str, Any]:
            return {
                "schema_version": 1,
                "document_type": "cogni-cloudflare-http-capture",
                "method": "GET",
                "resource": resource,
                "request_url": endpoint,
                "final_url": endpoint,
                "status": 200,
                "fetched_at": self.observed_at,
                "tls_verified": True,
                "tls_policy": "python-default-ca",
                "headers": {"content-type": "application/json"},
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_size_bytes": len(body),
            }

        deployment_capture = raw_capture(
            deployment_endpoint, "pages-deployment", deployment_body
        )
        project_capture = raw_capture(project_endpoint, "pages-project", project_body)
        evidence = {
            "schema_version": 1,
            "document_type": "cloudflare-pages-deployment-evidence",
            "attestation_level": "CLOUDFLARE_API_VERIFIED",
            "provider": "cloudflare-pages",
            "account_id": self.account_id,
            "project_name": "cogni-os-orchestrator",
            "deployment_id": deployment_id,
            "short_id": deployment_id[-8:],
            "environment": "production",
            "url": f"https://{deployment_id}.cogni-os-orchestrator.pages.dev",
            "created_on": created_on,
            "modified_on": created_on,
            "is_skipped": False,
            "source_commit": commit,
            "trigger": {
                "type": "github:push",
                "branch": "main",
                "commit_dirty": False,
            },
            "latest_stage": {
                "name": "deploy",
                "status": "success",
                "started_on": created_on,
                "ended_on": created_on,
            },
            "api_request": deployment_capture,
            "production_alias": {
                "api_verified": True,
                "canonical_url": "https://cogni-os-orchestrator.pages.dev",
                "deployment_id": canonical_deployment_id,
                "deployment_url": canonical_url,
                "source_commit": canonical_commit,
                "api_request": project_capture,
            },
        }
        return {
            "evidence": evidence,
            "deployment_body": deployment_body,
            "deployment_capture": deployment_capture,
            "project_body": project_body,
            "project_capture": project_capture,
        }

    def _snapshot(self, *, task_attempt: int = 1) -> dict[str, Any]:
        tasks = [
            {
                "id": "T-001",
                "title": "Historical truth task",
                "owner": "antigravity",
                "state": "verification_disputed",
                "raw_state": "verified",
                "historical_state": "verification_disputed",
                "historical_trusted": False,
                "verified_source_commit": None,
                "current_release_state": "verification_disputed",
                "current_release_validated": False,
                "progress": None,
                "next_step": "신뢰 실행기로 재검증",
                "updated_at": self.observed_at,
                "attempt": 1,
            }
        ]
        for index, phase_id in enumerate(VALIDATOR.PHASE_IDS):
            state = "submitted" if index == 0 else "pending"
            tasks.append(
                {
                    "id": phase_id,
                    "title": f"Phase {index + 1}",
                    "owner": "antigravity",
                    "state": state,
                    "raw_state": state,
                    "historical_state": state,
                    "historical_trusted": False,
                    "verified_source_commit": None,
                    "current_release_state": state,
                    "current_release_validated": False,
                    "progress": None,
                    "next_step": "독립 검증 대기" if index == 0 else "작업 선점 대기",
                    "updated_at": self.observed_at,
                    "attempt": task_attempt if index == 0 else 0,
                }
            )
        phases = [
            {
                "id": phase_id,
                "title": f"Phase {index + 1}",
                "state": "submitted" if index == 0 else "pending",
                "trusted_complete": False,
                "verified_source_commit": None,
                "current_release_state": "submitted" if index == 0 else "pending",
                "current_release_validated": False,
                "prerequisites": [] if index == 0 else [VALIDATOR.PHASE_IDS[index - 1]],
            }
            for index, phase_id in enumerate(VALIDATOR.PHASE_IDS)
        ]
        deployment = self._build_deployment(self.commit)
        return {
            "schema_version": "1.2",
            "system": "Cogni-OS Operations",
            "workspace_id": self.workspace_id,
            "workspace_name": "Phase 1 fixture",
            "sequence": 73,
            "observed_at": self.observed_at,
            "collector": {
                "id": "cogni-monitor-publisher",
                "version": "2.1.0",
                "host": "host-aabbccdd",
                "platform": "Windows",
                "attribution": {
                    "source_commit": self.commit,
                    "source_tree_clean": True,
                    "source_tree_fingerprint": "d" * 64,
                    "entrypoint_sha256": "e" * 64,
                },
            },
            "data_classification": "operational-metadata-only",
            "orchestrator": {
                "id": "codex",
                "role": "conductor",
                "status": "ACCOUNTABLE_NOT_ATTESTED",
            },
            "tasks_summary": {
                "total": len(tasks),
                "pending": 10,
                "claimed": 0,
                "running": 0,
                "blocked": 0,
                "submitted": 1,
                "trusted_verified": 0,
                "verification_disputed": 1,
                "verification_revoked": 0,
                "rejected": 0,
                "current_release_validated": 0,
                "completion_percentage": 0.0,
                "progress_basis": "historically-trusted-ledger-task-states",
            },
            "roadmap": {
                "schema_version": 1,
                "total": 11,
                "trusted_complete": 0,
                "current_release_validated": 0,
                "progress_percent": 0.0,
                "progress_basis": "historically-trusted-roadmap-task-states",
                "phases": phases,
            },
            "agents": [],
            "tasks": tasks,
            "ledger_events": [],
            "ledger": {
                "status": "VERIFIED",
                "valid": True,
                "events": 1,
                "head": self.baseline["event_hash"],
                "signed": True,
            },
            "gpus": [],
            "gpu_policy": {
                "allowed_ids": [0, 1, 2, 3, 4, 5],
                "denied_ids": [6, 7],
                "telemetry_state": "MEASURED",
                "violating_ids": [],
                "measurement_complete": True,
                "source_states": {
                    "telemetry": "MEASURED",
                    "processes": "MEASURED",
                    "containers": "MEASURED",
                    "scheduler": "MEASURED",
                },
                "evidence_counts": {
                    "processes": 0,
                    "container_claims": 0,
                    "scheduler_reservations": 0,
                },
            },
            "resources": {},
            "alerts": [
                {
                    "severity": "critical",
                    "code": "UNTRUSTED_VERIFICATION",
                    "message": "T-001 remains disputed",
                    "observed_at": self.observed_at,
                }
            ],
            "release_gate": {
                "status": "NO_GO",
                "reasons": ["Phase 1 is submitted, not independently verified"],
                "evidence_sha256": None,
            },
            "source": {
                "git_commit": self.commit,
                "status_scope": "trusted-source-v1",
                "tree_clean": True,
                "tree_fingerprint": "f" * 64,
                "change_count": 0,
                "operational_state": {
                    "valid": True,
                    "change_count": 8,
                    "fingerprint": "1" * 64,
                    "unclassified_count": 0,
                    "unclassified_fingerprint": "2" * 64,
                    "reference_count": 3,
                    "conflict_count": 0,
                    "missing_count": 0,
                    "unbound_count": 0,
                    "hash_mismatch_count": 0,
                    "audit_fingerprint": "3" * 64,
                },
                "task_projection_audit": {
                    "valid": True,
                    "events_count": 1,
                    "projected_count": len(tasks),
                    "actual_count": len(tasks),
                    "mismatch_count": 0,
                },
            },
            "timestamp": self.observed_at,
            "monitoring": {
                "state": "LIVE",
                "reason": "서명 검증된 최신 운영 스냅샷",
                "signature_verified": True,
                "payload_signature_verified": True,
                "fresh": True,
                "current_source_commit_bound": True,
                "deployment_verified": True,
                "sequence": 73,
                "age_seconds": 0.4,
                "observed_at": self.observed_at,
                "received_at": self.observed_at,
                "body_sha256": "4" * 64,
                "max_age_seconds": 180,
            },
            "deployment": deployment,
            "release_deployment": {
                "provider": "cloudflare-pages",
                "api_verified": True,
                "deployment_id": self.current_deployment_id,
                "deployment_url": deployment["deployment_url"],
                "canonical_url": "https://cogni-os-orchestrator.pages.dev",
                "source_commit": self.commit,
            },
        }

    def _capture(self, endpoint: str, filename: str, body: bytes) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "document_type": "cogni-production-http-capture",
            "method": "GET",
            "request_url": endpoint,
            "final_url": endpoint,
            "status": 200,
            "fetched_at": self.observed_at,
            "tls_verified": True,
            "tls_policy": "python-default-ca",
            "headers": {
                "content-type": "application/json; charset=utf-8",
                "content-length": str(len(body)),
            },
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_size_bytes": len(body),
            "body_file": filename,
        }

    def _fixture(
        self,
        mutate_documents: Callable[[dict[str, dict[str, Any]]], None] | None = None,
        *,
        task_attempt: int = 1,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        deployment = self._build_deployment(self.commit)
        health = {
            "ok": True,
            "service": "cogni-os-monitoring",
            "state": "CONFIGURED",
            "checks": {
                "runtime_configuration_ready": True,
                "d1_binding": True,
                "storage_state": "READY",
                "storage_schema_verified": True,
                "workspace_id": True,
                "publisher_keyring": True,
                "publisher_keys": 1,
                "deployment_attribution": "BUILD_BOUND",
                "build_attribution_ready": True,
                "operational_ingest_ready": True,
                "release_attribution_ready": False,
                "release_evidence_state": "API_EVIDENCE_REQUIRED",
                "minimum_release_snapshot_schema": "1.2",
            },
            "deployment": deployment,
            "timestamp": self.observed_at,
        }
        snapshot = self._snapshot(task_attempt=task_attempt)
        health_body = _json_bytes(health)
        snapshot_body = _json_bytes(snapshot)
        current_cloudflare = self._cloudflare(
            deployment_id=self.current_deployment_id,
            commit=self.commit,
            created_on="2026-08-01T00:00:00Z",
        )
        rollback_cloudflare = self._cloudflare(
            deployment_id=self.rollback_deployment_id,
            commit=self.rollback_commit,
            created_on="2026-07-31T00:00:00Z",
        )
        documents = {
            "health": health,
            "snapshot": snapshot,
            "health_capture": self._capture(
                VALIDATOR.PRODUCTION_ENDPOINTS["health"],
                VALIDATOR.ARTIFACT_FILES["production-health-body"],
                health_body,
            ),
            "snapshot_capture": self._capture(
                VALIDATOR.PRODUCTION_ENDPOINTS["snapshot"],
                VALIDATOR.ARTIFACT_FILES["production-snapshot-body"],
                snapshot_body,
            ),
            "current": current_cloudflare["evidence"],
            "rollback": rollback_cloudflare["evidence"],
            "current_cloudflare": current_cloudflare,
            "rollback_cloudflare": rollback_cloudflare,
        }
        documents["receipt"] = {
            "schema_version": 1,
            "document_type": "cloudflare-pages-rollback-dry-run-receipt",
            "attestation_level": "CLOUDFLARE_API_VERIFIED",
            "validated_at": self.observed_at,
            "validated_by": "codex",
            "provider": "cloudflare-pages",
            "project_name": "cogni-os-orchestrator",
            "account_id": self.account_id,
            "operation": "rollback-plan-validation",
            "mutation_performed": False,
            "current_deployment_id": self.current_deployment_id,
            "current_source_commit": self.commit,
            "target_deployment_id": self.rollback_deployment_id,
            "target_source_commit": self.rollback_commit,
            "checks": {
                "current_deployment_api_verified": True,
                "target_deployment_api_verified": True,
                "target_is_prior_distinct_deployment": True,
                "target_is_successful_production": True,
                "commits_are_distinct": True,
            },
        }
        if mutate_documents is not None:
            mutate_documents(documents)
        # Re-encode after mutation and bind captures to exactly those body bytes.
        health_body = _json_bytes(documents["health"])
        snapshot_body = _json_bytes(documents["snapshot"])
        documents["health_capture"] = self._capture(
            VALIDATOR.PRODUCTION_ENDPOINTS["health"],
            VALIDATOR.ARTIFACT_FILES["production-health-body"],
            health_body,
        )
        documents["snapshot_capture"] = self._capture(
            VALIDATOR.PRODUCTION_ENDPOINTS["snapshot"],
            VALIDATOR.ARTIFACT_FILES["production-snapshot-body"],
            snapshot_body,
        )
        artifact_values = {
            "production-health-body": health_body,
            "production-health-capture": _json_bytes(documents["health_capture"]),
            "production-snapshot-body": snapshot_body,
            "production-snapshot-capture": _json_bytes(documents["snapshot_capture"]),
            "cloudflare-deployment-evidence": _json_bytes(documents["current"]),
            "cloudflare-current-deployment-body": documents[
                "current_cloudflare"
            ]["deployment_body"],
            "cloudflare-current-deployment-capture": _json_bytes(
                documents["current_cloudflare"]["deployment_capture"]
            ),
            "cloudflare-current-project-body": documents["current_cloudflare"][
                "project_body"
            ],
            "cloudflare-current-project-capture": _json_bytes(
                documents["current_cloudflare"]["project_capture"]
            ),
            "cloudflare-rollback-target-evidence": _json_bytes(documents["rollback"]),
            "cloudflare-rollback-deployment-body": documents[
                "rollback_cloudflare"
            ]["deployment_body"],
            "cloudflare-rollback-deployment-capture": _json_bytes(
                documents["rollback_cloudflare"]["deployment_capture"]
            ),
            "cloudflare-rollback-project-body": documents["rollback_cloudflare"][
                "project_body"
            ],
            "cloudflare-rollback-project-capture": _json_bytes(
                documents["rollback_cloudflare"]["project_capture"]
            ),
            "cloudflare-rollback-dry-run-receipt": _json_bytes(documents["receipt"]),
        }
        artifacts = [
            {
                "kind": kind,
                "filename": VALIDATOR.ARTIFACT_FILES[kind],
                "sha256": hashlib.sha256(value).hexdigest(),
                "size_bytes": len(value),
            }
            for kind, value in artifact_values.items()
        ]
        producer = {
            "schema_version": 1,
            "actor": "codex",
            "control_principal": "codex-conductor",
            "model_family": "openai-codex",
            "alias_of": None,
            "alias_chain": [],
            "role": "orchestrator",
        }
        actor_capability = {
            "schema_version": 2,
            "receipt_type": "actor-capability-consumption",
            "workspace_id": self.workspace_id,
            "actor": "codex",
            "operation": "release.evidence.collect",
            "task_id": "P01-TRUTH",
            "run_id": None,
            "task_attempt": task_attempt,
            "nonce_sha256": "9" * 64,
            "key_version": 1,
            "issued_at_epoch": 1,
            "expires_at_epoch": 3,
            "consumed_at_epoch": 1,
            "os_principal_attestation": {
                "schema_version": 1,
                "provider": "unit-test-external-broker",
                "principal_sha256": "8" * 64,
                "trust_root": "unit-test-independent-root",
                "independent_trust_root": True,
                "actor_os_isolation_proven": True,
            },
            "independent_trust_root": True,
            "actor_os_isolation_proven": True,
            "signature_algorithm": "unit-test-independent-signature",
            "signature": "unit-test-signature",
        }
        bundle = {
            "schema_version": 1,
            "kind": "production-release-evidence",
            "task_id": "P01-TRUTH",
            "task_attempt": task_attempt,
            "producer": producer,
            "actor_capability": actor_capability,
            "source_commit": self.commit,
            "collected_at": self.observed_at,
            "replay_results": [
                {
                    "endpoint": name,
                    "url": VALIDATOR.PRODUCTION_ENDPOINTS[name],
                    "status": documents[f"{name}_capture"]["status"],
                    "body_sha256": documents[f"{name}_capture"]["body_sha256"],
                    "body_size_bytes": documents[f"{name}_capture"]["body_size_bytes"],
                }
                for name in ("health", "snapshot")
            ],
            "deployment_attestation": "CLOUDFLARE_API_VERIFIED",
            "rollback_mutation_performed": False,
            "artifacts": artifacts,
        }
        bundle_bytes = _json_bytes(bundle)
        bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
        relative_directory = (
            f"archive/release-evidence/P01-TRUTH/attempt-{task_attempt}/{bundle_sha}"
        )
        directory = self.root / Path(relative_directory)
        directory.mkdir(parents=True)
        for kind, value in artifact_values.items():
            (directory / VALIDATOR.ARTIFACT_FILES[kind]).write_bytes(value)
        (directory / "bundle.json").write_bytes(bundle_bytes)
        payload = {
            "schema_version": 1,
            "producer": producer,
            "actor_capability": actor_capability,
            "source_commit": self.commit,
            "task_attempt": task_attempt,
            "collection": {
                "kind": "production-release-evidence",
                "bundle_path": f"{relative_directory}/bundle.json",
                "bundle_sha256": bundle_sha,
                "artifacts": [
                    {
                        "kind": artifact["kind"],
                        "archive_path": (
                            f"{relative_directory}/{artifact['filename']}"
                        ),
                        "sha256": artifact["sha256"],
                        "size_bytes": artifact["size_bytes"],
                    }
                    for artifact in artifacts
                ],
            },
        }
        event = self.ledger.append(
            actor="codex",
            action="release.evidence_collected",
            task_id="P01-TRUTH",
            payload=payload,
        )
        self.assertEqual(event["action"], "release.evidence_collected")
        self.assertTrue(self.ledger.verify()["signed"])
        return event, documents

    def _validate(self, event: dict[str, Any]) -> dict[str, Any]:
        events = self.ledger.read()
        selected = VALIDATOR._select_collection_event(
            events,
            sequence=event["sequence"],
            event_hash=event["event_hash"],
            orchestrator="codex",
            expected_commit=self.commit,
        )
        return VALIDATOR._validate_collection(
            self.root,
            selected,
            expected_commit=self.commit,
            workspace_id=self.workspace_id,
            events=events,
            task_attempt=selected["payload"]["task_attempt"],
        )

    def test_accepts_complete_signed_event_derived_bundle(self) -> None:
        event, _ = self._fixture()
        result = self._validate(event)
        self.assertEqual(
            result["bundle_sha256"], event["payload"]["collection"]["bundle_sha256"]
        )
        self.assertEqual(result["source_commit"], self.commit)

    def test_accepts_recovered_second_attempt_from_signed_event(self) -> None:
        event, _ = self._fixture(task_attempt=2)
        result = self._validate(event)
        self.assertEqual(event["payload"]["task_attempt"], 2)
        self.assertEqual(
            result["bundle_sha256"], event["payload"]["collection"]["bundle_sha256"]
        )

    def test_rejects_same_commit_different_production_alias(self) -> None:
        def replace_alias(documents: dict[str, dict[str, Any]]) -> None:
            alias = documents["current"]["production_alias"]
            alias["deployment_id"] = "same-commit-other-deployment"
            alias["deployment_url"] = (
                "https://same-commit-other-deployment.cogni-os-orchestrator.pages.dev"
            )

        event, _ = self._fixture(replace_alias)
        with self.assertRaisesRegex(
            VALIDATOR.ValidationError, "does not match archived raw responses"
        ):
            self._validate(event)

    def test_rejects_snapshot_bound_to_different_direct_deployment(self) -> None:
        def replace_direct_url(documents: dict[str, dict[str, Any]]) -> None:
            documents["snapshot"]["release_deployment"]["deployment_url"] = (
                "https://same-commit-other-deployment.cogni-os-orchestrator.pages.dev"
            )

        event, _ = self._fixture(replace_direct_url)
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "not the build serving"):
            self._validate(event)

    def test_rejects_disabled_gpu_evidence_as_release_measurement(self) -> None:
        def disable_gpu_evidence(documents: dict[str, dict[str, Any]]) -> None:
            policy = documents["snapshot"]["gpu_policy"]
            policy["telemetry_state"] = "UNMEASURED"
            policy["measurement_complete"] = False
            policy["source_states"]["scheduler"] = "DISABLED"

        event, _ = self._fixture(disable_gpu_evidence)
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "GPU"):
            self._validate(event)

    def test_rejects_live_snapshot_without_complete_monitor_binding(self) -> None:
        for field in (
            "payload_signature_verified",
            "fresh",
            "current_source_commit_bound",
            "deployment_verified",
        ):
            with self.subTest(field=field):
                def invalidate(documents: dict[str, dict[str, Any]]) -> None:
                    documents["snapshot"]["monitoring"][field] = False

                event, _ = self._fixture(invalidate)
                with self.assertRaisesRegex(
                    VALIDATOR.ValidationError, "fresh, signed, and LIVE"
                ):
                    self._validate(event)

    def test_ignores_mutable_reports_and_runs_as_release_truth(self) -> None:
        event, _ = self._fixture()
        for relative in (
            Path("reports") / "P01-TRUTH.json",
            Path("runs") / "P01-TRUTH" / "latest.json",
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                '{"status":"VERIFIED","trusted_complete":true}',
                encoding="utf-8",
            )

        result = self._validate(event)

        self.assertEqual(
            result["bundle_sha256"],
            event["payload"]["collection"]["bundle_sha256"],
        )

    def test_rejects_ads_backslash_absolute_and_traversal_paths(self) -> None:
        for path in (
            "archive/file.json:stream",
            "archive\\file.json",
            "C:/archive/file.json",
            "/archive/file.json",
            "archive/../file.json",
            "archive/./file.json",
        ):
            with self.subTest(path=path), self.assertRaises(VALIDATOR.ValidationError):
                VALIDATOR._safe_relative_parts(path)

    def test_rejects_symlink_or_reparse_artifact(self) -> None:
        event, _ = self._fixture()
        artifact = event["payload"]["collection"]["artifacts"][0]
        path = self.root / Path(artifact["archive_path"])
        outside = self.root / "outside.json"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        linked = False
        try:
            os.symlink(outside, path)
            linked = True
        except OSError:
            path.write_bytes(outside.read_bytes())
        if linked:
            with self.assertRaisesRegex(
                VALIDATOR.ValidationError,
                "symlink|reparse|link",
            ):
                self._validate(event)
        else:
            original = VALIDATOR._is_reparse_or_link

            def reparse_file(info: os.stat_result) -> bool:
                return info.st_size == path.stat().st_size or original(info)

            with (
                patch.object(
                    VALIDATOR, "_is_reparse_or_link", side_effect=reparse_file
                ),
                self.assertRaises(VALIDATOR.ValidationError),
            ):
                self._validate(event)

    def test_rejects_deleted_artifact(self) -> None:
        event, _ = self._fixture()
        artifact = event["payload"]["collection"]["artifacts"][0]
        (self.root / Path(artifact["archive_path"])).unlink()
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "missing"):
            self._validate(event)

    def test_rejects_artifact_hash_mismatch(self) -> None:
        event, _ = self._fixture()
        artifact = event["payload"]["collection"]["artifacts"][0]
        path = self.root / Path(artifact["archive_path"])
        value = bytearray(path.read_bytes())
        value[-2] ^= 1
        path.write_bytes(value)
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "hash"):
            self._validate(event)

    def test_rejects_nested_schema_injection(self) -> None:
        def inject(documents: dict[str, dict[str, Any]]) -> None:
            documents["snapshot"]["source"]["operational_state"]["trusted"] = True

        event, _ = self._fixture(inject)
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "schema"):
            self._validate(event)

    def test_rejects_extra_selected_event_key(self) -> None:
        event, _ = self._fixture()
        injected = {**event, "unsigned_claim": "PASS"}
        events = [self.baseline, injected]
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "schema"):
            VALIDATOR._select_collection_event(
                events,
                sequence=event["sequence"],
                event_hash=event["event_hash"],
                orchestrator="codex",
                expected_commit=self.commit,
            )

    def test_rejects_old_actor_controlled_policy_arguments(self) -> None:
        parser = VALIDATOR.build_parser()
        valid = [
            "--expected-commit",
            self.commit,
            "--expected-collection-sequence",
            "2",
            "--expected-collection-event-hash",
            "d" * 64,
        ]
        for forbidden in (
            "--expected-tests",
            "--expected-contract-sha256",
            "--expected-roadmap-complete",
            "--expected-phase-state",
            "--evidence-bundle",
            "--expected-evidence-sha256",
        ):
            with (
                self.subTest(forbidden=forbidden),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                parser.parse_args([*valid, forbidden, "forbidden"])


if __name__ == "__main__":
    unittest.main()
