"""Phase-specific evidence semantics for the Cogni-OS Phase 1-11 roadmap.

This module consumes evidence only after the normal manifest validator, trusted
runner, signed ledger, and trust projection have established their own facts.
Worker-provided ``passed``, ``expected``, and ``observed`` fields never grant a
phase result here.  A phase requirement is covered only when a canonical test
selector was executed by the trusted verifier and its retained output digest is
bound to a distinct, hash-verified requirement artifact.

The result is semantic coverage telemetry.  It never grants release authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .trust_projection import task_trust_projection

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TRUSTED_RUNNER_ID = "cogni-os-trusted-runner-v3"
_TRUSTED_RUNTIME_POLICY_ID = "fixed-admin-runtime-readonly-v1"
_TRUSTED_RUNTIME_PROVENANCE = "fixed-admin-path-chain"

PHASE_EVIDENCE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "P01-TRUTH": (
        "authoritative_source_commit",
        "ledger_projection_integrity",
        "deployment_attribution_and_rollback",
    ),
    "P02-ORCHESTRATION": (
        "trusted_runner_isolation",
        "signed_monitor_ingest",
        "gpu_policy_0_through_5_only",
        "publisher_restart_recovery",
    ),
    "P03-EVIDENCE": (
        "typed_evidence_capsule",
        "missing_field_forces_no_go",
        "replay_and_rollback_provenance",
    ),
    "P04-WORLD": (
        "estc_transition_constraints",
        "deterministic_state_replay",
        "human_escalation_and_rollback",
    ),
    "P05-FINANCE": (
        "point_in_time_guard",
        "paper_execution_reconciliation",
        "risk_limits_known_answer",
    ),
    "P06-TWIN": (
        "golden_scenario_replay",
        "fault_injection",
        "poisoning_detection",
    ),
    "P07-WORKSPACE": (
        "bounded_conversation_runtime",
        "rag_attachment_voice_contract",
        "tool_cancel_and_recovery",
    ),
    "P08-CORE": (
        "gemma4_deq_convergence",
        "rtx4090_vram_latency_quality",
        "fwp_ple_router_safety",
    ),
    "P09-HARNESS": (
        "day_night_exclusion",
        "isolated_canary_promotion",
        "signed_rollback",
    ),
    "P10-COGNIBOARD": (
        "signed_live_snapshot_ui",
        "fail_closed_status",
        "operator_replay_and_rollback",
    ),
    "P11-RELEASE": (
        "rtx4090_30_run_reproduction",
        "offline_network_zero",
        "installer_restart_recovery",
        "finance_bio_defense_replay",
    ),
}


def _phase_slug(phase_id: str) -> str:
    return phase_id.lower().replace("-", "_")


PHASE_REQUIREMENT_TEST_SELECTORS: dict[str, dict[str, str]] = {
    phase_id: {
        requirement_id: (
            "cogni_os.tests.acceptance."
            f"test_{_phase_slug(phase_id)}.PhaseAcceptanceTests."
            f"test_{requirement_id}"
        )
        for requirement_id in requirements
    }
    for phase_id, requirements in PHASE_EVIDENCE_REQUIREMENTS.items()
}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def _is_commit(value: Any) -> bool:
    return isinstance(value, str) and bool(_COMMIT_RE.fullmatch(value))


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _sequence(value: Any) -> Sequence[Any] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return None


def _normalized_manifest(task: Mapping[str, Any]) -> Mapping[str, Any] | None:
    result = _mapping(task.get("result"))
    return _mapping(result.get("manifest")) if result is not None else None


def _artifact_hashes(manifest: Mapping[str, Any]) -> set[str]:
    hashes: set[str] = set()
    artifacts = _sequence(manifest.get("artifacts"))
    if artifacts is None:
        return hashes
    for artifact in artifacts:
        record = _mapping(artifact)
        digest = record.get("sha256") if record is not None else None
        path = record.get("path") if record is not None else None
        if _is_sha256(digest) and isinstance(path, str) and path:
            hashes.add(str(digest))
    return hashes


def _trusted_validation(task: Mapping[str, Any]) -> Mapping[str, Any] | None:
    verification = _mapping(task.get("verification"))
    return (
        _mapping(verification.get("trusted_validation"))
        if verification is not None
        else None
    )


def _trusted_outputs(
    trusted: Mapping[str, Any] | None,
    *,
    current_source_commit: str,
) -> tuple[dict[str, str], list[str]]:
    reasons: list[str] = []
    if trusted is None:
        return {}, ["TRUSTED_VALIDATION_MISSING"]
    if trusted.get("passed") is not True:
        reasons.append("TRUSTED_VALIDATION_NOT_PASSED")
    if trusted.get("source_clean") is not True:
        reasons.append("TRUSTED_SOURCE_NOT_CLEAN")
    if trusted.get("source_postcheck_passed") is not True:
        reasons.append("TRUSTED_SOURCE_POSTCHECK_FAILED")
    if trusted.get("source_commit") != current_source_commit:
        reasons.append("TRUSTED_SOURCE_COMMIT_MISMATCH")
    if (
        trusted.get("runner") != _TRUSTED_RUNNER_ID
        or trusted.get("isolation_attested") is not True
        or trusted.get("snapshot_precheck_passed") is not True
        or trusted.get("snapshot_postcheck_passed") is not True
        or not isinstance(trusted.get("operational_change_count"), int)
        or isinstance(trusted.get("operational_change_count"), bool)
        or trusted.get("operational_change_count") < 0
        or trusted.get("network_allowed") is not False
        or any(
            not _is_sha256(trusted.get(field))
            for field in (
                "receipt_sha256",
                "receipt_preimage_sha256",
                "verifier_manifest_sha256",
                "validation_contract_sha256",
                "environment_sha256",
                "sandbox_environment_sha256",
            )
        )
    ):
        reasons.append("TRUSTED_RUNNER_PROVENANCE_INVALID")
    validations = _sequence(trusted.get("validations"))
    if validations is None:
        return {}, [*reasons, "TRUSTED_VALIDATIONS_INVALID"]

    by_selector: dict[str, str] = {}
    seen_outputs: set[str] = set()
    for index, value in enumerate(validations):
        record = _mapping(value)
        if record is None:
            reasons.append(f"TRUSTED_VALIDATION_{index}_INVALID")
            continue
        argv = _sequence(record.get("command_argv"))
        executed_argv = _sequence(record.get("executed_argv"))
        command_policy = _mapping(record.get("command_policy"))
        digest = record.get("output_sha256")
        size = record.get("output_size_bytes")
        if (
            record.get("exit_code") != 0
            or record.get("timed_out") is not False
            or record.get("output_truncated") is not False
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not _is_sha256(digest)
            or argv is None
            or any(not isinstance(argument, str) or not argument for argument in argv)
            or executed_argv is None
            or any(
                not isinstance(argument, str) or not argument
                for argument in executed_argv
            )
            or command_policy is None
        ):
            reasons.append(f"TRUSTED_VALIDATION_{index}_FAILED")
            continue
        arguments = list(argv)
        if len(arguments) != 4 or arguments[1:3] != ["-m", "unittest"]:
            reasons.append(f"TRUSTED_VALIDATION_{index}_COMMAND_NOT_PINNED")
            continue
        selector = arguments[-1]
        executed_arguments = list(executed_argv)
        executable_binding = _mapping(command_policy.get("executable_binding"))
        code_paths = _sequence(command_policy.get("code_paths"))
        expected_test_suffix = (
            Path("src")
            .joinpath(*selector.split(".")[:-2])
            .with_suffix(".py")
            .as_posix()
        )
        code_record = (
            _mapping(code_paths[0])
            if code_paths is not None and len(code_paths) == 1
            else None
        )
        code_path = code_record.get("path") if code_record is not None else None
        code_digest = code_record.get("sha256") if code_record is not None else None
        executable_path = command_policy.get("executable_path")
        executable_digest = command_policy.get("executable_sha256")
        if (
            len(executed_arguments) != 4
            or executed_arguments[1:] != arguments[1:]
            or not isinstance(executable_path, str)
            or not Path(executable_path).is_absolute()
            or arguments[0] != executable_path
            or executed_arguments[0] != executable_path
            or command_policy.get("kind") != "python"
            or command_policy.get("executed_argv") != executed_arguments
            or not _is_sha256(executable_digest)
            or record.get("executable_sha256_after") != executable_digest
            or executable_binding is None
            or executable_binding.get("policy_id") != _TRUSTED_RUNTIME_POLICY_ID
            or executable_binding.get("kind") != "python"
            or executable_binding.get("path") != executable_path
            or executable_binding.get("sha256") != executable_digest
            or executable_binding.get("provenance")
            not in {_TRUSTED_RUNTIME_PROVENANCE, "test-only-fixture"}
            or not isinstance(code_path, str)
            or not Path(code_path).as_posix().endswith(expected_test_suffix)
            or not _is_sha256(code_digest)
            or code_digest in {digest, executable_digest}
        ):
            reasons.append(f"TRUSTED_VALIDATION_{index}_PROVENANCE_INVALID")
            continue
        if selector in by_selector:
            reasons.append(f"TRUSTED_VALIDATION_SELECTOR_REUSED:{selector}")
            continue
        if digest in seen_outputs:
            reasons.append("TRUSTED_VALIDATION_OUTPUT_REUSED")
            continue
        by_selector[selector] = str(digest)
        seen_outputs.add(str(digest))
    return by_selector, reasons


def _coverage_result(
    phase_id: str,
    reasons: Sequence[str],
    artifact_hashes: Sequence[str],
    validation_hashes: Sequence[str],
    source_commit: str | None,
) -> dict[str, Any]:
    return {
        "phase_id": phase_id,
        "coverage_status": ("SEMANTIC_COVERAGE_PASS" if not reasons else "NO_GO"),
        "reasons": list(dict.fromkeys(reasons)),
        "source_commit": source_commit,
        "artifact_sha256": list(artifact_hashes),
        "trusted_output_sha256": list(validation_hashes),
        "release_authority": False,
    }


def audit_phase_task(
    task: Mapping[str, Any],
    *,
    current_source_commit: str,
    workspace_root: Path,
) -> dict[str, Any]:
    """Audit one phase task over trusted projection and verifier-owned outputs."""

    phase_id = task.get("id")
    if phase_id not in PHASE_EVIDENCE_REQUIREMENTS:
        raise ValueError("task is not a canonical Phase 1-11 task")
    phase_id = str(phase_id)
    reasons: list[str] = []
    if not _is_commit(current_source_commit):
        reasons.append("CURRENT_SOURCE_COMMIT_INVALID")
    if task.get("state") not in {"verified", "archived"}:
        reasons.append("TASK_NOT_VERIFIED")

    try:
        trust = task_trust_projection(
            dict(task),
            current_commit=current_source_commit,
            workspace_root=workspace_root.resolve(),
        )
    except (OSError, TypeError, ValueError):
        trust = {}
    if (
        trust.get("historical_trusted") is not True
        or trust.get("current_release_validated") is not True
        or trust.get("verified_source_commit") != current_source_commit
        or trust.get("current_release_state") not in {"verified", "archived"}
    ):
        reasons.append("TASK_TRUST_NOT_CURRENT")

    trusted_outputs, trusted_reasons = _trusted_outputs(
        _trusted_validation(task),
        current_source_commit=current_source_commit,
    )
    reasons.extend(trusted_reasons)

    manifest = _normalized_manifest(task)
    if manifest is None:
        reasons.append("NORMALIZED_MANIFEST_MISSING")
        return _coverage_result(phase_id, reasons, (), (), None)
    artifacts = _artifact_hashes(manifest)
    phase_evidence = _mapping(manifest.get("phase_evidence"))
    if phase_evidence is None:
        reasons.append("PHASE_EVIDENCE_MISSING")
        return _coverage_result(phase_id, reasons, (), (), None)

    if set(phase_evidence) != {
        "schema",
        "phase_id",
        "source_commit",
        "requirements",
    }:
        reasons.append("PHASE_EVIDENCE_SCHEMA_FIELDS_INVALID")
    if phase_evidence.get("schema") != "cogni.phase-evidence.v1":
        reasons.append("PHASE_EVIDENCE_SCHEMA_INVALID")
    if phase_evidence.get("phase_id") != phase_id:
        reasons.append("PHASE_ID_MISMATCH")
    evidence_commit = phase_evidence.get("source_commit")
    if evidence_commit != current_source_commit:
        reasons.append("PHASE_SOURCE_COMMIT_MISMATCH")

    records = _sequence(phase_evidence.get("requirements"))
    if records is None:
        reasons.append("PHASE_REQUIREMENTS_INVALID")
        records = ()
    expected_ids = PHASE_EVIDENCE_REQUIREMENTS[phase_id]
    observed_ids: list[str] = []
    bound_artifacts: list[str] = []
    bound_outputs: list[str] = []
    for index, value in enumerate(records):
        record = _mapping(value)
        if record is None or set(record) != {
            "requirement_id",
            "artifact_sha256",
            "trusted_output_sha256",
        }:
            reasons.append(f"REQUIREMENT_{index}_FIELDS_INVALID")
            continue
        requirement_id = record.get("requirement_id")
        artifact_sha256 = record.get("artifact_sha256")
        output_sha256 = record.get("trusted_output_sha256")
        if not isinstance(requirement_id, str):
            reasons.append(f"REQUIREMENT_{index}_ID_INVALID")
            continue
        observed_ids.append(requirement_id)
        if not _is_sha256(artifact_sha256) or artifact_sha256 not in artifacts:
            reasons.append(f"{requirement_id}:ARTIFACT_NOT_BOUND")
        else:
            bound_artifacts.append(str(artifact_sha256))
        selector = PHASE_REQUIREMENT_TEST_SELECTORS[phase_id].get(requirement_id)
        trusted_digest = trusted_outputs.get(selector) if selector is not None else None
        if not _is_sha256(output_sha256) or trusted_digest != output_sha256:
            reasons.append(f"{requirement_id}:TRUSTED_OUTPUT_NOT_BOUND")
        else:
            bound_outputs.append(str(output_sha256))
        if (
            _is_sha256(artifact_sha256)
            and _is_sha256(output_sha256)
            and artifact_sha256 == output_sha256
        ):
            reasons.append(f"{requirement_id}:ARTIFACT_OUTPUT_DIGEST_COLLISION")

    if tuple(observed_ids) != expected_ids:
        reasons.append("PHASE_REQUIREMENT_COVERAGE_MISMATCH")
    if len(bound_artifacts) != len(set(bound_artifacts)):
        reasons.append("PHASE_REQUIREMENT_ARTIFACT_REUSE")
    if len(bound_outputs) != len(set(bound_outputs)):
        reasons.append("PHASE_REQUIREMENT_OUTPUT_REUSE")
    return _coverage_result(
        phase_id,
        reasons,
        tuple(bound_artifacts),
        tuple(bound_outputs),
        str(evidence_commit) if _is_commit(evidence_commit) else None,
    )


def audit_phase_tasks(
    tasks: Sequence[Mapping[str, Any]],
    *,
    current_source_commit: str,
    workspace_root: Path,
) -> dict[str, Any]:
    """Audit all eleven phases and invalidate every owner of reused evidence."""

    by_id: dict[str, Mapping[str, Any]] = {}
    duplicate_ids: set[str] = set()
    for task in tasks:
        task_id = task.get("id") if isinstance(task, Mapping) else None
        if task_id not in PHASE_EVIDENCE_REQUIREMENTS:
            continue
        task_id = str(task_id)
        if task_id in by_id:
            duplicate_ids.add(task_id)
        else:
            by_id[task_id] = task

    phases: list[dict[str, Any]] = []
    for phase_id in PHASE_EVIDENCE_REQUIREMENTS:
        task = by_id.get(phase_id)
        if task is None:
            result = _coverage_result(phase_id, ["PHASE_TASK_MISSING"], (), (), None)
        else:
            result = audit_phase_task(
                task,
                current_source_commit=current_source_commit,
                workspace_root=workspace_root,
            )
        if phase_id in duplicate_ids:
            result["coverage_status"] = "NO_GO"
            result["reasons"].append("PHASE_TASK_ID_DUPLICATED")
        phases.append(result)

    for field, reason in (
        ("artifact_sha256", "CROSS_PHASE_ARTIFACT_REUSE"),
        ("trusted_output_sha256", "CROSS_PHASE_TRUSTED_OUTPUT_REUSE"),
    ):
        owners: dict[str, set[str]] = {}
        for phase in phases:
            for digest in phase[field]:
                owners.setdefault(digest, set()).add(phase["phase_id"])
        reused = {
            digest: values for digest, values in owners.items() if len(values) > 1
        }
        for digest, phase_ids in reused.items():
            for phase in phases:
                if phase["phase_id"] in phase_ids:
                    phase["coverage_status"] = "NO_GO"
                    phase["reasons"].append(f"{reason}:{digest}")

    artifact_owners: dict[str, set[str]] = {}
    output_owners: dict[str, set[str]] = {}
    for phase in phases:
        for digest in phase["artifact_sha256"]:
            artifact_owners.setdefault(digest, set()).add(phase["phase_id"])
        for digest in phase["trusted_output_sha256"]:
            output_owners.setdefault(digest, set()).add(phase["phase_id"])
    for digest in sorted(set(artifact_owners) & set(output_owners)):
        affected = artifact_owners[digest] | output_owners[digest]
        for phase in phases:
            if phase["phase_id"] in affected:
                phase["coverage_status"] = "NO_GO"
                phase["reasons"].append(f"CROSS_DOMAIN_DIGEST_REUSE:{digest}")

    validated = sum(
        phase["coverage_status"] == "SEMANTIC_COVERAGE_PASS" for phase in phases
    )
    return {
        "schema": "cogni.phase-evidence-audit.v2",
        "coverage_status": (
            "SEMANTIC_COVERAGE_PASS"
            if validated == len(PHASE_EVIDENCE_REQUIREMENTS)
            else "NO_GO"
        ),
        "source_commit": current_source_commit,
        "total_phases": len(PHASE_EVIDENCE_REQUIREMENTS),
        "validated_phases": validated,
        "progress_percent": round(
            100.0 * validated / len(PHASE_EVIDENCE_REQUIREMENTS), 1
        ),
        "phases": phases,
        "release_authority": False,
    }


__all__ = [
    "PHASE_EVIDENCE_REQUIREMENTS",
    "PHASE_REQUIREMENT_TEST_SELECTORS",
    "audit_phase_task",
    "audit_phase_tasks",
]
