"""Fail-closed lifecycle audit for durable verification runs."""

from __future__ import annotations

import re
from typing import Any

VERIFICATION_TERMINAL_ACTIONS = frozenset(
    {"verification.failed", "task.verified", "task.rejected"}
)
_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _receipt_is_bound(
    value: Any,
    *,
    actor: Any,
    operation: str,
    task_id: Any,
    run_id: str,
    task_attempt: Any,
) -> bool:
    """Check receipt shape/scope; cryptographic validation happens read-side."""

    if not isinstance(value, dict):
        return False
    attestation = value.get("os_principal_attestation")
    return (
        value.get("schema_version") == 2
        and value.get("receipt_type") == "actor-capability-consumption"
        and value.get("actor") == actor
        and value.get("operation") == operation
        and value.get("task_id") == task_id
        and value.get("run_id") == run_id
        and value.get("task_attempt") == task_attempt
        and isinstance(value.get("nonce_sha256"), str)
        and bool(_SHA256_RE.fullmatch(value["nonce_sha256"]))
        and isinstance(value.get("signature"), str)
        and bool(value["signature"])
        and isinstance(attestation, dict)
        and isinstance(value.get("independent_trust_root"), bool)
        and isinstance(value.get("actor_os_isolation_proven"), bool)
        and attestation.get("independent_trust_root")
        is value.get("independent_trust_root")
        and attestation.get("actor_os_isolation_proven")
        is value.get("actor_os_isolation_proven")
    )


def _verification_binding_reasons(
    start: dict[str, Any], terminal: dict[str, Any]
) -> list[str]:
    """Return semantic start/terminal binding failures for one run."""

    reasons: list[str] = []
    start_payload = start.get("payload", {})
    terminal_payload = terminal.get("payload", {})
    run_id = start_payload.get("run_id")
    task_id = start.get("task_id")
    task_attempt = start_payload.get("task_attempt")
    start_actor = start.get("actor")
    start_receipt = start_payload.get("capability_receipt")
    if not _receipt_is_bound(
        start_receipt,
        actor=start_actor,
        operation="task.verify",
        task_id=task_id,
        run_id=run_id,
        task_attempt=task_attempt,
    ):
        reasons.append("started_capability_receipt_invalid")

    identity = start_payload.get("verifier_identity")
    verifier_manifest = start_payload.get("verifier_manifest_sha256")
    worker_manifest = start_payload.get("worker_manifest_sha256")
    contract_inputs = start_payload.get("verification_contract_inputs_sha256")
    if not isinstance(identity, dict):
        reasons.append("started_verifier_identity_missing")
    if not isinstance(verifier_manifest, str) or not _SHA256_RE.fullmatch(
        verifier_manifest.lower()
    ):
        reasons.append("started_verifier_manifest_invalid")
    if worker_manifest is not None and (
        not isinstance(worker_manifest, str)
        or not _SHA256_RE.fullmatch(worker_manifest.lower())
    ):
        reasons.append("started_worker_manifest_invalid")
    if not isinstance(contract_inputs, str) or not _SHA256_RE.fullmatch(
        contract_inputs.lower()
    ):
        reasons.append("started_contract_inputs_invalid")

    action = terminal.get("action")
    if action in {"task.verified", "task.rejected"}:
        terminal_task = terminal_payload.get("task")
        verification = (
            terminal_task.get("verification")
            if isinstance(terminal_task, dict)
            else None
        )
        if terminal.get("actor") != start_actor:
            reasons.append("terminal_actor_mismatch")
        if not isinstance(verification, dict):
            reasons.append("terminal_verification_missing")
            return reasons
        if (
            terminal_payload.get("verifier_identity") != identity
            or verification.get("verifier_identity") != identity
        ):
            reasons.append("terminal_verifier_identity_mismatch")
        verifier_evidence = verification.get("verifier_evidence")
        if (
            not isinstance(verifier_evidence, dict)
            or verifier_evidence.get("manifest_sha256") != verifier_manifest
            or terminal_payload.get("verifier_evidence") != verifier_evidence
        ):
            reasons.append("terminal_verifier_manifest_mismatch")
        elif not isinstance(verifier_evidence.get("executor_attestation"), dict):
            reasons.append("terminal_executor_attestation_missing")
        if (
            verification.get("worker_manifest_sha256") != worker_manifest
            or terminal_payload.get("worker_manifest_sha256") != worker_manifest
        ):
            reasons.append("terminal_worker_manifest_mismatch")
        if (
            verification.get("verification_contract_inputs_sha256") != contract_inputs
            or terminal_payload.get("verification_contract_inputs_sha256")
            != contract_inputs
        ):
            reasons.append("terminal_contract_inputs_mismatch")
        if (
            verification.get("capability_receipt") != start_receipt
            or terminal_payload.get("capability_receipt") != start_receipt
        ):
            reasons.append("terminal_capability_receipt_mismatch")
        trusted = verification.get("trusted_validation")
        if terminal_payload.get("trusted_validation") != trusted:
            reasons.append("terminal_trusted_contract_mismatch")
        elif (
            not isinstance(trusted, dict)
            or not isinstance(trusted.get("validation_contract_sha256"), str)
            or not _SHA256_RE.fullmatch(trusted["validation_contract_sha256"].lower())
        ):
            reasons.append("terminal_trusted_contract_invalid")
    elif action == "verification.failed":
        recovery = terminal_payload.get("stage") == "recovery"
        if recovery:
            if (
                terminal_payload.get("started_actor") != start_actor
                or terminal_payload.get("started_capability_receipt") != start_receipt
            ):
                reasons.append("recovery_started_binding_mismatch")
            if not _receipt_is_bound(
                terminal_payload.get("capability_receipt"),
                actor=terminal.get("actor"),
                operation="task.reconcile_verification",
                task_id=task_id,
                run_id=run_id,
                task_attempt=task_attempt,
            ):
                reasons.append("recovery_capability_receipt_invalid")
        else:
            if terminal.get("actor") != start_actor:
                reasons.append("failed_terminal_actor_mismatch")
            if terminal_payload.get("capability_receipt") != start_receipt:
                reasons.append("failed_terminal_capability_receipt_mismatch")
        if (
            terminal_payload.get("verifier_identity") != identity
            or terminal_payload.get("verifier_manifest_sha256") != verifier_manifest
            or terminal_payload.get("worker_manifest_sha256") != worker_manifest
            or terminal_payload.get("verification_contract_inputs_sha256")
            != contract_inputs
        ):
            reasons.append("failed_terminal_context_mismatch")
    return reasons


def validate_verification_run_id(value: str) -> str:
    """Validate the opaque identifier used to reconcile one verification run."""

    if not isinstance(value, str) or not _RUN_ID_RE.fullmatch(value):
        raise ValueError("Verification run id must be 32 lowercase hexadecimal chars")
    return value


def audit_verification_runs(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Group signed lifecycle events and report orphaned or conflicting runs.

    Legacy ``task.verified`` events without a ``run_id`` predate the durable
    lifecycle protocol and are deliberately ignored here.  Any lifecycle event
    that does carry a run id must have exactly one ``verification.started`` and
    no more than one terminal event.
    """

    grouped: dict[str, dict[str, Any]] = {}
    invalid_events: list[dict[str, Any]] = []
    for event in events:
        action = event.get("action")
        if (
            action != "verification.started"
            and action not in VERIFICATION_TERMINAL_ACTIONS
        ):
            continue
        payload = event.get("payload")
        run_id = payload.get("run_id") if isinstance(payload, dict) else None
        if run_id is None and action in {"task.verified", "task.rejected"}:
            continue
        if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
            invalid_events.append(
                {
                    "sequence": event.get("sequence"),
                    "task_id": event.get("task_id"),
                    "action": action,
                    "reason": "invalid_run_id",
                }
            )
            continue
        record = grouped.setdefault(
            run_id,
            {"run_id": run_id, "started": [], "terminal": []},
        )
        bucket = "started" if action == "verification.started" else "terminal"
        record[bucket].append(event)

    runs: list[dict[str, Any]] = []
    orphaned: list[dict[str, Any]] = []
    invalid_runs: list[dict[str, Any]] = []
    for run_id, grouped_run in sorted(grouped.items()):
        starts = grouped_run["started"]
        terminals = grouped_run["terminal"]
        reasons: list[str] = []
        if len(starts) != 1:
            reasons.append("missing_started" if not starts else "duplicate_started")
        if len(terminals) > 1:
            reasons.append("multiple_terminal_events")

        start = starts[0] if len(starts) == 1 else None
        terminal = terminals[0] if len(terminals) == 1 else None
        if start is not None and terminal is not None:
            start_payload = start.get("payload", {})
            terminal_payload = terminal.get("payload", {})
            if terminal.get("task_id") != start.get("task_id"):
                reasons.append("terminal_task_id_mismatch")
            if not isinstance(terminal.get("sequence"), int) or terminal[
                "sequence"
            ] <= start.get("sequence", 0):
                reasons.append("terminal_not_after_started")
            terminal_attempt = terminal_payload.get("task_attempt")
            if terminal_attempt is None:
                terminal_task = terminal_payload.get("task")
                if isinstance(terminal_task, dict):
                    terminal_attempt = terminal_task.get("attempt")
            if terminal_attempt != start_payload.get("task_attempt"):
                reasons.append("terminal_attempt_mismatch")
            if terminal.get("action") in {"task.verified", "task.rejected"}:
                terminal_task = terminal_payload.get("task")
                expected_state = (
                    "verified"
                    if terminal.get("action") == "task.verified"
                    else "rejected"
                )
                if not isinstance(terminal_task, dict):
                    reasons.append("terminal_task_missing")
                else:
                    if terminal_task.get("id") != start.get("task_id"):
                        reasons.append("terminal_task_snapshot_id_mismatch")
                    if terminal_task.get("state") != expected_state:
                        reasons.append("terminal_task_state_mismatch")
                    verification = terminal_task.get("verification")
                    if (
                        not isinstance(verification, dict)
                        or verification.get("run_id") != run_id
                    ):
                        reasons.append("terminal_task_run_id_mismatch")
            elif terminal.get("action") == "verification.failed":
                if terminal_payload.get("schema_version") != 1:
                    reasons.append("failed_terminal_schema_mismatch")
                if not isinstance(terminal_payload.get("stage"), str):
                    reasons.append("failed_terminal_stage_missing")
                if not isinstance(terminal_payload.get("error_type"), str):
                    reasons.append("failed_terminal_error_type_missing")
            reasons.extend(_verification_binding_reasons(start, terminal))

        record = {
            "run_id": run_id,
            "task_id": start.get("task_id")
            if start is not None
            else (terminal.get("task_id") if terminal is not None else None),
            "started_sequence": start.get("sequence") if start is not None else None,
            "terminal_sequence": terminal.get("sequence")
            if terminal is not None
            else None,
            "terminal_action": terminal.get("action") if terminal is not None else None,
            "valid": not reasons,
            "reasons": reasons,
        }
        runs.append(record)
        if start is not None and not terminals and not reasons:
            orphaned.append(record)
        if reasons:
            invalid_runs.append(record)

    return {
        "valid": not invalid_events and not invalid_runs and not orphaned,
        "runs": runs,
        "orphaned_runs": orphaned,
        "invalid_runs": invalid_runs,
        "invalid_events": invalid_events,
    }


def find_verification_run(
    events: list[dict[str, Any]], *, task_id: str, run_id: str
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Return the unique start and all terminal events for one bound run."""

    starts: list[dict[str, Any]] = []
    terminals: list[dict[str, Any]] = []
    for event in events:
        payload = event.get("payload")
        if not isinstance(payload, dict) or payload.get("run_id") != run_id:
            continue
        if (
            event.get("action") != "verification.started"
            and event.get("action") not in VERIFICATION_TERMINAL_ACTIONS
        ):
            continue
        if event.get("task_id") != task_id:
            raise ValueError("Verification run id is bound to a different task")
        if event.get("action") == "verification.started":
            starts.append(event)
        elif event.get("action") in VERIFICATION_TERMINAL_ACTIONS:
            terminals.append(event)
    if len(starts) > 1:
        raise ValueError("Verification run has duplicate started events")
    if len(starts) == 1 and len(terminals) == 1:
        reasons = _verification_binding_reasons(starts[0], terminals[0])
        if reasons:
            raise ValueError(
                "Verification run start/terminal binding is invalid: "
                + ", ".join(reasons)
            )
    return (starts[0] if starts else None), terminals


def require_authoritative_verification_terminal(
    events: list[dict[str, Any]],
    *,
    task_id: str,
    run_id: str,
    terminal_event: dict[str, Any],
) -> dict[str, Any]:
    """Return the unique start only for one conflict-free selected terminal.

    Consumers must not select a plausible ``task.verified`` event in isolation.
    The entire same-run lifecycle is audited so a second failure/rejection or a
    terminal that precedes the start invalidates the selected verification,
    regardless of ledger ordering.
    """

    validate_verification_run_id(run_id)
    started, terminals = find_verification_run(
        events,
        task_id=task_id,
        run_id=run_id,
    )
    if started is None or len(terminals) != 1 or terminals[0] != terminal_event:
        raise ValueError("Verification run must have one exact selected terminal event")
    matching = [
        record
        for record in audit_verification_runs(events)["runs"]
        if record.get("run_id") == run_id and record.get("task_id") == task_id
    ]
    if (
        len(matching) != 1
        or matching[0].get("valid") is not True
        or matching[0].get("started_sequence") != started.get("sequence")
        or matching[0].get("terminal_sequence") != terminal_event.get("sequence")
        or matching[0].get("terminal_action") != terminal_event.get("action")
    ):
        raise ValueError("Verification run lifecycle audit rejected the terminal")
    return started
