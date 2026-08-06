"""Exact wire and receipt schemas for the dedicated verifier service.

This module is intentionally pure.  It validates ledger-bound dispatches,
execution preimages, and final receipt envelopes without reading mutable
workspace state or performing cryptographic operations.  Cryptographic trust
and durable state transitions live in :mod:`cogni_os.verifier_receipt` and
:mod:`cogni_os.verifier_service` respectively.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from datetime import datetime
from typing import Any, Final

from .errors import EvidenceError
from .snapshot_broker_protocol import (
    SnapshotBrokerError,
    validate_signed_envelope as validate_broker_envelope,
)

VERIFIER_SCHEMA_VERSION: Final = 1
VERIFIER_PROTOCOL_ID: Final = "cogni-os.verifier-service.v1"
VERIFIER_LEDGER_DOMAIN: Final = "cogni-os.ledger-event.v2"
VERIFIER_RECEIPT_DOMAIN: Final = "cogni-os.verification-receipt.v1"
VERIFIER_SIGNATURE_ALGORITHM: Final = "ed25519-openssl-pkeyutl-raw-v1"

MAX_VERIFIER_DOCUMENT_BYTES: Final = 4 * 1024 * 1024
MAX_DISPATCH_TTL_SECONDS: Final = 600
MAX_CLOCK_SKEW_SECONDS: Final = 60
MAX_COMMANDS: Final = 128
MAX_ARGV_ITEMS: Final = 256
MAX_ARG_BYTES: Final = 16 * 1024
MAX_OUTPUT_BYTES: Final = 64 * 1024 * 1024

_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_40_OR_64 = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")

SOURCE_KEYS: Final = frozenset(
    {"artifact_id", "bundle_sha256", "size_bytes", "commit_oid", "tree_oid"}
)
DISPATCH_KEYS: Final = frozenset(
    {
        "schema_version",
        "protocol_id",
        "kind",
        "ledger_domain",
        "dispatch_event_hash",
        "ledger_head_hash",
        "workspace_id",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "source",
        "verifier_manifest_sha256",
        "validation_contract_sha256",
        "capability_receipt_sha256",
        "network_allowed",
        "gpu_allowed",
        "nonce",
        "issued_at",
        "expires_at",
    }
)
WAKEUP_KEYS: Final = frozenset(
    {
        "schema_version",
        "protocol_id",
        "kind",
        "dispatch_event_hash",
        "task_id",
        "run_id",
        "nonce",
    }
)
RUNTIME_KEYS: Final = frozenset(
    {
        "runtime_manifest_sha256",
        "entrypoint_sha256",
        "interpreter_sha256",
        "package_tree_sha256",
        "service_unit_sha256",
        "policy_sha256",
    }
)
COMMAND_KEYS: Final = frozenset(
    {
        "index",
        "executable_path",
        "executable_sha256",
        "argv",
        "cwd",
        "environment_sha256",
        "exit_code",
        "timed_out",
        "output_truncated",
        "stdout_sha256",
        "stdout_size_bytes",
        "stderr_sha256",
        "stderr_size_bytes",
        "started_monotonic_ns",
        "completed_monotonic_ns",
    }
)
ISOLATION_KEYS: Final = frozenset(
    {
        "network_disabled",
        "gpu_disabled",
        "namespace_sha256",
        "cgroup_sha256",
    }
)
POSTCHECK_KEYS: Final = frozenset({"passed", "observed_sha256"})
EXECUTION_PREIMAGE_KEYS: Final = frozenset(
    {
        "schema_version",
        "protocol_id",
        "kind",
        "domain",
        "dispatch_event_hash",
        "request_event_hash",
        "start_event_hash",
        "ledger_head_hash",
        "workspace_id",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "source",
        "verifier_manifest_sha256",
        "validation_contract_sha256",
        "snapshot_manifest_sha256",
        "acquire_proof_sha256",
        "runtime",
        "commands",
        "isolation",
        "source_postcheck",
        "snapshot_postcheck",
        "started_at",
        "completed_at",
        "started_monotonic_ns",
        "completed_monotonic_ns",
        "result",
        "failure_code",
    }
)
RECEIPT_KEYS: Final = frozenset(
    {
        "schema_version",
        "protocol_id",
        "kind",
        "domain",
        "algorithm",
        "public_key_sha256",
        "execution_preimage",
        "execution_preimage_sha256",
        "execution_signature_b64",
        "cleanup_proof",
        "cleanup_proof_sha256",
        "sealed_at",
        "final_signature_b64",
    }
)


class VerifierProtocolError(EvidenceError):
    """A dedicated-verifier document violates the fixed protocol."""


def canonical_json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise VerifierProtocolError("Verifier document is not canonical JSON") from exc
    if len(encoded) > MAX_VERIFIER_DOCUMENT_BYTES:
        raise VerifierProtocolError("Verifier document exceeds its byte limit")
    return encoded


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_object(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise VerifierProtocolError(f"{label} schema is not exact")
    canonical_json_bytes(value)
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise VerifierProtocolError(f"{label} must be a lowercase SHA-256")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise VerifierProtocolError(f"{label} is invalid")
    return value


def _positive_int(value: Any, label: str, *, allow_zero: bool = False) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < (0 if allow_zero else 1)
    ):
        raise VerifierProtocolError(f"{label} must be a bounded integer")
    return value


def _timestamp(value: Any, label: str) -> float:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise VerifierProtocolError(f"{label} timestamp is invalid")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
        epoch = parsed.timestamp()
    except (OverflowError, OSError, ValueError) as exc:
        raise VerifierProtocolError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise VerifierProtocolError(f"{label} timestamp has no timezone")
    return epoch


def _signature(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or len(value) > 1024:
        raise VerifierProtocolError(f"{label} encoding is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise VerifierProtocolError(f"{label} encoding is invalid") from exc
    if len(decoded) != 64:
        raise VerifierProtocolError(f"{label} Ed25519 length is invalid")
    return decoded


def _validate_source(value: Any) -> dict[str, Any]:
    source = _exact_object(value, SOURCE_KEYS, "Verifier source")
    _identifier(source["artifact_id"], "source.artifact_id")
    _sha256(source["bundle_sha256"], "source.bundle_sha256")
    _positive_int(source["size_bytes"], "source.size_bytes")
    commit = source["commit_oid"]
    tree = source["tree_oid"]
    if (
        not isinstance(commit, str)
        or not _HEX_40_OR_64.fullmatch(commit)
        or not isinstance(tree, str)
        or not _HEX_40_OR_64.fullmatch(tree)
        or len(commit) != len(tree)
    ):
        raise VerifierProtocolError("Verifier source Git OIDs are invalid")
    return source


def validate_dispatch(document: Any, *, now: int | None = None) -> dict[str, Any]:
    dispatch = _exact_object(document, DISPATCH_KEYS, "Verifier dispatch")
    if (
        dispatch["schema_version"] != VERIFIER_SCHEMA_VERSION
        or dispatch["protocol_id"] != VERIFIER_PROTOCOL_ID
        or dispatch["kind"] != "verification-dispatch"
        or dispatch["ledger_domain"] != VERIFIER_LEDGER_DOMAIN
    ):
        raise VerifierProtocolError("Verifier dispatch identity is invalid")
    for key in ("dispatch_event_hash", "ledger_head_hash"):
        _sha256(dispatch[key], key)
    for key in ("workspace_id", "task_id", "actor", "nonce"):
        _identifier(dispatch[key], key)
    if not isinstance(dispatch["run_id"], str) or not _HEX_32.fullmatch(
        dispatch["run_id"]
    ):
        raise VerifierProtocolError("run_id must be 32 lowercase hex characters")
    _positive_int(dispatch["attempt"], "attempt")
    _validate_source(dispatch["source"])
    for key in (
        "verifier_manifest_sha256",
        "validation_contract_sha256",
        "capability_receipt_sha256",
    ):
        _sha256(dispatch[key], key)
    if dispatch["network_allowed"] is not False or dispatch["gpu_allowed"] is not False:
        raise VerifierProtocolError("Verifier dispatch must deny network and GPU")
    issued_at = _positive_int(dispatch["issued_at"], "issued_at")
    expires_at = _positive_int(dispatch["expires_at"], "expires_at")
    if expires_at <= issued_at or expires_at - issued_at > MAX_DISPATCH_TTL_SECONDS:
        raise VerifierProtocolError("Verifier dispatch lifetime is invalid")
    current = int(time.time()) if now is None else now
    if issued_at > current + MAX_CLOCK_SKEW_SECONDS or expires_at < current:
        raise VerifierProtocolError("Verifier dispatch is expired or not yet valid")
    return dispatch


def validate_wakeup(document: Any) -> dict[str, Any]:
    wakeup = _exact_object(document, WAKEUP_KEYS, "Verifier wakeup")
    if (
        wakeup["schema_version"] != VERIFIER_SCHEMA_VERSION
        or wakeup["protocol_id"] != VERIFIER_PROTOCOL_ID
        or wakeup["kind"] != "verification-wakeup"
    ):
        raise VerifierProtocolError("Verifier wakeup identity is invalid")
    _sha256(wakeup["dispatch_event_hash"], "dispatch_event_hash")
    _identifier(wakeup["task_id"], "task_id")
    _identifier(wakeup["nonce"], "nonce")
    if not isinstance(wakeup["run_id"], str) or not _HEX_32.fullmatch(
        wakeup["run_id"]
    ):
        raise VerifierProtocolError("Verifier wakeup run_id is invalid")
    if len(canonical_json_bytes(wakeup)) > 4096:
        raise VerifierProtocolError("Verifier wakeup exceeds 4 KiB")
    return wakeup


def _validate_runtime(value: Any) -> dict[str, Any]:
    runtime = _exact_object(value, RUNTIME_KEYS, "Verifier runtime")
    for key in RUNTIME_KEYS:
        _sha256(runtime[key], f"runtime.{key}")
    return runtime


def _canonical_posix_absolute_path(
    value: Any,
    label: str,
    *,
    allow_root: bool,
) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "\x00" in value
        or "\\" in value
        or len(value.encode("utf-8")) > 4096
    ):
        raise VerifierProtocolError(f"{label} is not a canonical POSIX path")
    if value == "/":
        if allow_root:
            return value
        raise VerifierProtocolError(f"{label} may not name the filesystem root")
    if value.endswith("/"):
        raise VerifierProtocolError(f"{label} has a trailing slash")
    components = value[1:].split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise VerifierProtocolError(f"{label} has a noncanonical component")
    return value


def _validate_command(value: Any, expected_index: int) -> dict[str, Any]:
    command = _exact_object(value, COMMAND_KEYS, "Verifier command")
    if command["index"] != expected_index:
        raise VerifierProtocolError("Verifier command indexes are not contiguous")
    executable = _canonical_posix_absolute_path(
        command["executable_path"],
        "Verifier executable_path",
        allow_root=False,
    )
    cwd = _canonical_posix_absolute_path(
        command["cwd"],
        "Verifier cwd",
        allow_root=True,
    )
    argv = command["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > MAX_ARGV_ITEMS
        or any(
            not isinstance(argument, str)
            or not argument
            or len(argument.encode("utf-8")) > MAX_ARG_BYTES
            for argument in argv
        )
        or argv[0] != executable
    ):
        raise VerifierProtocolError("Verifier command argv is invalid")
    for key in (
        "executable_sha256",
        "environment_sha256",
        "stdout_sha256",
        "stderr_sha256",
    ):
        _sha256(command[key], f"command.{key}")
    if not isinstance(command["exit_code"], int) or isinstance(
        command["exit_code"], bool
    ):
        raise VerifierProtocolError("Verifier command exit_code is invalid")
    for key in ("timed_out", "output_truncated"):
        if not isinstance(command[key], bool):
            raise VerifierProtocolError(f"Verifier command {key} is invalid")
    for key in ("stdout_size_bytes", "stderr_size_bytes"):
        size = _positive_int(command[key], key, allow_zero=True)
        if size > MAX_OUTPUT_BYTES:
            raise VerifierProtocolError("Verifier command output exceeds its limit")
    started = _positive_int(command["started_monotonic_ns"], "started_monotonic_ns")
    completed = _positive_int(
        command["completed_monotonic_ns"], "completed_monotonic_ns"
    )
    if completed < started:
        raise VerifierProtocolError("Verifier command monotonic interval is invalid")
    return command


def _validate_postcheck(value: Any, label: str) -> dict[str, Any]:
    postcheck = _exact_object(value, POSTCHECK_KEYS, label)
    if not isinstance(postcheck["passed"], bool):
        raise VerifierProtocolError(f"{label}.passed must be boolean")
    _sha256(postcheck["observed_sha256"], f"{label}.observed_sha256")
    return postcheck


def validate_execution_preimage(
    document: Any,
    *,
    dispatch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    preimage = _exact_object(
        document, EXECUTION_PREIMAGE_KEYS, "Verifier execution preimage"
    )
    if (
        preimage["schema_version"] != VERIFIER_SCHEMA_VERSION
        or preimage["protocol_id"] != VERIFIER_PROTOCOL_ID
        or preimage["kind"] != "verification-execution-preimage"
        or preimage["domain"] != VERIFIER_RECEIPT_DOMAIN
    ):
        raise VerifierProtocolError("Verifier execution preimage identity is invalid")
    for key in (
        "dispatch_event_hash",
        "request_event_hash",
        "start_event_hash",
        "ledger_head_hash",
        "verifier_manifest_sha256",
        "validation_contract_sha256",
        "snapshot_manifest_sha256",
        "acquire_proof_sha256",
    ):
        _sha256(preimage[key], key)
    for key in ("workspace_id", "task_id", "actor"):
        _identifier(preimage[key], key)
    _positive_int(preimage["attempt"], "attempt")
    if not isinstance(preimage["run_id"], str) or not _HEX_32.fullmatch(
        preimage["run_id"]
    ):
        raise VerifierProtocolError("Verifier execution run_id is invalid")
    _validate_source(preimage["source"])
    _validate_runtime(preimage["runtime"])
    commands = preimage["commands"]
    if not isinstance(commands, list) or not commands or len(commands) > MAX_COMMANDS:
        raise VerifierProtocolError("Verifier commands must be a bounded non-empty list")
    for index, command in enumerate(commands):
        _validate_command(command, index)
    isolation = _exact_object(preimage["isolation"], ISOLATION_KEYS, "Isolation")
    if isolation["network_disabled"] is not True or isolation["gpu_disabled"] is not True:
        raise VerifierProtocolError("Verifier isolation must disable network and GPU")
    _sha256(isolation["namespace_sha256"], "isolation.namespace_sha256")
    _sha256(isolation["cgroup_sha256"], "isolation.cgroup_sha256")
    source_postcheck = _validate_postcheck(preimage["source_postcheck"], "Source postcheck")
    snapshot_postcheck = _validate_postcheck(
        preimage["snapshot_postcheck"], "Snapshot postcheck"
    )
    started_at = _timestamp(preimage["started_at"], "started_at")
    completed_at = _timestamp(preimage["completed_at"], "completed_at")
    if completed_at < started_at:
        raise VerifierProtocolError("Verifier wall-clock interval is invalid")
    monotonic_started = _positive_int(
        preimage["started_monotonic_ns"], "started_monotonic_ns"
    )
    monotonic_completed = _positive_int(
        preimage["completed_monotonic_ns"], "completed_monotonic_ns"
    )
    if monotonic_completed < monotonic_started:
        raise VerifierProtocolError("Verifier monotonic interval is invalid")
    result = preimage["result"]
    failure_code = preimage["failure_code"]
    if result not in {"passed", "failed"}:
        raise VerifierProtocolError("Verifier result is invalid")
    if failure_code is not None:
        _identifier(failure_code, "failure_code")
    if result == "passed":
        if (
            failure_code is not None
            or not source_postcheck["passed"]
            or not snapshot_postcheck["passed"]
            or any(
                command["exit_code"] != 0
                or command["timed_out"]
                or command["output_truncated"]
                for command in commands
            )
        ):
            raise VerifierProtocolError("Passed verifier result contradicts its evidence")
    elif failure_code is None:
        raise VerifierProtocolError("Failed verifier result requires a failure_code")

    if dispatch is not None:
        validated_dispatch = validate_dispatch(dispatch, now=dispatch["issued_at"])
        for key in (
            "dispatch_event_hash",
            "ledger_head_hash",
            "workspace_id",
            "task_id",
            "attempt",
            "actor",
            "run_id",
            "source",
            "verifier_manifest_sha256",
            "validation_contract_sha256",
        ):
            if preimage[key] != validated_dispatch[key]:
                raise VerifierProtocolError(
                    f"Verifier execution preimage does not match dispatch field {key}"
                )
    return preimage


def unsigned_receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    _exact_object(receipt, RECEIPT_KEYS, "Verifier receipt")
    return {key: receipt[key] for key in RECEIPT_KEYS if key != "final_signature_b64"}


def validate_receipt_envelope(
    document: Any,
    *,
    dispatch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = _exact_object(document, RECEIPT_KEYS, "Verifier receipt")
    if (
        receipt["schema_version"] != VERIFIER_SCHEMA_VERSION
        or receipt["protocol_id"] != VERIFIER_PROTOCOL_ID
        or receipt["kind"] != "verification-receipt"
        or receipt["domain"] != VERIFIER_RECEIPT_DOMAIN
        or receipt["algorithm"] != VERIFIER_SIGNATURE_ALGORITHM
    ):
        raise VerifierProtocolError("Verifier receipt identity is invalid")
    _sha256(receipt["public_key_sha256"], "public_key_sha256")
    preimage = validate_execution_preimage(
        receipt["execution_preimage"], dispatch=dispatch
    )
    preimage_sha256 = canonical_json_sha256(preimage)
    if receipt["execution_preimage_sha256"] != preimage_sha256:
        raise VerifierProtocolError("Verifier execution preimage hash is invalid")
    _signature(receipt["execution_signature_b64"], "execution_signature_b64")
    cleanup_proof = receipt["cleanup_proof"]
    try:
        cleanup_payload = validate_broker_envelope(
            cleanup_proof,
            kind="snapshot-cleaned",
        )
    except SnapshotBrokerError as exc:
        raise VerifierProtocolError("Verifier cleanup proof is malformed") from exc
    if receipt["cleanup_proof_sha256"] != canonical_json_sha256(cleanup_proof):
        raise VerifierProtocolError("Verifier cleanup proof hash is invalid")
    for key in ("task_id", "attempt", "actor", "run_id"):
        if cleanup_payload[key] != preimage[key]:
            raise VerifierProtocolError(
                f"Verifier cleanup proof does not match execution field {key}"
            )
    if cleanup_payload["receipt_preimage_sha256"] != preimage_sha256:
        raise VerifierProtocolError(
            "Verifier cleanup proof does not bind the execution preimage"
        )
    sealed_at = _timestamp(receipt["sealed_at"], "sealed_at")
    if sealed_at < _timestamp(preimage["completed_at"], "completed_at"):
        raise VerifierProtocolError("Verifier receipt was sealed before execution ended")
    _signature(receipt["final_signature_b64"], "final_signature_b64")
    return receipt
