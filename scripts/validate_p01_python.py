#!/usr/bin/env python3
"""Fail-closed Phase 1 known-answer and production-evidence validator.

The only caller supplied values are selectors for already signed facts: the
source commit and the sequence/hash of one ``release.evidence_collected``
ledger event.  Policy, expected results, archive locations, and test counts
are deliberately not configurable from the command line.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import unittest
import urllib.parse
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

PHASE_IDS = [
    "P01-TRUTH",
    "P02-ORCHESTRATION",
    "P03-EVIDENCE",
    "P04-WORLD",
    "P05-FINANCE",
    "P06-TWIN",
    "P07-WORKSPACE",
    "P08-CORE",
    "P09-HARNESS",
    "P10-COGNIBOARD",
    "P11-RELEASE",
]
P01_TASK_ID = "P01-TRUTH"
PRODUCTION_ORIGIN = "https://cogni-os-orchestrator.pages.dev"
PRODUCTION_ENDPOINTS = {
    "health": f"{PRODUCTION_ORIGIN}/api/health",
    "snapshot": f"{PRODUCTION_ORIGIN}/api/snapshot",
}
CLOUDFLARE_PROJECT = "cogni-os-orchestrator"
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
EXPECTED_PYTHON_TESTS = 290
EXPECTED_TEST_INVENTORY_SHA256 = (
    "8da3591f044e01910bd7df1dd2d68b52677ee4f3923298fe51a45210e039b39c"
)
T001_ORIGINAL_SEQUENCE = 9
T001_ORIGINAL_HASH = "fefc108428d76fa50ddb254e463c58e7e19849145c9f309bbc856fb84de83a78"
T001_RESTATEMENT_SEQUENCE = 10
T001_RESTATEMENT_REASON = "worker와 verifier가 같은 canonical model family이므로 독립 검증 요건을 충족하지 않음"
OPERATIONAL_PREFIXES = (
    "archive/",
    "ledger/",
    "reports/",
    "runs/",
    "submissions/",
    "tasks/",
)
ARTIFACT_FILES = {
    "production-health-body": "production_health.body.json",
    "production-health-capture": "production_health.capture.json",
    "production-snapshot-body": "production_snapshot.body.json",
    "production-snapshot-capture": "production_snapshot.capture.json",
    "cloudflare-deployment-evidence": "cloudflare_deployment.json",
    "cloudflare-rollback-target-evidence": "cloudflare_rollback_target.json",
    "cloudflare-rollback-dry-run-receipt": "cloudflare_rollback_dry_run.json",
    "cloudflare-current-deployment-body": "cloudflare_current_deployment.body.json",
    "cloudflare-current-deployment-capture": "cloudflare_current_deployment.capture.json",
    "cloudflare-current-project-body": "cloudflare_current_project.body.json",
    "cloudflare-current-project-capture": "cloudflare_current_project.capture.json",
    "cloudflare-rollback-deployment-body": "cloudflare_rollback_deployment.body.json",
    "cloudflare-rollback-deployment-capture": "cloudflare_rollback_deployment.capture.json",
    "cloudflare-rollback-project-body": "cloudflare_rollback_project.body.json",
    "cloudflare-rollback-project-capture": "cloudflare_rollback_project.capture.json",
}
SELECTED_HEADERS = {
    "cache-control",
    "cf-cache-status",
    "cf-ray",
    "content-length",
    "content-type",
    "date",
    "etag",
    "last-modified",
    "x-cogni-body-sha256",
    "x-cogni-data-state",
    "x-cogni-sequence",
}


class ValidationError(ValueError):
    """Raised when immutable Phase 1 evidence fails closed."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_git_commit(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 40
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _expect_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValidationError(f"{label} schema is not exact")
    return value


def _json_object(value: bytes, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} is not UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise ValidationError(f"{label} must be a JSON object")
    return decoded


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ValidationError(f"{label} timestamp is invalid")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        result = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValidationError(f"{label} timestamp is invalid") from exc
    if result.tzinfo is None:
        raise ValidationError(f"{label} timestamp has no timezone")
    return result


def _safe_relative_parts(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValidationError("archive path is missing or uses a backslash")
    if value.startswith("/") or value.endswith("/") or "\x00" in value:
        raise ValidationError("archive path is not workspace-relative")
    parts = tuple(value.split("/"))
    if any(
        not part
        or part in {".", ".."}
        or ":" in part
        or any(ord(character) < 32 for character in part)
        for part in parts
    ):
        raise ValidationError("archive path contains an unsafe component")
    return parts


def _is_reparse_or_link(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = int(getattr(info, "st_file_attributes", 0))
    return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def _checked_path(root: Path, relative: str, *, directory: bool) -> Path:
    parts = _safe_relative_parts(relative)
    current = root
    try:
        root_info = current.lstat()
    except FileNotFoundError as exc:
        raise ValidationError("workspace root is missing") from exc
    if _is_reparse_or_link(root_info) or not stat.S_ISDIR(root_info.st_mode):
        raise ValidationError("workspace root is not a regular directory")
    for index, component in enumerate(parts):
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            raise ValidationError(f"archive path is missing: {relative}") from exc
        if _is_reparse_or_link(info):
            raise ValidationError("archive path crosses a symlink or reparse point")
        final = index == len(parts) - 1
        expected_mode = stat.S_ISDIR if directory or not final else stat.S_ISREG
        if not expected_mode(info.st_mode):
            raise ValidationError("archive path has an unexpected file type")
    return current


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_mode),
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
    )


def _read_bounded_bytes(
    root: Path,
    relative: str,
    *,
    maximum: int = MAX_EVIDENCE_BYTES,
) -> bytes:
    """Read one regular archive file once and detect path/content replacement."""

    parts = _safe_relative_parts(relative)
    path = _checked_path(root, relative, directory=False)
    chain_paths = [root]
    for component in parts[:-1]:
        chain_paths.append(chain_paths[-1] / component)
    chain_before = {
        chain_path: _stat_identity(chain_path.lstat()) for chain_path in chain_paths
    }
    before = path.lstat()
    if before.st_size < 0 or before.st_size > maximum:
        raise ValidationError("archive artifact exceeds the size bound")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValidationError("archive artifact could not be safely opened") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(
            before
        ):
            raise ValidationError("archive artifact changed before reading")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            value = handle.read(maximum + 1)
        after_handle = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = path.lstat()
    except FileNotFoundError as exc:
        raise ValidationError("archive artifact disappeared after reading") from exc
    if (
        len(value) > maximum
        or len(value) != before.st_size
        or _is_reparse_or_link(after_path)
        or _stat_identity(after_handle) != _stat_identity(before)
        or _stat_identity(after_path) != _stat_identity(before)
    ):
        raise ValidationError("archive artifact changed while reading")
    for chain_path, expected_identity in chain_before.items():
        try:
            chain_info = chain_path.lstat()
        except FileNotFoundError as exc:
            raise ValidationError("archive directory changed while reading") from exc
        if (
            _is_reparse_or_link(chain_info)
            or not stat.S_ISDIR(chain_info.st_mode)
            or _stat_identity(chain_info) != expected_identity
        ):
            raise ValidationError("archive directory changed while reading")
    return value


def _exact_directory_names(root: Path, relative: str, expected: set[str]) -> None:
    directory = _checked_path(root, relative, directory=True)
    observed: set[str] = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.is_symlink():
                raise ValidationError("evidence directory contains a link")
            info = entry.stat(follow_symlinks=False)
            if _is_reparse_or_link(info) or not stat.S_ISREG(info.st_mode):
                raise ValidationError("evidence directory contains a non-regular file")
            observed.add(entry.name)
    if observed != expected:
        raise ValidationError("evidence directory has extra or missing files")


def _run_git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        timeout=15,
    )
    return result.stdout


def _git_commit(root: Path) -> str:
    return (
        _run_git(root, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    )


def _source_clean_before_import(root: Path) -> bool:
    tracked = _run_git(root, "diff", "--name-only", "-z", "HEAD", "--")
    untracked = _run_git(root, "ls-files", "--others", "--exclude-standard", "-z")
    paths = {
        value.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        for value in (*tracked.split(b"\0"), *untracked.split(b"\0"))
        if value
    }
    return not [path for path in paths if not path.startswith(OPERATIONAL_PREFIXES)]


def _load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValidationError(f"validation module could not be loaded: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_tracked_publisher(root: Path) -> Any:
    return _load_module(
        root / "scripts" / "publish_monitor_snapshot.py",
        "_cogni_p01_publisher",
    )


def _iter_tests(suite: unittest.TestSuite) -> Iterable[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_tests(item)
        else:
            yield item


def _run_tests(root: Path) -> dict[str, Any]:
    integration_policy = _load_module(
        root / "scripts" / "validate_snapshot_broker_integration_inventory.py",
        "_cogni_broker_integration_inventory",
    )
    integration = integration_policy.validate_static_contract(root)
    if (
        integration.get("proof_scope") != "broker-snapshot-only"
        or integration.get("phase1_release_eligible") is not False
        or integration.get("validator_execution_trusted") is not False
    ):
        raise ValidationError("broker-only integration delegation is unsafe")
    suite = integration_policy.build_portable_suite(root)
    identifiers = sorted(test.id() for test in _iter_tests(suite))
    inventory_sha256 = _sha256(("\n".join(identifiers) + "\n").encode("utf-8"))
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    return {
        "errors": len(result.errors),
        "failures": len(result.failures),
        "skipped": len(result.skipped),
        "tests_run": result.testsRun,
        "inventory_sha256": inventory_sha256,
    }


def _validate_producer(value: Any, orchestrator: str) -> dict[str, Any]:
    producer = _expect_keys(
        value,
        {
            "schema_version",
            "actor",
            "control_principal",
            "model_family",
            "alias_of",
            "alias_chain",
            "role",
        },
        "release producer",
    )
    if (
        producer["schema_version"] != 1
        or producer["actor"] != orchestrator
        or producer["role"] != "orchestrator"
        or producer["alias_of"] is not None
        or producer["alias_chain"] != []
        or not isinstance(producer["control_principal"], str)
        or not producer["control_principal"]
        or not isinstance(producer["model_family"], str)
        or not producer["model_family"]
    ):
        raise ValidationError("release producer identity is not the conductor")
    return producer


def _validate_actor_capability(
    value: Any,
    *,
    orchestrator: str,
    workspace_id: str | None = None,
    task_attempt: int,
) -> dict[str, Any]:
    receipt = _expect_keys(
        value,
        {
            "schema_version",
            "receipt_type",
            "workspace_id",
            "actor",
            "operation",
            "task_id",
            "run_id",
            "task_attempt",
            "nonce_sha256",
            "key_version",
            "issued_at_epoch",
            "expires_at_epoch",
            "consumed_at_epoch",
            "os_principal_attestation",
            "independent_trust_root",
            "actor_os_isolation_proven",
            "signature_algorithm",
            "signature",
        },
        "actor capability receipt",
    )
    attestation = _expect_keys(
        receipt["os_principal_attestation"],
        {
            "schema_version",
            "provider",
            "principal_sha256",
            "trust_root",
            "independent_trust_root",
            "actor_os_isolation_proven",
        },
        "actor capability OS principal attestation",
    )
    issued_at = receipt["issued_at_epoch"]
    expires_at = receipt["expires_at_epoch"]
    consumed_at = receipt["consumed_at_epoch"]
    if (
        receipt["schema_version"] != 2
        or receipt["receipt_type"] != "actor-capability-consumption"
        or (workspace_id is not None and receipt["workspace_id"] != workspace_id)
        or not isinstance(receipt["workspace_id"], str)
        or not receipt["workspace_id"]
        or receipt["actor"] != orchestrator
        or receipt["operation"] != "release.evidence.collect"
        or receipt["task_id"] != P01_TASK_ID
        or receipt["run_id"] is not None
        or receipt["task_attempt"] != task_attempt
        or not _is_sha256(receipt["nonce_sha256"])
        or not isinstance(receipt["key_version"], int)
        or isinstance(receipt["key_version"], bool)
        or receipt["key_version"] < 1
        or any(
            not isinstance(epoch, int) or isinstance(epoch, bool)
            for epoch in (issued_at, expires_at, consumed_at)
        )
        or not issued_at <= consumed_at < expires_at
        or expires_at - issued_at > 300
        or receipt["independent_trust_root"] is not True
        or receipt["actor_os_isolation_proven"] is not True
        or attestation["schema_version"] != 1
        or not isinstance(attestation["provider"], str)
        or not attestation["provider"]
        or not _is_sha256(attestation["principal_sha256"])
        or not isinstance(attestation["trust_root"], str)
        or not attestation["trust_root"]
        or attestation["independent_trust_root"] is not True
        or attestation["actor_os_isolation_proven"] is not True
        or not isinstance(receipt["signature_algorithm"], str)
        or not receipt["signature_algorithm"]
        or not isinstance(receipt["signature"], str)
        or not receipt["signature"]
    ):
        raise ValidationError("release evidence actor capability is invalid")
    return receipt


def _select_collection_event(
    events: list[dict[str, Any]],
    *,
    sequence: int,
    event_hash: str,
    orchestrator: str,
    expected_commit: str,
) -> dict[str, Any]:
    selected = [event for event in events if event.get("sequence") == sequence]
    if len(selected) != 1:
        raise ValidationError("collection sequence does not select one signed event")
    event = _expect_keys(
        selected[0],
        {
            "sequence",
            "timestamp",
            "actor",
            "action",
            "task_id",
            "payload",
            "previous_hash",
            "event_hash",
            "signature",
        },
        "collection ledger event",
    )
    if (
        event["event_hash"] != event_hash
        or event["actor"] != orchestrator
        or event["action"] != "release.evidence_collected"
        or event["task_id"] != P01_TASK_ID
        or not _is_sha256(event["previous_hash"])
        or not _is_sha256(event["signature"])
    ):
        raise ValidationError("collection ledger event selector or identity is invalid")
    _timestamp(event["timestamp"], "collection event")
    payload = _expect_keys(
        event["payload"],
        {
            "schema_version",
            "producer",
            "actor_capability",
            "source_commit",
            "task_attempt",
            "collection",
        },
        "collection payload",
    )
    _validate_producer(payload["producer"], orchestrator)
    if (
        payload["schema_version"] != 1
        or payload["source_commit"] != expected_commit
        or not isinstance(payload["task_attempt"], int)
        or isinstance(payload["task_attempt"], bool)
        or payload["task_attempt"] < 1
    ):
        raise ValidationError("collection payload provenance is invalid")
    _validate_actor_capability(
        payload["actor_capability"],
        orchestrator=orchestrator,
        task_attempt=payload["task_attempt"],
    )
    return event


def _validate_capture(
    metadata: dict[str, Any],
    body: bytes,
    *,
    endpoint: str,
    filename: str,
) -> dict[str, Any]:
    _expect_keys(
        metadata,
        {
            "schema_version",
            "document_type",
            "method",
            "request_url",
            "final_url",
            "status",
            "fetched_at",
            "tls_verified",
            "tls_policy",
            "headers",
            "body_sha256",
            "body_size_bytes",
            "body_file",
        },
        "HTTP capture",
    )
    headers = metadata["headers"]
    if not isinstance(headers, dict) or not headers or set(headers) - SELECTED_HEADERS:
        raise ValidationError("HTTP capture headers are not allowlisted")
    if not str(headers.get("content-type", "")).lower().startswith("application/json"):
        raise ValidationError("HTTP capture did not record JSON content")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in headers.items()
    ):
        raise ValidationError("HTTP capture headers are malformed")
    if (
        metadata["schema_version"] != 1
        or metadata["document_type"] != "cogni-production-http-capture"
        or metadata["method"] != "GET"
        or metadata["request_url"] != endpoint
        or metadata["final_url"] != endpoint
        or metadata["status"] != 200
        or metadata["tls_verified"] is not True
        or metadata["tls_policy"] != "python-default-ca"
        or metadata["body_sha256"] != _sha256(body)
        or metadata["body_size_bytes"] != len(body)
        or metadata["body_file"] != filename
    ):
        raise ValidationError("HTTP capture is not bound to the archived body")
    _timestamp(metadata["fetched_at"], "HTTP capture")
    if "content-length" in headers and headers["content-length"] != str(len(body)):
        raise ValidationError("HTTP Content-Length does not match the archived body")
    if "x-cogni-body-sha256" in headers and not _is_sha256(
        headers["x-cogni-body-sha256"]
    ):
        raise ValidationError("HTTP response body header is invalid")
    return _json_object(body, "HTTP response body")


def _validate_build_deployment(value: Any, expected_commit: str) -> dict[str, Any]:
    deployment = _expect_keys(
        value,
        {
            "provider",
            "project",
            "environment",
            "source_commit",
            "branch",
            "url",
            "deployment_url",
            "attribution",
        },
        "build deployment",
    )
    if (
        deployment["provider"] != "cloudflare-pages"
        or deployment["project"] != CLOUDFLARE_PROJECT
        or deployment["environment"] != "production"
        or deployment["source_commit"] != expected_commit
        or deployment["branch"] != "main"
        or deployment["url"] != PRODUCTION_ORIGIN
        or not _pages_url(deployment["deployment_url"])
        or deployment["attribution"] != "BUILD_BOUND"
    ):
        raise ValidationError("deployment is not build-bound to the expected commit")
    return deployment


def _validate_release_deployment_binding(
    value: Any, expected_commit: str
) -> dict[str, Any]:
    deployment = _expect_keys(
        value,
        {
            "provider",
            "api_verified",
            "deployment_id",
            "deployment_url",
            "canonical_url",
            "source_commit",
        },
        "release deployment",
    )
    deployment_id = deployment["deployment_id"]
    if (
        deployment["provider"] != "cloudflare-pages"
        or deployment["api_verified"] is not True
        or deployment["canonical_url"] != PRODUCTION_ORIGIN
        or deployment["source_commit"] != expected_commit
        or not _pages_url(deployment["deployment_url"])
        or not isinstance(deployment_id, str)
        or not 1 <= len(deployment_id) <= 64
        or deployment_id[0]
        not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
            for character in deployment_id
        )
    ):
        raise ValidationError("release deployment binding is invalid")
    return deployment


def _validate_health(value: dict[str, Any], expected_commit: str) -> dict[str, Any]:
    _expect_keys(
        value, {"ok", "service", "state", "checks", "deployment", "timestamp"}, "health"
    )
    checks = _expect_keys(
        value["checks"],
        {
            "runtime_configuration_ready",
            "d1_binding",
            "storage_state",
            "storage_schema_verified",
            "workspace_id",
            "publisher_keyring",
            "publisher_keys",
            "deployment_attribution",
            "build_attribution_ready",
            "operational_ingest_ready",
            "release_attribution_ready",
            "release_evidence_state",
            "minimum_release_snapshot_schema",
        },
        "health checks",
    )
    if (
        value["ok"] is not True
        or value["service"] != "cogni-os-monitoring"
        or value["state"] != "CONFIGURED"
        or checks["runtime_configuration_ready"] is not True
        or checks["d1_binding"] is not True
        or checks["storage_state"] != "READY"
        or checks["storage_schema_verified"] is not True
        or checks["workspace_id"] is not True
        or checks["publisher_keyring"] is not True
        or not isinstance(checks["publisher_keys"], int)
        or isinstance(checks["publisher_keys"], bool)
        or checks["publisher_keys"] < 1
        or checks["deployment_attribution"] != "BUILD_BOUND"
        or checks["build_attribution_ready"] is not True
        or checks["operational_ingest_ready"] is not True
        or checks["release_attribution_ready"] is not False
        or checks["release_evidence_state"] != "API_EVIDENCE_REQUIRED"
        or checks["minimum_release_snapshot_schema"] != "1.2"
    ):
        raise ValidationError("production health is not configured")
    _timestamp(value["timestamp"], "health")
    return _validate_build_deployment(value["deployment"], expected_commit)


def _validate_snapshot(
    value: dict[str, Any],
    *,
    expected_commit: str,
    workspace_id: str,
    events: list[dict[str, Any]],
    collection_sequence: int,
    task_attempt: int,
) -> dict[str, Any]:
    _expect_keys(
        value,
        {
            "schema_version",
            "system",
            "workspace_id",
            "workspace_name",
            "sequence",
            "observed_at",
            "collector",
            "data_classification",
            "orchestrator",
            "tasks_summary",
            "roadmap",
            "agents",
            "tasks",
            "ledger_events",
            "ledger",
            "gpus",
            "gpu_policy",
            "resources",
            "alerts",
            "release_gate",
            "source",
            "timestamp",
            "monitoring",
            "deployment",
            "release_deployment",
        },
        "production snapshot",
    )
    if (
        value["schema_version"] != "1.2"
        or value["system"] != "Cogni-OS Operations"
        or value["workspace_id"] != workspace_id
        or value["data_classification"] != "operational-metadata-only"
        or not isinstance(value["sequence"], int)
        or isinstance(value["sequence"], bool)
        or value["sequence"] < 1
    ):
        raise ValidationError("snapshot top-level provenance is invalid")
    observed_at = _timestamp(value["observed_at"], "snapshot observed_at")
    _timestamp(value["timestamp"], "snapshot response")

    collector = _expect_keys(
        value["collector"],
        {"id", "version", "host", "platform", "attribution"},
        "collector",
    )
    attribution = _expect_keys(
        collector["attribution"],
        {
            "source_commit",
            "source_tree_clean",
            "source_tree_fingerprint",
            "entrypoint_sha256",
        },
        "collector attribution",
    )
    if (
        collector["id"] != "cogni-monitor-publisher"
        or not all(
            isinstance(collector[field], str) and collector[field]
            for field in ("version", "host", "platform")
        )
        or attribution["source_commit"] != expected_commit
        or attribution["source_tree_clean"] is not True
        or not _is_sha256(attribution["source_tree_fingerprint"])
        or not _is_sha256(attribution["entrypoint_sha256"])
    ):
        raise ValidationError("collector is not bound to a clean expected commit")

    orchestrator = _expect_keys(
        value["orchestrator"], {"id", "role", "status"}, "snapshot orchestrator"
    )
    if (
        orchestrator["id"] != "codex"
        or orchestrator["role"] != "conductor"
        or orchestrator["status"] != "ACCOUNTABLE_NOT_ATTESTED"
    ):
        raise ValidationError("snapshot orchestrator role is not accountable")

    monitoring = _expect_keys(
        value["monitoring"],
        {
            "state",
            "reason",
            "signature_verified",
            "sequence",
            "age_seconds",
            "observed_at",
            "received_at",
            "body_sha256",
            "max_age_seconds",
        },
        "monitoring envelope",
    )
    if (
        monitoring["state"] != "LIVE"
        or monitoring["signature_verified"] is not True
        or monitoring["sequence"] != value["sequence"]
        or monitoring["observed_at"] != value["observed_at"]
        or not isinstance(monitoring["age_seconds"], (int, float))
        or isinstance(monitoring["age_seconds"], bool)
        or monitoring["age_seconds"] < 0
        or not isinstance(monitoring["max_age_seconds"], (int, float))
        or monitoring["age_seconds"] > monitoring["max_age_seconds"]
        or not _is_sha256(monitoring["body_sha256"])
    ):
        raise ValidationError("snapshot is not fresh, signed, and LIVE")
    if _timestamp(monitoring["observed_at"], "monitoring observed_at") != observed_at:
        raise ValidationError("monitoring observation time is inconsistent")
    _timestamp(monitoring["received_at"], "monitoring received_at")
    build_deployment = _validate_build_deployment(value["deployment"], expected_commit)
    release_deployment = _validate_release_deployment_binding(
        value["release_deployment"], expected_commit
    )
    if release_deployment["deployment_url"] != build_deployment["deployment_url"]:
        raise ValidationError(
            "snapshot release deployment is not the build serving the canonical URL"
        )

    source = _expect_keys(
        value["source"],
        {
            "git_commit",
            "status_scope",
            "tree_clean",
            "tree_fingerprint",
            "change_count",
            "operational_state",
            "task_projection_audit",
        },
        "snapshot source",
    )
    operational = _expect_keys(
        source["operational_state"],
        {
            "valid",
            "change_count",
            "fingerprint",
            "unclassified_count",
            "unclassified_fingerprint",
            "reference_count",
            "conflict_count",
            "missing_count",
            "unbound_count",
            "hash_mismatch_count",
            "audit_fingerprint",
        },
        "operational evidence audit",
    )
    projection = _expect_keys(
        source["task_projection_audit"],
        {"valid", "events_count", "projected_count", "actual_count", "mismatch_count"},
        "task projection audit",
    )
    zero_fields = (
        "unclassified_count",
        "conflict_count",
        "missing_count",
        "unbound_count",
        "hash_mismatch_count",
    )
    if (
        source["git_commit"] != expected_commit
        or source["status_scope"] != "trusted-source-v1"
        or source["tree_clean"] is not True
        or source["change_count"] != 0
        or not _is_sha256(source["tree_fingerprint"])
        or operational["valid"] is not True
        or not all(
            _is_nonnegative_int(operational[field])
            for field in (
                "change_count",
                "unclassified_count",
                "reference_count",
                "conflict_count",
                "missing_count",
                "unbound_count",
                "hash_mismatch_count",
            )
        )
        or any(operational[field] != 0 for field in zero_fields)
        or not all(
            _is_sha256(operational[field])
            for field in (
                "fingerprint",
                "unclassified_fingerprint",
                "audit_fingerprint",
            )
        )
        or projection["valid"] is not True
        or not all(
            _is_nonnegative_int(projection[field])
            for field in (
                "events_count",
                "projected_count",
                "actual_count",
                "mismatch_count",
            )
        )
        or projection["mismatch_count"] != 0
    ):
        raise ValidationError("snapshot source or operational state is not clean")

    ledger = _expect_keys(
        value["ledger"],
        {"status", "valid", "events", "head", "signed"},
        "snapshot ledger",
    )
    if (
        ledger["status"] != "VERIFIED"
        or ledger["valid"] is not True
        or ledger["signed"] is not True
        or not isinstance(ledger["events"], int)
        or isinstance(ledger["events"], bool)
        or ledger["events"] < 1
        or ledger["events"] >= collection_sequence
        or ledger["events"] > len(events)
        or not _is_sha256(ledger["head"])
        or events[ledger["events"] - 1].get("event_hash") != ledger["head"]
    ):
        raise ValidationError("snapshot ledger proof is not a signed prior head")

    policy = _expect_keys(
        value["gpu_policy"],
        {
            "allowed_ids",
            "denied_ids",
            "telemetry_state",
            "violating_ids",
            "measurement_complete",
            "source_states",
            "evidence_counts",
        },
        "GPU policy",
    )
    source_states = _expect_keys(
        policy["source_states"],
        {"telemetry", "processes", "containers", "scheduler"},
        "GPU evidence source states",
    )
    evidence_counts = _expect_keys(
        policy["evidence_counts"],
        {"processes", "container_claims", "scheduler_reservations"},
        "GPU evidence counts",
    )
    if (
        policy["allowed_ids"] != [0, 1, 2, 3, 4, 5]
        or policy["denied_ids"] != [6, 7]
        or policy["violating_ids"] != []
        or policy["telemetry_state"] != "MEASURED"
        or policy["measurement_complete"] is not True
        or any(state != "MEASURED" for state in source_states.values())
        or any(not _is_nonnegative_int(count) for count in evidence_counts.values())
        or not isinstance(value["gpus"], list)
        or any(
            not isinstance(gpu, dict) or gpu.get("id") not in range(6)
            for gpu in value["gpus"]
        )
    ):
        raise ValidationError("snapshot violates the GPU 0-5-only policy")
    for gpu in value["gpus"]:
        _expect_keys(
            gpu,
            {
                "id",
                "name",
                "utilization",
                "vram_used_gib",
                "vram_total_gib",
                "temperature_c",
                "power_w",
            },
            "GPU telemetry",
        )

    tasks = value["tasks"]
    if not isinstance(tasks, list):
        raise ValidationError("snapshot tasks are invalid")
    task_by_id: dict[str, dict[str, Any]] = {}
    for task in tasks:
        _expect_keys(
            task,
            {
                "id",
                "title",
                "owner",
                "state",
                "raw_state",
                "historical_state",
                "historical_trusted",
                "verified_source_commit",
                "current_release_state",
                "current_release_validated",
                "progress",
                "next_step",
                "updated_at",
                "attempt",
            },
            "snapshot task",
        )
        if not isinstance(task["id"], str) or task["id"] in task_by_id:
            raise ValidationError("snapshot task identity is invalid")
        task_by_id[task["id"]] = task
    p01 = task_by_id.get(P01_TASK_ID)
    if (
        not p01
        or p01["state"] != "submitted"
        or p01["raw_state"] != "submitted"
        or p01["historical_state"] != "submitted"
        or p01["historical_trusted"] is not False
        or p01["verified_source_commit"] is not None
        or p01["current_release_state"] != "submitted"
        or p01["current_release_validated"] is not False
        or p01["attempt"] != task_attempt
    ):
        raise ValidationError("snapshot does not show the signed submitted P01 attempt")

    summary = _expect_keys(
        value["tasks_summary"],
        {
            "total",
            "pending",
            "claimed",
            "running",
            "blocked",
            "submitted",
            "trusted_verified",
            "verification_disputed",
            "verification_revoked",
            "rejected",
            "current_release_validated",
            "completion_percentage",
            "progress_basis",
        },
        "task summary",
    )
    derived_counts = {
        "pending": 0,
        "claimed": 0,
        "running": 0,
        "blocked": 0,
        "submitted": 0,
        "trusted_verified": 0,
        "verification_disputed": 0,
        "verification_revoked": 0,
        "rejected": 0,
    }
    for task in tasks:
        state = task["state"]
        if state in {"verified", "archived"}:
            derived_counts["trusted_verified"] += 1
        elif state in derived_counts:
            derived_counts[state] += 1
    if (
        summary["total"] != len(tasks)
        or any(summary[field] != count for field, count in derived_counts.items())
        or summary["trusted_verified"] != 0
        or summary["submitted"] < 1
        or summary["verification_disputed"] < 1
        or summary["current_release_validated"] != 0
        or summary["progress_basis"] != "historically-trusted-ledger-task-states"
    ):
        raise ValidationError("snapshot task summary is not Phase 1 fail-closed state")

    roadmap = _expect_keys(
        value["roadmap"],
        {
            "schema_version",
            "total",
            "trusted_complete",
            "current_release_validated",
            "progress_percent",
            "progress_basis",
            "phases",
        },
        "roadmap",
    )
    phases = roadmap["phases"]
    if (
        roadmap["schema_version"] != 1
        or roadmap["total"] != len(PHASE_IDS)
        or roadmap["trusted_complete"] != 0
        or roadmap["current_release_validated"] != 0
        or roadmap["progress_percent"] != 0.0
        or roadmap["progress_basis"] != "historically-trusted-roadmap-task-states"
        or not isinstance(phases, list)
        or len(phases) != len(PHASE_IDS)
    ):
        raise ValidationError("roadmap is not the canonical 0-of-11 Phase 1 state")
    for index, phase in enumerate(phases):
        _expect_keys(
            phase,
            {
                "id",
                "title",
                "state",
                "trusted_complete",
                "verified_source_commit",
                "current_release_state",
                "current_release_validated",
                "prerequisites",
            },
            "roadmap phase",
        )
        expected_prerequisites = [] if index == 0 else [PHASE_IDS[index - 1]]
        expected_state = "submitted" if index == 0 else "pending"
        if (
            phase["id"] != PHASE_IDS[index]
            or phase["prerequisites"] != expected_prerequisites
            or phase["trusted_complete"] is not False
            or phase["state"] != expected_state
            or phase["verified_source_commit"] is not None
            or phase["current_release_state"] != expected_state
            or phase["current_release_validated"] is not False
        ):
            raise ValidationError("roadmap phase order or state is not canonical")

    gate = _expect_keys(
        value["release_gate"], {"status", "reasons", "evidence_sha256"}, "release gate"
    )
    if (
        gate["status"] != "NO_GO"
        or gate["evidence_sha256"] is not None
        or not isinstance(gate["reasons"], list)
        or not gate["reasons"]
        or any(not isinstance(reason, str) or not reason for reason in gate["reasons"])
    ):
        raise ValidationError("Phase 1 must retain a reasoned global NO_GO gate")
    if not isinstance(value["alerts"], list):
        raise ValidationError("snapshot alerts must be a list")
    allowed_critical = {"UNTRUSTED_VERIFICATION"}
    for alert in value["alerts"]:
        _expect_keys(
            alert,
            {"severity", "code", "message", "observed_at"},
            "snapshot alert",
        )
        if (
            alert["severity"] not in {"info", "warning", "critical"}
            or not isinstance(alert["code"], str)
            or not alert["code"]
            or not isinstance(alert["message"], str)
            or not alert["message"]
        ):
            raise ValidationError("snapshot alert content is invalid")
        _timestamp(alert["observed_at"], "snapshot alert")
        if alert["severity"] == "critical" and alert["code"] not in allowed_critical:
            raise ValidationError(
                "snapshot contains an unexpected critical integrity alert"
            )
    return {
        "build_deployment": build_deployment,
        "release_deployment": release_deployment,
    }


def _pages_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urllib.parse.urlsplit(value)
    return bool(
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
        and parsed.port is None
        and not parsed.query
        and not parsed.fragment
        and parsed.path in {"", "/"}
        and (parsed.hostname or "").lower().endswith(f".{CLOUDFLARE_PROJECT}.pages.dev")
    )


def _normalized_pages_url(value: Any) -> str:
    if not _pages_url(value):
        raise ValidationError("Cloudflare raw deployment URL is invalid")
    parsed = urllib.parse.urlsplit(value)
    return f"https://{(parsed.hostname or '').lower()}"


def _cloudflare_raw_result(
    metadata: dict[str, Any],
    body: bytes,
    *,
    endpoint: str,
    resource: str,
) -> dict[str, Any]:
    _expect_keys(
        metadata,
        {
            "schema_version",
            "document_type",
            "method",
            "resource",
            "request_url",
            "final_url",
            "status",
            "fetched_at",
            "tls_verified",
            "tls_policy",
            "headers",
            "body_sha256",
            "body_size_bytes",
        },
        "Cloudflare raw capture",
    )
    headers = metadata["headers"]
    if (
        metadata["schema_version"] != 1
        or metadata["document_type"] != "cogni-cloudflare-http-capture"
        or metadata["method"] != "GET"
        or metadata["resource"] != resource
        or metadata["request_url"] != endpoint
        or metadata["final_url"] != endpoint
        or metadata["status"] != 200
        or metadata["tls_verified"] is not True
        or metadata["tls_policy"] != "python-default-ca"
        or not isinstance(headers, dict)
        or set(headers) - SELECTED_HEADERS
        or not str(headers.get("content-type", ""))
        .lower()
        .startswith("application/json")
        or metadata["body_sha256"] != _sha256(body)
        or metadata["body_size_bytes"] != len(body)
    ):
        raise ValidationError("Cloudflare raw capture binding is invalid")
    _timestamp(metadata["fetched_at"], "Cloudflare raw capture")
    for name, value in headers.items():
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or "\r" in value
            or "\n" in value
            or len(value.encode("utf-8")) > 4096
        ):
            raise ValidationError("Cloudflare raw capture header is invalid")
    envelope = _json_object(body, "Cloudflare raw response")
    if envelope.get("success") is not True or not isinstance(
        envelope.get("result"), dict
    ):
        raise ValidationError("Cloudflare raw API envelope is invalid")
    return envelope["result"]


def _assert_cloudflare_raw_derivation(
    derived: dict[str, Any],
    *,
    account_id: str,
    deployment_id: str,
    deployment_metadata: dict[str, Any],
    deployment_body: bytes,
    project_metadata: dict[str, Any],
    project_body: bytes,
) -> None:
    deployment_endpoint = (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{account_id}/pages/projects/{CLOUDFLARE_PROJECT}/deployments/"
        f"{deployment_id}"
    )
    project_endpoint = (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{account_id}/pages/projects/{CLOUDFLARE_PROJECT}"
    )
    result = _cloudflare_raw_result(
        deployment_metadata,
        deployment_body,
        endpoint=deployment_endpoint,
        resource="pages-deployment",
    )
    project = _cloudflare_raw_result(
        project_metadata,
        project_body,
        endpoint=project_endpoint,
        resource="pages-project",
    )
    stage = result.get("latest_stage")
    trigger = result.get("deployment_trigger")
    trigger_metadata = trigger.get("metadata") if isinstance(trigger, dict) else None
    canonical = project.get("canonical_deployment")
    canonical_trigger = (
        canonical.get("deployment_trigger") if isinstance(canonical, dict) else None
    )
    canonical_metadata = (
        canonical_trigger.get("metadata")
        if isinstance(canonical_trigger, dict)
        else None
    )
    if not all(
        isinstance(value, dict)
        for value in (stage, trigger, trigger_metadata, canonical, canonical_metadata)
    ):
        raise ValidationError("Cloudflare raw provenance is incomplete")
    expected = {
        "schema_version": 1,
        "document_type": "cloudflare-pages-deployment-evidence",
        "attestation_level": "CLOUDFLARE_API_VERIFIED",
        "provider": "cloudflare-pages",
        "account_id": account_id,
        "project_name": result.get("project_name"),
        "deployment_id": result.get("id"),
        "short_id": str(result.get("short_id", ""))[:64],
        "environment": result.get("environment"),
        "url": _normalized_pages_url(result.get("url")),
        "created_on": result.get("created_on"),
        "modified_on": result.get("modified_on"),
        "is_skipped": bool(result.get("is_skipped", False)),
        "source_commit": trigger_metadata.get("commit_hash"),
        "trigger": {
            "type": str(trigger.get("type", ""))[:64],
            "branch": trigger_metadata.get("branch"),
            "commit_dirty": False,
        },
        "latest_stage": {
            "name": str(stage.get("name", ""))[:64],
            "status": stage.get("status"),
            "started_on": str(stage.get("started_on", ""))[:64],
            "ended_on": str(stage.get("ended_on", ""))[:64],
        },
        "api_request": deployment_metadata,
        "production_alias": {
            "api_verified": True,
            "canonical_url": PRODUCTION_ORIGIN,
            "deployment_id": canonical.get("id"),
            "deployment_url": _normalized_pages_url(canonical.get("url")),
            "source_commit": canonical_metadata.get("commit_hash"),
            "api_request": project_metadata,
        },
    }
    if derived != expected or expected["deployment_id"] != deployment_id:
        raise ValidationError(
            "Cloudflare derived evidence does not match archived raw responses"
        )


def _validate_cloudflare_deployment(
    value: dict[str, Any], expected_commit: str, *, require_current_alias: bool = False
) -> dict[str, Any]:
    _expect_keys(
        value,
        {
            "schema_version",
            "document_type",
            "attestation_level",
            "provider",
            "account_id",
            "project_name",
            "deployment_id",
            "short_id",
            "environment",
            "url",
            "created_on",
            "modified_on",
            "is_skipped",
            "source_commit",
            "trigger",
            "latest_stage",
            "api_request",
            "production_alias",
        },
        "Cloudflare deployment evidence",
    )
    trigger = _expect_keys(
        value["trigger"], {"type", "branch", "commit_dirty"}, "Cloudflare trigger"
    )
    stage = _expect_keys(
        value["latest_stage"],
        {"name", "status", "started_on", "ended_on"},
        "Cloudflare stage",
    )
    request = _expect_keys(
        value["api_request"],
        {
            "schema_version",
            "document_type",
            "method",
            "resource",
            "request_url",
            "final_url",
            "fetched_at",
            "tls_verified",
            "tls_policy",
            "status",
            "headers",
            "body_sha256",
            "body_size_bytes",
        },
        "Cloudflare API receipt",
    )
    production_alias = _expect_keys(
        value["production_alias"],
        {
            "api_verified",
            "canonical_url",
            "deployment_id",
            "deployment_url",
            "source_commit",
            "api_request",
        },
        "Cloudflare production alias",
    )
    alias_request = _expect_keys(
        production_alias["api_request"],
        {
            "schema_version",
            "document_type",
            "method",
            "resource",
            "request_url",
            "final_url",
            "fetched_at",
            "tls_verified",
            "tls_policy",
            "status",
            "headers",
            "body_sha256",
            "body_size_bytes",
        },
        "Cloudflare project API receipt",
    )
    if (
        value["schema_version"] != 1
        or value["document_type"] != "cloudflare-pages-deployment-evidence"
        or value["attestation_level"] != "CLOUDFLARE_API_VERIFIED"
        or value["provider"] != "cloudflare-pages"
        or not isinstance(value["account_id"], str)
        or len(value["account_id"]) != 32
        or not all(character in "0123456789abcdef" for character in value["account_id"])
        or value["project_name"] != CLOUDFLARE_PROJECT
        or value["environment"] != "production"
        or value["source_commit"] != expected_commit
        or value["is_skipped"] is not False
        or not _pages_url(value["url"])
        or not isinstance(trigger["type"], str)
        or not trigger["type"]
        or trigger["branch"] != "main"
        or trigger["commit_dirty"] is not False
        or stage["status"] != "success"
        or request["method"] != "GET"
        or request["resource"] != "pages-deployment"
        or request["tls_verified"] is not True
        or request["status"] != 200
        or not _is_sha256(request["body_sha256"])
        or not isinstance(request["body_size_bytes"], int)
        or isinstance(request["body_size_bytes"], bool)
        or request["body_size_bytes"] < 1
        or production_alias["api_verified"] is not True
        or production_alias["canonical_url"] != PRODUCTION_ORIGIN
        or not isinstance(production_alias["deployment_id"], str)
        or not production_alias["deployment_id"]
        or len(production_alias["deployment_id"]) > 64
        or not _pages_url(production_alias["deployment_url"])
        or not _is_git_commit(production_alias["source_commit"])
        or alias_request["method"] != "GET"
        or alias_request["resource"] != "pages-project"
        or alias_request["tls_verified"] is not True
        or alias_request["status"] != 200
        or not _is_sha256(alias_request["body_sha256"])
        or not isinstance(alias_request["body_size_bytes"], int)
        or isinstance(alias_request["body_size_bytes"], bool)
        or alias_request["body_size_bytes"] < 1
    ):
        raise ValidationError("Cloudflare API deployment evidence is invalid")
    for field in ("deployment_id", "short_id"):
        if not isinstance(value[field], str) or len(value[field]) > 64:
            raise ValidationError("Cloudflare deployment identity is invalid")
    if not value["deployment_id"]:
        raise ValidationError("Cloudflare deployment id is missing")
    for field in ("created_on", "modified_on"):
        _timestamp(value[field], f"Cloudflare {field}")
    _timestamp(request["fetched_at"], "Cloudflare API fetch")
    _timestamp(alias_request["fetched_at"], "Cloudflare project API fetch")
    if require_current_alias and (
        production_alias["deployment_id"] != value["deployment_id"]
        or production_alias["deployment_url"] != value["url"]
        or production_alias["source_commit"] != value["source_commit"]
    ):
        raise ValidationError(
            "Cloudflare production alias is not serving the selected deployment"
        )
    return value


def _validate_rollback_receipt(
    value: dict[str, Any],
    *,
    producer: dict[str, Any],
    current: dict[str, Any],
    rollback: dict[str, Any],
) -> None:
    _expect_keys(
        value,
        {
            "schema_version",
            "document_type",
            "attestation_level",
            "validated_at",
            "validated_by",
            "provider",
            "project_name",
            "account_id",
            "operation",
            "mutation_performed",
            "current_deployment_id",
            "current_source_commit",
            "target_deployment_id",
            "target_source_commit",
            "checks",
        },
        "rollback dry-run receipt",
    )
    checks = _expect_keys(
        value["checks"],
        {
            "current_deployment_api_verified",
            "target_deployment_api_verified",
            "target_is_prior_distinct_deployment",
            "target_is_successful_production",
            "commits_are_distinct",
        },
        "rollback dry-run checks",
    )
    if (
        value["schema_version"] != 1
        or value["document_type"] != "cloudflare-pages-rollback-dry-run-receipt"
        or value["attestation_level"] != "CLOUDFLARE_API_VERIFIED"
        or value["validated_by"] != producer["actor"]
        or value["provider"] != "cloudflare-pages"
        or value["project_name"] != CLOUDFLARE_PROJECT
        or value["account_id"] != current["account_id"]
        or value["operation"] != "rollback-plan-validation"
        or value["mutation_performed"] is not False
        or value["current_deployment_id"] != current["deployment_id"]
        or value["current_source_commit"] != current["source_commit"]
        or value["target_deployment_id"] != rollback["deployment_id"]
        or value["target_source_commit"] != rollback["source_commit"]
        or any(check is not True for check in checks.values())
    ):
        raise ValidationError("rollback proof is not an API-verified dry run")
    _timestamp(value["validated_at"], "rollback receipt")


def _validate_collection(
    root: Path,
    event: dict[str, Any],
    *,
    expected_commit: str,
    workspace_id: str,
    events: list[dict[str, Any]],
    task_attempt: int,
) -> dict[str, Any]:
    payload = event["payload"]
    producer = payload["producer"]
    collection = _expect_keys(
        payload["collection"],
        {"kind", "bundle_path", "bundle_sha256", "artifacts"},
        "collection",
    )
    bundle_sha = collection["bundle_sha256"]
    if collection["kind"] != "production-release-evidence" or not _is_sha256(
        bundle_sha
    ):
        raise ValidationError("collection bundle identity is invalid")
    directory = (
        f"archive/release-evidence/{P01_TASK_ID}/attempt-{task_attempt}/{bundle_sha}"
    )
    bundle_path = f"{directory}/bundle.json"
    if collection["bundle_path"] != bundle_path:
        raise ValidationError("collection bundle path is not canonical")

    event_artifacts = collection["artifacts"]
    if not isinstance(event_artifacts, list) or len(event_artifacts) != len(
        ARTIFACT_FILES
    ):
        raise ValidationError("collection artifact inventory is incomplete")
    by_kind: dict[str, dict[str, Any]] = {}
    for artifact in event_artifacts:
        _expect_keys(
            artifact,
            {"kind", "archive_path", "sha256", "size_bytes"},
            "collection artifact",
        )
        kind = artifact["kind"]
        if kind not in ARTIFACT_FILES or kind in by_kind:
            raise ValidationError("collection artifact kind is invalid")
        expected_path = f"{directory}/{ARTIFACT_FILES[kind]}"
        if (
            artifact["archive_path"] != expected_path
            or not _is_sha256(artifact["sha256"])
            or not isinstance(artifact["size_bytes"], int)
            or isinstance(artifact["size_bytes"], bool)
            or artifact["size_bytes"] < 0
            or artifact["size_bytes"] > MAX_EVIDENCE_BYTES
        ):
            raise ValidationError("collection artifact binding is invalid")
        by_kind[kind] = artifact
    if set(by_kind) != set(ARTIFACT_FILES):
        raise ValidationError("collection artifact set is incomplete")

    _exact_directory_names(root, directory, {"bundle.json", *ARTIFACT_FILES.values()})
    bundle_bytes = _read_bounded_bytes(root, bundle_path)
    if _sha256(bundle_bytes) != bundle_sha:
        raise ValidationError("collection bundle hash mismatch")
    bundle = _json_object(bundle_bytes, "release evidence bundle")
    _expect_keys(
        bundle,
        {
            "schema_version",
            "kind",
            "task_id",
            "task_attempt",
            "producer",
            "actor_capability",
            "source_commit",
            "collected_at",
            "replay_results",
            "deployment_attestation",
            "rollback_mutation_performed",
            "artifacts",
        },
        "release evidence bundle",
    )
    if (
        bundle["schema_version"] != 1
        or bundle["kind"] != "production-release-evidence"
        or bundle["task_id"] != P01_TASK_ID
        or bundle["task_attempt"] != task_attempt
        or bundle["producer"] != producer
        or bundle["actor_capability"] != payload["actor_capability"]
        or bundle["source_commit"] != expected_commit
        or bundle["deployment_attestation"] != "CLOUDFLARE_API_VERIFIED"
        or bundle["rollback_mutation_performed"] is not False
    ):
        raise ValidationError("release evidence bundle provenance is invalid")
    _validate_actor_capability(
        bundle["actor_capability"],
        orchestrator=producer["actor"],
        workspace_id=workspace_id,
        task_attempt=task_attempt,
    )
    _timestamp(bundle["collected_at"], "bundle collection")

    bundle_artifacts = bundle["artifacts"]
    if not isinstance(bundle_artifacts, list) or len(bundle_artifacts) != len(
        ARTIFACT_FILES
    ):
        raise ValidationError("bundle artifact inventory is incomplete")
    bytes_by_kind: dict[str, bytes] = {}
    normalized_bundle_artifacts: dict[str, dict[str, Any]] = {}
    for artifact in bundle_artifacts:
        _expect_keys(
            artifact, {"kind", "filename", "sha256", "size_bytes"}, "bundle artifact"
        )
        kind = artifact["kind"]
        if (
            kind not in ARTIFACT_FILES
            or kind in normalized_bundle_artifacts
            or artifact["filename"] != ARTIFACT_FILES[kind]
        ):
            raise ValidationError("bundle artifact filename is invalid")
        if (
            artifact["sha256"] != by_kind[kind]["sha256"]
            or artifact["size_bytes"] != by_kind[kind]["size_bytes"]
        ):
            raise ValidationError("event and bundle artifact metadata differ")
        value = _read_bounded_bytes(root, by_kind[kind]["archive_path"])
        if len(value) != artifact["size_bytes"] or _sha256(value) != artifact["sha256"]:
            raise ValidationError("archived artifact hash or size mismatch")
        normalized_bundle_artifacts[kind] = artifact
        bytes_by_kind[kind] = value
    if set(normalized_bundle_artifacts) != set(ARTIFACT_FILES):
        raise ValidationError("bundle artifact set is incomplete")

    health_capture = _json_object(
        bytes_by_kind["production-health-capture"], "health capture"
    )
    health = _validate_capture(
        health_capture,
        bytes_by_kind["production-health-body"],
        endpoint=PRODUCTION_ENDPOINTS["health"],
        filename=ARTIFACT_FILES["production-health-body"],
    )
    health_deployment = _validate_health(health, expected_commit)

    snapshot_capture = _json_object(
        bytes_by_kind["production-snapshot-capture"], "snapshot capture"
    )
    snapshot = _validate_capture(
        snapshot_capture,
        bytes_by_kind["production-snapshot-body"],
        endpoint=PRODUCTION_ENDPOINTS["snapshot"],
        filename=ARTIFACT_FILES["production-snapshot-body"],
    )
    snapshot_attribution = _validate_snapshot(
        snapshot,
        expected_commit=expected_commit,
        workspace_id=workspace_id,
        events=events,
        collection_sequence=event["sequence"],
        task_attempt=task_attempt,
    )
    if snapshot_attribution["build_deployment"] != health_deployment:
        raise ValidationError("health and snapshot deployment attribution differ")

    replay = bundle["replay_results"]
    expected_replay = [
        {
            "endpoint": name,
            "url": PRODUCTION_ENDPOINTS[name],
            "status": capture["status"],
            "body_sha256": capture["body_sha256"],
            "body_size_bytes": capture["body_size_bytes"],
        }
        for name, capture in (
            ("health", health_capture),
            ("snapshot", snapshot_capture),
        )
    ]
    if replay != expected_replay:
        raise ValidationError("bundle replay results do not match archived captures")

    current_document = _json_object(
        bytes_by_kind["cloudflare-deployment-evidence"], "current deployment"
    )
    current_deployment_capture = _json_object(
        bytes_by_kind["cloudflare-current-deployment-capture"],
        "current Cloudflare deployment capture",
    )
    current_project_capture = _json_object(
        bytes_by_kind["cloudflare-current-project-capture"],
        "current Cloudflare project capture",
    )
    _assert_cloudflare_raw_derivation(
        current_document,
        account_id=current_document.get("account_id"),
        deployment_id=current_document.get("deployment_id"),
        deployment_metadata=current_deployment_capture,
        deployment_body=bytes_by_kind["cloudflare-current-deployment-body"],
        project_metadata=current_project_capture,
        project_body=bytes_by_kind["cloudflare-current-project-body"],
    )
    current = _validate_cloudflare_deployment(
        current_document,
        expected_commit,
        require_current_alias=True,
    )
    release_deployment = snapshot_attribution["release_deployment"]
    if (
        release_deployment["deployment_id"] != current["deployment_id"]
        or release_deployment["deployment_url"] != current["url"]
        or release_deployment["canonical_url"]
        != current["production_alias"]["canonical_url"]
        or release_deployment["source_commit"] != current["source_commit"]
    ):
        raise ValidationError(
            "production response is not bound to the API-selected deployment"
        )
    rollback_document = _json_object(
        bytes_by_kind["cloudflare-rollback-target-evidence"],
        "rollback deployment",
    )
    rollback_commit = rollback_document.get("source_commit")
    if not _is_git_commit(rollback_commit):
        raise ValidationError("rollback source commit is invalid")
    _assert_cloudflare_raw_derivation(
        rollback_document,
        account_id=rollback_document.get("account_id"),
        deployment_id=rollback_document.get("deployment_id"),
        deployment_metadata=_json_object(
            bytes_by_kind["cloudflare-rollback-deployment-capture"],
            "rollback Cloudflare deployment capture",
        ),
        deployment_body=bytes_by_kind["cloudflare-rollback-deployment-body"],
        project_metadata=_json_object(
            bytes_by_kind["cloudflare-rollback-project-capture"],
            "rollback Cloudflare project capture",
        ),
        project_body=bytes_by_kind["cloudflare-rollback-project-body"],
    )
    rollback = _validate_cloudflare_deployment(rollback_document, rollback_commit)
    if (
        rollback["source_commit"] == expected_commit
        or rollback["deployment_id"] == current["deployment_id"]
        or rollback["account_id"] != current["account_id"]
        or rollback["project_name"] != current["project_name"]
        or _timestamp(rollback["created_on"], "rollback created_on")
        >= _timestamp(current["created_on"], "current created_on")
    ):
        raise ValidationError(
            "rollback target is not a prior distinct production deployment"
        )
    receipt = _json_object(
        bytes_by_kind["cloudflare-rollback-dry-run-receipt"], "rollback receipt"
    )
    _validate_rollback_receipt(
        receipt, producer=producer, current=current, rollback=rollback
    )
    return {
        "bundle_path": bundle_path,
        "bundle_sha256": bundle_sha,
        "artifact_sha256": {kind: by_kind[kind]["sha256"] for kind in sorted(by_kind)},
        "deployment_id": current["deployment_id"],
        "deployment_url": current["url"],
        "rollback_deployment_id": rollback["deployment_id"],
        "source_commit": expected_commit,
    }


def _canonical_json_sha(value: Any) -> str:
    return _sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )


def _validate_phase_contract(
    task: dict[str, Any], phase_contract: dict[str, Any]
) -> str:
    keys = (
        "schema_version",
        "id",
        "title",
        "description",
        "owner",
        "prerequisites",
        "allowed_write_roots",
        "permissions",
        "gates",
        "idempotency_key",
    )
    observed = {key: task.get(key) for key in keys}
    expected = {
        "schema_version": 1,
        **{key: phase_contract[key] for key in keys if key in phase_contract},
        "idempotency_key": f"cogni-os-roadmap-v1:{P01_TASK_ID}",
    }
    if observed != expected:
        raise ValidationError("P01 task contract differs from the canonical roadmap")
    return _canonical_json_sha(expected)


def _validate_t001(events: list[dict[str, Any]], doctor: dict[str, Any]) -> None:
    original = events[T001_ORIGINAL_SEQUENCE - 1]
    restatement = events[T001_RESTATEMENT_SEQUENCE - 1]
    if (
        original.get("sequence") != T001_ORIGINAL_SEQUENCE
        or original.get("event_hash") != T001_ORIGINAL_HASH
        or original.get("action") != "task.verified"
        or original.get("task_id") != "T-001"
    ):
        raise ValidationError("historical T-001 verification identity changed")
    payload = _expect_keys(
        restatement.get("payload"),
        {
            "schema_version",
            "effective_status",
            "original_verifier",
            "reason",
            "target_verification_hash",
            "target_verification_sequence",
        },
        "T-001 restatement",
    )
    if (
        restatement.get("sequence") != T001_RESTATEMENT_SEQUENCE
        or restatement.get("actor") != "codex"
        or restatement.get("action") != "verification.restatement"
        or restatement.get("task_id") != "T-001"
        or payload["schema_version"] != 1
        or payload["effective_status"] != "verification_disputed"
        or payload["reason"] != T001_RESTATEMENT_REASON
        or payload["target_verification_hash"] != T001_ORIGINAL_HASH
        or payload["target_verification_sequence"] != T001_ORIGINAL_SEQUENCE
    ):
        raise ValidationError("T-001 verification is not exactly restated as disputed")
    claims = doctor["checks"]["current_verification_claims"]["claims"]
    claim = next((item for item in claims if item.get("task_id") == "T-001"), None)
    if (
        not claim
        or claim.get("historical_state") != "verification_disputed"
        or claim.get("historical_trusted") is not False
        or claim.get("current_release_state") != "verification_disputed"
        or claim.get("current_release_validated") is not False
        or claim.get("restated") is not True
    ):
        raise ValidationError("doctor does not project T-001 as a restated dispute")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-collection-sequence", required=True, type=int)
    parser.add_argument("--expected-collection-event-hash", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    root = Path(__file__).absolute().parents[1]
    expected_commit = args.expected_commit.lower()
    expected_event_hash = args.expected_collection_event_hash.lower()
    preflight = bool(
        sys.flags.isolated == 1
        and Path.cwd().absolute() == root
        and _is_git_commit(expected_commit)
        and _is_sha256(expected_event_hash)
        and isinstance(args.expected_collection_sequence, int)
        and args.expected_collection_sequence > 0
        and _git_commit(root) == expected_commit
        and _source_clean_before_import(root)
    )
    if not preflight:
        print(json.dumps({"passed": False, "preflight": False}, separators=(",", ":")))
        return 1

    sys.path.insert(0, str(root / "src"))
    from cogni_os.doctor import audit_workspace
    from cogni_os.roadmap import phase_contracts, roadmap_status
    from cogni_os.workspace import Workspace

    workspace = Workspace(root)
    ledger = workspace.ledger.verify()
    events = workspace.ledger.read()
    event = _select_collection_event(
        events,
        sequence=args.expected_collection_sequence,
        event_hash=expected_event_hash,
        orchestrator=workspace.orchestrator,
        expected_commit=expected_commit,
    )
    task_attempt = event["payload"]["task_attempt"]
    doctor = audit_workspace(root)
    _validate_t001(events, doctor)
    task = workspace.get_task(P01_TASK_ID)
    if task.get("state") != "submitted" or task.get("attempt") != task_attempt:
        raise ValidationError(
            "P01 must be submitted at the signed collection attempt before verification"
        )
    contract_sha256 = _validate_phase_contract(task, phase_contracts("antigravity")[0])
    roadmap = roadmap_status(workspace)
    if (
        [phase.get("id") for phase in roadmap.get("phases", [])] != PHASE_IDS
        or roadmap.get("total") != len(PHASE_IDS)
        or roadmap.get("trusted_complete") != 0
    ):
        raise ValidationError("workspace roadmap is not canonical 0-of-11")

    publisher = _load_tracked_publisher(root)
    tree = publisher.git_tree_status(root)
    operational = publisher.audit_operational_evidence(root, events, tree)
    if (
        tree.get("clean") is not True
        or tree.get("unclassified_change_count") != 0
        or operational.get("valid") is not True
    ):
        raise ValidationError("source or immutable operational evidence is not clean")

    evidence = _validate_collection(
        root,
        event,
        expected_commit=expected_commit,
        workspace_id=str(workspace.config["workspace_id"]),
        events=events,
        task_attempt=task_attempt,
    )
    tests = _run_tests(root)
    expected_tests = {
        "errors": 0,
        "failures": 0,
        "skipped": 0,
        "tests_run": EXPECTED_PYTHON_TESTS,
        "inventory_sha256": EXPECTED_TEST_INVENTORY_SHA256,
    }
    passed = bool(
        doctor.get("healthy") is True
        and doctor.get("release_ready") is False
        and ledger.get("valid") is True
        and ledger.get("signed") is True
        and doctor["checks"]["integrity"]["valid"] is True
        and tests == expected_tests
    )
    record = {
        "passed": passed,
        "preflight": True,
        "source_commit": expected_commit,
        "collection_event": {
            "sequence": event["sequence"],
            "event_hash": event["event_hash"],
        },
        "contract_sha256": contract_sha256,
        "roadmap": {
            "total": roadmap["total"],
            "trusted_complete": roadmap["trusted_complete"],
        },
        "ledger": ledger,
        "evidence": evidence,
        "tests": tests,
    }
    print(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
