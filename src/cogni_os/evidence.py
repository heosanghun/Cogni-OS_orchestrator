"""Validation for worker reports and machine-readable evidence manifests for Cogni-OS."""

from __future__ import annotations

import hmac
import math
import re
from pathlib import Path
from typing import Any

from .errors import EvidenceError
from .util import is_relative_to, read_json, sha256_file

SECTION_RE = re.compile(r"^##\s+([1-6])(?:[.)]|\s)", re.MULTILINE)
REQUIRED_SECTION_NUMBERS = {"1", "2", "3", "4", "5", "6"}
CLAIM_KINDS = {"functional", "performance", "resource", "provenance"}
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PLACEHOLDER_VALUES = {
    "[fill]",
    "<fill>",
    "fill",
    "n/a",
    "none",
    "not measured",
    "not-measured",
    "placeholder",
    "tbd",
    "todo",
    "unknown",
    "unmeasured",
}


def validate_report(path: Path) -> dict[str, Any]:
    """Check that a Markdown report contains the six protocol sections."""
    if not path.is_file():
        raise EvidenceError(f"Report does not exist: {path}")
    text = path.read_text(encoding="utf-8")
    if "[FILL]" in text.upper():
        raise EvidenceError("Report contains an unresolved [FILL] placeholder")
    matches = list(SECTION_RE.finditer(text))
    ordered_sections = [match.group(1) for match in matches]
    sections = set(ordered_sections)
    missing = sorted(REQUIRED_SECTION_NUMBERS - sections)
    if missing:
        raise EvidenceError(
            f"Report is missing required numbered sections: {', '.join(missing)}"
        )
    if ordered_sections != ["1", "2", "3", "4", "5", "6"]:
        raise EvidenceError(
            "Report sections must appear exactly once in the order 1 through 6"
        )
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[match.end() : end].strip()
        if not body:
            raise EvidenceError(f"Report section {match.group(1)} is empty")
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "sections": ordered_sections,
        "contains_fill_marker": False,
    }


def _resolve_evidence_path(
    value: str,
    manifest_path: Path,
    *,
    allowed_root: Path | None = None,
) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = manifest_path.parent / path
    resolved = path.resolve()
    if allowed_root is not None and not is_relative_to(
        resolved,
        allowed_root.resolve(),
    ):
        raise EvidenceError(
            f"Evidence path escapes the verifier-owned report directory: {resolved}"
        )
    return resolved


def _require_int(record: dict[str, Any], name: str, context: str) -> int:
    value = record.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise EvidenceError(f"{context}.{name} must be an integer")
    return value


def _reject_non_finite(value: Any, context: str = "manifest") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise EvidenceError(f"{context} contains a non-finite number")
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_non_finite(child, f"{context}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_non_finite(child, f"{context}[{index}]")


def _reject_placeholders(value: Any, context: str = "manifest") -> None:
    """Reject exact placeholder strings without rejecting legitimate prose."""
    if isinstance(value, str) and value.strip().lower() in PLACEHOLDER_VALUES:
        raise EvidenceError(f"{context} contains an unresolved placeholder")
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_placeholders(child, f"{context}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_placeholders(child, f"{context}[{index}]")


def validate_manifest(
    manifest_path: Path,
    *,
    permissions: dict[str, bool],
    gates: dict[str, Any],
    require_command_argv: bool = False,
    allowed_root: Path | None = None,
) -> dict[str, Any]:
    """Validate a reproducibility manifest against preregistered task gates."""
    manifest_path = manifest_path.resolve()
    if allowed_root is not None and not is_relative_to(
        manifest_path,
        allowed_root.resolve(),
    ):
        raise EvidenceError(
            "Evidence manifest must be inside the actor-owned report directory"
        )
    if not manifest_path.is_file():
        raise EvidenceError(f"Evidence manifest does not exist: {manifest_path}")
    manifest = read_json(manifest_path)
    _reject_non_finite(manifest)
    _reject_placeholders(manifest)
    if manifest.get("schema_version") != 1:
        raise EvidenceError("Evidence manifest schema_version must be 1")

    artifacts = manifest.get("artifacts", [])
    validations = manifest.get("validations", [])
    known_checks = manifest.get("known_answer_checks", [])
    claims = manifest.get("claims", [])
    for name, value in (
        ("artifacts", artifacts),
        ("validations", validations),
        ("known_answer_checks", known_checks),
        ("claims", claims),
    ):
        if not isinstance(value, list):
            raise EvidenceError(f"Evidence manifest {name} must be a list")

    artifact_results: list[dict[str, Any]] = []
    for index, artifact in enumerate(artifacts):
        context = f"artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise EvidenceError(f"{context} must be an object")
        value = artifact.get("path")
        expected_sha = artifact.get("sha256")
        if not isinstance(value, str) or not value:
            raise EvidenceError(f"{context}.path must be a non-empty string")
        if not isinstance(expected_sha, str) or not SHA256_RE.fullmatch(expected_sha):
            raise EvidenceError(f"{context}.sha256 must be a full SHA-256")
        path = _resolve_evidence_path(
            value,
            manifest_path,
            allowed_root=allowed_root,
        )
        if not path.is_file():
            raise EvidenceError(f"Evidence artifact does not exist: {path}")
        actual_sha = sha256_file(path)
        if actual_sha != expected_sha.lower():
            raise EvidenceError(
                f"Evidence artifact SHA mismatch for {path}: "
                f"expected {expected_sha}, observed {actual_sha}"
            )
        artifact_results.append({"path": str(path), "sha256": actual_sha})

    if gates.get("require_validation", True) and not validations:
        raise EvidenceError("At least one validation command is required")
    validation_results: list[dict[str, Any]] = []
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    for index, validation in enumerate(validations):
        context = f"validations[{index}]"
        if not isinstance(validation, dict):
            raise EvidenceError(f"{context} must be an object")
        command = validation.get("command")
        if not isinstance(command, str) or not command.strip():
            raise EvidenceError(f"{context}.command must be a non-empty string")
        command_argv = validation.get("command_argv")
        if command_argv is not None or require_command_argv:
            if (
                not isinstance(command_argv, list)
                or not command_argv
                or any(
                    not isinstance(argument, str) or not argument
                    for argument in command_argv
                )
            ):
                raise EvidenceError(
                    f"{context}.command_argv must be a non-empty string array"
                )
        exit_code = _require_int(validation, "exit_code", context)
        passed = _require_int(validation, "passed", context)
        failed = _require_int(validation, "failed", context)
        skipped = _require_int(validation, "skipped", context)
        if min(passed, failed, skipped) < 0:
            raise EvidenceError(f"{context} counts cannot be negative")
        if passed + failed + skipped == 0:
            raise EvidenceError(f"{context} contains no measured checks")
        if exit_code != 0 or failed:
            raise EvidenceError(
                f"{context} did not pass: exit_code={exit_code}, failed={failed}"
            )
        skip_reasons = validation.get("skip_reasons", [])
        if not isinstance(skip_reasons, list):
            raise EvidenceError(f"{context}.skip_reasons must be a list")
        if skipped and len(skip_reasons) < skipped:
            raise EvidenceError(
                f"{context} has {skipped} skipped checks but lacks a reason for each"
            )
        if skipped and not gates.get("allow_skips", False):
            raise EvidenceError(
                f"{context} has {skipped} skipped checks; skip is not pass"
            )
        raw_output = validation.get("raw_output_path")
        raw_output_sha = validation.get("raw_output_sha256")
        if not isinstance(raw_output, str) or not raw_output:
            raise EvidenceError(f"{context}.raw_output_path must be a non-empty string")
        if not isinstance(raw_output_sha, str) or not SHA256_RE.fullmatch(raw_output_sha):
            raise EvidenceError(f"{context}.raw_output_sha256 must be a full SHA-256")
        output_path = _resolve_evidence_path(
            raw_output,
            manifest_path,
            allowed_root=allowed_root,
        )
        if not output_path.is_file():
            raise EvidenceError(f"Raw validation output is missing: {output_path}")
        if output_path.stat().st_size == 0:
            raise EvidenceError(f"Raw validation output is empty: {output_path}")
        observed_output_sha = sha256_file(output_path)
        if not hmac.compare_digest(raw_output_sha.lower(), observed_output_sha):
            raise EvidenceError(
                f"Raw validation output SHA mismatch for {output_path}"
            )
        raw_output_result = {
            "path": str(output_path),
            "sha256": observed_output_sha,
        }
        total_passed += passed
        total_failed += failed
        total_skipped += skipped
        validation_results.append(
            {
                "command": command,
                "command_argv": list(command_argv) if command_argv else None,
                "exit_code": exit_code,
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "raw_output": raw_output_result,
            }
        )

    if gates.get("require_known_answer_check", True) and not known_checks:
        raise EvidenceError("At least one known-answer comparison is required")
    for index, check in enumerate(known_checks):
        context = f"known_answer_checks[{index}]"
        if not isinstance(check, dict):
            raise EvidenceError(f"{context} must be an object")
        if check.get("passed") is not True:
            raise EvidenceError(f"{context} is not explicitly passed")
        if "expected" not in check or "observed" not in check:
            raise EvidenceError(f"{context} must record expected and observed values")
        if check["expected"] != check["observed"]:
            raise EvidenceError(
                f"{context} expected {check['expected']!r} but observed {check['observed']!r}"
            )

    for index, claim in enumerate(claims):
        context = f"claims[{index}]"
        if not isinstance(claim, dict):
            raise EvidenceError(f"{context} must be an object")
        kind = claim.get("kind")
        if kind not in CLAIM_KINDS:
            raise EvidenceError(f"{context}.kind must be one of {sorted(CLAIM_KINDS)}")
        if kind == "resource" and not permissions.get("gpu", False):
            raise EvidenceError(
                f"{context} claims GPU/resource usage without task permission"
            )
        if kind == "performance" and not permissions.get("performance_metrics", False):
            raise EvidenceError(
                f"{context} claims performance metrics without task permission"
            )

    return {
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": sha256_file(manifest_path),
        "artifacts": artifact_results,
        "validations": validation_results,
        "known_answer_checks": known_checks,
        "claims": claims,
        "totals": {
            "passed": total_passed,
            "failed": total_failed,
            "skipped": total_skipped,
        },
    }


def validate_submission(
    report_path: Path,
    manifest_path: Path,
    *,
    permissions: dict[str, bool],
    gates: dict[str, Any],
    allowed_root: Path | None = None,
) -> dict[str, Any]:
    """Validate both the report and the evidence manifest."""
    report_path = report_path.resolve()
    manifest_path = manifest_path.resolve()
    if allowed_root is not None:
        resolved_root = allowed_root.resolve()
        if not is_relative_to(report_path, resolved_root):
            raise EvidenceError(
                "Submission report must be inside the actor-owned report directory"
            )
        if not is_relative_to(manifest_path, resolved_root):
            raise EvidenceError(
                "Evidence manifest must be inside the actor-owned report directory"
            )
    report = validate_report(report_path)
    manifest = validate_manifest(
        manifest_path,
        permissions=permissions,
        gates=gates,
        allowed_root=allowed_root,
    )
    return {"report": report, "manifest": manifest}
