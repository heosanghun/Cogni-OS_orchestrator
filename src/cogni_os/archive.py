"""Immutable local retention for reports and bounded evidence artifacts in Cogni-OS."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .errors import EvidenceError
from .util import atomic_write_json, sha256_file

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_name(path: Path) -> str:
    value = SAFE_NAME_RE.sub("_", path.name).strip("._")
    return value or "artifact"


def _atomic_copy_verified(source: Path, destination: Path, expected_sha: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".copy.", dir=destination.parent)
    temp_path = Path(temp_name)
    try:
        with source.open("rb") as source_handle, os.fdopen(fd, "wb") as output:
            for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        observed = sha256_file(temp_path)
        if observed != expected_sha:
            raise EvidenceError(
                f"Evidence changed while being archived: {source} "
                f"(expected {expected_sha}, observed {observed})"
            )
        if destination.exists():
            if sha256_file(destination) != expected_sha:
                raise EvidenceError(
                    f"Archived evidence path already has different content: {destination}"
                )
            temp_path.unlink()
            return
        os.replace(temp_path, destination)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def archive_evidence_bundle(
    *,
    submissions_root: Path,
    task_id: str,
    attempt: int,
    label: str,
    report: dict[str, Any] | None,
    manifest: dict[str, Any],
    max_artifact_bytes: int,
    extra_files: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Retain reports, manifests, and bounded artifacts under content hashes."""
    if max_artifact_bytes < 0:
        raise EvidenceError("max_artifact_bytes cannot be negative")
    manifest_sha = manifest.get("sha256") or manifest.get("manifest_sha256") or "0"*64
    bundle_id = f"{label}-{manifest_sha[:16]}"
    destination = (
        submissions_root / task_id / f"attempt-{attempt:03d}" / bundle_id
    ).resolve()
    files: list[tuple[Path, str, str, bool]] = []
    if report is not None:
        files.append(
            (
                Path(report["path"]).resolve(),
                report["sha256"],
                "report",
                True,
            )
        )
    manifest_path = manifest.get("path") or manifest.get("manifest_path")
    if manifest_path:
        files.append(
            (
                Path(manifest_path).resolve(),
                manifest_sha,
                "manifest",
                True,
            )
        )
    for artifact in manifest.get("artifacts", []):
        files.append(
            (
                Path(artifact["path"]).resolve(),
                artifact["sha256"],
                "artifact",
                False,
            )
        )
    for validation in manifest.get("validations", []):
        raw_output = validation.get("raw_output")
        if raw_output:
            files.append(
                (
                    Path(raw_output["path"]).resolve(),
                    raw_output["sha256"],
                    "raw_output",
                    False,
                )
            )
    for extra in extra_files or []:
        files.append(
            (
                Path(extra["path"]).resolve(),
                extra["sha256"],
                str(extra.get("kind", "extra")),
                bool(extra.get("force", True)),
            )
        )

    retained: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for source, expected_sha, kind, force in files:
        key = (str(source), expected_sha)
        if key in seen:
            continue
        seen.add(key)
        if not source.is_file():
            raise EvidenceError(f"Evidence disappeared before archival: {source}")
        size = source.stat().st_size
        should_copy = force or size <= max_artifact_bytes
        record: dict[str, Any] = {
            "kind": kind,
            "source": str(source),
            "sha256": expected_sha,
            "size_bytes": size,
            "retained": should_copy,
            "archive_path": None,
        }
        if should_copy:
            relative = Path("files") / f"{expected_sha}_{_safe_name(source)}"
            target = destination / relative
            _atomic_copy_verified(source, target, expected_sha)
            record["archive_path"] = str(target)
        retained.append(record)

    bundle = {
        "schema_version": 1,
        "task_id": task_id,
        "attempt": attempt,
        "label": label,
        "manifest_sha256": manifest_sha,
        "max_artifact_bytes": max_artifact_bytes,
        "files": retained,
    }
    bundle_path = destination / "bundle.json"
    atomic_write_json(bundle_path, bundle)
    return {
        "task_id": task_id,
        "attempt": attempt,
        "label": label,
        "bundle_id": bundle_id,
        "path": str(destination),
        "manifest_path": str(bundle_path),
        "manifest_sha256": sha256_file(bundle_path),
        "files": retained,
        "retained": sum(item["retained"] for item in retained),
        "external": sum(not item["retained"] for item in retained),
    }
