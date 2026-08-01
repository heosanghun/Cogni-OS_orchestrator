"""Immutable local retention for reports and bounded evidence artifacts in Cogni-OS."""

from __future__ import annotations

import sys
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .errors import EvidenceError
from .util import atomic_write_json, sha256_file

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_name(path: Path) -> str:
    value = SAFE_NAME_RE.sub("_", path.name).strip("._")
    value = value[:32].rstrip(".")
    return value if value else "artifact"


def _win_long_path(path: Path) -> str:
    resolved = str(path.resolve())
    if sys.platform == "win32" and not resolved.startswith("\\\\?\\"):
        return "\\\\?\\" + resolved
    return resolved


def _atomic_copy_verified(source: Path, destination: Path, expected_sha: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    dest_str = _win_long_path(destination)
    dest_parent = Path(dest_str).parent
    dest_parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(prefix=".copy.", dir=str(dest_parent))
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
        if os.path.exists(dest_str):
            if sha256_file(Path(dest_str)) != expected_sha:
                raise EvidenceError(
                    f"Archived evidence path already has different content: {destination}"
                )
            temp_path.unlink()
            return

        try:
            os.replace(temp_path, dest_str)
        except OSError:
            shutil.copy2(str(temp_path), dest_str)
            temp_path.unlink()
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


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
    """Archive a submission or verification evidence bundle immutably."""
    bundle_dir = submissions_root / task_id / f"attempt-{attempt:03d}" / f"{label}-{manifest['manifest_sha256'][:8]}"
    files_dir = bundle_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    archived_artifacts: list[dict[str, Any]] = []
    manifest_dir = Path(manifest["manifest_path"]).parent.resolve()

    if report is not None:
        report_src = Path(report["path"]).resolve()
        report_dest = files_dir / f"{report['sha256'][:8]}_{_safe_name(report_src)}"
        _atomic_copy_verified(report_src, report_dest, report["sha256"])

    manifest_dest = files_dir / f"{manifest['manifest_sha256'][:8]}_{_safe_name(Path(manifest['manifest_path']))}"
    _atomic_copy_verified(Path(manifest["manifest_path"]).resolve(), manifest_dest, manifest["manifest_sha256"])

    for artifact in manifest.get("artifacts", []):
        src = (manifest_dir / artifact["path"]).resolve()
        dest = files_dir / f"{artifact['sha256'][:8]}_{_safe_name(src)}"
        _atomic_copy_verified(src, dest, artifact["sha256"])
        archived_artifacts.append({"path": str(dest.resolve()), "sha256": artifact["sha256"]})

    for validation in manifest.get("validations", []):
        raw = validation.get("raw_output")
        if isinstance(raw, dict):
            src = Path(raw["path"]).resolve()
            dest = files_dir / f"{raw['sha256'][:8]}_{_safe_name(src)}"
            _atomic_copy_verified(src, dest, raw["sha256"])

    if extra_files:
        for extra in extra_files:
            src = Path(extra["path"]).resolve()
            dest = files_dir / f"{extra['sha256'][:8]}_{_safe_name(src)}"
            _atomic_copy_verified(src, dest, extra["sha256"])

    bundle_record = {
        "schema_version": 1,
        "task_id": task_id,
        "attempt": attempt,
        "label": label,
        "manifest_sha256": manifest["manifest_sha256"],
        "bundle_dir": str(bundle_dir.resolve()),
        "archived_artifacts": archived_artifacts,
    }
    atomic_write_json(bundle_dir / "bundle.json", bundle_record)
    return bundle_record
