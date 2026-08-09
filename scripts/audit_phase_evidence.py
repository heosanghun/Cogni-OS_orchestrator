"""Audit Phase 1-11 semantic evidence coverage without release authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cogni_os.phase_evidence import (  # noqa: E402
    PHASE_EVIDENCE_REQUIREMENTS,
    audit_phase_tasks,
)

MAX_TASK_BYTES = 4 * 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
AUDITOR_POLICY_FILES = (
    Path(__file__).resolve(),
    (SRC / "cogni_os" / "phase_evidence.py").resolve(),
)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        getattr(value, "st_file_attributes", 0),
    )


def _current_commit(workspace: Path) -> str:
    completed = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={workspace.as_posix()}",
            "-C",
            str(workspace),
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    commit = completed.stdout.strip().lower()
    if (
        completed.returncode != 0
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise RuntimeError("workspace does not expose one authoritative Git commit")
    return commit


def _read_task(path: Path) -> dict[str, Any]:
    before_path = path.lstat()
    if (
        path.is_symlink()
        or _is_reparse(before_path)
        or not stat.S_ISREG(before_path.st_mode)
    ):
        raise RuntimeError(
            f"phase task must be a non-reparse regular file: {path.name}"
        )
    if before_path.st_size > MAX_TASK_BYTES:
        raise RuntimeError(f"phase task exceeds the size limit: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        before_handle = os.fstat(handle.fileno())
        content = handle.read(MAX_TASK_BYTES + 1)
        after_handle = os.fstat(handle.fileno())
    after_path = path.lstat()
    if len(content) > MAX_TASK_BYTES:
        raise RuntimeError(f"phase task exceeds the size limit: {path.name}")
    if (
        len(content) != before_handle.st_size
        or _identity(before_path) != _identity(before_handle)
        or _identity(before_handle) != _identity(after_handle)
        or _identity(after_handle) != _identity(after_path)
    ):
        raise RuntimeError(f"phase task changed while being read: {path.name}")
    payload = json.loads(
        content.decode("utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(payload, dict):
        raise TypeError(f"phase task is not a JSON object: {path.name}")
    if payload.get("id") != path.stem:
        raise ValueError(f"phase task id does not match filename: {path.name}")
    return payload


def _load_tasks(workspace: Path) -> list[dict[str, Any]]:
    tasks_directory = workspace / "tasks"
    directory_stat = tasks_directory.lstat()
    if (
        tasks_directory.is_symlink()
        or _is_reparse(directory_stat)
        or not stat.S_ISDIR(directory_stat.st_mode)
    ):
        raise RuntimeError("workspace tasks directory is not a trusted directory")

    expected = {f"{phase_id}.json" for phase_id in PHASE_EVIDENCE_REQUIREMENTS}
    observed = {
        path.name
        for path in tasks_directory.iterdir()
        if path.name.startswith("P") and path.name.endswith(".json")
    }
    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    if missing or unexpected:
        raise RuntimeError(
            "canonical phase task inventory mismatch: "
            f"missing={missing}, unexpected={unexpected}"
        )

    tasks = [_read_task(tasks_directory / name) for name in sorted(expected)]
    task_ids = [str(task["id"]) for task in tasks]
    if len(task_ids) != len(set(task_ids)):
        raise RuntimeError("duplicate phase task ids are not allowed")
    if _identity(directory_stat) != _identity(tasks_directory.lstat()):
        raise RuntimeError("workspace tasks directory changed during the audit")
    return tasks


def _auditor_policy_provenance() -> dict[str, Any]:
    source_commit = _current_commit(ROOT)
    tree_result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={ROOT.as_posix()}",
            "-C",
            str(ROOT),
            "rev-parse",
            "--verify",
            f"{source_commit}^{{tree}}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    source_tree = tree_result.stdout.strip().lower()
    if (
        tree_result.returncode != 0
        or len(source_tree) != 40
        or any(character not in "0123456789abcdef" for character in source_tree)
    ):
        raise RuntimeError("auditor policy source tree is unavailable")
    status_result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={ROOT.as_posix()}",
            "-C",
            str(ROOT),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        check=False,
        capture_output=True,
        timeout=10,
    )
    if status_result.returncode != 0:
        raise RuntimeError("auditor policy source status is unavailable")
    files: list[dict[str, str]] = []
    source_bound = not status_result.stdout
    for path in AUDITOR_POLICY_FILES:
        content = path.read_bytes()
        if len(content) > MAX_TASK_BYTES:
            raise RuntimeError(
                f"auditor policy file exceeds the size limit: {path.name}"
            )
        relative = path.relative_to(ROOT).as_posix()
        digest = hashlib.sha256(content).hexdigest()
        committed = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={ROOT.as_posix()}",
                "-C",
                str(ROOT),
                "show",
                f"{source_commit}:{relative}",
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
        source_bound = source_bound and (
            committed.returncode == 0
            and hashlib.sha256(committed.stdout).hexdigest() == digest
        )
        files.append({"path": relative, "sha256": digest})
    policy_document = {
        "files": files,
        "source_commit": source_commit,
        "source_tree": source_tree,
    }
    policy_sha256 = hashlib.sha256(
        json.dumps(
            policy_document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "source_commit": source_commit,
        "source_tree": source_tree,
        "current_source_commit_bound": source_bound,
        "policy_sha256": policy_sha256,
        "files": files,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audit-phase-evidence")
    parser.add_argument("--workspace", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    workspace = args.workspace.resolve()
    try:
        auditor_policy = _auditor_policy_provenance()
        if auditor_policy["current_source_commit_bound"] is not True:
            raise RuntimeError("auditor policy source is not clean and commit-bound")
        source_commit = _current_commit(workspace)
        report = audit_phase_tasks(
            _load_tasks(workspace),
            current_source_commit=source_commit,
            workspace_root=workspace,
        )
        if _current_commit(workspace) != source_commit:
            raise RuntimeError("authoritative Git commit changed during the audit")
        if _auditor_policy_provenance() != auditor_policy:
            raise RuntimeError("auditor policy changed during the audit")
        report["auditor_policy"] = auditor_policy
    except (
        json.JSONDecodeError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": "cogni.phase-evidence-audit-error.v2",
                    "coverage_status": "ERROR",
                    "error": f"{type(exc).__name__}: {exc}",
                    "release_authority": False,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["coverage_status"] == "SEMANTIC_COVERAGE_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
