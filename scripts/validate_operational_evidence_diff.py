#!/usr/bin/env python3
"""Reject destructive changes to committed operational evidence.

Historical evidence is immutable at every commit transition in the inspected
range.  New non-executable evidence blobs may be added within fixed resource
budgets, but existing evidence may not be deleted, renamed, replaced, or
rewritten.  The legacy HMAC ledger cannot be authenticated in public CI because
its signing key is intentionally absent, so source-control ledger changes are
rejected rather than described as signed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

IMMUTABLE_ROOTS = (
    "archive",
    "ledger",
    "reports",
    "runs",
    "submissions",
    "tasks",
)
APPEND_ONLY_LEDGER = "ledger/events.jsonl"
MAX_DIFF_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_ADDITION_BYTES = 64 * 1024 * 1024
MAX_COMMIT_TRANSITIONS = 256
MAX_ADDITIONS = 1024
MAX_STDERR_BYTES = 64 * 1024
GIT_COMMIT_HEX_LENGTH = 40
LS_TREE_METADATA_FIELD_COUNT = 3
SAFE_EVIDENCE_SUFFIXES = {
    ".csv",
    ".jpeg",
    ".jpg",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".out",
    ".pdf",
    ".png",
    ".sha256",
    ".toml",
    ".tsv",
    ".txt",
    ".webp",
    ".yaml",
    ".yml",
}


class EvidenceDiffError(RuntimeError):
    """Raised when a commit range violates append-only evidence policy."""


def _git(root: Path, arguments: list[str], *, maximum: int = MAX_DIFF_BYTES) -> bytes:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result = subprocess.run(
                ["git", *arguments],
                cwd=root,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=30,
            )
        except subprocess.TimeoutExpired as error:
            raise EvidenceDiffError("Git evidence query timed out") from error
        output_size = stdout.tell()
        error_size = stderr.tell()
        if output_size > maximum or error_size > MAX_STDERR_BYTES:
            raise EvidenceDiffError("Git evidence query exceeded its byte budget")
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read(maximum + 1)
        error_output = stderr.read(MAX_STDERR_BYTES + 1)
    if result.returncode != 0:
        error = error_output.decode("utf-8", errors="replace")[:2048]
        raise EvidenceDiffError(f"Git evidence query failed: {error}")
    return output


def _commit(root: Path, value: str) -> str:
    raw = _git(root, ["rev-parse", "--verify", f"{value}^{{commit}}"], maximum=128)
    commit = raw.decode("ascii", errors="strict").strip().lower()
    if len(commit) != GIT_COMMIT_HEX_LENGTH or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise EvidenceDiffError("Evidence diff endpoint is not an exact Git commit")
    return commit


def _safe_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or len(path.parts) < 2
        or path.parts[0] not in IMMUTABLE_ROOTS
    ):
        raise EvidenceDiffError("Operational evidence path is unsafe")
    return path.as_posix()


def _changes(root: Path, base: str, head: str) -> list[tuple[str, str]]:
    raw = _git(
        root,
        [
            "diff",
            "--name-status",
            "--no-renames",
            "-z",
            base,
            head,
            "--",
            *IMMUTABLE_ROOTS,
        ],
    )
    fields = raw.decode("utf-8", errors="strict").split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 2:
        raise EvidenceDiffError("Operational evidence diff framing is invalid")
    changes: list[tuple[str, str]] = []
    for index in range(0, len(fields), 2):
        status = fields[index]
        path = _safe_path(fields[index + 1])
        if status not in {"A", "D", "M", "T"}:
            raise EvidenceDiffError("Operational evidence diff status is unsupported")
        changes.append((status, path))
    return changes


def _blob_size(root: Path, commit: str, path: str) -> int:
    raw = _git(root, ["cat-file", "-s", f"{commit}:{path}"], maximum=64)
    try:
        size = int(raw.decode("ascii", errors="strict").strip())
    except ValueError as error:
        raise EvidenceDiffError("Operational evidence blob size is invalid") from error
    if size < 0 or size > MAX_EVIDENCE_FILE_BYTES:
        raise EvidenceDiffError("Operational evidence file exceeded its byte budget")
    return size


def _regular_blob(root: Path, commit: str, path: str) -> int:
    raw = _git(
        root,
        ["--literal-pathspecs", "ls-tree", "-z", commit, "--", path],
        maximum=4096,
    )
    if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
        raise EvidenceDiffError("New operational evidence tree identity is ambiguous")
    record = raw[:-1]
    if record.count(b"\t") != 1:
        raise EvidenceDiffError("New operational evidence tree framing is invalid")
    metadata, raw_path = record.split(b"\t", 1)
    fields = metadata.decode("ascii", errors="strict").split()
    returned_path = raw_path.decode("utf-8", errors="strict")
    if (
        len(fields) != LS_TREE_METADATA_FIELD_COUNT
        or fields[1] != "blob"
        or fields[0] != "100644"
        or returned_path != path
    ):
        raise EvidenceDiffError(
            "New operational evidence must be a non-executable regular Git blob"
        )
    if PurePosixPath(path).suffix.lower() not in SAFE_EVIDENCE_SUFFIXES:
        raise EvidenceDiffError("Operational evidence file type is not allowlisted")
    return _blob_size(root, commit, path)


def _commit_edges(root: Path, base: str, head: str) -> list[tuple[str, str]]:
    merge_base = _commit(root, f"{base}^{{commit}}")
    common = _git(root, ["merge-base", base, head], maximum=128)
    if common.decode("ascii", errors="strict").strip().lower() != merge_base:
        raise EvidenceDiffError("Evidence diff base must be an ancestor of head")
    raw = _git(
        root,
        ["rev-list", "--parents", "--topo-order", f"{base}..{head}"],
    )
    lines = raw.decode("ascii", errors="strict").splitlines()
    if len(lines) > MAX_COMMIT_TRANSITIONS:
        raise EvidenceDiffError("Evidence commit range exceeded its transition budget")
    edges: list[tuple[str, str]] = []
    for line in lines:
        values = line.split()
        if len(values) < 2:
            raise EvidenceDiffError("Evidence history contains a parentless transition")
        commit = values[0].lower()
        if len(commit) != GIT_COMMIT_HEX_LENGTH:
            raise EvidenceDiffError("Evidence history commit identity is invalid")
        parents = [parent.lower() for parent in values[1:]]
        inspected_parents = parents
        if len(parents) > 1:
            inspected_parents = []
            for parent in parents:
                parent_base = _git(
                    root,
                    ["merge-base", base, parent],
                    maximum=128,
                ).decode("ascii", errors="strict").strip().lower()
                if parent_base == base:
                    inspected_parents.append(parent)
            if not inspected_parents:
                raise EvidenceDiffError(
                    "Evidence history merge has no trusted-base parent"
                )
        for parent in inspected_parents:
            edges.append((parent, commit))
            if len(edges) > MAX_COMMIT_TRANSITIONS:
                raise EvidenceDiffError(
                    "Evidence commit range exceeded its transition budget"
                )
    return edges


def validate_operational_evidence_diff(
    root: Path,
    *,
    base: str,
    head: str = "HEAD",
) -> dict[str, Any]:
    root = root.resolve()
    base_commit = _commit(root, base)
    head_commit = _commit(root, head)
    additions = 0
    addition_bytes = 0
    edges = _commit_edges(root, base_commit, head_commit)
    for parent, commit in edges:
        for status, path in _changes(root, parent, commit):
            if status == "A":
                if path.startswith("ledger/"):
                    raise EvidenceDiffError(
                        "Source-control ledger additions require a public verifier"
                    )
                addition_bytes += _regular_blob(root, commit, path)
                additions += 1
                if (
                    additions > MAX_ADDITIONS
                    or addition_bytes > MAX_TOTAL_ADDITION_BYTES
                ):
                    raise EvidenceDiffError(
                        "New operational evidence exceeded its aggregate budget"
                    )
                continue
            if path == APPEND_ONLY_LEDGER:
                raise EvidenceDiffError(
                    "Legacy HMAC ledger changes require an offline trusted verifier"
                )
            raise EvidenceDiffError(
                f"Historical operational evidence is immutable: {status} {path}"
            )
    return {
        "passed": True,
        "base": base_commit,
        "head": head_commit,
        "additions": additions,
        "addition_bytes": addition_bytes,
        "transitions": len(edges),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        record = validate_operational_evidence_diff(
            args.root,
            base=args.base,
            head=args.head,
        )
    except EvidenceDiffError as error:
        print(json.dumps({"passed": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
