"""Portable release-evidence fixtures excluded from production distributions.

Production deliberately requires descriptor-relative POSIX archive primitives.
These path-based helpers exist only so Windows unit tests can exercise the
collector's validation and recovery logic.  ``pyproject.toml`` excludes the
entire ``cogni_os.tests`` package from built wheels.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from cogni_os.errors import EvidenceError
from cogni_os.release_evidence import (
    MAX_RESPONSE_BYTES,
    _artifact_filename_inventory,
    validate_archive_relative_path,
)
from cogni_os.workspace import Workspace

_BUNDLE_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def _directory_chain(root: Path, relative: Path, *, create: bool) -> Path | None:
    relative = validate_archive_relative_path(relative)
    if create:
        root.mkdir(parents=True, exist_ok=True)
    try:
        root.lstat()
    except FileNotFoundError:
        return None
    if _is_link_or_reparse(root) or not root.is_dir():
        raise EvidenceError("Test archive root is not a safe directory")
    current = root
    for component in relative.parts:
        current = current / component
        try:
            current.lstat()
        except FileNotFoundError:
            if not create:
                return None
            current.mkdir()
        if _is_link_or_reparse(current) or not current.is_dir():
            raise EvidenceError("Test archive path crosses a symlink or reparse point")
    return current


def _write_exclusive(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise EvidenceError(
            f"Immutable test archive artifact already exists: {path.name}"
        ) from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise EvidenceError("Test archive artifact is not a regular file")
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short test archive write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def portable_store_release_bundle(
    workspace: Workspace,
    *,
    destination_relative: Path,
    artifact_values: list[tuple[str, str, bytes]],
    bundle_bytes: bytes,
) -> None:
    """Path-based test double for the fixed production archive transport."""

    destination = validate_archive_relative_path(destination_relative)
    if not destination.parts or destination.parts[0] != "archive":
        raise EvidenceError("Release evidence destination must be below archive")
    artifact_names = _artifact_filename_inventory(artifact_values)
    expected_names = {"bundle.json", *artifact_names}
    directory = _directory_chain(
        workspace.root / "archive",
        destination.relative_to("archive"),
        create=True,
    )
    if directory is None:  # pragma: no cover - create=True is authoritative.
        raise AssertionError("test archive directory was not created")
    if any(directory.iterdir()):
        raise EvidenceError("Immutable release evidence destination is not empty")
    for _, filename, value in artifact_values:
        _write_exclusive(directory / filename, value)
    _write_exclusive(directory / "bundle.json", bundle_bytes)
    if {entry.name for entry in directory.iterdir()} != expected_names:
        raise EvidenceError("Release evidence archive inventory is not exact")


def _read_regular_file(path: Path) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise EvidenceError(
            f"Recoverable test archive artifact is missing: {path.name}"
        ) from exc
    if _is_link_or_reparse(path) or not stat.S_ISREG(info.st_mode):
        raise EvidenceError("Recoverable test archive artifact is not regular")
    if info.st_size < 0 or info.st_size > MAX_RESPONSE_BYTES:
        raise EvidenceError("Recoverable test archive artifact exceeds size limit")
    value = path.read_bytes()
    if len(value) != info.st_size or len(value) > MAX_RESPONSE_BYTES:
        raise EvidenceError("Recoverable test archive artifact changed during read")
    return value


def portable_load_recovery_archive_files(
    workspace: Workspace,
    *,
    attempt_relative: Path,
) -> tuple[str, dict[str, bytes]] | None:
    """Path-based test double for the fixed production recovery transport."""

    from cogni_os.release_evidence import _REQUIRED_ARTIFACT_FILES

    attempt = _directory_chain(
        workspace.root / "archive",
        attempt_relative,
        create=False,
    )
    if attempt is None:
        return None
    children = list(attempt.iterdir())
    if len(children) != 1:
        raise EvidenceError("Release evidence recovery requires exactly one bundle")
    bundle = children[0]
    if (
        not _BUNDLE_SHA_RE.fullmatch(bundle.name)
        or _is_link_or_reparse(bundle)
        or not bundle.is_dir()
    ):
        raise EvidenceError("Release evidence recovery bundle directory is invalid")
    expected_names = {"bundle.json", *_REQUIRED_ARTIFACT_FILES.values()}
    if {entry.name for entry in bundle.iterdir()} != expected_names:
        raise EvidenceError(
            "Release evidence recovery directory has extra or missing files"
        )
    values = {
        filename: _read_regular_file(bundle / filename) for filename in expected_names
    }
    if {entry.name for entry in bundle.iterdir()} != expected_names:
        raise EvidenceError("Release evidence recovery directory changed during read")
    return bundle.name, values
