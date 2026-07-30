"""Small cross-platform utilities used by Cogni-OS."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ConfigurationError

TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,49}$")


def utc_now() -> str:
    """Return a stable UTC timestamp suitable for JSON records."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    """Parse a timestamp created by :func:`utc_now`."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical_json(value: Any) -> bytes:
    """Encode JSON deterministically for hashing and signatures."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def read_json(path: Path) -> dict[str, Any]:
    """Read a UTF-8 JSON object."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"Expected a JSON object in {path}")
    return value


def atomic_write_json(path: Path, value: Any) -> None:
    """Write JSON through a same-directory temporary file and atomic replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculate a file SHA-256 without loading the file into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_task_id(value: str) -> str:
    """Validate and return a task identifier."""
    if not TASK_ID_RE.fullmatch(value):
        raise ConfigurationError(
            "Task id must start with an alphanumeric character and contain only "
            "letters, numbers, dot, underscore, or hyphen (maximum 80 characters)"
        )
    return value


def validate_agent_id(value: str) -> str:
    """Validate and return an agent identifier."""
    if not AGENT_ID_RE.fullmatch(value):
        raise ConfigurationError(
            "Agent id must start with an alphanumeric character and contain only "
            "letters, numbers, dot, underscore, or hyphen (maximum 50 characters)"
        )
    return value


def is_relative_to(path: Path, parent: Path) -> bool:
    """Return whether a resolved path is under another resolved path."""
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
