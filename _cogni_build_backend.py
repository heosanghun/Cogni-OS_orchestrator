"""Minimal, offline PEP 517 wheel backend for the Cogni-OS runtime package.

The release jobs must be reproducible on a runner that has only the Python
standard library.  This backend deliberately supports the one pure-Python
wheel produced by this repository and excludes test-only modules from that
wheel boundary.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import re
import time
import zipfile
from pathlib import Path
from typing import Any


DIST_NAME = "cogni_os"


def _root() -> Path:
    return Path.cwd().resolve()


def _project_value(name: str) -> str:
    source = (_root() / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(
        rf"(?m)^\s*{re.escape(name)}\s*=\s*\"([^\"]+)\"\s*$",
        source,
    )
    if match is None:
        raise RuntimeError(f"Missing project metadata: {name}")
    return match.group(1)


def _version() -> str:
    return _project_value("version")


def _dist_info() -> str:
    return f"{DIST_NAME}-{_version()}.dist-info"


def _metadata() -> bytes:
    return (
        "Metadata-Version: 2.1\n"
        "Name: cogni-os\n"
        f"Version: {_version()}\n"
        f"Summary: {_project_value('description')}\n"
        f"Requires-Python: {_project_value('requires-python')}\n"
        "\n"
    ).encode("utf-8")


def _wheel_metadata() -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: cogni-os-stdlib-backend\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
        "\n"
    ).encode("utf-8")


def _entry_points() -> bytes:
    return (
        "[console_scripts]\n"
        "cogni = cogni_os.cli:main\n"
        "cognios = cogni_os.cli:main\n"
        "cogni-snapshot-broker = cogni_os.snapshot_broker:main\n"
    ).encode("utf-8")


def _package_files() -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    package_root = _root() / "src" / "cogni_os"
    for path in sorted(package_root.rglob("*.py")):
        relative = path.relative_to(package_root)
        if "tests" in relative.parts or path.name.endswith("_test_support.py"):
            continue
        archive_path = str(Path("cogni_os") / relative).replace("\\", "/")
        files.append((archive_path, path.read_bytes()))
    if not files:
        raise RuntimeError("Cogni-OS package sources are unavailable")
    return files


def _zip_datetime() -> tuple[int, int, int, int, int, int]:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))
    return time.gmtime(max(epoch, 315532800))[:6]


def _write_member(archive: zipfile.ZipFile, name: str, content: bytes) -> None:
    info = zipfile.ZipInfo(name, _zip_datetime())
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, content)


def _record_row(name: str, content: bytes) -> tuple[str, str, str]:
    digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
    return name, f"sha256={digest.decode('ascii')}", str(len(content))


def get_requires_for_build_wheel(config_settings: Any = None) -> list[str]:
    del config_settings
    return []


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: Any = None,
) -> str:
    del config_settings
    dist_info = _dist_info()
    target = Path(metadata_directory) / dist_info
    target.mkdir(parents=True, exist_ok=False)
    (target / "METADATA").write_bytes(_metadata())
    (target / "WHEEL").write_bytes(_wheel_metadata())
    (target / "entry_points.txt").write_bytes(_entry_points())
    return dist_info


def build_wheel(
    wheel_directory: str,
    config_settings: Any = None,
    metadata_directory: str | None = None,
) -> str:
    del config_settings, metadata_directory
    dist_info = _dist_info()
    wheel_name = f"{DIST_NAME}-{_version()}-py3-none-any.whl"
    destination = Path(wheel_directory) / wheel_name
    destination.parent.mkdir(parents=True, exist_ok=True)
    members = _package_files()
    members.extend(
        [
            (f"{dist_info}/METADATA", _metadata()),
            (f"{dist_info}/WHEEL", _wheel_metadata()),
            (f"{dist_info}/entry_points.txt", _entry_points()),
        ]
    )
    rows = [_record_row(name, content) for name, content in members]
    record_name = f"{dist_info}/RECORD"
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerows([*rows, (record_name, "", "")])
    members.append((record_name, buffer.getvalue().encode("utf-8")))
    with zipfile.ZipFile(destination, "w") as archive:
        for name, content in members:
            _write_member(archive, name, content)
    return wheel_name
