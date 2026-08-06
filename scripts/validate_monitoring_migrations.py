#!/usr/bin/env python3
"""Validate the complete ordered monitoring migration chain in memory."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

EXPECTED_MIGRATIONS = [
    "0001_monitoring.sql",
    "0002_monitoring_schema_floor.sql",
]
EXPECTED_TABLES = {
    "monitor_history",
    "monitor_nonces",
    "monitor_schema_floors",
    "monitor_snapshots",
}


def _validate(connection: sqlite3.Connection, migration_dir: Path) -> dict[str, object]:
    observed = sorted(path.name for path in migration_dir.glob("*.sql"))
    if observed != EXPECTED_MIGRATIONS:
        raise RuntimeError("monitoring migration inventory is not exact")
    for name in observed:
        connection.executescript((migration_dir / name).read_text(encoding="utf-8"))
    # Every migration must also be safe when a deployment retries it.
    for name in observed:
        connection.executescript((migration_dir / name).read_text(encoding="utf-8"))

    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name LIKE 'monitor_%'"
        )
    }
    if tables != EXPECTED_TABLES:
        raise RuntimeError("monitoring table inventory is not exact")
    floor_columns = [
        row[1] for row in connection.execute("PRAGMA table_info(monitor_schema_floors)")
    ]
    if floor_columns != [
        "workspace_id",
        "minimum_schema_rank",
        "minimum_schema_version",
        "updated_at",
    ]:
        raise RuntimeError("schema floor columns are not exact")

    connection.execute(
        "INSERT INTO monitor_schema_floors VALUES (?, ?, ?, ?)",
        ("workspace-test", 120, "1.2", "2026-08-01T00:00:00Z"),
    )
    for invalid_rank in (99, 200):
        try:
            connection.execute(
                "INSERT INTO monitor_schema_floors VALUES (?, ?, ?, ?)",
                (
                    f"workspace-invalid-{invalid_rank}",
                    invalid_rank,
                    "invalid",
                    "2026-08-01T00:00:00Z",
                ),
            )
        except sqlite3.IntegrityError:
            continue
        raise RuntimeError("schema floor rank constraint was not enforced")
    return {"migrations": observed, "tables": sorted(tables)}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    if sys.flags.isolated != 1 or Path.cwd().resolve() != root:
        print(json.dumps({"passed": False, "reason": "non-isolated-preflight"}))
        return 1
    try:
        with sqlite3.connect(":memory:") as connection:
            evidence = _validate(connection, root / "migrations")
    except Exception as error:  # noqa: BLE001 - emit a bounded CI failure record.
        print(json.dumps({"passed": False, "reason": str(error)}))
        return 1
    print(
        json.dumps({"passed": True, **evidence}, sort_keys=True, separators=(",", ":"))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
