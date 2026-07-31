from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "migrations" / "0001_monitoring.sql"


class MonitoringMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = sqlite3.connect(":memory:")
        self.database.execute("PRAGMA foreign_keys = ON")
        self.database.executescript(MIGRATION.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.database.close()

    def _columns(self, table: str) -> dict[str, tuple[object, ...]]:
        rows = self.database.execute(f"PRAGMA table_info({table})").fetchall()
        return {str(row[1]): row for row in rows}

    def test_v2_schema_has_key_ids_and_operational_indexes(self) -> None:
        expected_columns = {
            "monitor_snapshots": {
                "workspace_id",
                "sequence",
                "observed_at",
                "received_at",
                "key_id",
                "nonce",
                "body_sha256",
                "signature",
                "payload",
            },
            "monitor_history": {
                "workspace_id",
                "sequence",
                "observed_at",
                "received_at",
                "key_id",
                "nonce",
                "body_sha256",
                "signature",
                "payload",
            },
            "monitor_nonces": {
                "workspace_id",
                "key_id",
                "nonce",
                "sequence",
                "received_at",
            },
        }
        for table, expected in expected_columns.items():
            with self.subTest(table=table):
                columns = self._columns(table)
                self.assertEqual(set(columns), expected)
                self.assertEqual(columns["key_id"][3], 1)

        history_indexes = {
            str(row[1])
            for row in self.database.execute(
                "PRAGMA index_list(monitor_history)"
            ).fetchall()
        }
        nonce_indexes = {
            str(row[1])
            for row in self.database.execute(
                "PRAGMA index_list(monitor_nonces)"
            ).fetchall()
        }
        self.assertIn("monitor_history_observed", history_indexes)
        self.assertIn("monitor_nonces_received", nonce_indexes)

    def test_snapshot_sequence_and_digest_constraints_fail_closed(self) -> None:
        insert = """
            INSERT INTO monitor_snapshots
              (workspace_id, sequence, observed_at, received_at, key_id,
               nonce, body_sha256, signature, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        valid = (
            "workspace-a",
            1,
            "2026-07-31T00:00:00Z",
            "2026-07-31T00:00:01Z",
            "publisher-2026q3",
            "nonce-0123456789abcdef",
            "a" * 64,
            "b" * 64,
            "{}",
        )
        self.database.execute(insert, valid)

        with self.assertRaises(sqlite3.IntegrityError):
            self.database.execute(
                insert,
                (
                    "workspace-b",
                    0,
                    valid[2],
                    valid[3],
                    valid[4],
                    "nonce-0011223344556677",
                    valid[6],
                    valid[7],
                    valid[8],
                ),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.execute(
                insert,
                (
                    "workspace-c",
                    2,
                    valid[2],
                    valid[3],
                    valid[4],
                    "nonce-fedcba9876543210",
                    "c" * 63,
                    valid[7],
                    valid[8],
                ),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.execute(
                insert,
                (
                    valid[0],
                    2,
                    valid[2],
                    valid[3],
                    valid[4],
                    "nonce-aabbccddeeff0011",
                    valid[6],
                    valid[7],
                    valid[8],
                ),
            )

    def test_history_and_nonce_replay_constraints_fail_closed(self) -> None:
        history_insert = """
            INSERT INTO monitor_history
              (workspace_id, sequence, observed_at, received_at, key_id,
               nonce, body_sha256, signature, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        valid = (
            "workspace-a",
            1,
            "2026-07-31T00:00:00Z",
            "2026-07-31T00:00:01Z",
            "publisher-2026q3",
            "nonce-0123456789abcdef",
            "a" * 64,
            "b" * 64,
            "{}",
        )
        self.database.execute(history_insert, valid)

        with self.assertRaises(sqlite3.IntegrityError):
            self.database.execute(
                history_insert,
                (
                    valid[0],
                    valid[1],
                    valid[2],
                    valid[3],
                    valid[4],
                    "nonce-fedcba9876543210",
                    valid[6],
                    valid[7],
                    valid[8],
                ),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.execute(
                history_insert,
                (
                    valid[0],
                    2,
                    valid[2],
                    valid[3],
                    valid[4],
                    valid[5],
                    valid[6],
                    valid[7],
                    valid[8],
                ),
            )

        nonce_insert = """
            INSERT INTO monitor_nonces
              (workspace_id, key_id, nonce, sequence, received_at)
            VALUES (?, ?, ?, ?, ?)
        """
        nonce_row = (
            "workspace-a",
            "publisher-2026q3",
            "nonce-0123456789abcdef",
            1,
            "2026-07-31T00:00:01Z",
        )
        self.database.execute(nonce_insert, nonce_row)
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.execute(
                nonce_insert,
                (
                    nonce_row[0],
                    "publisher-2026q4",
                    nonce_row[2],
                    2,
                    nonce_row[4],
                ),
            )


if __name__ == "__main__":
    unittest.main()
