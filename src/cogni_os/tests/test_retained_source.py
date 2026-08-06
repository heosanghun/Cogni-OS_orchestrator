from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cogni_os.retained_source import (
    GIT_BUNDLE_FILENAME,
    RECORD_FILENAME,
    RETAINED_SOURCE_API_ASSURANCE,
    RETAINED_SOURCE_CONTRACT_ID,
    RETAINED_SOURCE_SCHEMA_VERSION,
    VALIDATION_CONTRACT_FILENAME,
    VERIFIER_MANIFEST_FILENAME,
    RetainedSourceError,
    VerifierIntegrityError,
    load_retained_source,
    retain_source_artifact,
    retained_source_api_assurance,
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class RetainedSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.store = self.base / "immutable-store"
        self.actor_tree = self.base / "actor-working-tree"
        self.inbox = self.base / "admin-artifact-inbox"
        for path in (self.store, self.actor_tree, self.inbox):
            path.mkdir()
        self.bundle_bytes = b"git-bundle-placeholder-for-byte-contract\n"
        self.manifest_bytes = b'{"schema_version":1,"producer":"independent"}\n'
        self.contract_bytes = b'{"network":false,"gpu":false}\n'
        self.bundle = self.inbox / "source.bundle"
        self.manifest = self.inbox / "verifier.json"
        self.contract = self.inbox / "contract.json"
        self.bundle.write_bytes(self.bundle_bytes)
        self.manifest.write_bytes(self.manifest_bytes)
        self.contract.write_bytes(self.contract_bytes)

    def tearDown(self) -> None:
        if os.name == "posix":
            for directory, subdirectories, filenames in os.walk(self.base):
                del subdirectories
                try:
                    os.chmod(directory, 0o700)
                except OSError:
                    pass
                for filename in filenames:
                    try:
                        os.chmod(Path(directory) / filename, 0o600)
                    except OSError:
                        pass
        self.temporary.cleanup()

    def kwargs(self) -> dict[str, object]:
        return {
            "immutable_root": self.store.resolve(),
            "forbidden_actor_working_tree": self.actor_tree.resolve(),
            "repository_id": "heosanghun/Cogni-OS_orchestrator",
            "workspace_id": "cogni-production",
            "task_id": "P01-TRUTH",
            "attempt": 13,
            "run_id": "1" * 32,
            "git_bundle_path": self.bundle.resolve(),
            "git_bundle_sha256": _sha256(self.bundle_bytes),
            "git_bundle_size_bytes": len(self.bundle_bytes),
            "commit_oid": "a" * 40,
            "tree_oid": "b" * 40,
            "verifier_manifest_path": self.manifest.resolve(),
            "verifier_manifest_sha256": _sha256(self.manifest_bytes),
            "validation_contract_path": self.contract.resolve(),
            "validation_contract_sha256": _sha256(self.contract_bytes),
        }

    def test_retains_exact_content_addressed_schema_and_rehashes_bytes(self) -> None:
        artifact = retain_source_artifact(**self.kwargs())

        self.assertTrue(artifact.created)
        self.assertEqual(artifact.directory.parent, self.store.resolve())
        self.assertEqual(artifact.directory.name, artifact.artifact_id)
        self.assertEqual(
            {entry.name for entry in artifact.directory.iterdir()},
            {
                GIT_BUNDLE_FILENAME,
                VERIFIER_MANIFEST_FILENAME,
                VALIDATION_CONTRACT_FILENAME,
                RECORD_FILENAME,
            },
        )
        self.assertEqual(artifact.git_bundle_path.read_bytes(), self.bundle_bytes)
        self.assertEqual(
            artifact.verifier_manifest_path.read_bytes(), self.manifest_bytes
        )
        self.assertEqual(
            artifact.validation_contract_path.read_bytes(), self.contract_bytes
        )

        record = artifact.record
        self.assertEqual(record["schema_version"], RETAINED_SOURCE_SCHEMA_VERSION)
        self.assertEqual(record["contract_id"], RETAINED_SOURCE_CONTRACT_ID)
        self.assertEqual(
            set(record),
            {
                "schema_version",
                "contract_id",
                "artifact_id",
                "identity",
                "source",
                "verifier_manifest",
                "validation_contract",
                "storage",
                "assurance",
            },
        )
        self.assertEqual(
            record["identity"],
            {
                "repository_id": "heosanghun/Cogni-OS_orchestrator",
                "workspace_id": "cogni-production",
                "task_id": "P01-TRUTH",
                "attempt": 13,
                "run_id": "1" * 32,
            },
        )
        self.assertEqual(
            record["source"]["git_bundle"]["sha256"], _sha256(self.bundle_bytes)
        )
        self.assertEqual(
            record["source"]["git_bundle"]["size_bytes"], len(self.bundle_bytes)
        )
        self.assertEqual(record["source"]["commit_oid"], "a" * 40)
        self.assertEqual(record["source"]["tree_oid"], "b" * 40)
        self.assertEqual(
            record["storage"]["immutable_root_path"], str(self.store.resolve())
        )
        self.assertEqual(record["assurance"], RETAINED_SOURCE_API_ASSURANCE)
        raw_record = artifact.directory.joinpath(RECORD_FILENAME).read_bytes()
        self.assertEqual(hashlib.sha256(raw_record).hexdigest(), artifact.record_sha256)
        self.assertEqual(
            raw_record,
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n",
        )

    def test_identical_request_is_idempotent_and_does_not_rewrite(self) -> None:
        first = retain_source_artifact(**self.kwargs())
        record_stat = (first.directory / RECORD_FILENAME).stat()
        second = retain_source_artifact(**self.kwargs())

        self.assertFalse(second.created)
        self.assertEqual(first.artifact_id, second.artifact_id)
        self.assertEqual(
            record_stat.st_ino, (second.directory / RECORD_FILENAME).stat().st_ino
        )
        self.assertEqual(
            record_stat.st_mtime_ns,
            (second.directory / RECORD_FILENAME).stat().st_mtime_ns,
        )

    def test_loader_fails_closed_on_tampered_retained_bytes(self) -> None:
        artifact = retain_source_artifact(**self.kwargs())
        retained = artifact.git_bundle_path
        os.chmod(retained, 0o600)
        retained.write_bytes(b"tampered\n")

        with self.assertRaisesRegex(RetainedSourceError, "bytes do not match"):
            load_retained_source(self.store.resolve(), artifact.artifact_id)

    def test_loader_rejects_extra_inventory_and_record_schema_field(self) -> None:
        artifact = retain_source_artifact(**self.kwargs())
        directory = artifact.directory
        if os.name == "posix":
            os.chmod(directory, 0o700)
        (directory / "unexpected.txt").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(
            VerifierIntegrityError, "exceeds the fixed entry limit"
        ):
            load_retained_source(self.store.resolve(), artifact.artifact_id)

        (directory / "unexpected.txt").unlink()
        record_path = directory / RECORD_FILENAME
        os.chmod(record_path, 0o600)
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["unexpected"] = True
        record_path.write_bytes(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        with self.assertRaisesRegex(RetainedSourceError, "schema is not exact"):
            load_retained_source(self.store.resolve(), artifact.artifact_id)

    def test_inventory_scan_stops_immediately_at_the_fifth_entry(self) -> None:
        artifact = retain_source_artifact(**self.kwargs())

        class CountingScandir:
            def __init__(self) -> None:
                self.consumed = 0
                self.closed = False

            def __iter__(self):
                return self

            def __next__(self):
                if self.consumed >= 100_000:
                    raise StopIteration
                self.consumed += 1
                return type("Entry", (), {"name": f"entry-{self.consumed}"})()

            def close(self) -> None:
                self.closed = True

        fake = CountingScandir()
        with patch("cogni_os.retained_source.os.scandir", return_value=fake):
            with self.assertRaisesRegex(
                VerifierIntegrityError, "exceeds the fixed entry limit"
            ):
                load_retained_source(self.store.resolve(), artifact.artifact_id)
        self.assertLessEqual(fake.consumed, 5)
        self.assertEqual(fake.consumed, 5)
        self.assertTrue(fake.closed)

    def test_rejects_actor_working_tree_and_overlapping_store(self) -> None:
        actor_bundle = self.actor_tree / "source.bundle"
        actor_bundle.write_bytes(self.bundle_bytes)
        values = self.kwargs()
        values["git_bundle_path"] = actor_bundle.resolve()
        with self.assertRaisesRegex(RetainedSourceError, "actor working tree"):
            retain_source_artifact(**values)

        values = self.kwargs()
        values["forbidden_actor_working_tree"] = self.store.resolve()
        with self.assertRaisesRegex(RetainedSourceError, "must not overlap"):
            retain_source_artifact(**values)

    def test_rejects_dispatch_digest_size_and_oid_mismatch(self) -> None:
        values = self.kwargs()
        values["git_bundle_sha256"] = "f" * 64
        with self.assertRaisesRegex(RetainedSourceError, "dispatch binding"):
            retain_source_artifact(**values)

        values = self.kwargs()
        values["git_bundle_size_bytes"] = len(self.bundle_bytes) + 1
        with self.assertRaisesRegex(RetainedSourceError, "dispatch binding"):
            retain_source_artifact(**values)

        values = self.kwargs()
        values["tree_oid"] = "b" * 64
        with self.assertRaisesRegex(RetainedSourceError, "same hash format"):
            retain_source_artifact(**values)

    def test_rejects_symlink_and_hardlink_inputs(self) -> None:
        symlink = self.inbox / "bundle-link"
        try:
            symlink.symlink_to(self.bundle)
        except (OSError, NotImplementedError):
            symlink = None
        if symlink is not None:
            values = self.kwargs()
            values["git_bundle_path"] = symlink
            with self.assertRaisesRegex(RetainedSourceError, "regular non-link"):
                retain_source_artifact(**values)

        hardlink = self.inbox / "bundle-hardlink"
        try:
            os.link(self.bundle, hardlink)
        except OSError:
            hardlink = None
        if hardlink is not None:
            values = self.kwargs()
            values["git_bundle_path"] = hardlink
            with self.assertRaisesRegex(RetainedSourceError, "hard-linked"):
                retain_source_artifact(**values)

    def test_source_change_between_inspection_and_copy_fails_closed(self) -> None:
        values = self.kwargs()
        from cogni_os import retained_source

        original_copy = retained_source._copy_exclusive
        changed = False

        def mutate_before_copy(source, destination, maximum, expected, label):
            nonlocal changed
            if label == "git bundle" and not changed:
                changed = True
                source.write_bytes(b"changed-after-inspection\n")
            return original_copy(source, destination, maximum, expected, label)

        with patch(
            "cogni_os.retained_source._copy_exclusive", side_effect=mutate_before_copy
        ):
            with self.assertRaisesRegex(
                RetainedSourceError, "changed between inspection"
            ):
                retain_source_artifact(**values)

    def test_api_assurance_explicitly_preserves_followup_blockers(self) -> None:
        assurance = retained_source_api_assurance()
        self.assertFalse(assurance["actor_working_tree_execution_input"])
        self.assertFalse(assurance["ancestor_junction_reparse_chain_verified"])
        self.assertFalse(assurance["git_bundle_object_graph_verified"])
        self.assertFalse(assurance["git_materialization_performed"])
        self.assertFalse(assurance["linux_root_owned_immutable_store_e2e"])
        self.assertFalse(assurance["release_eligible"])
        self.assertEqual(
            assurance["remaining_blockers"],
            [
                "actual-git-bundle-and-commit-tree-verification",
                "git-materialization-from-retained-objects-only",
                "linux-root-owned-immutable-store-e2e",
                "ancestor-junction-reparse-chain-verification",
            ],
        )
        assurance["remaining_blockers"].append("mutation-does-not-touch-constant")
        self.assertEqual(len(RETAINED_SOURCE_API_ASSURANCE["remaining_blockers"]), 4)


if __name__ == "__main__":
    unittest.main()
