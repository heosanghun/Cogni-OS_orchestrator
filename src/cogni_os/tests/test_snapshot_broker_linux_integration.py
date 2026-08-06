from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from cogni_os.snapshot_broker import SnapshotBrokerClient
from cogni_os.snapshot_broker_protocol import (
    BROKER_DESCRIPTOR_TYPE,
    canonical_json_sha256,
    verify_signed_envelope,
)
from cogni_os.trusted_runner import (
    _committed_snapshot_manifest,
    _committed_snapshot_postcheck,
    _materialize_committed_snapshot,
    _remove_committed_snapshot,
    trusted_git_source_commit,
)


@unittest.skipUnless(
    os.name == "posix"
    and sys.platform.startswith("linux")
    and os.environ.get("COGNI_RUN_ROOT_BROKER_INTEGRATION") == "1",
    "requires an installed root broker and explicit integration opt-in",
)
class InstalledSnapshotBrokerIntegrationTests(unittest.TestCase):
    def test_fixed_root_broker_preflight(self) -> None:
        # This deliberately does not silently emulate root or use a variable
        # temporary socket.  CI must provision the real service and trust files.
        client = SnapshotBrokerClient()
        client.preflight()
        self.assertIsNotNone(client.runtime_binding)
        assert client.runtime_binding is not None
        self.assertRegex(client.runtime_binding["manifest_sha256"], r"^[0-9a-f]{64}$")

    def test_real_fd_lease_ed25519_scm_rights_and_cleanup(self) -> None:
        workspace_value = os.environ.get("COGNI_BROKER_TEST_WORKSPACE")
        self.assertIsNotNone(
            workspace_value,
            "COGNI_BROKER_TEST_WORKSPACE must name a non-root-owned Git workspace",
        )
        workspace = Path(str(workspace_value)).resolve(strict=True)
        commit = trusted_git_source_commit(workspace)
        snapshot = _committed_snapshot_manifest(workspace, commit)
        with tempfile.TemporaryDirectory(prefix="cogni-broker-source-") as raw:
            source_root = Path(raw) / "sealed-source"
            materialized = _materialize_committed_snapshot(
                workspace,
                source_root,
                commit,
            )
            self.assertEqual(materialized, snapshot)
            try:
                lease = SnapshotBrokerClient().acquire(
                    source_root=source_root,
                    source_commit=commit,
                    tree_oid=snapshot["tree_oid"],
                    task_id="P01-BROKER-CI",
                    attempt=1,
                    actor="cogni-ci",
                    run_id="b0c0b0c0b0c0b0c0b0c0b0c0b0c0b0c0",
                    validation_contract_sha256="c" * 64,
                    expected_snapshot_sha256=snapshot["sha256"],
                )
            finally:
                if source_root.exists():
                    _remove_committed_snapshot(source_root)
        try:
            acquire = verify_signed_envelope(
                lease.acquire_attestation, kind="snapshot-acquired"
            )
            descriptor = os.fstat(lease.descriptor)
            self.assertTrue(stat.S_ISDIR(descriptor.st_mode))
            self.assertEqual(acquire["descriptor_type"], BROKER_DESCRIPTOR_TYPE)
            self.assertEqual(acquire["snapshot_device"], descriptor.st_dev)
            self.assertEqual(acquire["snapshot_inode"], descriptor.st_ino)
            self.assertEqual(
                canonical_json_sha256(lease.acquire_attestation),
                lease.acquire_attestation_sha256,
            )
            self.assertEqual(
                _committed_snapshot_postcheck(
                    lease.snapshot_root,
                    lease.snapshot,
                    snapshot_descriptor=lease.descriptor,
                ),
                lease.snapshot,
            )
            cleanup = lease.release(receipt_preimage_sha256="d" * 64)
            cleanup_payload = verify_signed_envelope(cleanup, kind="snapshot-cleaned")
            self.assertTrue(cleanup_payload["namespace_removed"])
            self.assertEqual(
                cleanup_payload["acquire_attestation_sha256"],
                lease.acquire_attestation_sha256,
            )
            self.assertEqual(cleanup_payload["receipt_preimage_sha256"], "d" * 64)
        finally:
            if not lease.released:
                lease.close_without_claiming_cleanup()


if __name__ == "__main__":
    unittest.main()
