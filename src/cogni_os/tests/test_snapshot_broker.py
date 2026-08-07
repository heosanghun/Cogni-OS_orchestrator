from __future__ import annotations

import array
import base64
import inspect
import os
import socket
import stat
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cogni_os.errors import EvidenceError
from cogni_os.snapshot_broker import (
    BROKER_CONNECTION_TIMEOUT_SECONDS,
    MAX_ACTIVE_BROKER_LEASES,
    MAX_BROKER_CONNECTION_WORKERS,
    MAX_BROKER_PENDING_CONNECTIONS,
    MAX_CLEANUP_TOMBSTONES,
    BrokerLease,
    BrokerPaths,
    SnapshotBrokerClient,
    SnapshotBrokerDaemon,
    _bounded_sorted_directory_names,
    _NonceReplayStore,
    _receive_response_with_fd,
    _require_sealed_source_entry,
    _ServerLease,
)
from cogni_os.snapshot_broker_protocol import (
    BROKER_PROOF_SCOPE,
    BROKER_PROTOCOL_ID,
    BROKER_SCHEMA_VERSION,
    BROKER_SOURCE_DESCRIPTOR_TYPE,
    SnapshotBrokerError,
    canonical_json_bytes,
    canonical_json_sha256,
    encode_frame,
    validate_request,
    validate_signed_envelope,
)
from cogni_os.trusted_runner import (
    TRUSTED_RECEIPT_RESULT_KEYS,
    TRUSTED_RUNNER_ID,
    _BrokerLeaseGuard,
    snapshot_broker_contract,
    trusted_receipt_preimage_sha256,
)

from cogni_os import trust_projection, trusted_runner

RUN_ID = "1" * 32


def acquire_request() -> dict[str, object]:
    now = int(time.time())
    return {
        "schema_version": BROKER_SCHEMA_VERSION,
        "protocol_id": BROKER_PROTOCOL_ID,
        "operation": "acquire",
        "request_id": "request-1",
        "nonce": "nonce-1",
        "issued_at": now,
        "expires_at": now + 60,
        "source_descriptor_type": BROKER_SOURCE_DESCRIPTOR_TYPE,
        "source_commit": "a" * 40,
        "tree_oid": "b" * 40,
        "materialization_policy": "git-object-dirfd-nofollow-stream-v2",
        "task_id": "P01",
        "attempt": 2,
        "actor": "antigravity-verifier",
        "run_id": RUN_ID,
        "validation_contract_sha256": "c" * 64,
        "expected_snapshot_sha256": "d" * 64,
    }


def release_request() -> dict[str, object]:
    now = int(time.time())
    return {
        "schema_version": BROKER_SCHEMA_VERSION,
        "protocol_id": BROKER_PROTOCOL_ID,
        "operation": "release",
        "request_id": "request-2",
        "nonce": "nonce-2",
        "issued_at": now,
        "expires_at": now + 60,
        "lease_id": "lease-1",
        "acquire_attestation_sha256": "e" * 64,
        "task_id": "P01",
        "attempt": 2,
        "actor": "antigravity-verifier",
        "run_id": RUN_ID,
        "validation_contract_sha256": "c" * 64,
        "receipt_preimage_sha256": "f" * 64,
    }


class SnapshotBrokerProtocolTests(unittest.TestCase):
    def test_nonce_pruning_streams_uid_directories_without_materializing_them(
        self,
    ) -> None:
        source = inspect.getsource(_NonceReplayStore._prune_expired)
        self.assertNotIn("list(uid_iterator)", source)
        self.assertIn("uid_directories > MAX_NONCE_UID_DIRECTORIES", source)

    def test_directory_enumeration_stops_at_limit_plus_one_before_sorting(
        self,
    ) -> None:
        class BoundedEntries:
            def __init__(self) -> None:
                self.consumed = 0
                self.closed = False

            def __enter__(self) -> "BoundedEntries":
                return self

            def __exit__(self, *args: object) -> None:
                self.closed = True

            def __iter__(self) -> BoundedEntries:
                return self

            def __next__(self) -> SimpleNamespace:
                self.consumed += 1
                return SimpleNamespace(name=f"entry-{self.consumed:04d}")

        entries = BoundedEntries()
        with (
            patch("cogni_os.snapshot_broker.MAX_SOURCE_TREE_NODE_COUNT", 4),
            patch("cogni_os.snapshot_broker.os.scandir", return_value=entries),
            self.assertRaisesRegex(SnapshotBrokerError, "directory is unbounded"),
        ):
            _bounded_sorted_directory_names(123)
        self.assertEqual(entries.consumed, 5)
        self.assertTrue(entries.closed)

    def test_default_daemon_construction_uses_fixed_paths(self) -> None:
        daemon = SnapshotBrokerDaemon()
        self.assertEqual(daemon.paths, BrokerPaths())

    def test_request_rejects_unknown_fields(self) -> None:
        request = acquire_request()
        request["unexpected"] = True
        with self.assertRaisesRegex(SnapshotBrokerError, "schema is not exact"):
            validate_request(request)

    def test_broker_resource_bounds_are_fixed(self) -> None:
        self.assertEqual(BROKER_CONNECTION_TIMEOUT_SECONDS, 5)
        self.assertEqual(MAX_BROKER_CONNECTION_WORKERS, 8)
        self.assertEqual(MAX_BROKER_PENDING_CONNECTIONS, 16)
        self.assertEqual(MAX_ACTIVE_BROKER_LEASES, 64)

    def test_error_response_requires_no_file_descriptor(self) -> None:
        response = {
            "schema_version": BROKER_SCHEMA_VERSION,
            "protocol_id": BROKER_PROTOCOL_ID,
            "operation": "acquire",
            "request_id": "request-1",
            "ok": False,
            "error_code": "SnapshotBrokerError",
            "message": "denied",
        }
        frame = encode_frame(response)

        class FakeSocket:
            def recvmsg(self, _size: int, _ancillary_size: int, _flags: int):
                return frame, [], 0, None

            def recv(self, _size: int) -> bytes:
                raise AssertionError("complete frame must not require another read")

        with patch(
            "cogni_os.snapshot_broker.socket.CMSG_SPACE",
            return_value=64,
            create=True,
        ):
            decoded, descriptor = _receive_response_with_fd(FakeSocket())
        self.assertEqual(decoded, response)
        self.assertIsNone(descriptor)

    def test_truncated_frame_closes_every_received_descriptor(self) -> None:
        descriptor, other = os.pipe()
        os.close(other)
        rights = array.array("i", [descriptor]).tobytes()

        class FakeSocket:
            def recvmsg(self, _size: int, _ancillary_size: int, _flags: int):
                return (
                    b"\x00\x00",
                    [(socket.SOL_SOCKET, 9999, rights)],
                    0,
                    None,
                )

            def recv(self, _size: int) -> bytes:
                return b""

        with (
            patch("cogni_os.snapshot_broker.socket.SCM_RIGHTS", 9999, create=True),
            patch(
                "cogni_os.snapshot_broker.socket.CMSG_SPACE",
                return_value=64,
                create=True,
            ),
            self.assertRaisesRegex(SnapshotBrokerError, "truncated"),
        ):
            _receive_response_with_fd(FakeSocket())
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_excess_scm_rights_closes_every_received_descriptor(self) -> None:
        first, first_other = os.pipe()
        second, second_other = os.pipe()
        os.close(first_other)
        os.close(second_other)
        rights = array.array("i", [first, second]).tobytes()
        response = {
            "schema_version": BROKER_SCHEMA_VERSION,
            "protocol_id": BROKER_PROTOCOL_ID,
            "operation": "acquire",
            "request_id": "request-1",
            "ok": False,
            "error_code": "SnapshotBrokerError",
            "message": "denied",
        }

        class FakeSocket:
            def recvmsg(self, _size: int, _ancillary_size: int, _flags: int):
                return (
                    encode_frame(response),
                    [(socket.SOL_SOCKET, 9999, rights)],
                    0,
                    None,
                )

            def recv(self, _size: int) -> bytes:
                return b""

        with (
            patch("cogni_os.snapshot_broker.socket.SCM_RIGHTS", 9999, create=True),
            patch(
                "cogni_os.snapshot_broker.socket.CMSG_SPACE",
                return_value=64,
                create=True,
            ),
            self.assertRaisesRegex(SnapshotBrokerError, "too many"),
        ):
            _receive_response_with_fd(FakeSocket())
        for descriptor in (first, second):
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_root_acquire_path_has_no_git_or_process_or_device_control(self) -> None:
        source = inspect.getsource(SnapshotBrokerDaemon._acquire).lower()
        for forbidden in (
            "_run_git",
            "_committed_tree_manifest",
            "_materialize_committed_snapshot",
            "subprocess",
            "popen",
            "af_inet",
            "cuda",
            "nvidia",
        ):
            self.assertNotIn(forbidden, source)
        module_source = Path(
            inspect.getsourcefile(SnapshotBrokerDaemon) or ""
        ).read_text(encoding="utf-8")
        self.assertNotIn("from .trusted_runner", module_source)
        self.assertNotIn("import subprocess", module_source)
        self.assertNotIn("subprocess.", module_source)
        self.assertNotIn("socket.AF_INET", module_source)
        self.assertNotIn("CUDA_VISIBLE_DEVICES", module_source)
        self.assertNotIn("/dev/nvidia", module_source)

    def test_broker_contract_explicitly_disclaims_source_authenticity(self) -> None:
        contract = snapshot_broker_contract()
        self.assertEqual(
            contract["source_descriptor_type"], BROKER_SOURCE_DESCRIPTOR_TYPE
        )
        self.assertEqual(contract["source_authenticity"], "not-attested-by-broker")
        self.assertIn("bidirectional-scm-rights", contract["transport"])

    def test_acquire_rejects_legacy_path_or_wrong_descriptor_type(self) -> None:
        legacy = acquire_request()
        del legacy["source_descriptor_type"]
        legacy["workspace_root"] = "/actor/controlled"
        with self.assertRaisesRegex(SnapshotBrokerError, "schema is not exact"):
            validate_request(legacy)

        wrong_type = acquire_request()
        wrong_type["source_descriptor_type"] = "path"
        with self.assertRaisesRegex(SnapshotBrokerError, "acquire binding"):
            validate_request(wrong_type)

    def test_writable_or_special_caller_source_is_rejected(self) -> None:
        writable_directory = SimpleNamespace(
            st_uid=1000,
            st_mode=stat.S_IFDIR | 0o755,
        )
        with self.assertRaisesRegex(SnapshotBrokerError, "not a sealed"):
            _require_sealed_source_entry(
                writable_directory,  # type: ignore[arg-type]
                caller_uid=1000,
                directory=True,
            )
        special = SimpleNamespace(
            st_uid=1000,
            st_mode=stat.S_IFLNK | 0o444,
        )
        with self.assertRaisesRegex(SnapshotBrokerError, "not a sealed"):
            _require_sealed_source_entry(
                special,  # type: ignore[arg-type]
                caller_uid=1000,
                directory=False,
            )

    def test_request_rejects_expired_window(self) -> None:
        request = acquire_request()
        request["issued_at"] = 1
        request["expires_at"] = 2
        with self.assertRaisesRegex(SnapshotBrokerError, "expired"):
            validate_request(request, now=100)

    def test_canonical_json_rejects_non_finite_numbers(self) -> None:
        with self.assertRaises(SnapshotBrokerError):
            canonical_json_bytes({"value": float("nan")})

    def test_signed_payload_rejects_unknown_fields(self) -> None:
        payload = {
            "schema_version": BROKER_SCHEMA_VERSION,
            "protocol_id": BROKER_PROTOCOL_ID,
            "kind": "snapshot-cleaned",
            "request_sha256": "a" * 64,
            "request_id": "request-1",
            "request_nonce": "nonce-1",
            "caller_pid": 1,
            "caller_uid": 1000,
            "caller_gid": 1000,
            "lease_id": "lease-1",
            "acquire_attestation_sha256": "b" * 64,
            "snapshot_sha256": "c" * 64,
            "snapshot_device": 1,
            "snapshot_inode": 2,
            "removed": True,
            "issued_at": int(time.time()),
            "broker_nonce": "broker-1",
            "unexpected": True,
        }
        envelope = {
            "schema_version": BROKER_SCHEMA_VERSION,
            "algorithm": "ed25519-openssl-pkeyutl-raw-v1",
            "public_key_sha256": "d" * 64,
            "payload": payload,
            "signature_b64": base64.b64encode(b"0" * 64).decode("ascii"),
        }
        with self.assertRaisesRegex(SnapshotBrokerError, "schema is not exact"):
            validate_signed_envelope(envelope, kind="snapshot-cleaned")

    def test_release_request_rejects_missing_execution_binding(self) -> None:
        request = release_request()
        del request["run_id"]
        with self.assertRaisesRegex(SnapshotBrokerError, "schema is not exact"):
            validate_request(request)

    def test_daemon_rejects_old_proof_reused_for_another_run(self) -> None:
        daemon = SnapshotBrokerDaemon()
        daemon._runtime_binding = {"manifest_sha256": "9" * 64}
        daemon._leases["lease-1"] = _ServerLease(
            lease_id="lease-1",
            caller_uid=1000,
            caller_gid=1000,
            caller_pid=123,
            snapshot_path=Path("/never-read-after-binding-rejection"),
            snapshot={"sha256": "d" * 64},
            snapshot_device=1,
            snapshot_inode=2,
            acquire_attestation_sha256="e" * 64,
            expires_at=int(time.time()) + 60,
            task_id="P01",
            attempt=2,
            actor="antigravity-verifier",
            run_id=RUN_ID,
            validation_contract_sha256="c" * 64,
        )
        request = release_request()
        request["run_id"] = "2" * 32
        with self.assertRaisesRegex(SnapshotBrokerError, "execution binding changed"):
            daemon._release(request, pid=123, uid=1000, gid=1000)

    def test_persisted_lease_rejects_noncanonical_run_id(self) -> None:
        daemon = SnapshotBrokerDaemon()
        lease = _ServerLease(
            lease_id="lease-" + ("1" * 32),
            caller_uid=1000,
            caller_gid=1000,
            caller_pid=123,
            snapshot_path=daemon.paths.store_root / ("lease-" + ("1" * 32)),
            snapshot={"sha256": "a" * 64},
            snapshot_device=1,
            snapshot_inode=2,
            acquire_attestation_sha256="b" * 64,
            expires_at=int(time.time()) + 60,
            task_id="P01",
            attempt=2,
            actor="antigravity-verifier",
            run_id=RUN_ID,
            validation_contract_sha256="c" * 64,
        )
        document = daemon._lease_record(lease)
        document["run_id"] = "A" * 32
        content = canonical_json_bytes(document)
        path = MagicMock()
        path.stem = lease.lease_id
        path.stat.return_value = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=0,
            st_size=len(content),
        )
        path.read_bytes.return_value = content
        with self.assertRaisesRegex(SnapshotBrokerError, "run id is invalid"):
            daemon._decode_lease_record(path)

    def test_runner_guard_cleans_up_after_abort_once(self) -> None:
        class FakeLease:
            acquire_attestation_sha256 = "a" * 64
            task_id = "P01"
            attempt = 2
            actor = "antigravity-verifier"
            run_id = "run-1"
            validation_contract_sha256 = "b" * 64
            released = False

            def __init__(self) -> None:
                self.preimages: list[str] = []

            def release(self, *, receipt_preimage_sha256: str) -> dict[str, object]:
                self.preimages.append(receipt_preimage_sha256)
                self.released = True
                return {}

            def close_without_claiming_cleanup(self) -> None:
                raise AssertionError(
                    "successful abort cleanup must not close as leaked"
                )

        lease = FakeLease()
        guard = _BrokerLeaseGuard()
        guard.attach(lease)
        guard.cleanup_after_abort()
        guard.cleanup_after_abort()
        self.assertEqual(len(lease.preimages), 1)
        self.assertRegex(lease.preimages[0], r"^[0-9a-f]{64}$")

    def test_runner_guard_retries_exact_cleanup_after_response_loss(self) -> None:
        class FakeLease:
            acquire_attestation_sha256 = "a" * 64
            task_id = "P01"
            attempt = 2
            actor = "antigravity-verifier"
            run_id = "run-1"
            validation_contract_sha256 = "b" * 64
            released = False

            def __init__(self) -> None:
                self.preimages: list[str] = []
                self.closed_without_proof = False

            def release(self, *, receipt_preimage_sha256: str) -> dict[str, object]:
                self.preimages.append(receipt_preimage_sha256)
                if len(self.preimages) == 1:
                    raise TimeoutError("cleanup response was lost")
                self.released = True
                return {"cleanup_attestation": "replayed"}

            def close_without_claiming_cleanup(self) -> None:
                self.closed_without_proof = True

        lease = FakeLease()
        guard = _BrokerLeaseGuard()
        guard.attach(lease)
        with self.assertRaisesRegex(TimeoutError, "response was lost"):
            guard.release("c" * 64)
        guard.cleanup_after_abort()

        self.assertEqual(lease.preimages, ["c" * 64, "c" * 64])
        self.assertTrue(lease.released)
        self.assertFalse(lease.closed_without_proof)

    def test_client_reuses_identical_release_frame_after_response_loss(self) -> None:
        sent_frames: list[bytes] = []
        decode_calls = 0

        class FakeConnection:
            def __enter__(self) -> FakeConnection:  # noqa: PYI034
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def sendall(self, payload: bytes) -> None:
                sent_frames.append(payload)

            def makefile(self, *_args: object, **_kwargs: object) -> object:
                return object()

        client = SnapshotBrokerClient.__new__(SnapshotBrokerClient)
        client.runtime_binding = {"manifest_sha256": "9" * 64}
        client._connect = lambda: FakeConnection()  # type: ignore[method-assign]
        lease = BrokerLease(
            client=client,
            lease_id="lease-1",
            descriptor=-1,
            snapshot_root=Path("/unused"),
            snapshot={"sha256": "a" * 64},
            acquire_attestation={
                "payload": {"snapshot_device": 10, "snapshot_inode": 20}
            },
            acquire_attestation_sha256="b" * 64,
            task_id="P01",
            attempt=2,
            actor="antigravity-verifier",
            run_id=RUN_ID,
            validation_contract_sha256="c" * 64,
        )

        def decode_response(_stream: object) -> dict[str, object]:
            nonlocal decode_calls
            decode_calls += 1
            if decode_calls == 1:
                raise TimeoutError("response was lost")
            assert lease.release_request is not None
            return {
                "schema_version": BROKER_SCHEMA_VERSION,
                "protocol_id": BROKER_PROTOCOL_ID,
                "operation": "release",
                "request_id": lease.release_request["request_id"],
                "ok": True,
                "cleanup_attestation": {"signed": "cleanup"},
            }

        def verified_cleanup(
            _envelope: object,
            *,
            kind: str,
        ) -> dict[str, object]:
            self.assertEqual(kind, "snapshot-cleaned")
            assert lease.release_request is not None
            return {
                "request_sha256": canonical_json_sha256(lease.release_request),
                "request_nonce": lease.release_request["nonce"],
                "lease_id": lease.lease_id,
                "acquire_attestation_sha256": lease.acquire_attestation_sha256,
                "snapshot_sha256": lease.snapshot["sha256"],
                "snapshot_device": 10,
                "snapshot_inode": 20,
                "task_id": lease.task_id,
                "attempt": lease.attempt,
                "actor": lease.actor,
                "run_id": lease.run_id,
                "validation_contract_sha256": lease.validation_contract_sha256,
                "receipt_preimage_sha256": "d" * 64,
                "broker_runtime_manifest_sha256": "9" * 64,
                "namespace_removed": True,
            }

        with (
            patch(
                "cogni_os.snapshot_broker.decode_frame_from_stream",
                side_effect=decode_response,
            ),
            patch(
                "cogni_os.snapshot_broker.verify_signed_envelope",
                side_effect=verified_cleanup,
            ),
        ):
            with self.assertRaisesRegex(TimeoutError, "response was lost"):
                client.release(lease, receipt_preimage_sha256="d" * 64)
            cleanup = client.release(lease, receipt_preimage_sha256="d" * 64)

        self.assertEqual(cleanup, {"signed": "cleanup"})
        self.assertEqual(len(sent_frames), 2)
        self.assertEqual(sent_frames[0], sent_frames[1])

    def test_daemon_cleanup_tombstone_is_exact_and_bounded(self) -> None:
        daemon = SnapshotBrokerDaemon()
        request = release_request()
        response = {"ok": True, "cleanup_attestation": {"signed": "cleanup"}}
        daemon._remember_cleanup_response(
            request,
            uid=1000,
            gid=1000,
            response=response,
        )
        self.assertEqual(
            daemon._cached_cleanup_response(request, uid=1000, gid=1000),
            response,
        )

        changed = dict(request)
        changed["receipt_preimage_sha256"] = "0" * 64
        with self.assertRaisesRegex(SnapshotBrokerError, "does not match"):
            daemon._cached_cleanup_response(changed, uid=1000, gid=1000)

        for index in range(MAX_CLEANUP_TOMBSTONES + 3):
            candidate = dict(release_request())
            candidate["lease_id"] = f"lease-{index + 2}"
            candidate["request_id"] = f"request-{index + 3}"
            candidate["nonce"] = f"nonce-{index + 3}"
            daemon._remember_cleanup_response(
                candidate,
                uid=1000,
                gid=1000,
                response=response,
            )
        self.assertEqual(len(daemon._cleanup_tombstones), MAX_CLEANUP_TOMBSTONES)

    def test_client_descriptor_is_closed_before_cleanup_request(self) -> None:
        descriptor, other = os.pipe()
        os.close(other)

        class FakeClient:
            def release(
                self,
                _lease: BrokerLease,
                *,
                receipt_preimage_sha256: str,
            ) -> dict[str, object]:
                self.assert_preimage = receipt_preimage_sha256
                with self_test.assertRaises(OSError):
                    os.fstat(descriptor)
                return {"snapshot_cleanup_only": True}

        self_test = self
        client = FakeClient()
        lease = BrokerLease(
            client=client,  # type: ignore[arg-type]
            lease_id="lease-1",
            descriptor=descriptor,
            snapshot_root=Path(f"/proc/self/fd/{descriptor}"),
            snapshot={"sha256": "a" * 64},
            acquire_attestation={},
            acquire_attestation_sha256="b" * 64,
            task_id="P01",
            attempt=2,
            actor="antigravity-verifier",
            run_id=RUN_ID,
            validation_contract_sha256="c" * 64,
        )
        cleanup = lease.release(receipt_preimage_sha256="d" * 64)
        self.assertEqual(cleanup, {"snapshot_cleanup_only": True})
        self.assertEqual(lease.descriptor, -1)
        self.assertTrue(lease.released)

    def test_public_runner_finally_cleans_after_post_acquire_failure(self) -> None:
        class FakeLease:
            acquire_attestation_sha256 = "a" * 64
            task_id = "P01"
            attempt = 2
            actor = "antigravity-verifier"
            run_id = RUN_ID
            validation_contract_sha256 = "b" * 64
            released = False

            def __init__(self) -> None:
                self.preimages: list[str] = []

            def release(self, *, receipt_preimage_sha256: str) -> dict[str, object]:
                self.preimages.append(receipt_preimage_sha256)
                self.released = True
                return {}

            def close_without_claiming_cleanup(self) -> None:
                raise AssertionError("abort cleanup unexpectedly leaked")

        lease = FakeLease()

        def acquire_then_fail(**kwargs: object) -> dict[str, object]:
            guard = kwargs["_lease_guard"]
            assert isinstance(guard, _BrokerLeaseGuard)
            guard.attach(lease)
            raise RuntimeError("failure after acquire")

        with (
            patch.object(
                trusted_runner,
                "_run_trusted_validations_impl",
                side_effect=acquire_then_fail,
            ),
            self.assertRaisesRegex(RuntimeError, "failure after acquire"),
        ):
            trusted_runner.run_trusted_validations(
                workspace_root=Path("."),
                runs_root=Path("runs"),
                task_id="P01",
                attempt=2,
                actor="antigravity-verifier",
                run_id=RUN_ID,
                manifest={},
                gpu_allowed=False,
                network_allowed=False,
            )
        self.assertEqual(len(lease.preimages), 1)

    def test_broker_lease_is_guarded_before_caller_source_cleanup(self) -> None:
        source = inspect.getsource(trusted_runner._run_trusted_validations_impl)
        production_branch = source.split(
            'caller_source_root = run_directory / "caller-sealed-source"', 1
        )[1]
        self.assertLess(
            production_branch.index("_lease_guard.attach(broker_lease)"),
            production_branch.index("_remove_committed_snapshot(caller_source_root)"),
        )

    def test_public_runner_rejects_noncanonical_run_id_before_execution(self) -> None:
        with (
            patch.object(trusted_runner, "_run_trusted_validations_impl") as execute,
            self.assertRaisesRegex(EvidenceError, "32 lowercase hexadecimal"),
        ):
            trusted_runner.run_trusted_validations(
                workspace_root=Path("."),
                runs_root=Path("runs"),
                task_id="P01",
                attempt=2,
                actor="antigravity-verifier",
                run_id="runner-generated-run",
                manifest={},
                gpu_allowed=False,
                network_allowed=False,
            )
        execute.assert_not_called()

    def test_installer_uses_fixed_immutable_runtime_and_isolated_entrypoint(
        self,
    ) -> None:
        repository_root = Path(__file__).resolve().parents[3]
        installer = (
            repository_root / "scripts" / "install_snapshot_broker.sh"
        ).read_text(encoding="utf-8")
        unit = (
            repository_root / "deploy" / "systemd" / "cogni-snapshot-broker.service"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "STAGING_ROOT=/var/lib/cogni-os/snapshot-broker",
            installer,
        )
        self.assertIn(
            "RUNTIME_ROOT=/usr/local/lib/cogni-os/snapshot-broker-v1",
            installer,
        )
        self.assertIn("for component in /var /var/lib /var/lib/cogni-os", installer)
        self.assertNotIn("$(pwd)", installer.lower())
        self.assertNotIn("$PWD", installer)
        entrypoint = (
            "ExecStart=/usr/local/lib/cogni-os/snapshot-broker-v1/venv/bin/python "
            "-I -m cogni_os.snapshot_broker serve"
        )
        self.assertIn(entrypoint, installer)
        self.assertIn(entrypoint, unit)
        inaccessible_git = (
            "InaccessiblePaths=-/usr/bin/git -/usr/lib/git-core -/usr/libexec/git-core"
        )
        self.assertIn(inaccessible_git, installer)
        self.assertIn(inaccessible_git, unit)
        self.assertIn("PrivateDevices=yes", installer)
        self.assertIn("PrivateDevices=yes", unit)
        self.assertIn("DevicePolicy=closed", installer)
        self.assertIn("DevicePolicy=closed", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", installer)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", unit)

    def test_receipt_preimage_is_non_circular_but_execution_bound(self) -> None:
        document = {
            "task_id": "P01",
            "attempt": 2,
            "actor": "antigravity-verifier",
            "run_id": RUN_ID,
            "snapshot_protection": {"cleanup_attestation": {"one": 1}},
            "receipt_preimage_sha256": "0" * 64,
        }
        first = trusted_receipt_preimage_sha256(document)
        document["snapshot_protection"]["cleanup_attestation"] = {"two": 2}
        document["receipt_preimage_sha256"] = first
        self.assertEqual(trusted_receipt_preimage_sha256(document), first)
        document["run_id"] = "2" * 32
        self.assertNotEqual(trusted_receipt_preimage_sha256(document), first)

    def test_client_is_explicit_no_go_off_linux(self) -> None:
        if os.name == "posix" and sys.platform.startswith("linux"):
            # Linux support is exercised only by the fixed root-broker
            # integration inventory.  The portable suite still records this
            # platform branch without turning it into a skip.
            self.assertEqual(sys.platform, "linux")
            return
        with self.assertRaisesRegex(SnapshotBrokerError, "Linux-only"):
            SnapshotBrokerClient()

    def test_client_preflight_fails_before_socket_when_forced_non_posix(self) -> None:
        with (
            patch("cogni_os.snapshot_broker.os.name", "nt"),
            self.assertRaisesRegex(SnapshotBrokerError, "Linux-only"),
        ):
            SnapshotBrokerClient()

    def test_projection_requires_matching_acquire_and_cleanup_proofs(self) -> None:
        acquire_envelope = {"signed": "acquire"}
        acquire_sha = canonical_json_sha256(acquire_envelope)
        acquire = {
            "caller_uid": 1000,
            "caller_gid": 1000,
            "snapshot_owner_uid": 0,
            "descriptor_type": "O_PATH-directory",
            "snapshot_device": 10,
            "snapshot_inode": 20,
            "source_commit": "a" * 40,
            "tree_oid": "b" * 40,
            "snapshot_sha256": "c" * 64,
            "lease_id": "lease-1",
            "task_id": "P01",
            "attempt": 2,
            "actor": "antigravity-verifier",
            "run_id": RUN_ID,
            "validation_contract_sha256": "e" * 64,
            "broker_runtime_manifest_sha256": "f" * 64,
        }
        cleanup = {
            "lease_id": "lease-1",
            "acquire_attestation_sha256": acquire_sha,
            "snapshot_sha256": "c" * 64,
            "snapshot_device": 10,
            "snapshot_inode": 20,
            "caller_uid": 1000,
            "caller_gid": 1000,
            "task_id": "P01",
            "attempt": 2,
            "actor": "antigravity-verifier",
            "run_id": RUN_ID,
            "validation_contract_sha256": "e" * 64,
            "broker_runtime_manifest_sha256": "f" * 64,
            "namespace_removed": True,
        }
        protection = {
            "policy_id": "cogni-os-root-broker-snapshot-v1",
            "platform": "linux",
            "broker": "external-privileged-fd-lease",
            "runner_euid": 1000,
            "owner_uid": 0,
            "actor_write_access": False,
            "links_rejected": True,
            "proof": BROKER_PROOF_SCOPE,
            "descriptor_type": "O_PATH-directory",
            "snapshot_device": 10,
            "snapshot_inode": 20,
            "acquire_attestation_sha256": acquire_sha,
            "acquire_attestation": acquire_envelope,
            "cleanup_attestation": {"signed": "cleanup"},
        }
        trusted = {
            "task_id": "P01",
            "attempt": 2,
            "actor": "antigravity-verifier",
            "run_id": RUN_ID,
            "validation_contract_sha256": "e" * 64,
            "source_commit": "a" * 40,
            "snapshot": {
                "tree_oid": "b" * 40,
                "sha256": "c" * 64,
            },
            "snapshot_protection": protection,
        }
        trusted["receipt_preimage_sha256"] = trusted_receipt_preimage_sha256(trusted)
        cleanup["receipt_preimage_sha256"] = trusted["receipt_preimage_sha256"]
        with (
            patch(
                "cogni_os.trust_projection.verify_signed_envelope",
                side_effect=[acquire, cleanup],
            ),
            patch(
                "cogni_os.trust_projection.trusted_broker_runtime_binding",
                return_value={"manifest_sha256": "f" * 64},
            ),
        ):
            self.assertTrue(
                trust_projection._signed_broker_protection_valid(
                    trusted,
                    protection,
                )
            )
        protection["cleanup_attestation"] = None
        with patch(
            "cogni_os.trust_projection.verify_signed_envelope",
            side_effect=SnapshotBrokerError("missing cleanup"),
        ):
            self.assertFalse(
                trust_projection._signed_broker_protection_valid(
                    trusted,
                    protection,
                )
            )

    def test_broker_signing_oracle_cannot_become_execution_verification(
        self,
    ) -> None:
        """Arbitrary broker receipt bindings remain NO_GO without a second key."""

        trusted = {key: None for key in TRUSTED_RECEIPT_RESULT_KEYS}
        trusted.update(
            {
                "schema_version": 3,
                "runner": TRUSTED_RUNNER_ID,
                "task_id": "P01",
                "attempt": 2,
                "actor": "arbitrary-cogni-broker-group-member",
                "run_id": RUN_ID,
                "validation_contract_sha256": "a" * 64,
                "receipt_preimage_sha256": "b" * 64,
                "snapshot_protection": {
                    "broker": "external-privileged-fd-lease",
                    "proof": BROKER_PROOF_SCOPE,
                },
            }
        )
        verification = {
            "verified_by": trusted["actor"],
            "run_id": trusted["run_id"],
            "verifier_evidence": {
                "manifest_sha256": "c" * 64,
                "bundle": {},
                # The attacker can obtain snapshot signatures, but has no
                # independent executor-attestation key.
            },
            "trusted_validation": trusted,
        }
        with (
            patch(
                "cogni_os.trust_projection._trusted_receipt_shape_valid",
                return_value=True,
            ),
            patch(
                "cogni_os.trust_projection._verification_run_binding_valid",
                return_value=True,
            ),
        ):
            self.assertFalse(
                trust_projection._valid_trusted_verification(
                    verification,
                    task={"id": "P01", "attempt": 2},
                    current_commit=None,
                    workspace_root=Path("."),
                    bundle={},
                    bundle_directory=Path("."),
                )
            )

    def test_workspace_and_runner_run_ids_must_be_identical(self) -> None:
        self.assertFalse(
            trust_projection._verification_run_binding_valid(
                {"run_id": "workspace-run"},
                {"run_id": "runner-generated-different-run"},
            )
        )


if __name__ == "__main__":
    unittest.main()
