from __future__ import annotations

import base64
import copy
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cogni_os.snapshot_broker_protocol import (
    BROKER_PROTOCOL_ID,
    BROKER_SCHEMA_VERSION,
    BROKER_SIGNATURE_ALGORITHM,
)
from cogni_os.util import sha256_file
from cogni_os.verifier_journal import (
    CLEANUP_ACKED,
    EXECUTING,
    EXECUTION_SEALED,
    RECEIPT_PERSISTED,
    RELEASE_PENDING,
    SNAPSHOT_ACQUIRED,
    SOURCE_VERIFIED,
    VerifierJournal,
)
from cogni_os.verifier_protocol import (
    VERIFIER_LEDGER_DOMAIN,
    VERIFIER_PROTOCOL_ID,
    VERIFIER_RECEIPT_DOMAIN,
    VERIFIER_SCHEMA_VERSION,
    VerifierProtocolError,
    canonical_json_bytes,
    canonical_json_sha256,
)
from cogni_os.verifier_receipt import (
    VerifierReceiptError,
    _openssl_ed25519,
    sign_verification_receipt,
    trusted_receipt_signing_binding,
    trusted_receipt_verification_binding,
    verify_verification_receipt,
)
from cogni_os.verifier_service import (
    DedicatedVerifierService,
    VerifierServiceError,
    _bounded_receipt_entry_names,
    _validate_posix_receipt_root_identity,
    _validate_posix_receipt_root_policy,
)

NOW = 1_800_000_000
DISPATCH_HASH = "a" * 64
RUN_ID = "1" * 32


def _dispatch(*, dispatch_hash: str = DISPATCH_HASH) -> dict[str, object]:
    return {
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "protocol_id": VERIFIER_PROTOCOL_ID,
        "kind": "verification-dispatch",
        "ledger_domain": VERIFIER_LEDGER_DOMAIN,
        "dispatch_event_hash": dispatch_hash,
        "ledger_head_hash": "b" * 64,
        "workspace_id": "workspace-p01",
        "task_id": "P01-TRUTH",
        "attempt": 1,
        "actor": "codex",
        "run_id": RUN_ID,
        "source": {
            "artifact_id": "retained-source-p01",
            "bundle_sha256": "c" * 64,
            "size_bytes": 4096,
            "commit_oid": "d" * 40,
            "tree_oid": "e" * 40,
        },
        "verifier_manifest_sha256": "f" * 64,
        "validation_contract_sha256": "0" * 64,
        "capability_receipt_sha256": "2" * 64,
        "network_allowed": False,
        "gpu_allowed": False,
        "nonce": "dispatch-nonce-p01",
        "issued_at": NOW - 10,
        "expires_at": NOW + 300,
    }


def _wakeup(dispatch: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "protocol_id": VERIFIER_PROTOCOL_ID,
        "kind": "verification-wakeup",
        "dispatch_event_hash": dispatch["dispatch_event_hash"],
        "task_id": dispatch["task_id"],
        "run_id": dispatch["run_id"],
        "nonce": dispatch["nonce"],
    }


def _execution_preimage(dispatch: dict[str, object]) -> dict[str, object]:
    executable = "/opt/cogni-os/verifier/runtime/bin/python"
    return {
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "protocol_id": VERIFIER_PROTOCOL_ID,
        "kind": "verification-execution-preimage",
        "domain": VERIFIER_RECEIPT_DOMAIN,
        "dispatch_event_hash": dispatch["dispatch_event_hash"],
        "request_event_hash": "3" * 64,
        "start_event_hash": "4" * 64,
        "ledger_head_hash": dispatch["ledger_head_hash"],
        "workspace_id": dispatch["workspace_id"],
        "task_id": dispatch["task_id"],
        "attempt": dispatch["attempt"],
        "actor": dispatch["actor"],
        "run_id": dispatch["run_id"],
        "source": copy.deepcopy(dispatch["source"]),
        "verifier_manifest_sha256": dispatch["verifier_manifest_sha256"],
        "validation_contract_sha256": dispatch["validation_contract_sha256"],
        "snapshot_manifest_sha256": "5" * 64,
        "acquire_proof_sha256": "6" * 64,
        "runtime": {
            "runtime_manifest_sha256": "7" * 64,
            "entrypoint_sha256": "8" * 64,
            "interpreter_sha256": "9" * 64,
            "package_tree_sha256": "a" * 64,
            "service_unit_sha256": "b" * 64,
            "policy_sha256": "c" * 64,
        },
        "commands": [
            {
                "index": 0,
                "executable_path": executable,
                "executable_sha256": "d" * 64,
                "argv": [executable, "-m", "unittest", "discover"],
                "cwd": "/workspace",
                "environment_sha256": "e" * 64,
                "exit_code": 0,
                "timed_out": False,
                "output_truncated": False,
                "stdout_sha256": "f" * 64,
                "stdout_size_bytes": 128,
                "stderr_sha256": "0" * 64,
                "stderr_size_bytes": 0,
                "started_monotonic_ns": 1_000,
                "completed_monotonic_ns": 2_000,
            }
        ],
        "isolation": {
            "network_disabled": True,
            "gpu_disabled": True,
            "namespace_sha256": "1" * 64,
            "cgroup_sha256": "2" * 64,
        },
        "source_postcheck": {"passed": True, "observed_sha256": "c" * 64},
        "snapshot_postcheck": {"passed": True, "observed_sha256": "5" * 64},
        "started_at": "2027-01-15T08:00:00Z",
        "completed_at": "2027-01-15T08:00:01Z",
        "started_monotonic_ns": 900,
        "completed_monotonic_ns": 2_100,
        "result": "passed",
        "failure_code": None,
    }


def _cleanup_proof(
    dispatch: dict[str, object], preimage_sha256: str
) -> dict[str, object]:
    payload = {
        "schema_version": BROKER_SCHEMA_VERSION,
        "protocol_id": BROKER_PROTOCOL_ID,
        "kind": "snapshot-cleaned",
        "request_sha256": "3" * 64,
        "request_id": "release-p01",
        "request_nonce": "release-nonce-p01",
        "caller_pid": 100,
        "caller_uid": 0,
        "caller_gid": 0,
        "lease_id": "lease-p01",
        "acquire_attestation_sha256": "4" * 64,
        "snapshot_sha256": "5" * 64,
        "snapshot_device": 11,
        "snapshot_inode": 22,
        "issued_at": NOW,
        "broker_nonce": "broker-nonce-p01",
        "task_id": dispatch["task_id"],
        "attempt": dispatch["attempt"],
        "actor": dispatch["actor"],
        "run_id": dispatch["run_id"],
        "validation_contract_sha256": dispatch["validation_contract_sha256"],
        "receipt_preimage_sha256": preimage_sha256,
        "broker_runtime_manifest_sha256": "6" * 64,
        "namespace_removed": True,
    }
    return {
        "schema_version": BROKER_SCHEMA_VERSION,
        "algorithm": BROKER_SIGNATURE_ALGORITHM,
        "public_key_sha256": "7" * 64,
        "payload": payload,
        "signature_b64": base64.b64encode(b"b" * 64).decode("ascii"),
    }


def _openssl_path() -> Path:
    discovered = shutil.which("openssl")
    candidates = (
        Path(discovered) if discovered else None,
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
    )
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise AssertionError("OpenSSL is required for the verifier receipt test")


def _pem_bytes(label: str, der: bytes, *, newline: bytes = b"\n") -> bytes:
    encoded = base64.b64encode(der)
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (
        f"-----BEGIN {label}-----".encode("ascii")
        + newline
        + newline.join(lines)
        + newline
        + f"-----END {label}-----".encode("ascii")
        + newline
    )


class VerifierServiceProtocolTests(unittest.TestCase):
    def test_receipt_inventory_stops_at_limit_plus_one(self) -> None:
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
                return SimpleNamespace(name=f"receipt-{self.consumed}")

        entries = BoundedEntries()
        with (
            patch("cogni_os.verifier_service.MAX_RECEIPT_STORE_ENTRIES", 4),
            patch("cogni_os.verifier_service.os.scandir", return_value=entries),
            self.assertRaisesRegex(VerifierServiceError, "entry limit"),
        ):
            _bounded_receipt_entry_names(Path("unused"))
        self.assertEqual(entries.consumed, 5)
        self.assertTrue(entries.closed)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.root = Path(self.temporary.name)
        self.journal = VerifierJournal(self.root / "journal")
        self.service = DedicatedVerifierService(
            journal=self.journal,
            receipt_root=self.root / "receipts",
            clock=lambda: NOW,
        )
        self.openssl = _openssl_path()
        self.private_key = self.root / "verifier-private.pem"
        self.public_key = self.root / "verifier-public.pem"
        subprocess.run(
            [
                str(self.openssl),
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(self.private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                str(self.openssl),
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            check=True,
            capture_output=True,
        )
        self.signing_binding = {
            "private_key_path": str(self.private_key),
            "public_key_path": str(self.public_key),
            "public_key_sha256": sha256_file(self.public_key),
            "openssl_path": str(self.openssl),
            "openssl_sha256": sha256_file(self.openssl),
        }
        self.verification_binding = {
            key: value
            for key, value in self.signing_binding.items()
            if key != "private_key_path"
        }
        self.patchers = (
            patch(
                "cogni_os.verifier_receipt.trusted_receipt_signing_binding",
                return_value=self.signing_binding,
            ),
            patch(
                "cogni_os.verifier_receipt.trusted_receipt_verification_binding",
                return_value=self.verification_binding,
            ),
            patch(
                "cogni_os.verifier_receipt.verify_broker_cleanup",
                side_effect=lambda envelope, *, kind: envelope["payload"],
            ),
        )
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.service.close()
        self.temporary.cleanup()

    def _receipt(self, dispatch: dict[str, object] | None = None) -> dict[str, object]:
        dispatch = _dispatch() if dispatch is None else dispatch
        preimage = _execution_preimage(dispatch)
        cleanup = _cleanup_proof(dispatch, canonical_json_sha256(preimage))
        return sign_verification_receipt(
            preimage,
            cleanup,
            sealed_at="2027-01-15T08:00:02Z",
            dispatch=dispatch,
        )

    def test_dispatch_wakeup_exact_schema_nonce_expiry_and_single_claim(self) -> None:
        dispatch = _dispatch()
        first = self.service.claim_dispatch(dispatch, _wakeup(dispatch))
        self.assertTrue(first.claim_acquired)
        duplicate = self.service.claim_dispatch(dispatch, _wakeup(dispatch))
        self.assertFalse(duplicate.claim_acquired)

        wrong_nonce = _wakeup(dispatch)
        wrong_nonce["nonce"] = "substituted-nonce"
        with self.assertRaisesRegex(VerifierServiceError, "nonce"):
            self.service.claim_dispatch(dispatch, wrong_nonce)

        extra_field = copy.deepcopy(dispatch)
        extra_field["authority"] = "socket"
        with self.assertRaisesRegex(VerifierProtocolError, "schema is not exact"):
            self.service.claim_dispatch(extra_field, _wakeup(dispatch))

        expired = _dispatch(dispatch_hash="8" * 64)
        expired["issued_at"] = NOW - 700
        expired["expires_at"] = NOW - 100
        with self.assertRaisesRegex(VerifierProtocolError, "expired"):
            self.service.claim_dispatch(expired, _wakeup(expired))
        self.assertFalse((self.journal.root / f"{'8' * 64}.json").exists())

    def test_receipt_exact_domain_and_two_real_ed25519_signatures(self) -> None:
        dispatch = _dispatch()
        receipt = self._receipt(dispatch)
        verified = verify_verification_receipt(receipt, dispatch=dispatch)
        self.assertEqual(verified["domain"], "cogni-os.verification-receipt.v1")
        self.assertEqual(len(base64.b64decode(verified["execution_signature_b64"])), 64)
        self.assertEqual(len(base64.b64decode(verified["final_signature_b64"])), 64)
        self.assertNotEqual(
            verified["execution_signature_b64"], verified["final_signature_b64"]
        )

        extra_field = copy.deepcopy(receipt)
        extra_field["release_ready"] = True
        with self.assertRaisesRegex(VerifierProtocolError, "schema is not exact"):
            verify_verification_receipt(extra_field, dispatch=dispatch)

        tampered_signature = copy.deepcopy(receipt)
        signature = bytearray(
            base64.b64decode(tampered_signature["final_signature_b64"])
        )
        signature[0] ^= 1
        tampered_signature["final_signature_b64"] = base64.b64encode(signature).decode(
            "ascii"
        )
        with self.assertRaisesRegex(VerifierReceiptError, "final receipt signature"):
            verify_verification_receipt(tampered_signature, dispatch=dispatch)

        preimage = _execution_preimage(dispatch)
        cleanup = _cleanup_proof(dispatch, "9" * 64)
        with self.assertRaisesRegex(VerifierReceiptError, "another preimage"):
            sign_verification_receipt(
                preimage,
                cleanup,
                sealed_at="2027-01-15T08:00:02Z",
                dispatch=dispatch,
            )

    def test_rfc8032_known_answer_and_same_spki_key_separation(self) -> None:
        # RFC 8032 section 7.1, test vector 2 (one-byte message 0x72).
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        public = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )
        expected = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c"
            "387b2eaeb4302aeeb00d291612bb0c00"
        )
        private_der = bytes.fromhex("302e020100300506032b657004220420") + seed
        public_der = bytes.fromhex("302a300506032b6570032100") + public
        known_private = self.root / "rfc8032-private.pem"
        known_public = self.root / "rfc8032-public.pem"
        known_private.write_bytes(_pem_bytes("PRIVATE KEY", private_der))
        known_public.write_bytes(_pem_bytes("PUBLIC KEY", public_der))
        observed = _openssl_ed25519(
            b"\x72",
            openssl_path=self.openssl,
            key_path=known_private,
            signature=None,
        )
        self.assertEqual(observed, expected)
        self.assertIs(
            _openssl_ed25519(
                b"\x72",
                openssl_path=self.openssl,
                key_path=known_public,
                signature=expected,
            ),
            True,
        )

        # Different PEM bytes and line endings must not bypass key-domain
        # separation when both documents encode the same canonical SPKI.
        broker_copy = self.root / "broker-public-different-pem.pem"
        broker_copy.write_bytes(_pem_bytes("PUBLIC KEY", public_der, newline=b"\r\n"))
        self.assertNotEqual(sha256_file(known_public), sha256_file(broker_copy))
        openssl_binding = {
            "path": str(self.openssl),
            "sha256": sha256_file(self.openssl),
        }
        with (
            patch(
                "cogni_os.verifier_receipt._require_root_owned_file",
                side_effect=lambda path, **_kwargs: Path(path),
            ),
            patch(
                "cogni_os.verifier_receipt._trusted_openssl_binding",
                return_value=openssl_binding,
            ),
        ):
            with self.assertRaisesRegex(VerifierReceiptError, "distinct Ed25519 keys"):
                trusted_receipt_verification_binding(
                    public_key_path=known_public,
                    openssl_path=self.openssl,
                    openssl_sha256_path=self.root / "unused.sha256",
                    snapshot_broker_public_key_path=broker_copy,
                )
            with self.assertRaisesRegex(VerifierReceiptError, "distinct Ed25519 keys"):
                trusted_receipt_signing_binding(
                    private_key_path=known_private,
                    public_key_path=known_public,
                    openssl_path=self.openssl,
                    openssl_sha256_path=self.root / "unused.sha256",
                    snapshot_broker_public_key_path=broker_copy,
                )

    def test_passed_result_rejects_truncated_output(self) -> None:
        dispatch = _dispatch()
        preimage = _execution_preimage(dispatch)
        preimage["commands"][0]["output_truncated"] = True
        cleanup = _cleanup_proof(dispatch, canonical_json_sha256(preimage))
        with self.assertRaisesRegex(
            VerifierProtocolError, "Passed verifier result contradicts"
        ):
            sign_verification_receipt(
                preimage,
                cleanup,
                sealed_at="2027-01-15T08:00:02Z",
                dispatch=dispatch,
            )

    def test_command_paths_must_be_canonical_posix_absolute_paths(self) -> None:
        dispatch = _dispatch()
        invalid_executables = (
            "relative/python",
            "/opt//python",
            "/opt/./python",
            "/opt/../python",
            "/opt/python/",
            "/opt\\python",
            "/opt/\x00python",
            "/",
        )
        for invalid in invalid_executables:
            with self.subTest(executable=repr(invalid)):
                preimage = _execution_preimage(dispatch)
                preimage["commands"][0]["executable_path"] = invalid
                preimage["commands"][0]["argv"][0] = invalid
                cleanup = _cleanup_proof(dispatch, canonical_json_sha256(preimage))
                with self.assertRaisesRegex(
                    VerifierProtocolError, "Verifier executable"
                ):
                    sign_verification_receipt(
                        preimage,
                        cleanup,
                        sealed_at="2027-01-15T08:00:02Z",
                        dispatch=dispatch,
                    )
        for invalid in ("work", "/work//task", "/work/../task", "/work/task/"):
            with self.subTest(cwd=repr(invalid)):
                preimage = _execution_preimage(dispatch)
                preimage["commands"][0]["cwd"] = invalid
                cleanup = _cleanup_proof(dispatch, canonical_json_sha256(preimage))
                with self.assertRaisesRegex(VerifierProtocolError, "Verifier cwd"):
                    sign_verification_receipt(
                        preimage,
                        cleanup,
                        sealed_at="2027-01-15T08:00:02Z",
                        dispatch=dispatch,
                    )

    def test_posix_receipt_root_policy_rejects_mode_and_writable_ancestry(self) -> None:
        root = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=1000,
            st_gid=100,
        )
        protected_ancestors = (
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
        )
        _validate_posix_receipt_root_policy(
            root,
            protected_ancestors,
            euid=1000,
            egid=100,
        )

        wrong_mode = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o750,
            st_uid=1000,
            st_gid=100,
        )
        with self.assertRaisesRegex(VerifierServiceError, "euid/egid 0700"):
            _validate_posix_receipt_root_policy(
                wrong_mode,
                protected_ancestors,
                euid=1000,
                egid=100,
            )

        writable_ancestor = (
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=1000),
        )
        with self.assertRaisesRegex(VerifierServiceError, "ancestry"):
            _validate_posix_receipt_root_policy(
                root,
                writable_ancestor,
                euid=1000,
                egid=100,
            )

    def test_posix_receipt_root_identity_policy_rejects_directory_swap(self) -> None:
        expected = (10, 20)
        valid = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=1000,
            st_gid=100,
            st_dev=10,
            st_ino=20,
        )
        _validate_posix_receipt_root_identity(
            valid,
            expected_identity=expected,
            euid=1000,
            egid=100,
        )
        swapped = SimpleNamespace(**{**vars(valid), "st_ino": 21})
        with self.assertRaisesRegex(
            VerifierServiceError, "identity or protection changed"
        ):
            _validate_posix_receipt_root_identity(
                swapped,
                expected_identity=expected,
                euid=1000,
                egid=100,
            )

    def test_receipt_persistence_requires_cleanup_and_is_idempotent(self) -> None:
        dispatch = _dispatch()
        self.service.claim_dispatch(dispatch, _wakeup(dispatch))
        receipt = self._receipt(dispatch)
        with self.assertRaisesRegex(VerifierServiceError, "only after cleanup"):
            self.service.persist_receipt(dispatch, receipt)

        for state in (
            SOURCE_VERIFIED,
            SNAPSHOT_ACQUIRED,
            EXECUTING,
            EXECUTION_SEALED,
            RELEASE_PENDING,
            CLEANUP_ACKED,
        ):
            self.journal.transition(DISPATCH_HASH, state)
        persisted = self.service.persist_receipt(dispatch, receipt)
        self.assertEqual(persisted.record.state, RECEIPT_PERSISTED)
        self.assertFalse(persisted.idempotent)
        self.assertEqual(
            json.loads(persisted.path.read_text(encoding="utf-8")), receipt
        )
        self.assertEqual(persisted.sha256, canonical_json_sha256(receipt))
        self.assertEqual(persisted.sha256, sha256_file(persisted.path))

        retried = self.service.persist_receipt(dispatch, receipt)
        self.assertEqual(retried.record.state, RECEIPT_PERSISTED)
        self.assertTrue(retried.idempotent)
        self.assertFalse(self.service.assurance["release_ready"])
        self.assertIn(
            "ledger_authority_ed25519_dispatch_integration_unimplemented",
            self.service.assurance["release_blockers"],
        )

        preimage = _execution_preimage(dispatch)
        cleanup = _cleanup_proof(dispatch, canonical_json_sha256(preimage))
        different_valid_receipt = sign_verification_receipt(
            preimage,
            cleanup,
            sealed_at="2027-01-15T08:00:03Z",
            dispatch=dispatch,
        )
        with self.assertRaisesRegex(VerifierServiceError, "differs or is unsafe"):
            self.service.persist_receipt(dispatch, different_valid_receipt)

    def test_existing_hardlinked_receipt_is_not_idempotent_evidence(self) -> None:
        dispatch = _dispatch()
        self.service.claim_dispatch(dispatch, _wakeup(dispatch))
        for state in (
            SOURCE_VERIFIED,
            SNAPSHOT_ACQUIRED,
            EXECUTING,
            EXECUTION_SEALED,
            RELEASE_PENDING,
            CLEANUP_ACKED,
        ):
            self.journal.transition(DISPATCH_HASH, state)
        receipt = self._receipt(dispatch)
        receipt_path = self.service.receipt_root / f"{DISPATCH_HASH}.receipt.json"
        receipt_path.write_bytes(canonical_json_bytes(receipt))
        alias = self.service.receipt_root / "attacker-hardlink"
        os.link(receipt_path, alias)
        with self.assertRaisesRegex(VerifierServiceError, "differs or is unsafe"):
            self.service.persist_receipt(dispatch, receipt)

    def test_same_length_write_fault_is_removed_and_never_persisted(self) -> None:
        dispatch = _dispatch()
        self.service.claim_dispatch(dispatch, _wakeup(dispatch))
        for state in (
            SOURCE_VERIFIED,
            SNAPSHOT_ACQUIRED,
            EXECUTING,
            EXECUTION_SEALED,
            RELEASE_PENDING,
            CLEANUP_ACKED,
        ):
            self.journal.transition(DISPATCH_HASH, state)
        receipt = self._receipt(dispatch)
        receipt_path = self.service.receipt_root / f"{DISPATCH_HASH}.receipt.json"
        real_write = os.write

        def same_length_corrupt_write(descriptor: int, value: object) -> int:
            payload = bytes(value)
            corrupted = bytes([payload[0] ^ 1]) + payload[1:]
            self.assertEqual(len(corrupted), len(payload))
            return real_write(descriptor, corrupted)

        with (
            patch(
                "cogni_os.verifier_service.os.write",
                side_effect=same_length_corrupt_write,
            ),
            self.assertRaisesRegex(VerifierServiceError, "durable write failed"),
        ):
            self.service.persist_receipt(dispatch, receipt)
        self.assertFalse(receipt_path.exists())
        self.assertEqual(self.journal.load(DISPATCH_HASH).state, CLEANUP_ACKED)


if __name__ == "__main__":
    unittest.main()
