from __future__ import annotations

import base64
import hashlib
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cogni_os.snapshot_broker_protocol import (
    BROKER_PUBLIC_KEY_PATH,
    canonical_json_bytes,
)
from cogni_os.verifier_attestation_protocol import (
    EXECUTOR_ATTESTATION_ALGORITHM,
    EXECUTOR_ATTESTATION_DOMAIN,
    EXECUTOR_ATTESTATION_PROTOCOL_ID,
    EXECUTOR_ATTESTATION_PUBLIC_KEY_PATH,
    EXECUTOR_ATTESTATION_SCHEMA_VERSION,
    EXECUTOR_VERIFIER_ID,
    VerifierAttestationError,
    command_output_digest_sha256,
    runner_runtime_digest_sha256,
    verifier_identity_sha256,
    verify_executor_attestation,
)

BASE_EPOCH = 1_700_000_000


def verifier_identity() -> dict[str, object]:
    return {
        "actor": "antigravity-verifier",
        "schema_version": 1,
        "control_principal": "independent-verifier-service",
        "model_family": "independent-verifier",
        "alias_of": None,
        "alias_chain": [],
    }


def _timestamp(offset: int) -> str:
    return datetime.fromtimestamp(BASE_EPOCH + offset, tz=timezone.utc).isoformat()


def trusted_receipt() -> dict[str, object]:
    cleanup_attestation = {"payload": {"issued_at": BASE_EPOCH + 3}}
    return {
        "schema_version": 3,
        "runner": "cogni-os-trusted-runner-v3",
        "task_id": "P01",
        "attempt": 2,
        "actor": "antigravity-verifier",
        "run_id": "1" * 32,
        "validation_contract_sha256": "a" * 64,
        "receipt_preimage_sha256": "b" * 64,
        "receipt_sha256": "c" * 64,
        "started_at": _timestamp(0),
        "completed_at": _timestamp(2),
        "sandbox_environment_sha256": "c" * 64,
        "isolation_policy": "cogni-os-deny-by-default-v2",
        "isolation_backend": {
            "id": "linux-bubblewrap-v1",
            "path": "/usr/bin/bwrap",
            "sha256": "d" * 64,
        },
        "snapshot_protection": {
            "acquire_attestation_sha256": "e" * 64,
            "acquire_attestation": {"payload": {"issued_at": BASE_EPOCH + 1}},
            "cleanup_attestation": cleanup_attestation,
        },
        "validations": [
            {
                "index": 0,
                "executed_argv": ["/usr/bin/python3.12", "-m", "pytest"],
                "isolation_launch_argv": ["/usr/bin/bwrap", "--", "pytest"],
                "command_policy": {
                    "executable_binding": {"sha256": "f" * 64},
                },
                "exit_code": 0,
                "timed_out": False,
                "output_truncated": False,
                "output_sha256": "1" * 64,
                "output_size_bytes": 12,
                "executable_sha256_after": "f" * 64,
            }
        ],
    }


def attestation_payload(receipt: dict[str, object]) -> dict[str, object]:
    protection = receipt["snapshot_protection"]
    assert isinstance(protection, dict)
    cleanup = protection["cleanup_attestation"]
    return {
        "schema_version": EXECUTOR_ATTESTATION_SCHEMA_VERSION,
        "protocol_id": EXECUTOR_ATTESTATION_PROTOCOL_ID,
        "domain": EXECUTOR_ATTESTATION_DOMAIN,
        "kind": "execution-verified",
        "verifier_id": EXECUTOR_VERIFIER_ID,
        "verifier_identity_sha256": verifier_identity_sha256(verifier_identity()),
        "attestation_nonce": "nonce-1",
        "task_id": receipt["task_id"],
        "attempt": receipt["attempt"],
        "actor": receipt["actor"],
        "run_id": receipt["run_id"],
        "validation_contract_sha256": receipt["validation_contract_sha256"],
        "acquire_attestation_sha256": protection["acquire_attestation_sha256"],
        "cleanup_attestation_sha256": hashlib.sha256(
            canonical_json_bytes(cleanup)
        ).hexdigest(),
        "command_output_digest_sha256": command_output_digest_sha256(receipt),
        "command_runtime_digest_sha256": runner_runtime_digest_sha256(receipt),
        "verifier_runtime_manifest_sha256": "5" * 64,
        "verifier_entrypoint_sha256": "6" * 64,
        "verifier_interpreter_sha256": "7" * 64,
        "verifier_package_tree_sha256": "8" * 64,
        "verifier_service_unit_sha256": "9" * 64,
        "verifier_policy_sha256": "0" * 64,
        "receipt_preimage_sha256": receipt["receipt_preimage_sha256"],
        "receipt_sha256": receipt["receipt_sha256"],
        "issued_at": BASE_EPOCH + 4,
    }


def attestation_envelope(payload: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": EXECUTOR_ATTESTATION_SCHEMA_VERSION,
        "algorithm": EXECUTOR_ATTESTATION_ALGORITHM,
        "public_key_sha256": "2" * 64,
        "payload": payload,
        "signature_b64": base64.b64encode(b"0" * 64).decode("ascii"),
    }


def _key_binding(*, public_key_path: Path) -> dict[str, str]:
    if Path(public_key_path) == EXECUTOR_ATTESTATION_PUBLIC_KEY_PATH:
        return {"path": str(public_key_path), "sha256": "2" * 64}
    if Path(public_key_path) == BROKER_PUBLIC_KEY_PATH:
        return {"path": str(public_key_path), "sha256": "4" * 64}
    raise AssertionError(f"unexpected public key path: {public_key_path}")


def protocol_patches(
    *,
    same_key: bool = False,
    same_semantic_key: bool = False,
) -> tuple[object, ...]:
    key_binding = (
        (lambda *, public_key_path: {"path": str(public_key_path), "sha256": "2" * 64})
        if same_key
        else _key_binding
    )
    return (
        patch(
            "cogni_os.verifier_attestation_protocol.trusted_public_key_binding",
            side_effect=key_binding,
        ),
        patch(
            "cogni_os.verifier_attestation_protocol.trusted_openssl_binding",
            return_value={"path": "/usr/bin/openssl", "sha256": "3" * 64},
        ),
        patch(
            "cogni_os.verifier_attestation_protocol._openssl_pkeyutl",
            return_value=True,
        ),
        patch(
            "cogni_os.verifier_attestation_protocol.trusted_executor_runtime_binding",
            return_value={
                "manifest_sha256": "5" * 64,
                "entrypoint_sha256": "6" * 64,
                "interpreter_sha256": "7" * 64,
                "package_tree_sha256": "8" * 64,
                "service_unit_sha256": "9" * 64,
                "runtime_policy_sha256": "0" * 64,
            },
        ),
        patch(
            "cogni_os.verifier_attestation_protocol._public_key_spki_sha256",
            side_effect=(
                ["a" * 64, "a" * 64]
                if same_semantic_key
                else ["a" * 64, "b" * 64]
            ),
        ),
    )


class ExecutorVerifierAttestationTests(unittest.TestCase):
    def _verify(
        self,
        envelope: dict[str, object],
        receipt: dict[str, object],
        *,
        identity: dict[str, object] | None = None,
        same_key: bool = False,
        same_semantic_key: bool = False,
    ) -> dict[str, object]:
        patches = protocol_patches(
            same_key=same_key,
            same_semantic_key=same_semantic_key,
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        return verify_executor_attestation(
            envelope,
            receipt=receipt,
            verifier_identity=identity or verifier_identity(),
        )

    def test_missing_attestation_is_fail_closed_before_platform_crypto(self) -> None:
        with self.assertRaisesRegex(VerifierAttestationError, "envelope schema"):
            verify_executor_attestation(
                None,
                receipt=trusted_receipt(),
                verifier_identity=verifier_identity(),
            )

    def test_separate_domain_attestation_binds_every_execution_digest(self) -> None:
        receipt = trusted_receipt()
        payload = attestation_payload(receipt)
        verified = self._verify(attestation_envelope(payload), receipt)
        self.assertEqual(verified, payload)

    def test_receipt_tamper_is_rejected(self) -> None:
        receipt = trusted_receipt()
        payload = attestation_payload(receipt)
        payload["receipt_preimage_sha256"] = "4" * 64
        with self.assertRaisesRegex(VerifierAttestationError, "does not match"):
            self._verify(attestation_envelope(payload), receipt)

    def test_verifier_identity_tamper_is_rejected(self) -> None:
        receipt = trusted_receipt()
        payload = attestation_payload(receipt)
        identity = verifier_identity()
        identity["control_principal"] = "different-principal"
        with self.assertRaisesRegex(VerifierAttestationError, "does not match"):
            self._verify(attestation_envelope(payload), receipt, identity=identity)

    def test_snapshot_broker_key_reuse_is_rejected(self) -> None:
        receipt = trusted_receipt()
        with self.assertRaisesRegex(VerifierAttestationError, "must differ"):
            self._verify(
                attestation_envelope(attestation_payload(receipt)),
                receipt,
                same_key=True,
            )

    def test_semantically_equal_snapshot_broker_key_is_rejected(self) -> None:
        receipt = trusted_receipt()
        with self.assertRaisesRegex(VerifierAttestationError, "must differ"):
            self._verify(
                attestation_envelope(attestation_payload(receipt)),
                receipt,
                same_semantic_key=True,
            )

    def test_noncanonical_run_id_is_rejected(self) -> None:
        receipt = trusted_receipt()
        payload = attestation_payload(receipt)
        payload["run_id"] = "A" * 32
        with self.assertRaisesRegex(VerifierAttestationError, "payload schema"):
            self._verify(attestation_envelope(payload), receipt)

    def test_unbounded_attestation_chronology_is_rejected(self) -> None:
        receipt = trusted_receipt()
        payload = attestation_payload(receipt)
        payload["issued_at"] = BASE_EPOCH + 10_000
        with self.assertRaisesRegex(VerifierAttestationError, "chronology"):
            self._verify(attestation_envelope(payload), receipt)


if __name__ == "__main__":
    unittest.main()
