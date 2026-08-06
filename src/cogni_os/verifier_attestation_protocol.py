"""Read-only protocol for an independent executor/verifier attestation.

The privileged snapshot broker proves only snapshot provenance and namespace
cleanup.  It is deliberately *not* an execution oracle.  A trusted validation
therefore needs a second Ed25519 trust domain whose signer independently
observed the immutable runner and its command outputs.  This module contains
verification scaffolding only; it intentionally exposes no signing function.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import EvidenceError
from .snapshot_broker_protocol import (
    BROKER_OPENSSL_PATH,
    BROKER_PUBLIC_KEY_PATH,
    _openssl_pkeyutl,
    _require_posix_root_owned,
    canonical_json_bytes,
    package_tree_sha256,
    trusted_openssl_binding,
    trusted_public_key_binding,
)
from .util import sha256_file

EXECUTOR_ATTESTATION_PROTOCOL_ID = "cogni-os-independent-executor-attestation-v2"
EXECUTOR_ATTESTATION_DOMAIN = "cogni-os-independent-executor-verifier-v2"
EXECUTOR_ATTESTATION_SCHEMA_VERSION = 2
EXECUTOR_ATTESTATION_ALGORITHM = "ed25519-openssl-pkeyutl-raw-v1"
EXECUTOR_VERIFIER_ID = "cogni-independent-verifier"
MAX_EXECUTOR_ATTESTATION_WINDOW_SECONDS = 3_900
MAX_EXECUTOR_ATTESTATION_DELAY_SECONDS = 300
EXECUTOR_ATTESTATION_PUBLIC_KEY_PATH = Path(
    "/etc/cogni-os/verifier-attestation/ed25519-public.pem"
)
EXECUTOR_ATTESTATION_OPENSSL_SHA256_PATH = Path(
    "/etc/cogni-os/verifier-attestation/openssl.sha256"
)
EXECUTOR_RUNTIME_MANIFEST_PATH = Path("/etc/cogni-os/verifier-attestation/runtime.json")
EXECUTOR_RUNTIME_ROOT = Path("/opt/cogni-os/verifier-v1")
EXECUTOR_ENTRYPOINT_PATH = EXECUTOR_RUNTIME_ROOT / "bin/cogni-verifier"
EXECUTOR_INTERPRETER_PATH = EXECUTOR_RUNTIME_ROOT / "venv/bin/python"
EXECUTOR_PACKAGE_ROOT = EXECUTOR_RUNTIME_ROOT / "lib/cogni_os"
EXECUTOR_SERVICE_UNIT_PATH = Path(
    "/etc/systemd/system/cogni-independent-verifier.service"
)
EXECUTOR_RUNTIME_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "runtime_id",
        "entrypoint_path",
        "entrypoint_sha256",
        "interpreter_path",
        "interpreter_sha256",
        "package_root",
        "package_tree_sha256",
        "service_unit_path",
        "service_unit_sha256",
        "runtime_policy_sha256",
    }
)

EXECUTOR_ATTESTATION_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "algorithm",
        "public_key_sha256",
        "payload",
        "signature_b64",
    }
)
EXECUTOR_ATTESTATION_PAYLOAD_KEYS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "domain",
        "kind",
        "verifier_id",
        "verifier_identity_sha256",
        "attestation_nonce",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "validation_contract_sha256",
        "acquire_attestation_sha256",
        "cleanup_attestation_sha256",
        "command_output_digest_sha256",
        "command_runtime_digest_sha256",
        "verifier_runtime_manifest_sha256",
        "verifier_entrypoint_sha256",
        "verifier_interpreter_sha256",
        "verifier_package_tree_sha256",
        "verifier_service_unit_sha256",
        "verifier_policy_sha256",
        "receipt_preimage_sha256",
        "receipt_sha256",
        "issued_at",
    }
)


class VerifierAttestationError(EvidenceError):
    """An independent executor attestation is missing or invalid."""


def _is_sha256(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _identifier(value: Any, *, maximum: int = 256) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= maximum and all(
        character.isalnum() or character in "-_." for character in value
    )


def _run_id(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 32
        and all(character in "0123456789abcdef" for character in value)
    )


def verifier_identity_sha256(identity: Any) -> str:
    """Commit the complete ledger-bound verifier identity snapshot."""

    if (
        not isinstance(identity, dict)
        or identity.get("schema_version") != 1
        or not _identifier(identity.get("actor"))
        or not isinstance(identity.get("control_principal"), str)
        or not identity["control_principal"]
        or not isinstance(identity.get("model_family"), str)
        or not identity["model_family"]
        or not isinstance(identity.get("alias_chain"), list)
    ):
        raise VerifierAttestationError(
            "Independent verifier identity binding is malformed"
        )
    try:
        encoded = canonical_json_bytes(identity)
    except (TypeError, ValueError) as exc:
        raise VerifierAttestationError(
            "Independent verifier identity binding is malformed"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _utc_epoch(value: Any, *, label: str) -> int:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise VerifierAttestationError(f"{label} timestamp is invalid")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
        epoch = int(parsed.timestamp())
    except (OverflowError, OSError, ValueError) as exc:
        raise VerifierAttestationError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise VerifierAttestationError(f"{label} timestamp has no timezone")
    return epoch


def _receipt_chronology_valid(
    receipt: dict[str, Any],
    *,
    attestation_issued_at: int,
) -> bool:
    protection = receipt.get("snapshot_protection")
    if not isinstance(protection, dict):
        return False
    acquire = protection.get("acquire_attestation")
    cleanup = protection.get("cleanup_attestation")
    acquire_payload = acquire.get("payload") if isinstance(acquire, dict) else None
    cleanup_payload = cleanup.get("payload") if isinstance(cleanup, dict) else None
    if not isinstance(acquire_payload, dict) or not isinstance(cleanup_payload, dict):
        return False
    try:
        started_at = _utc_epoch(receipt.get("started_at"), label="receipt start")
        completed_at = _utc_epoch(
            receipt.get("completed_at"), label="receipt completion"
        )
    except VerifierAttestationError:
        return False
    acquire_issued_at = acquire_payload.get("issued_at")
    cleanup_issued_at = cleanup_payload.get("issued_at")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 1
        for value in (acquire_issued_at, cleanup_issued_at, attestation_issued_at)
    ):
        return False
    return bool(
        started_at
        <= acquire_issued_at
        <= completed_at
        <= cleanup_issued_at
        <= attestation_issued_at
        and attestation_issued_at - started_at
        <= MAX_EXECUTOR_ATTESTATION_WINDOW_SECONDS
        and attestation_issued_at - cleanup_issued_at
        <= MAX_EXECUTOR_ATTESTATION_DELAY_SECONDS
    )


def _digest(value: Any, *, domain: str) -> str:
    return hashlib.sha256(
        canonical_json_bytes({"domain": domain, "value": value})
    ).hexdigest()


def _public_key_spki_sha256(*, public_key_path: Path, openssl_path: Path) -> str:
    """Canonicalize one Ed25519 public key before trust-domain comparison."""

    try:
        completed = subprocess.run(
            [
                str(openssl_path),
                "pkey",
                "-pubin",
                "-in",
                str(public_key_path),
                "-outform",
                "DER",
            ],
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": str(openssl_path.parent)},
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerifierAttestationError(
            "Independent verifier public key normalization failed"
        ) from exc
    if completed.returncode != 0 or not 1 <= len(completed.stdout) <= 4096:
        raise VerifierAttestationError(
            "Independent verifier public key normalization failed"
        )
    return hashlib.sha256(completed.stdout).hexdigest()


def command_output_digest_sha256(receipt: dict[str, Any]) -> str:
    """Digest only command identity and retained output/result commitments."""

    validations = receipt.get("validations")
    if not isinstance(validations, list) or not validations:
        raise VerifierAttestationError("Trusted receipt has no command results")
    projected: list[dict[str, Any]] = []
    for item in validations:
        if not isinstance(item, dict):
            raise VerifierAttestationError("Trusted command result is malformed")
        policy = item.get("command_policy")
        if not isinstance(policy, dict):
            raise VerifierAttestationError("Trusted command policy is malformed")
        executable = policy.get("executable_binding")
        if not isinstance(executable, dict):
            raise VerifierAttestationError("Trusted executable binding is malformed")
        output_sha256 = item.get("output_sha256")
        executable_after = item.get("executable_sha256_after")
        executable_before = executable.get("sha256")
        if not all(
            _is_sha256(value)
            for value in (output_sha256, executable_before, executable_after)
        ):
            raise VerifierAttestationError("Trusted command digest is malformed")
        projected.append(
            {
                "index": item.get("index"),
                "executed_argv": item.get("executed_argv"),
                "isolation_launch_argv": item.get("isolation_launch_argv"),
                "exit_code": item.get("exit_code"),
                "timed_out": item.get("timed_out"),
                "output_truncated": item.get("output_truncated"),
                "output_sha256": output_sha256,
                "output_size_bytes": item.get("output_size_bytes"),
                "executable_sha256_before": executable_before,
                "executable_sha256_after": executable_after,
            }
        )
    return _digest(
        projected,
        domain="cogni-os-command-output-commitments-v1",
    )


def runner_runtime_digest_sha256(receipt: dict[str, Any]) -> str:
    """Digest the runner policy, sandbox runtime, and command runtimes."""

    backend = receipt.get("isolation_backend")
    validations = receipt.get("validations")
    if not isinstance(backend, dict) or not isinstance(validations, list):
        raise VerifierAttestationError("Trusted runner runtime binding is malformed")
    executable_bindings: list[Any] = []
    for item in validations:
        if not isinstance(item, dict) or not isinstance(
            item.get("command_policy"), dict
        ):
            raise VerifierAttestationError(
                "Trusted runner command runtime binding is malformed"
            )
        executable_bindings.append(item["command_policy"].get("executable_binding"))
    return _digest(
        {
            "runner": receipt.get("runner"),
            "schema_version": receipt.get("schema_version"),
            "isolation_policy": receipt.get("isolation_policy"),
            "isolation_backend": backend,
            "sandbox_environment_sha256": receipt.get("sandbox_environment_sha256"),
            "executable_bindings": executable_bindings,
        },
        domain="cogni-os-immutable-runner-runtime-v1",
    )


def _validate_envelope(envelope: Any) -> dict[str, Any]:
    if (
        not isinstance(envelope, dict)
        or set(envelope) != EXECUTOR_ATTESTATION_ENVELOPE_KEYS
        or envelope.get("schema_version") != EXECUTOR_ATTESTATION_SCHEMA_VERSION
        or envelope.get("algorithm") != EXECUTOR_ATTESTATION_ALGORITHM
        or not _is_sha256(envelope.get("public_key_sha256"))
    ):
        raise VerifierAttestationError(
            "Independent verifier envelope schema is invalid"
        )
    payload = envelope.get("payload")
    if (
        not isinstance(payload, dict)
        or set(payload) != EXECUTOR_ATTESTATION_PAYLOAD_KEYS
        or payload.get("schema_version") != EXECUTOR_ATTESTATION_SCHEMA_VERSION
        or payload.get("protocol_id") != EXECUTOR_ATTESTATION_PROTOCOL_ID
        or payload.get("domain") != EXECUTOR_ATTESTATION_DOMAIN
        or payload.get("kind") != "execution-verified"
        or payload.get("verifier_id") != EXECUTOR_VERIFIER_ID
        or not _identifier(payload.get("attestation_nonce"))
        or not _identifier(payload.get("task_id"))
        or not _identifier(payload.get("actor"))
        or not _run_id(payload.get("run_id"))
        or not isinstance(payload.get("attempt"), int)
        or isinstance(payload.get("attempt"), bool)
        or payload["attempt"] < 1
        or not isinstance(payload.get("issued_at"), int)
        or isinstance(payload.get("issued_at"), bool)
        or payload["issued_at"] < 1
    ):
        raise VerifierAttestationError("Independent verifier payload schema is invalid")
    for key in (
        "verifier_identity_sha256",
        "validation_contract_sha256",
        "acquire_attestation_sha256",
        "cleanup_attestation_sha256",
        "command_output_digest_sha256",
        "command_runtime_digest_sha256",
        "verifier_runtime_manifest_sha256",
        "verifier_entrypoint_sha256",
        "verifier_interpreter_sha256",
        "verifier_package_tree_sha256",
        "verifier_service_unit_sha256",
        "verifier_policy_sha256",
        "receipt_preimage_sha256",
        "receipt_sha256",
    ):
        if not _is_sha256(payload.get(key)):
            raise VerifierAttestationError(
                "Independent verifier payload digest is invalid"
            )
    signature = envelope.get("signature_b64")
    if not isinstance(signature, str) or len(signature) > 1024:
        raise VerifierAttestationError(
            "Independent verifier signature encoding is invalid"
        )
    try:
        decoded = base64.b64decode(signature, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise VerifierAttestationError(
            "Independent verifier signature encoding is invalid"
        ) from exc
    if len(decoded) != 64:
        raise VerifierAttestationError(
            "Independent verifier Ed25519 signature length is invalid"
        )
    return payload


def trusted_executor_runtime_binding(
    *,
    manifest_path: Path = EXECUTOR_RUNTIME_MANIFEST_PATH,
) -> dict[str, str]:
    """Verify the independent verifier's fixed root-owned runtime manifest."""

    manifest_file = _require_posix_root_owned(manifest_path)
    try:
        raw = manifest_file.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerifierAttestationError(
            "Independent verifier runtime manifest is unreadable"
        ) from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != EXECUTOR_RUNTIME_MANIFEST_KEYS
        or canonical_json_bytes(manifest) != raw
        or manifest.get("schema_version") != 1
        or manifest.get("runtime_id") != "cogni-os-independent-verifier-runtime-v1"
        or manifest.get("entrypoint_path") != str(EXECUTOR_ENTRYPOINT_PATH)
        or manifest.get("interpreter_path") != str(EXECUTOR_INTERPRETER_PATH)
        or manifest.get("package_root") != str(EXECUTOR_PACKAGE_ROOT)
        or manifest.get("service_unit_path") != str(EXECUTOR_SERVICE_UNIT_PATH)
        or not all(
            _is_sha256(manifest.get(key))
            for key in (
                "entrypoint_sha256",
                "interpreter_sha256",
                "package_tree_sha256",
                "service_unit_sha256",
                "runtime_policy_sha256",
            )
        )
    ):
        raise VerifierAttestationError(
            "Independent verifier runtime manifest schema is invalid"
        )
    try:
        entrypoint = _require_posix_root_owned(EXECUTOR_ENTRYPOINT_PATH)
        interpreter = _require_posix_root_owned(EXECUTOR_INTERPRETER_PATH)
        service_unit = _require_posix_root_owned(EXECUTOR_SERVICE_UNIT_PATH)
    except (OSError, EvidenceError) as exc:
        raise VerifierAttestationError(
            "Independent verifier runtime is not root-protected"
        ) from exc
    if (
        sha256_file(entrypoint) != manifest["entrypoint_sha256"]
        or sha256_file(interpreter) != manifest["interpreter_sha256"]
        or package_tree_sha256(EXECUTOR_PACKAGE_ROOT) != manifest["package_tree_sha256"]
        or sha256_file(service_unit) != manifest["service_unit_sha256"]
        or executor_runtime_policy_sha256() != manifest["runtime_policy_sha256"]
    ):
        raise VerifierAttestationError(
            "Independent verifier runtime differs from its manifest"
        )
    return {
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "entrypoint_sha256": manifest["entrypoint_sha256"],
        "interpreter_sha256": manifest["interpreter_sha256"],
        "package_tree_sha256": manifest["package_tree_sha256"],
        "service_unit_sha256": manifest["service_unit_sha256"],
        "runtime_policy_sha256": manifest["runtime_policy_sha256"],
    }


def executor_runtime_policy_sha256() -> str:
    """Hash the non-configurable service identity and confinement contract."""

    return _digest(
        {
            "runtime_id": "cogni-os-independent-verifier-runtime-v1",
            "manifest_path": str(EXECUTOR_RUNTIME_MANIFEST_PATH),
            "entrypoint_path": str(EXECUTOR_ENTRYPOINT_PATH),
            "interpreter_path": str(EXECUTOR_INTERPRETER_PATH),
            "package_root": str(EXECUTOR_PACKAGE_ROOT),
            "service_unit_path": str(EXECUTOR_SERVICE_UNIT_PATH),
            "service_user": "cogni-verifier",
            "service_group": "cogni-verifier",
            "network_policy": "private-network-namespace",
            "signing_policy": "separate-ed25519-key-no-snapshot-broker-key-reuse",
        },
        domain="cogni-os-independent-verifier-runtime-policy-v1",
    )


def request_executor_attestation(
    *,
    receipt: dict[str, Any],
    verifier_identity: dict[str, Any],
) -> dict[str, Any]:
    """Request one signed envelope from the fixed independent service.

    The service transport and signer are intentionally not part of this
    process yet.  The only valid future return value is the exact detached
    envelope consumed by :func:`verify_executor_attestation`; arbitrary
    runner output is never treated as that envelope.  Until the separately
    deployed service exists, the write path must terminate fail-closed.
    """

    if not isinstance(receipt, dict) or not isinstance(verifier_identity, dict):
        raise VerifierAttestationError(
            "Independent executor verifier request is malformed"
        )
    raise VerifierAttestationError(
        "Independent executor verifier service is not deployed"
    )


def verify_executor_attestation(
    envelope: Any,
    *,
    receipt: dict[str, Any],
    verifier_identity: dict[str, Any],
) -> dict[str, Any]:
    """Verify a separate-domain signature and every execution binding.

    No signing helper exists here.  Until a dedicated, isolated verifier
    service installs the separate public-key trust root and emits this exact
    envelope, callers must remain NO_GO.
    """

    payload = _validate_envelope(envelope)
    public = trusted_public_key_binding(
        public_key_path=EXECUTOR_ATTESTATION_PUBLIC_KEY_PATH
    )
    if envelope["public_key_sha256"] != public["sha256"]:
        raise VerifierAttestationError(
            "Independent verifier envelope names a different key"
        )
    broker_public = trusted_public_key_binding(public_key_path=BROKER_PUBLIC_KEY_PATH)
    if hmac.compare_digest(public["sha256"], broker_public["sha256"]):
        raise VerifierAttestationError(
            "Independent verifier key must differ from the snapshot broker key"
        )
    openssl = trusted_openssl_binding(
        openssl_path=BROKER_OPENSSL_PATH,
        digest_path=EXECUTOR_ATTESTATION_OPENSSL_SHA256_PATH,
    )
    executor_spki = _public_key_spki_sha256(
        public_key_path=EXECUTOR_ATTESTATION_PUBLIC_KEY_PATH,
        openssl_path=Path(openssl["path"]),
    )
    broker_spki = _public_key_spki_sha256(
        public_key_path=BROKER_PUBLIC_KEY_PATH,
        openssl_path=Path(openssl["path"]),
    )
    if hmac.compare_digest(executor_spki, broker_spki):
        raise VerifierAttestationError(
            "Independent verifier key must differ from the snapshot broker key"
        )
    try:
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
        valid = _openssl_pkeyutl(
            payload=payload,
            signature=signature,
            key_path=EXECUTOR_ATTESTATION_PUBLIC_KEY_PATH,
            public=True,
            openssl_path=Path(openssl["path"]),
        )
    except (OSError, ValueError) as exc:
        raise VerifierAttestationError(
            "Independent verifier signature operation failed"
        ) from exc
    if valid is not True:
        raise VerifierAttestationError(
            "Independent verifier detached signature is invalid"
        )
    runtime = trusted_executor_runtime_binding()

    protection = receipt.get("snapshot_protection")
    backend = receipt.get("isolation_backend")
    if not isinstance(protection, dict) or not isinstance(backend, dict):
        raise VerifierAttestationError(
            "Trusted receipt lacks executor attestation bindings"
        )
    cleanup_attestation = protection.get("cleanup_attestation")
    if not isinstance(cleanup_attestation, dict):
        raise VerifierAttestationError(
            "Trusted receipt lacks the broker cleanup attestation"
        )
    if not _receipt_chronology_valid(
        receipt,
        attestation_issued_at=payload["issued_at"],
    ):
        raise VerifierAttestationError(
            "Independent verifier chronology is invalid or unbounded"
        )
    expected = {
        "verifier_identity_sha256": verifier_identity_sha256(verifier_identity),
        "task_id": receipt.get("task_id"),
        "attempt": receipt.get("attempt"),
        "actor": receipt.get("actor"),
        "run_id": receipt.get("run_id"),
        "validation_contract_sha256": receipt.get("validation_contract_sha256"),
        "acquire_attestation_sha256": protection.get("acquire_attestation_sha256"),
        "cleanup_attestation_sha256": hashlib.sha256(
            canonical_json_bytes(cleanup_attestation)
        ).hexdigest(),
        "command_output_digest_sha256": command_output_digest_sha256(receipt),
        # Bubblewrap and each command executable are part of this command
        # runtime commitment.  They are not mislabeled as the independent
        # verifier service executable.
        "command_runtime_digest_sha256": runner_runtime_digest_sha256(receipt),
        "verifier_runtime_manifest_sha256": runtime["manifest_sha256"],
        "verifier_entrypoint_sha256": runtime["entrypoint_sha256"],
        "verifier_interpreter_sha256": runtime["interpreter_sha256"],
        "verifier_package_tree_sha256": runtime["package_tree_sha256"],
        "verifier_service_unit_sha256": runtime["service_unit_sha256"],
        "verifier_policy_sha256": runtime["runtime_policy_sha256"],
        "receipt_preimage_sha256": receipt.get("receipt_preimage_sha256"),
        "receipt_sha256": receipt.get("receipt_sha256"),
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise VerifierAttestationError(
            "Independent verifier proof does not match the trusted receipt"
        )
    return payload


def attestation_verification_available() -> bool:
    """Conservatively report whether the production public trust root exists."""

    return bool(
        os.name == "posix"
        and EXECUTOR_ATTESTATION_PUBLIC_KEY_PATH.is_file()
        and EXECUTOR_ATTESTATION_OPENSSL_SHA256_PATH.is_file()
        and EXECUTOR_RUNTIME_MANIFEST_PATH.is_file()
    )
