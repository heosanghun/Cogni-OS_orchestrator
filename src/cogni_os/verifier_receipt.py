"""Ed25519 sealing and verification for dedicated-verifier receipts.

The verifier key is a third trust domain, distinct from the ledger authority
and snapshot broker.  Production defaults are fixed POSIX paths and every
trust file must be root-owned and non-actor-writable before OpenSSL executes.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Final

from .snapshot_broker_protocol import (
    BROKER_OPENSSL_PATH,
    BROKER_PUBLIC_KEY_PATH,
    verify_signed_envelope as verify_broker_cleanup,
)
from .util import sha256_file
from .verifier_protocol import (
    VERIFIER_PROTOCOL_ID,
    VERIFIER_RECEIPT_DOMAIN,
    VERIFIER_SCHEMA_VERSION,
    VERIFIER_SIGNATURE_ALGORITHM,
    VerifierProtocolError,
    canonical_json_bytes,
    canonical_json_sha256,
    unsigned_receipt_payload,
    validate_execution_preimage,
    validate_receipt_envelope,
)

VERIFIER_PRIVATE_KEY_PATH: Final = Path(
    "/etc/cogni-os/verifier/ed25519-private.pem"
)
VERIFIER_PUBLIC_KEY_PATH: Final = Path(
    "/etc/cogni-os/verifier/ed25519-public.pem"
)
VERIFIER_OPENSSL_SHA256_PATH: Final = Path(
    "/etc/cogni-os/verifier/openssl.sha256"
)
VERIFIER_SERVICE_UNIT_PATH: Final = Path(
    "/etc/systemd/system/cogni-verifier.service"
)


class VerifierReceiptError(VerifierProtocolError):
    """A verifier receipt could not be securely sealed or verified."""


def _require_root_owned_file(
    path: Path,
    *,
    private: bool = False,
    executable: bool = False,
) -> Path:
    path = Path(path)
    if os.name != "posix" or not path.is_absolute():
        raise VerifierReceiptError("Verifier trust material requires POSIX")
    try:
        metadata = path.stat(follow_symlinks=False)
        ancestors = [parent.stat(follow_symlinks=False) for parent in path.parents]
    except OSError as exc:
        raise VerifierReceiptError("Verifier trust material is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or any(
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0
            or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            for parent in ancestors
        )
    ):
        raise VerifierReceiptError("Verifier trust path is not root-protected")
    if private and metadata.st_mode & stat.S_IROTH:
        raise VerifierReceiptError("Verifier private key is world-readable")
    if executable and not os.access(path, os.X_OK):
        raise VerifierReceiptError("Verifier OpenSSL binary is not executable")
    return path


def _trusted_openssl_binding(
    *,
    openssl_path: Path = BROKER_OPENSSL_PATH,
    digest_path: Path = VERIFIER_OPENSSL_SHA256_PATH,
) -> dict[str, str]:
    openssl = _require_root_owned_file(openssl_path, executable=True)
    digest = _require_root_owned_file(digest_path)
    try:
        expected = digest.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError) as exc:
        raise VerifierReceiptError("Verifier OpenSSL digest is unreadable") from exc
    if len(expected) != 64 or any(value not in "0123456789abcdef" for value in expected):
        raise VerifierReceiptError("Verifier OpenSSL digest is invalid")
    observed = sha256_file(openssl)
    if observed != expected:
        raise VerifierReceiptError("Verifier OpenSSL binary digest mismatch")
    return {"path": str(openssl), "sha256": observed}


def _public_key_spki_sha256(*, public_key_path: Path, openssl_path: Path) -> str:
    """Return the canonical DER SubjectPublicKeyInfo digest for one key."""

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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LANG": "C", "LC_ALL": "C", "PATH": str(openssl_path.parent)},
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerifierReceiptError("Verifier public-key SPKI conversion failed") from exc
    der = completed.stdout
    if completed.returncode != 0 or not der or len(der) > 4096:
        raise VerifierReceiptError("Verifier public-key SPKI is invalid")
    return hashlib.sha256(der).hexdigest()


def _distinct_public_key_binding(
    *,
    verifier_public_key_path: Path,
    snapshot_broker_public_key_path: Path,
    openssl_path: Path,
) -> dict[str, str]:
    verifier_spki = _public_key_spki_sha256(
        public_key_path=verifier_public_key_path,
        openssl_path=openssl_path,
    )
    broker_spki = _public_key_spki_sha256(
        public_key_path=snapshot_broker_public_key_path,
        openssl_path=openssl_path,
    )
    if verifier_spki == broker_spki:
        raise VerifierReceiptError(
            "Verifier and snapshot broker must use distinct Ed25519 keys"
        )
    return {
        "public_key_spki_sha256": verifier_spki,
        "snapshot_broker_public_key_spki_sha256": broker_spki,
    }


def trusted_receipt_signing_binding(
    *,
    private_key_path: Path = VERIFIER_PRIVATE_KEY_PATH,
    public_key_path: Path = VERIFIER_PUBLIC_KEY_PATH,
    openssl_path: Path = BROKER_OPENSSL_PATH,
    openssl_sha256_path: Path = VERIFIER_OPENSSL_SHA256_PATH,
    snapshot_broker_public_key_path: Path = BROKER_PUBLIC_KEY_PATH,
) -> dict[str, str]:
    private = _require_root_owned_file(private_key_path, private=True)
    public = _require_root_owned_file(public_key_path)
    broker_public = _require_root_owned_file(snapshot_broker_public_key_path)
    openssl = _trusted_openssl_binding(
        openssl_path=openssl_path,
        digest_path=openssl_sha256_path,
    )
    distinct = _distinct_public_key_binding(
        verifier_public_key_path=public,
        snapshot_broker_public_key_path=broker_public,
        openssl_path=Path(openssl["path"]),
    )
    return {
        "private_key_path": str(private),
        "public_key_path": str(public),
        "public_key_sha256": sha256_file(public),
        "openssl_path": openssl["path"],
        "openssl_sha256": openssl["sha256"],
        **distinct,
    }


def trusted_receipt_verification_binding(
    *,
    public_key_path: Path = VERIFIER_PUBLIC_KEY_PATH,
    openssl_path: Path = BROKER_OPENSSL_PATH,
    openssl_sha256_path: Path = VERIFIER_OPENSSL_SHA256_PATH,
    snapshot_broker_public_key_path: Path = BROKER_PUBLIC_KEY_PATH,
) -> dict[str, str]:
    public = _require_root_owned_file(public_key_path)
    broker_public = _require_root_owned_file(snapshot_broker_public_key_path)
    openssl = _trusted_openssl_binding(
        openssl_path=openssl_path,
        digest_path=openssl_sha256_path,
    )
    distinct = _distinct_public_key_binding(
        verifier_public_key_path=public,
        snapshot_broker_public_key_path=broker_public,
        openssl_path=Path(openssl["path"]),
    )
    return {
        "public_key_path": str(public),
        "public_key_sha256": sha256_file(public),
        "openssl_path": openssl["path"],
        "openssl_sha256": openssl["sha256"],
        **distinct,
    }


def _openssl_ed25519(
    payload: bytes,
    *,
    openssl_path: Path,
    key_path: Path,
    signature: bytes | None,
) -> bytes | bool:
    try:
        with tempfile.TemporaryDirectory(prefix="cogni-verifier-crypto-") as raw:
            root = Path(raw)
            payload_path = root / "payload.json"
            signature_path = root / "signature.bin"
            payload_path.write_bytes(payload)
            if signature is not None:
                if len(signature) != 64:
                    raise VerifierReceiptError("Verifier Ed25519 signature is invalid")
                signature_path.write_bytes(signature)
            command = [
                str(openssl_path),
                "pkeyutl",
                "-verify" if signature is not None else "-sign",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(payload_path),
            ]
            if signature is None:
                command.extend(["-out", str(signature_path)])
            else:
                command.extend(["-pubin", "-sigfile", str(signature_path)])
            completed = subprocess.run(
                command,
                shell=False,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env={"LANG": "C", "LC_ALL": "C", "PATH": str(openssl_path.parent)},
                timeout=10,
            )
            if signature is not None:
                return completed.returncode == 0
            if completed.returncode != 0:
                raise VerifierReceiptError("OpenSSL refused the verifier signature")
            result = signature_path.read_bytes()
            if len(result) != 64:
                raise VerifierReceiptError("OpenSSL returned an invalid Ed25519 signature")
            return result
    except VerifierReceiptError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerifierReceiptError("Verifier Ed25519 operation failed") from exc


def _execution_signature_payload(
    preimage: dict[str, Any],
    preimage_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "domain": VERIFIER_RECEIPT_DOMAIN,
        "kind": "execution-preimage-signature",
        "payload_sha256": preimage_sha256,
        "payload": preimage,
    }


def _final_signature_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    unsigned = unsigned_receipt_payload(receipt)
    return {
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "domain": VERIFIER_RECEIPT_DOMAIN,
        "kind": "final-receipt-signature",
        "payload_sha256": canonical_json_sha256(unsigned),
        "payload": unsigned,
    }


def sign_verification_receipt(
    execution_preimage: dict[str, Any],
    cleanup_proof: dict[str, Any],
    *,
    sealed_at: str,
    dispatch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Seal one execution preimage and its broker cleanup proof.

    The broker proof is cryptographically verified before the dedicated
    verifier key is used.  The execution preimage and final receipt receive
    separate Ed25519 signatures in the same dedicated-verifier domain.
    """

    preimage = validate_execution_preimage(execution_preimage, dispatch=dispatch)
    preimage_sha256 = canonical_json_sha256(preimage)
    try:
        cleanup_payload = verify_broker_cleanup(
            cleanup_proof,
            kind="snapshot-cleaned",
        )
    except Exception as exc:
        raise VerifierReceiptError("Broker cleanup proof verification failed") from exc
    if cleanup_payload.get("receipt_preimage_sha256") != preimage_sha256:
        raise VerifierReceiptError("Broker cleanup proof binds another preimage")

    binding = trusted_receipt_signing_binding()
    private_key = Path(binding["private_key_path"])
    public_key = Path(binding["public_key_path"])
    openssl = Path(binding["openssl_path"])
    execution_payload = _execution_signature_payload(preimage, preimage_sha256)
    execution_signature = _openssl_ed25519(
        canonical_json_bytes(execution_payload),
        openssl_path=openssl,
        key_path=private_key,
        signature=None,
    )
    assert isinstance(execution_signature, bytes)
    receipt = {
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "protocol_id": VERIFIER_PROTOCOL_ID,
        "kind": "verification-receipt",
        "domain": VERIFIER_RECEIPT_DOMAIN,
        "algorithm": VERIFIER_SIGNATURE_ALGORITHM,
        "public_key_sha256": binding["public_key_sha256"],
        "execution_preimage": preimage,
        "execution_preimage_sha256": preimage_sha256,
        "execution_signature_b64": base64.b64encode(execution_signature).decode(
            "ascii"
        ),
        "cleanup_proof": cleanup_proof,
        "cleanup_proof_sha256": canonical_json_sha256(cleanup_proof),
        "sealed_at": sealed_at,
        "final_signature_b64": base64.b64encode(b"\x00" * 64).decode("ascii"),
    }
    validate_receipt_envelope(receipt, dispatch=dispatch)
    final_signature = _openssl_ed25519(
        canonical_json_bytes(_final_signature_payload(receipt)),
        openssl_path=openssl,
        key_path=private_key,
        signature=None,
    )
    assert isinstance(final_signature, bytes)
    receipt["final_signature_b64"] = base64.b64encode(final_signature).decode("ascii")

    # A mismatched public/private key pair must fail before a receipt leaves
    # the dedicated service boundary.
    execution_verified = _openssl_ed25519(
        canonical_json_bytes(execution_payload),
        openssl_path=openssl,
        key_path=public_key,
        signature=execution_signature,
    )
    final_verified = _openssl_ed25519(
        canonical_json_bytes(_final_signature_payload(receipt)),
        openssl_path=openssl,
        key_path=public_key,
        signature=final_signature,
    )
    if execution_verified is not True or final_verified is not True:
        raise VerifierReceiptError("Verifier public/private key pair does not match")
    return validate_receipt_envelope(receipt, dispatch=dispatch)


def verify_verification_receipt(
    receipt: dict[str, Any],
    *,
    dispatch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify exact schema, broker cleanup, and both verifier signatures."""

    document = validate_receipt_envelope(receipt, dispatch=dispatch)
    binding = trusted_receipt_verification_binding()
    if document["public_key_sha256"] != binding["public_key_sha256"]:
        raise VerifierReceiptError("Verifier receipt names a different public key")
    try:
        verify_broker_cleanup(document["cleanup_proof"], kind="snapshot-cleaned")
    except Exception as exc:
        raise VerifierReceiptError("Broker cleanup proof verification failed") from exc
    public_key = Path(binding["public_key_path"])
    openssl = Path(binding["openssl_path"])
    execution_signature = base64.b64decode(
        document["execution_signature_b64"], validate=True
    )
    final_signature = base64.b64decode(document["final_signature_b64"], validate=True)
    execution_payload = _execution_signature_payload(
        document["execution_preimage"],
        document["execution_preimage_sha256"],
    )
    if _openssl_ed25519(
        canonical_json_bytes(execution_payload),
        openssl_path=openssl,
        key_path=public_key,
        signature=execution_signature,
    ) is not True:
        raise VerifierReceiptError("Verifier execution signature is invalid")
    if _openssl_ed25519(
        canonical_json_bytes(_final_signature_payload(document)),
        openssl_path=openssl,
        key_path=public_key,
        signature=final_signature,
    ) is not True:
        raise VerifierReceiptError("Verifier final receipt signature is invalid")
    return document
