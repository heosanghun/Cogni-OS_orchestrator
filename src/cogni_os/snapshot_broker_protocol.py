"""Fail-closed protocol and Ed25519 trust helpers for snapshot FD leases.

The protocol intentionally has no shared secret.  A root daemon authenticates
the local caller with ``SO_PEERCRED`` and signs acquisition/cleanup statements
with an administrator-held Ed25519 key.  Readers verify those detached
signatures with a root-owned public key and a fixed, SHA-bound OpenSSL binary.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO

from .errors import EvidenceError
from .util import sha256_file

BROKER_PROTOCOL_ID = "cogni-os-snapshot-fd-lease-v1"
BROKER_SCHEMA_VERSION = 1
BROKER_SOCKET_PATH = Path("/run/cogni-os/trusted-snapshot-broker.sock")
BROKER_LOCK_PATH = Path("/run/cogni-os/trusted-snapshot-broker.lock")
BROKER_STORE_ROOT = Path("/run/cogni-os/trusted-snapshots")
BROKER_NONCE_ROOT = Path("/run/cogni-os/trusted-snapshot-nonces")
BROKER_LEASE_ROOT = Path("/run/cogni-os/trusted-snapshot-leases")
BROKER_PRIVATE_KEY_PATH = Path("/etc/cogni-os/snapshot-broker/ed25519-private.pem")
BROKER_PUBLIC_KEY_PATH = Path("/etc/cogni-os/snapshot-broker/ed25519-public.pem")
BROKER_OPENSSL_PATH = Path("/usr/bin/openssl")
BROKER_OPENSSL_SHA256_PATH = Path("/etc/cogni-os/snapshot-broker/openssl.sha256")
BROKER_RUNTIME_ROOT = Path("/opt/cogni-os/snapshot-broker-v1")
BROKER_PYTHON_PATH = BROKER_RUNTIME_ROOT / "venv/bin/python"
BROKER_RUNTIME_MANIFEST_PATH = Path("/etc/cogni-os/snapshot-broker/runtime.json")

BROKER_SIGNATURE_ALGORITHM = "ed25519-openssl-pkeyutl-raw-v1"
BROKER_DESCRIPTOR_TYPE = "O_PATH-directory"
BROKER_SOURCE_DESCRIPTOR_TYPE = "sealed-O_RDONLY-directory"
SNAPSHOT_MATERIALIZATION_POLICY_ID = "git-object-dirfd-nofollow-stream-v2"
# This proof is intentionally scoped to copied snapshot bytes, descriptor
# identity, and cleanup.  It attests neither source authenticity nor that a
# verifier command ran or succeeded.
BROKER_PROOF_SCOPE = "root-signed-snapshot-provenance-and-cleanup-only"
MAX_BROKER_FRAME_BYTES = 16 * 1024 * 1024
MAX_BROKER_ERROR_MESSAGE_BYTES = 1024
MAX_BROKER_TTL_SECONDS = 120
MAX_BROKER_CLOCK_SKEW_SECONDS = 5
MAX_BROKER_NONCE_BYTES = 128
MAX_BROKER_PATH_BYTES = 4096
MAX_BROKER_PACKAGE_FILES = 10_000
MAX_BROKER_PACKAGE_BYTES = 128 * 1024 * 1024

BROKER_RUNTIME_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "runtime_id",
        "python_path",
        "python_sha256",
        "package_root",
        "package_tree_sha256",
        "wheel_sha256",
        "entry_module",
    }
)

ACQUIRE_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "operation",
        "request_id",
        "nonce",
        "issued_at",
        "expires_at",
        "source_descriptor_type",
        "source_commit",
        "tree_oid",
        "materialization_policy",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "validation_contract_sha256",
        "expected_snapshot_sha256",
    }
)
RELEASE_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "operation",
        "request_id",
        "nonce",
        "issued_at",
        "expires_at",
        "lease_id",
        "acquire_attestation_sha256",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "validation_contract_sha256",
        "receipt_preimage_sha256",
    }
)
ACQUIRE_ATTESTATION_KEYS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "kind",
        "request_sha256",
        "request_id",
        "request_nonce",
        "caller_pid",
        "caller_uid",
        "caller_gid",
        "lease_id",
        "source_commit",
        "tree_oid",
        "snapshot_sha256",
        "snapshot_device",
        "snapshot_inode",
        "snapshot_owner_uid",
        "descriptor_type",
        "issued_at",
        "expires_at",
        "broker_nonce",
        "materialization_policy",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "validation_contract_sha256",
        "broker_runtime_manifest_sha256",
    }
)
CLEANUP_ATTESTATION_KEYS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "kind",
        "request_sha256",
        "request_id",
        "request_nonce",
        "caller_pid",
        "caller_uid",
        "caller_gid",
        "lease_id",
        "acquire_attestation_sha256",
        "snapshot_sha256",
        "snapshot_device",
        "snapshot_inode",
        "issued_at",
        "broker_nonce",
        "task_id",
        "attempt",
        "actor",
        "run_id",
        "validation_contract_sha256",
        "receipt_preimage_sha256",
        "broker_runtime_manifest_sha256",
        "namespace_removed",
    }
)
SIGNED_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "algorithm",
        "public_key_sha256",
        "payload",
        "signature_b64",
    }
)
ACQUIRE_RESPONSE_KEYS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "operation",
        "request_id",
        "ok",
        "snapshot",
        "attestation",
    }
)
RELEASE_RESPONSE_KEYS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "operation",
        "request_id",
        "ok",
        "cleanup_attestation",
    }
)
ERROR_RESPONSE_KEYS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "operation",
        "request_id",
        "ok",
        "error_code",
        "message",
    }
)


class SnapshotBrokerError(EvidenceError):
    """The privileged snapshot boundary could not be proven."""


def canonical_json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SnapshotBrokerError(
            "Snapshot broker document is not canonical JSON"
        ) from exc
    if len(encoded) > MAX_BROKER_FRAME_BYTES:
        raise SnapshotBrokerError("Snapshot broker document exceeds its byte limit")
    return encoded


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def encode_frame(value: Any) -> bytes:
    payload = canonical_json_bytes(value)
    return struct.pack("!I", len(payload)) + payload


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            raise SnapshotBrokerError("Snapshot broker frame was truncated")
        result.extend(chunk)
    return bytes(result)


def decode_frame_from_stream(stream: BinaryIO) -> dict[str, Any]:
    header = _read_exact(stream, 4)
    length = struct.unpack("!I", header)[0]
    if length < 2 or length > MAX_BROKER_FRAME_BYTES:
        raise SnapshotBrokerError("Snapshot broker frame length is invalid")
    payload = _read_exact(stream, length)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotBrokerError("Snapshot broker frame is not valid JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise SnapshotBrokerError("Snapshot broker frame is not canonical JSON")
    return value


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_identifier(value: Any, *, maximum: int = MAX_BROKER_NONCE_BYTES) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= maximum and all(
        character.isalnum() or character in "-_." for character in value
    )


def _validate_window(document: dict[str, Any], *, now: int | None = None) -> None:
    issued_at = document.get("issued_at")
    expires_at = document.get("expires_at")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_BROKER_TTL_SECONDS
    ):
        raise SnapshotBrokerError("Snapshot broker request lifetime is invalid")
    current = int(time.time()) if now is None else now
    if issued_at > current + MAX_BROKER_CLOCK_SKEW_SECONDS or expires_at < current:
        raise SnapshotBrokerError("Snapshot broker request is expired or not yet valid")


def _validate_execution_binding(document: dict[str, Any]) -> None:
    attempt = document.get("attempt")
    if (
        not _valid_identifier(document.get("task_id"), maximum=256)
        or not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or attempt < 1
        or not _valid_identifier(document.get("actor"), maximum=256)
        or not _is_hex(document.get("run_id"), 32)
        or not _is_hex(document.get("validation_contract_sha256"), 64)
    ):
        raise SnapshotBrokerError("Snapshot broker execution binding is invalid")


def validate_request(document: Any, *, now: int | None = None) -> str:
    if not isinstance(document, dict):
        raise SnapshotBrokerError("Snapshot broker request must be an object")
    operation = document.get("operation")
    expected = (
        ACQUIRE_REQUEST_KEYS
        if operation == "acquire"
        else RELEASE_REQUEST_KEYS
        if operation == "release"
        else None
    )
    if expected is None or set(document) != expected:
        raise SnapshotBrokerError("Snapshot broker request schema is not exact")
    if (
        document.get("schema_version") != BROKER_SCHEMA_VERSION
        or document.get("protocol_id") != BROKER_PROTOCOL_ID
        or not _valid_identifier(document.get("request_id"))
        or not _valid_identifier(document.get("nonce"))
    ):
        raise SnapshotBrokerError("Snapshot broker request identity is invalid")
    _validate_window(document, now=now)
    _validate_execution_binding(document)
    if operation == "acquire":
        if (
            document.get("source_descriptor_type") != BROKER_SOURCE_DESCRIPTOR_TYPE
            or not _is_hex(document.get("source_commit"), 40)
            or not _is_hex(document.get("tree_oid"), 40)
            or document.get("materialization_policy")
            != SNAPSHOT_MATERIALIZATION_POLICY_ID
            or not _is_hex(document.get("expected_snapshot_sha256"), 64)
        ):
            raise SnapshotBrokerError("Snapshot broker acquire binding is invalid")
    else:
        if (
            not _valid_identifier(document.get("lease_id"))
            or not _is_hex(document.get("acquire_attestation_sha256"), 64)
            or not _is_hex(document.get("receipt_preimage_sha256"), 64)
        ):
            raise SnapshotBrokerError("Snapshot broker release binding is invalid")
    return operation


def validate_signed_envelope(
    envelope: Any,
    *,
    kind: str,
) -> dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != SIGNED_ENVELOPE_KEYS:
        raise SnapshotBrokerError("Snapshot broker signed envelope schema is not exact")
    if (
        envelope.get("schema_version") != BROKER_SCHEMA_VERSION
        or envelope.get("algorithm") != BROKER_SIGNATURE_ALGORITHM
        or not _is_hex(envelope.get("public_key_sha256"), 64)
    ):
        raise SnapshotBrokerError("Snapshot broker signed envelope metadata is invalid")
    payload = envelope.get("payload")
    keys = (
        ACQUIRE_ATTESTATION_KEYS
        if kind == "snapshot-acquired"
        else CLEANUP_ATTESTATION_KEYS
        if kind == "snapshot-cleaned"
        else None
    )
    if keys is None or not isinstance(payload, dict) or set(payload) != keys:
        raise SnapshotBrokerError("Snapshot broker signed payload schema is not exact")
    if (
        payload.get("schema_version") != BROKER_SCHEMA_VERSION
        or payload.get("protocol_id") != BROKER_PROTOCOL_ID
        or payload.get("kind") != kind
        or not _is_hex(payload.get("request_sha256"), 64)
        or not _valid_identifier(payload.get("request_id"))
        or not _valid_identifier(payload.get("request_nonce"))
        or not _valid_identifier(payload.get("lease_id"))
        or not _valid_identifier(payload.get("broker_nonce"))
    ):
        raise SnapshotBrokerError("Snapshot broker signed payload identity is invalid")
    _validate_execution_binding(payload)
    if not _is_hex(payload.get("broker_runtime_manifest_sha256"), 64):
        raise SnapshotBrokerError("Snapshot broker runtime provenance is invalid")
    for field in (
        "caller_pid",
        "caller_uid",
        "caller_gid",
        "snapshot_device",
        "snapshot_inode",
    ):
        value = payload.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise SnapshotBrokerError(
                "Snapshot broker signed numeric binding is invalid"
            )
    if not isinstance(payload.get("issued_at"), int) or isinstance(
        payload.get("issued_at"), bool
    ):
        raise SnapshotBrokerError("Snapshot broker signed time binding is invalid")
    if kind == "snapshot-acquired":
        if (
            not _is_hex(payload.get("source_commit"), 40)
            or not _is_hex(payload.get("tree_oid"), 40)
            or not _is_hex(payload.get("snapshot_sha256"), 64)
            or payload.get("snapshot_owner_uid") != 0
            or payload.get("descriptor_type") != BROKER_DESCRIPTOR_TYPE
            or not isinstance(payload.get("expires_at"), int)
            or isinstance(payload.get("expires_at"), bool)
            or payload["expires_at"] <= payload["issued_at"]
            or not _valid_identifier(payload.get("materialization_policy"), maximum=128)
        ):
            raise SnapshotBrokerError("Snapshot broker acquisition binding is invalid")
    elif (
        not _is_hex(payload.get("acquire_attestation_sha256"), 64)
        or not _is_hex(payload.get("snapshot_sha256"), 64)
        or not _is_hex(payload.get("receipt_preimage_sha256"), 64)
        or payload.get("namespace_removed") is not True
    ):
        raise SnapshotBrokerError("Snapshot broker cleanup binding is invalid")
    signature = envelope.get("signature_b64")
    if not isinstance(signature, str) or len(signature) > 1024:
        raise SnapshotBrokerError("Snapshot broker signature encoding is invalid")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SnapshotBrokerError(
            "Snapshot broker signature encoding is invalid"
        ) from exc
    if len(decoded) != 64:
        raise SnapshotBrokerError("Snapshot broker Ed25519 signature length is invalid")
    return payload


def _require_posix_root_owned(path: Path, *, private: bool = False) -> Path:
    if os.name != "posix" or not path.is_absolute():
        raise SnapshotBrokerError("Snapshot broker trust material requires POSIX")
    try:
        target = path.stat(follow_symlinks=False)
        ancestors = [parent.stat(follow_symlinks=False) for parent in path.parents]
    except OSError as exc:
        raise SnapshotBrokerError(
            "Snapshot broker trust material is unavailable"
        ) from exc
    if stat.S_ISLNK(target.st_mode) or any(
        stat.S_ISLNK(value.st_mode) for value in ancestors
    ):
        raise SnapshotBrokerError("Snapshot broker trust path contains a link")
    if target.st_uid != 0 or any(value.st_uid != 0 for value in ancestors):
        raise SnapshotBrokerError("Snapshot broker trust path is not root-owned")
    if target.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or any(
        value.st_mode & (stat.S_IWGRP | stat.S_IWOTH) for value in ancestors
    ):
        raise SnapshotBrokerError("Snapshot broker trust path is actor-writable")
    if not stat.S_ISREG(target.st_mode):
        raise SnapshotBrokerError("Snapshot broker trust material is not a file")
    if private and target.st_mode & (stat.S_IRGRP | stat.S_IROTH):
        raise SnapshotBrokerError("Snapshot broker private key is not private")
    return path


def package_tree_sha256(package_root: Path) -> str:
    """Hash one root-owned, link-free immutable broker package tree."""

    if os.name != "posix" or not package_root.is_absolute():
        raise SnapshotBrokerError("Broker package tree requires an absolute POSIX path")
    try:
        protected_chain = (package_root, *package_root.parents)
        chain_metadata = [path.stat(follow_symlinks=False) for path in protected_chain]
    except OSError as exc:
        raise SnapshotBrokerError("Broker package tree is unavailable") from exc
    for index, metadata in enumerate(chain_metadata):
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            mode = stat.S_IMODE(metadata.st_mode)
            raise SnapshotBrokerError(
                "Broker package root ancestry is not root-protected: "
                f"component={index},owner={metadata.st_uid},mode={mode:o}"
            )
    pending = [package_root]
    records: list[dict[str, Any]] = []
    count = 0
    total = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            raise SnapshotBrokerError("Cannot enumerate broker package tree") from exc
        for entry in entries:
            count += 1
            if count > MAX_BROKER_PACKAGE_FILES:
                raise SnapshotBrokerError("Broker package tree exceeds its file limit")
            path = Path(entry.path)
            try:
                metadata = path.stat(follow_symlinks=False)
            except OSError as exc:
                raise SnapshotBrokerError(
                    "Cannot inspect broker package entry"
                ) from exc
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise SnapshotBrokerError(
                    "Broker package tree contains an unsafe entry"
                )
            relative = path.relative_to(package_root).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                records.append(
                    {
                        "path": relative + "/",
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "size": 0,
                        "sha256": None,
                    }
                )
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
                if total > MAX_BROKER_PACKAGE_BYTES:
                    raise SnapshotBrokerError(
                        "Broker package tree exceeds its byte limit"
                    )
                records.append(
                    {
                        "path": relative,
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "size": metadata.st_size,
                        "sha256": sha256_file(path),
                    }
                )
            else:
                raise SnapshotBrokerError("Broker package tree contains a special file")
    records.sort(key=lambda value: value["path"])
    return canonical_json_sha256(
        {
            "schema_version": 1,
            "file_count": count,
            "size_bytes": total,
            "records": records,
        }
    )


def trusted_broker_runtime_binding(
    *,
    manifest_path: Path = BROKER_RUNTIME_MANIFEST_PATH,
    require_current_interpreter: bool = True,
) -> dict[str, str]:
    """Verify the fixed interpreter and installed package against one manifest."""

    manifest_file = _require_posix_root_owned(manifest_path)
    try:
        raw = manifest_file.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotBrokerError("Broker runtime manifest is unreadable") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != BROKER_RUNTIME_MANIFEST_KEYS
        or canonical_json_bytes(manifest) != raw
        or manifest.get("schema_version") != 1
        or manifest.get("runtime_id") != "cogni-os-snapshot-broker-runtime-v1"
        or manifest.get("python_path") != str(BROKER_PYTHON_PATH)
        or manifest.get("entry_module") != "cogni_os.snapshot_broker"
        or not _is_hex(manifest.get("python_sha256"), 64)
        or not _is_hex(manifest.get("package_tree_sha256"), 64)
        or not _is_hex(manifest.get("wheel_sha256"), 64)
    ):
        raise SnapshotBrokerError("Broker runtime manifest schema is invalid")
    python = _require_posix_root_owned(BROKER_PYTHON_PATH)
    if (
        require_current_interpreter
        and Path(sys.executable).resolve() != BROKER_PYTHON_PATH.resolve()
    ):
        raise SnapshotBrokerError("Broker is not running under the fixed interpreter")
    if sha256_file(python) != manifest["python_sha256"]:
        raise SnapshotBrokerError("Broker interpreter does not match its manifest")
    package_root = Path(str(manifest.get("package_root", "")))
    try:
        package_root.relative_to(BROKER_RUNTIME_ROOT)
    except ValueError as exc:
        raise SnapshotBrokerError(
            "Broker package root escapes the immutable runtime"
        ) from exc
    if package_root.name != "cogni_os":
        raise SnapshotBrokerError("Broker package root is not the Cogni-OS package")
    if package_tree_sha256(package_root) != manifest["package_tree_sha256"]:
        raise SnapshotBrokerError("Broker package tree does not match its manifest")
    return {
        "manifest_path": str(manifest_file),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "python_path": str(python),
        "python_sha256": manifest["python_sha256"],
        "package_tree_sha256": manifest["package_tree_sha256"],
        "wheel_sha256": manifest["wheel_sha256"],
    }


def trusted_openssl_binding(
    *,
    openssl_path: Path = BROKER_OPENSSL_PATH,
    digest_path: Path = BROKER_OPENSSL_SHA256_PATH,
) -> dict[str, str]:
    openssl = _require_posix_root_owned(openssl_path)
    digest_file = _require_posix_root_owned(digest_path)
    try:
        expected = digest_file.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError) as exc:
        raise SnapshotBrokerError("Cannot read the OpenSSL trust digest") from exc
    if not _is_hex(expected, 64):
        raise SnapshotBrokerError("OpenSSL trust digest is invalid")
    actual = sha256_file(openssl)
    if actual != expected:
        raise SnapshotBrokerError(
            "OpenSSL binary does not match the administrator digest"
        )
    if not os.access(openssl, os.X_OK):
        raise SnapshotBrokerError("Fixed OpenSSL binary is not executable")
    return {"path": str(openssl), "sha256": actual}


def trusted_public_key_binding(
    *,
    public_key_path: Path = BROKER_PUBLIC_KEY_PATH,
) -> dict[str, str]:
    key = _require_posix_root_owned(public_key_path)
    return {"path": str(key), "sha256": sha256_file(key)}


def _openssl_pkeyutl(
    *,
    payload: dict[str, Any],
    signature: bytes | None,
    key_path: Path,
    public: bool,
    openssl_path: Path,
) -> bytes | bool:
    payload_bytes = canonical_json_bytes(payload)
    temporary_root = Path("/run/cogni-os") if os.geteuid() == 0 else None
    try:
        with tempfile.TemporaryDirectory(
            prefix="cogni-broker-crypto-", dir=temporary_root
        ) as raw:
            root = Path(raw)
            payload_path = root / "payload.json"
            signature_path = root / "signature.bin"
            payload_path.write_bytes(payload_bytes)
            if signature is not None:
                signature_path.write_bytes(signature)
            command = [
                str(openssl_path),
                "pkeyutl",
                "-verify" if public else "-sign",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(payload_path),
            ]
            if public:
                command.extend(["-pubin", "-sigfile", str(signature_path)])
            else:
                command.extend(["-out", str(signature_path)])
            completed = subprocess.run(
                command,
                shell=False,
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": str(openssl_path.parent)},
                timeout=10,
            )
            if public:
                return completed.returncode == 0
            if completed.returncode != 0:
                raise SnapshotBrokerError("OpenSSL refused the broker signature")
            result = signature_path.read_bytes()
            if len(result) != 64:
                raise SnapshotBrokerError(
                    "OpenSSL returned an invalid Ed25519 signature"
                )
            return result
    except (OSError, subprocess.SubprocessError) as exc:
        raise SnapshotBrokerError("OpenSSL broker signature operation failed") from exc


def sign_payload(
    payload: dict[str, Any],
    *,
    private_key_path: Path = BROKER_PRIVATE_KEY_PATH,
    public_key_path: Path = BROKER_PUBLIC_KEY_PATH,
    openssl_path: Path = BROKER_OPENSSL_PATH,
    openssl_sha256_path: Path = BROKER_OPENSSL_SHA256_PATH,
) -> dict[str, Any]:
    validate_signed_envelope(
        {
            "schema_version": BROKER_SCHEMA_VERSION,
            "algorithm": BROKER_SIGNATURE_ALGORITHM,
            "public_key_sha256": "0" * 64,
            "payload": payload,
            "signature_b64": base64.b64encode(b"0" * 64).decode("ascii"),
        },
        kind=str(payload.get("kind")),
    )
    _require_posix_root_owned(private_key_path, private=True)
    public = trusted_public_key_binding(public_key_path=public_key_path)
    openssl = trusted_openssl_binding(
        openssl_path=openssl_path,
        digest_path=openssl_sha256_path,
    )
    signature = _openssl_pkeyutl(
        payload=payload,
        signature=None,
        key_path=private_key_path,
        public=False,
        openssl_path=Path(openssl["path"]),
    )
    assert isinstance(signature, bytes)
    return {
        "schema_version": BROKER_SCHEMA_VERSION,
        "algorithm": BROKER_SIGNATURE_ALGORITHM,
        "public_key_sha256": public["sha256"],
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def verify_signed_envelope(
    envelope: Any,
    *,
    kind: str,
    public_key_path: Path = BROKER_PUBLIC_KEY_PATH,
    openssl_path: Path = BROKER_OPENSSL_PATH,
    openssl_sha256_path: Path = BROKER_OPENSSL_SHA256_PATH,
) -> dict[str, Any]:
    payload = validate_signed_envelope(envelope, kind=kind)
    public = trusted_public_key_binding(public_key_path=public_key_path)
    if envelope["public_key_sha256"] != public["sha256"]:
        raise SnapshotBrokerError("Broker envelope names a different public key")
    openssl = trusted_openssl_binding(
        openssl_path=openssl_path,
        digest_path=openssl_sha256_path,
    )
    signature = base64.b64decode(envelope["signature_b64"], validate=True)
    verified = _openssl_pkeyutl(
        payload=payload,
        signature=signature,
        key_path=public_key_path,
        public=True,
        openssl_path=Path(openssl["path"]),
    )
    if verified is not True:
        raise SnapshotBrokerError("Broker detached signature is invalid")
    return payload
