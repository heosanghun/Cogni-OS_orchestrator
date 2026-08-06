"""Bounded Ed25519 v2 trust domain for future Ledger Authority events.

The workspace ledger in :mod:`cogni_os.ledger` remains an HMAC v1 ledger.
This module neither reads nor upgrades that file.  It defines an exact,
separate v2 envelope, key-domain binding, chain verifier, audit-only migration
anchor, and signed verifier-dispatch API.  Deployment and integration remain
explicit release blockers.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from .errors import IntegrityError
from .snapshot_broker_protocol import BROKER_OPENSSL_PATH, BROKER_PUBLIC_KEY_PATH
from .util import sha256_file
from .verifier_protocol import DISPATCH_KEYS, validate_dispatch
from .verifier_receipt import VERIFIER_PUBLIC_KEY_PATH

LEDGER_V2_SCHEMA_VERSION: Final = 2
LEDGER_V2_PROTOCOL_ID: Final = "cogni-os.ledger-authority.v2"
LEDGER_V2_DOMAIN: Final = "cogni-os.ledger-event.v2"
LEDGER_V2_SIGNATURE_ALGORITHM: Final = "ed25519-openssl-pkeyutl-raw-v1"
LEDGER_V2_GENESIS_HASH: Final = "0" * 64

LEDGER_AUTHORITY_PRIVATE_KEY_PATH: Final = Path(
    "/etc/cogni-os/ledger-authority/ed25519-private.pem"
)
LEDGER_AUTHORITY_PUBLIC_KEY_PATH: Final = Path(
    "/etc/cogni-os/ledger-authority/ed25519-public.pem"
)
LEDGER_AUTHORITY_OPENSSL_SHA256_PATH: Final = Path(
    "/etc/cogni-os/ledger-authority/openssl.sha256"
)

MAX_LEDGER_V2_DOCUMENT_BYTES: Final = 4 * 1024 * 1024
MAX_LEDGER_V2_EVENTS: Final = 1_000_000
MAX_LEGACY_SNAPSHOT_BYTES: Final = 512 * 1024 * 1024

EVENT_KEYS: Final = frozenset(
    {
        "sequence",
        "ledger_id",
        "timestamp",
        "actor",
        "action",
        "task_id",
        "payload",
        "previous_hash",
    }
)
ENVELOPE_KEYS: Final = frozenset(
    {
        "schema_version",
        "protocol_id",
        "domain",
        "kind",
        "algorithm",
        "key_id",
        "event",
        "event_hash",
        "signature_b64",
    }
)
LEGACY_HMAC_V1_EVENT_KEYS: Final = frozenset(
    {
        "sequence",
        "timestamp",
        "actor",
        "action",
        "task_id",
        "payload",
        "previous_hash",
        "event_hash",
        "signature",
    }
)
SIGNED_DISPATCH_PAYLOAD_KEYS: Final = frozenset(
    DISPATCH_KEYS - {"dispatch_event_hash"}
)
MIGRATION_PAYLOAD_KEYS: Final = frozenset(
    {
        "schema_version",
        "kind",
        "legacy_scheme",
        "legacy_head_hash",
        "legacy_event_count",
        "legacy_snapshot_sha256",
        "legacy_snapshot_size_bytes",
        "migration_policy",
        "legacy_authoritative",
    }
)
MIGRATION_ACTION: Final = "ledger.migration.v1-anchored"
MIGRATION_POLICY: Final = "audit-only-no-authority-inheritance"

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")

SIGNATURE_PREIMAGE_KEYS: Final = frozenset(
    {
        "schema_version",
        "protocol_id",
        "domain",
        "kind",
        "algorithm",
        "key_id",
        "ledger_id",
        "event_hash",
        "event",
    }
)


class LedgerAuthorityV2Error(IntegrityError):
    """An Ed25519 v2 ledger authority contract failed closed."""


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
        raise LedgerAuthorityV2Error("Ledger v2 document is not canonical JSON") from exc
    if len(encoded) > MAX_LEDGER_V2_DOCUMENT_BYTES:
        raise LedgerAuthorityV2Error("Ledger v2 document exceeds its byte limit")
    return encoded


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_object(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise LedgerAuthorityV2Error(f"{label} schema is not exact")
    canonical_json_bytes(value)
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise LedgerAuthorityV2Error(f"{label} must be a lowercase SHA-256")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise LedgerAuthorityV2Error(f"{label} is invalid")
    return value


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise LedgerAuthorityV2Error("Ledger v2 timestamp is invalid")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise LedgerAuthorityV2Error("Ledger v2 timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LedgerAuthorityV2Error("Ledger v2 timestamp has no timezone")
    return value


def validate_v2_event(event: Any) -> dict[str, Any]:
    document = _exact_object(event, EVENT_KEYS, "Ledger v2 event")
    sequence = document["sequence"]
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
        or sequence > MAX_LEDGER_V2_EVENTS
    ):
        raise LedgerAuthorityV2Error("Ledger v2 sequence is invalid")
    _identifier(document["ledger_id"], "Ledger v2 ledger_id")
    _timestamp(document["timestamp"])
    _identifier(document["actor"], "Ledger v2 actor")
    _identifier(document["action"], "Ledger v2 action")
    task_id = document["task_id"]
    if task_id is not None:
        _identifier(task_id, "Ledger v2 task_id")
    if not isinstance(document["payload"], dict):
        raise LedgerAuthorityV2Error("Ledger v2 payload must be an object")
    _sha256(document["previous_hash"], "Ledger v2 previous_hash")
    return document


def validate_v2_envelope(envelope: Any) -> dict[str, Any]:
    document = _exact_object(envelope, ENVELOPE_KEYS, "Ledger v2 envelope")
    if (
        document["schema_version"] != LEDGER_V2_SCHEMA_VERSION
        or document["protocol_id"] != LEDGER_V2_PROTOCOL_ID
        or document["domain"] != LEDGER_V2_DOMAIN
        or document["kind"] != "ledger-event"
        or document["algorithm"] != LEDGER_V2_SIGNATURE_ALGORITHM
    ):
        raise LedgerAuthorityV2Error("Ledger v2 envelope identity is invalid")
    _sha256(document["key_id"], "Ledger v2 key_id")
    event = validate_v2_event(document["event"])
    event_hash = canonical_json_sha256(event)
    if document["event_hash"] != event_hash:
        raise LedgerAuthorityV2Error("Ledger v2 event hash is invalid")
    signature = document["signature_b64"]
    if not isinstance(signature, str) or len(signature) > 1024:
        raise LedgerAuthorityV2Error("Ledger v2 signature encoding is invalid")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise LedgerAuthorityV2Error("Ledger v2 signature encoding is invalid") from exc
    if len(decoded) != 64:
        raise LedgerAuthorityV2Error("Ledger v2 Ed25519 signature length is invalid")
    return document


def decode_canonical_v2_envelope(encoded: bytes) -> dict[str, Any]:
    if not isinstance(encoded, bytes) or not encoded:
        raise LedgerAuthorityV2Error("Ledger v2 encoded envelope is invalid")
    if len(encoded) > MAX_LEDGER_V2_DOCUMENT_BYTES:
        raise LedgerAuthorityV2Error("Ledger v2 encoded envelope exceeds its limit")
    try:
        document = json.loads(encoded.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LedgerAuthorityV2Error("Ledger v2 encoded envelope is invalid") from exc
    if canonical_json_bytes(document) != encoded:
        raise LedgerAuthorityV2Error("Ledger v2 envelope bytes are not canonical")
    return validate_v2_envelope(document)


def _require_root_owned_file(
    path: Path,
    *,
    private: bool = False,
    executable: bool = False,
) -> Path:
    path = Path(path)
    if os.name != "posix" or not path.is_absolute():
        raise LedgerAuthorityV2Error("Ledger v2 trust material requires POSIX")
    try:
        metadata = path.stat(follow_symlinks=False)
        ancestors = [parent.stat(follow_symlinks=False) for parent in path.parents]
    except OSError as exc:
        raise LedgerAuthorityV2Error("Ledger v2 trust material is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or any(
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != 0
            or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            for parent in ancestors
        )
    ):
        raise LedgerAuthorityV2Error("Ledger v2 trust path is not root-protected")
    if private and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise LedgerAuthorityV2Error("Ledger v2 private key must be mode 0600")
    if executable and not os.access(path, os.X_OK):
        raise LedgerAuthorityV2Error("Ledger v2 OpenSSL binary is not executable")
    return path


def _trusted_openssl_binding(
    *,
    openssl_path: Path,
    digest_path: Path,
) -> dict[str, str]:
    openssl = _require_root_owned_file(openssl_path, executable=True)
    digest = _require_root_owned_file(digest_path)
    try:
        expected = digest.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError) as exc:
        raise LedgerAuthorityV2Error("Ledger v2 OpenSSL digest is unreadable") from exc
    _sha256(expected, "Ledger v2 OpenSSL digest")
    observed = sha256_file(openssl)
    if observed != expected:
        raise LedgerAuthorityV2Error("Ledger v2 OpenSSL binary digest mismatch")
    return {"path": str(openssl), "sha256": observed}


def _public_key_spki_sha256(*, public_key_path: Path, openssl_path: Path) -> str:
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
        raise LedgerAuthorityV2Error("Ledger v2 public-key SPKI conversion failed") from exc
    if completed.returncode != 0 or not completed.stdout or len(completed.stdout) > 4096:
        raise LedgerAuthorityV2Error("Ledger v2 public-key SPKI is invalid")
    return hashlib.sha256(completed.stdout).hexdigest()


def _distinct_authority_spki_binding(
    *,
    ledger_public_key_path: Path,
    broker_public_key_path: Path,
    verifier_public_key_path: Path,
    openssl_path: Path,
) -> dict[str, str]:
    bindings = {
        "ledger_public_key_spki_sha256": _public_key_spki_sha256(
            public_key_path=ledger_public_key_path,
            openssl_path=openssl_path,
        ),
        "broker_public_key_spki_sha256": _public_key_spki_sha256(
            public_key_path=broker_public_key_path,
            openssl_path=openssl_path,
        ),
        "verifier_public_key_spki_sha256": _public_key_spki_sha256(
            public_key_path=verifier_public_key_path,
            openssl_path=openssl_path,
        ),
    }
    if len(set(bindings.values())) != 3:
        raise LedgerAuthorityV2Error(
            "Ledger, broker, and verifier must use distinct Ed25519 SPKI keys"
        )
    return bindings


def trusted_ledger_signing_binding(
    *,
    private_key_path: Path = LEDGER_AUTHORITY_PRIVATE_KEY_PATH,
    public_key_path: Path = LEDGER_AUTHORITY_PUBLIC_KEY_PATH,
    broker_public_key_path: Path = BROKER_PUBLIC_KEY_PATH,
    verifier_public_key_path: Path = VERIFIER_PUBLIC_KEY_PATH,
    openssl_path: Path = BROKER_OPENSSL_PATH,
    openssl_sha256_path: Path = LEDGER_AUTHORITY_OPENSSL_SHA256_PATH,
) -> dict[str, str]:
    private = _require_root_owned_file(private_key_path, private=True)
    public = _require_root_owned_file(public_key_path)
    broker = _require_root_owned_file(broker_public_key_path)
    verifier = _require_root_owned_file(verifier_public_key_path)
    openssl = _trusted_openssl_binding(
        openssl_path=openssl_path,
        digest_path=openssl_sha256_path,
    )
    distinct = _distinct_authority_spki_binding(
        ledger_public_key_path=public,
        broker_public_key_path=broker,
        verifier_public_key_path=verifier,
        openssl_path=Path(openssl["path"]),
    )
    return {
        "private_key_path": str(private),
        "public_key_path": str(public),
        "key_id": distinct["ledger_public_key_spki_sha256"],
        "openssl_path": openssl["path"],
        "openssl_sha256": openssl["sha256"],
        **distinct,
    }


def trusted_ledger_verification_binding(
    *,
    public_key_path: Path = LEDGER_AUTHORITY_PUBLIC_KEY_PATH,
    broker_public_key_path: Path = BROKER_PUBLIC_KEY_PATH,
    verifier_public_key_path: Path = VERIFIER_PUBLIC_KEY_PATH,
    openssl_path: Path = BROKER_OPENSSL_PATH,
    openssl_sha256_path: Path = LEDGER_AUTHORITY_OPENSSL_SHA256_PATH,
) -> dict[str, str]:
    public = _require_root_owned_file(public_key_path)
    broker = _require_root_owned_file(broker_public_key_path)
    verifier = _require_root_owned_file(verifier_public_key_path)
    openssl = _trusted_openssl_binding(
        openssl_path=openssl_path,
        digest_path=openssl_sha256_path,
    )
    distinct = _distinct_authority_spki_binding(
        ledger_public_key_path=public,
        broker_public_key_path=broker,
        verifier_public_key_path=verifier,
        openssl_path=Path(openssl["path"]),
    )
    return {
        "public_key_path": str(public),
        "key_id": distinct["ledger_public_key_spki_sha256"],
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
        with tempfile.TemporaryDirectory(prefix="cogni-ledger-v2-crypto-") as raw:
            root = Path(raw)
            payload_path = root / "payload.json"
            signature_path = root / "signature.bin"
            payload_path.write_bytes(payload)
            if signature is not None:
                if len(signature) != 64:
                    raise LedgerAuthorityV2Error("Ledger v2 Ed25519 signature is invalid")
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
                raise LedgerAuthorityV2Error("OpenSSL refused the Ledger v2 signature")
            result = signature_path.read_bytes()
            if len(result) != 64:
                raise LedgerAuthorityV2Error("OpenSSL returned an invalid Ledger v2 signature")
            return result
    except LedgerAuthorityV2Error:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise LedgerAuthorityV2Error("Ledger v2 Ed25519 operation failed") from exc


def _signature_payload(
    event: dict[str, Any],
    event_hash: str,
    key_id: str,
) -> dict[str, Any]:
    payload = {
        "schema_version": LEDGER_V2_SCHEMA_VERSION,
        "protocol_id": LEDGER_V2_PROTOCOL_ID,
        "domain": LEDGER_V2_DOMAIN,
        "kind": "ledger-event-signature",
        "algorithm": LEDGER_V2_SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "ledger_id": event["ledger_id"],
        "event_hash": event_hash,
        "event": event,
    }
    return _exact_object(
        payload, SIGNATURE_PREIMAGE_KEYS, "Ledger v2 signature preimage"
    )


def sign_v2_event(event: dict[str, Any]) -> dict[str, Any]:
    document = validate_v2_event(event)
    event_hash = canonical_json_sha256(document)
    binding = trusted_ledger_signing_binding()
    key_id = _sha256(binding.get("key_id"), "Ledger v2 signing key_id")
    signature = _openssl_ed25519(
        canonical_json_bytes(_signature_payload(document, event_hash, key_id)),
        openssl_path=Path(binding["openssl_path"]),
        key_path=Path(binding["private_key_path"]),
        signature=None,
    )
    assert isinstance(signature, bytes)
    envelope = {
        "schema_version": LEDGER_V2_SCHEMA_VERSION,
        "protocol_id": LEDGER_V2_PROTOCOL_ID,
        "domain": LEDGER_V2_DOMAIN,
        "kind": "ledger-event",
        "algorithm": LEDGER_V2_SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "event": document,
        "event_hash": event_hash,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    validate_v2_envelope(envelope)
    verified = _openssl_ed25519(
        canonical_json_bytes(_signature_payload(document, event_hash, key_id)),
        openssl_path=Path(binding["openssl_path"]),
        key_path=Path(binding["public_key_path"]),
        signature=signature,
    )
    if verified is not True:
        raise LedgerAuthorityV2Error("Ledger v2 public/private key pair does not match")
    return envelope


def verify_v2_event(envelope: dict[str, Any]) -> dict[str, Any]:
    document = validate_v2_envelope(envelope)
    binding = trusted_ledger_verification_binding()
    key_id = _sha256(binding.get("key_id"), "Ledger v2 verification key_id")
    if document["key_id"] != key_id:
        raise LedgerAuthorityV2Error("Ledger v2 envelope names another public key")
    signature = base64.b64decode(document["signature_b64"], validate=True)
    verified = _openssl_ed25519(
        canonical_json_bytes(
            _signature_payload(
                document["event"], document["event_hash"], document["key_id"]
            )
        ),
        openssl_path=Path(binding["openssl_path"]),
        key_path=Path(binding["public_key_path"]),
        signature=signature,
    )
    if verified is not True:
        raise LedgerAuthorityV2Error("Ledger v2 detached signature is invalid")
    return document


def verify_v2_chain(envelopes: list[dict[str, Any]]) -> dict[str, Any]:
    if len(envelopes) > MAX_LEDGER_V2_EVENTS:
        raise LedgerAuthorityV2Error("Ledger v2 chain exceeds its event limit")
    if any(
        isinstance(item, dict) and set(item) == LEGACY_HMAC_V1_EVENT_KEYS
        for item in envelopes
    ):
        raise LedgerAuthorityV2Error(
            "HMAC v1 and Ed25519 v2 events must not be mixed"
        )
    previous_hash = LEDGER_V2_GENESIS_HASH
    migrated_from_v1 = False
    ledger_id: str | None = None
    for expected_sequence, envelope in enumerate(envelopes, start=1):
        document = verify_v2_event(envelope)
        event = document["event"]
        if event["sequence"] != expected_sequence:
            raise LedgerAuthorityV2Error("Ledger v2 chain sequence is invalid")
        if event["previous_hash"] != previous_hash:
            raise LedgerAuthorityV2Error("Ledger v2 chain link is invalid")
        if ledger_id is None:
            ledger_id = event["ledger_id"]
        elif event["ledger_id"] != ledger_id:
            raise LedgerAuthorityV2Error("Ledger v2 chain ledger_id changed")
        if event["action"] == MIGRATION_ACTION:
            if expected_sequence != 1:
                raise LedgerAuthorityV2Error(
                    "Ledger v1 migration anchor must be the first v2 event"
                )
            _validate_migration_event(document)
            migrated_from_v1 = True
        previous_hash = document["event_hash"]
    return {
        "valid": True,
        "scheme": LEDGER_V2_DOMAIN,
        "events": len(envelopes),
        "head": previous_hash,
        "ledger_id": ledger_id,
        "migrated_from_v1_audit_only": migrated_from_v1,
        "release_ready": False,
    }


def build_v1_migration_anchor_payload(
    *,
    legacy_head_hash: str,
    legacy_event_count: int,
    legacy_snapshot_sha256: str,
    legacy_snapshot_size_bytes: int,
) -> dict[str, Any]:
    _sha256(legacy_head_hash, "legacy_head_hash")
    _sha256(legacy_snapshot_sha256, "legacy_snapshot_sha256")
    if (
        not isinstance(legacy_event_count, int)
        or isinstance(legacy_event_count, bool)
        or legacy_event_count < 0
        or legacy_event_count > MAX_LEDGER_V2_EVENTS
    ):
        raise LedgerAuthorityV2Error("legacy_event_count is invalid")
    if (
        not isinstance(legacy_snapshot_size_bytes, int)
        or isinstance(legacy_snapshot_size_bytes, bool)
        or legacy_snapshot_size_bytes < 0
        or legacy_snapshot_size_bytes > MAX_LEGACY_SNAPSHOT_BYTES
    ):
        raise LedgerAuthorityV2Error("legacy_snapshot_size_bytes is invalid")
    return {
        "schema_version": 1,
        "kind": "ledger-v1-migration-anchor",
        "legacy_scheme": "cogni-os.ledger-hmac.v1",
        "legacy_head_hash": legacy_head_hash,
        "legacy_event_count": legacy_event_count,
        "legacy_snapshot_sha256": legacy_snapshot_sha256,
        "legacy_snapshot_size_bytes": legacy_snapshot_size_bytes,
        "migration_policy": MIGRATION_POLICY,
        "legacy_authoritative": False,
    }


def _validate_migration_event(envelope: dict[str, Any]) -> dict[str, Any]:
    event = envelope["event"]
    payload = _exact_object(
        event["payload"], MIGRATION_PAYLOAD_KEYS, "Ledger v1 migration anchor"
    )
    expected = build_v1_migration_anchor_payload(
        legacy_head_hash=payload["legacy_head_hash"],
        legacy_event_count=payload["legacy_event_count"],
        legacy_snapshot_sha256=payload["legacy_snapshot_sha256"],
        legacy_snapshot_size_bytes=payload["legacy_snapshot_size_bytes"],
    )
    if (
        event["sequence"] != 1
        or event["previous_hash"] != LEDGER_V2_GENESIS_HASH
        or event["action"] != MIGRATION_ACTION
        or event["task_id"] is not None
        or payload != expected
    ):
        raise LedgerAuthorityV2Error("Ledger v1 migration boundary is invalid")
    return payload


def verify_v1_migration_anchor(envelope: dict[str, Any]) -> dict[str, Any]:
    return _validate_migration_event(verify_v2_event(envelope))


def verify_signed_dispatch(
    full_chain: list[dict[str, Any]],
    *,
    dispatch_event_hash: str,
    now: int | None = None,
) -> dict[str, Any]:
    _sha256(dispatch_event_hash, "dispatch_event_hash")
    if not full_chain:
        raise LedgerAuthorityV2Error("Signed dispatch requires a non-empty full chain")
    chain_snapshot = [
        json.loads(canonical_json_bytes(envelope).decode("utf-8"))
        for envelope in full_chain
    ]
    chain = verify_v2_chain(chain_snapshot)
    if chain["head"] != dispatch_event_hash:
        raise LedgerAuthorityV2Error(
            "Signed dispatch is not the current full-chain head"
        )
    document = verify_v2_event(chain_snapshot[-1])
    event = document["event"]
    if (
        event["action"] != "verification.requested"
        or document["event_hash"] != dispatch_event_hash
    ):
        raise LedgerAuthorityV2Error("Signed dispatch head event is invalid")
    payload = _exact_object(
        event["payload"], SIGNED_DISPATCH_PAYLOAD_KEYS, "Signed dispatch payload"
    )
    if (
        event["task_id"] != payload["task_id"]
        or event["actor"] != payload["actor"]
        or event["ledger_id"] != payload["workspace_id"]
        or payload["ledger_domain"] != LEDGER_V2_DOMAIN
        or payload["ledger_head_hash"] != event["previous_hash"]
    ):
        raise LedgerAuthorityV2Error("Signed dispatch event binding is invalid")
    dispatch = {**payload, "dispatch_event_hash": document["event_hash"]}
    try:
        return validate_dispatch(dispatch, now=now)
    except Exception as exc:
        raise LedgerAuthorityV2Error("Signed dispatch contract is invalid") from exc


def ledger_authority_v2_assurance() -> dict[str, Any]:
    return {
        "scope": "bounded-ed25519-v2-schema-and-verification-api-only",
        "domain": LEDGER_V2_DOMAIN,
        "release_ready": False,
        "legacy_ledger": "hmac-sha256-v1-separate-unmodified",
        "migration": MIGRATION_POLICY,
        "release_blockers": [
            "legacy_workspace_ledger_remains_hmac_v1",
            "ledger_authority_append_daemon_not_deployed",
            "ledger_authority_key_rotation_registry_not_implemented",
            "durable_bounded_v2_log_checkpoint_not_implemented",
            "v1_to_v2_migration_not_executed",
            "legacy_bounded_byte_validation_not_implemented",
            "workspace_projection_release_gate_not_v2_integrated",
            "current_task_terminal_supersession_projection_not_integrated",
            "ubuntu_root_key_install_and_ed25519_e2e_unverified",
        ],
    }
