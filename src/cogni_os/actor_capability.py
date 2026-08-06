"""Out-of-workspace, one-time actor capabilities for privileged operations.

The append-only workspace ledger proves integrity, not process identity: every
workspace process can otherwise ask the shared ledger key to sign an arbitrary
``actor`` label.  This module adds a separate bearer-capability boundary.

Threat model
============

* A caller that only controls workspace files, the shared ledger key, command
  arguments, or another actor's high-entropy bootstrap secret cannot perform a
  privileged operation as the conductor.
* Capability material is kept outside the workspace and repository.  Proofs
  are bound to actor, workspace id, operation, nonce, key version and expiry,
  and are consumed once in an external replay store.
* Windows DPAPI protects the verifier key at rest for the current OS user.
  This does **not** prove isolation between Codex and Antigravity when both run
  as the same OS user.  Strong actor isolation requires distinct OS principals
  (or an external secret broker) with ACL-separated capability homes.  The
  implementation reports that limitation and never upgrades it to a claim.
* If a guard, key record, supplied credential, or proof is unavailable, the
  operation fails closed.  Existing workspaces are never auto-migrated.

The bootstrap guard is deliberately not creatable by the normal ``cogni``
command.  An installer/OS administrator must call :meth:`provision_guard` from
an ACL-isolated setup context, then deliver the same random secret to the actor
through a secret channel.  Bootstrap consumes that guard exactly once.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .errors import AuthorizationError, ConfigurationError, IntegrityError
from .lock import FileLock
from .util import atomic_write_json, canonical_json, is_relative_to, read_json

SCHEMA_VERSION = 1
TOKEN_VERSION = 1
RECEIPT_SCHEMA_VERSION = 2
RECEIPT_SIGNATURE_ALGORITHM = "hmac-sha256-local-actor-key-v1"
MIN_SECRET_BYTES = 32
MAX_TOKEN_BYTES = 8192
DEFAULT_TTL_SECONDS = 120
MAX_TTL_SECONDS = 300
OPERATION_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,99}$")
TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
CAPABILITY_SECRET_ENV = "COGNI_ACTOR_CAPABILITY_SECRET"
CAPABILITY_BOOTSTRAP_ENV = "COGNI_ACTOR_CAPABILITY_BOOTSTRAP_SECRET"
CAPABILITY_NEW_SECRET_ENV = "COGNI_ACTOR_CAPABILITY_NEW_SECRET"
CAPABILITY_HOME_ENV = "COGNI_CAPABILITY_HOME"


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise AuthorizationError("Actor capability is malformed")
    try:
        raw = value.encode("ascii")
        return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    except (UnicodeEncodeError, ValueError) as exc:
        raise AuthorizationError("Actor capability is malformed") from exc


def _secret_bytes(value: str | bytes | bytearray, *, label: str) -> bytes:
    if isinstance(value, str):
        try:
            secret = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise AuthorizationError(f"{label} is invalid") from exc
    elif isinstance(value, (bytes, bytearray)):
        secret = bytes(value)
    else:
        raise AuthorizationError(f"{label} is unavailable")
    if len(secret) < MIN_SECRET_BYTES:
        raise AuthorizationError(
            f"{label} must contain at least {MIN_SECRET_BYTES} bytes"
        )
    return secret


def _binding_fields(
    *,
    task_id: str | None,
    run_id: str | None,
    task_attempt: int | None,
) -> dict[str, Any]:
    """Return one canonical task/run/attempt binding, including explicit nulls."""

    if task_id is not None and not TASK_ID_RE.fullmatch(task_id):
        raise AuthorizationError("Actor capability task binding is invalid")
    if run_id is not None and not RUN_ID_RE.fullmatch(run_id):
        raise AuthorizationError("Actor capability run binding is invalid")
    if task_attempt is not None and (
        not isinstance(task_attempt, int)
        or isinstance(task_attempt, bool)
        or task_attempt < 1
    ):
        raise AuthorizationError("Actor capability attempt binding is invalid")
    if run_id is not None and task_id is None:
        raise AuthorizationError("Actor capability run binding requires a task")
    if task_attempt is not None and task_id is None:
        raise AuthorizationError("Actor capability attempt binding requires a task")
    return {
        "task_id": task_id,
        "run_id": run_id,
        "task_attempt": task_attempt,
    }


def _os_principal_attestation() -> dict[str, Any]:
    """Describe the observed principal without claiming an independent attestor.

    The local HMAC signs this snapshot so later readers can detect mutation.  It
    remains a same-user observation, not proof that another same-user process
    could not impersonate the actor.
    """

    if hasattr(os, "geteuid"):
        principal = {
            "platform": sys.platform,
            "effective_uid": int(os.geteuid()),
            "effective_gid": int(os.getegid()),
        }
        provider = "posix-effective-principal-observation"
    else:
        principal = {
            "platform": sys.platform,
            "user_domain": os.environ.get("USERDOMAIN", ""),
            "user_name": os.environ.get("USERNAME", ""),
            "user_profile": os.environ.get("USERPROFILE", ""),
        }
        provider = "windows-current-user-observation"
    return {
        "schema_version": 1,
        "provider": provider,
        "principal_sha256": hashlib.sha256(canonical_json(principal)).hexdigest(),
        "trust_root": "same-user-local-key",
        "independent_trust_root": False,
        "actor_os_isolation_proven": False,
    }


def consume_secret_environment(name: str) -> bytes:
    """Remove one secret from the environment before any child can inherit it."""

    value = os.environ.pop(name, None)
    if value is None:
        raise AuthorizationError(f"Required secret environment {name} is unavailable")
    return _secret_bytes(value, label="Actor capability secret")


def scrub_capability_environment(environment: dict[str, str]) -> dict[str, str]:
    """Return a child environment without actor capability material."""

    clean = dict(environment)
    clean.pop(CAPABILITY_SECRET_ENV, None)
    clean.pop(CAPABILITY_BOOTSTRAP_ENV, None)
    clean.pop(CAPABILITY_NEW_SECRET_ENV, None)
    return clean


def _default_home() -> Path:
    configured = os.environ.get(CAPABILITY_HOME_ENV)
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise ConfigurationError("LOCALAPPDATA is required for actor capabilities")
        return (Path(base) / "CogniOS" / "actor-capabilities").resolve()
    state = os.environ.get("XDG_STATE_HOME")
    base = Path(state).expanduser() if state else Path.home() / ".local" / "state"
    return (base / "cogni-os" / "actor-capabilities").resolve()


def _has_reparse_component(path: Path) -> bool:
    current = path
    while True:
        if current.exists():
            try:
                st = current.lstat()
            except OSError as exc:
                raise ConfigurationError(
                    "Cannot inspect capability store path"
                ) from exc
            attributes = getattr(st, "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if current.is_symlink() or bool(attributes & reparse):
                return True
        if current.parent == current:
            return False
        current = current.parent


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(value: bytes) -> tuple[_DataBlob, Any]:
    buffer = ctypes.create_string_buffer(value)
    return (
        _DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))),
        buffer,
    )


def _dpapi_protect(value: bytes, entropy: bytes) -> bytes:
    if os.name != "nt":
        return value
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    source, source_buffer = _blob(value)
    extra, extra_buffer = _blob(entropy)
    output = _DataBlob()
    # CRYPTPROTECT_UI_FORBIDDEN prevents an authorization path from hanging on
    # an interactive Windows prompt.
    if not crypt32.CryptProtectData(
        ctypes.byref(source),
        None,
        ctypes.byref(extra),
        None,
        None,
        0x1,
        ctypes.byref(output),
    ):
        raise AuthorizationError("Windows DPAPI could not protect capability key")
    del source_buffer, extra_buffer
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)


def _dpapi_unprotect(value: bytes, entropy: bytes) -> bytes:
    if os.name != "nt":
        return value
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    source, source_buffer = _blob(value)
    extra, extra_buffer = _blob(entropy)
    output = _DataBlob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        ctypes.byref(extra),
        None,
        None,
        0x1,
        ctypes.byref(output),
    ):
        raise AuthorizationError("Actor capability key is unavailable to this OS user")
    del source_buffer, extra_buffer
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)


class ActorCapabilityAuthority:
    """Bootstrap, mint, consume and rotate isolated actor capabilities."""

    def __init__(
        self,
        *,
        workspace_root: str | Path,
        workspace_id: str,
        home: str | Path | None = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.workspace_id = str(workspace_id)
        if not self.workspace_id:
            raise ConfigurationError("Workspace id is required for actor capabilities")
        self.home = Path(home).expanduser().resolve() if home else _default_home()
        if is_relative_to(self.home, self.workspace_root):
            raise ConfigurationError(
                "Actor capability home must be outside the workspace"
            )
        if _has_reparse_component(self.home):
            raise ConfigurationError(
                "Actor capability home cannot traverse a reparse point"
            )
        workspace_digest = hashlib.sha256(self.workspace_id.encode("utf-8")).hexdigest()
        self.workspace_dir = self.home / workspace_digest

    def _actor_dir(self, actor: str) -> Path:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,49}", actor):
            raise AuthorizationError("Actor capability principal is invalid")
        return self.workspace_dir / actor

    def _record_path(self, actor: str) -> Path:
        return self._actor_dir(actor) / "key.json"

    def _guard_path(self, actor: str) -> Path:
        return self._actor_dir(actor) / "bootstrap.guard.json"

    def _used_dir(self, actor: str) -> Path:
        return self._actor_dir(actor) / "used"

    def _rotation_lock_path(self, actor: str) -> Path:
        return self._actor_dir(actor) / "rotation.lock"

    def _secure_directory(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        if _has_reparse_component(path):
            raise ConfigurationError("Actor capability store cannot use reparse points")
        if os.name != "nt":
            path.chmod(0o700)

    def _secure_write(self, path: Path, value: dict[str, Any]) -> None:
        self._secure_directory(path.parent)
        atomic_write_json(path, value)
        if os.name != "nt":
            path.chmod(0o600)

    def _entropy(self, actor: str) -> bytes:
        return hashlib.sha256(
            canonical_json(
                {
                    "domain": "cogni-os-actor-capability-dpapi-v1",
                    "workspace_id": self.workspace_id,
                    "actor": actor,
                }
            )
        ).digest()

    def _derive_key(self, actor: str, secret: bytes) -> bytes:
        return hmac.new(
            secret,
            canonical_json(
                {
                    "domain": "cogni-os-actor-capability-key-v1",
                    "workspace_id": self.workspace_id,
                    "actor": actor,
                }
            ),
            hashlib.sha256,
        ).digest()

    def _guard_digest(self, actor: str, secret: bytes) -> bytes:
        return hmac.new(
            secret,
            canonical_json(
                {
                    "domain": "cogni-os-actor-capability-bootstrap-v1",
                    "workspace_id": self.workspace_id,
                    "actor": actor,
                }
            ),
            hashlib.sha256,
        ).digest()

    def provision_guard(
        self, *, actor: str, bootstrap_secret: str | bytes
    ) -> dict[str, Any]:
        """Pre-provision a one-time guard from an OS-admin/installer context.

        This method is intentionally absent from the normal CLI.  The caller is
        responsible for enforcing an OS-admin boundary before invoking it.
        """

        secret = _secret_bytes(bootstrap_secret, label="Bootstrap secret")
        actor_dir = self._actor_dir(actor)
        record_path = self._record_path(actor)
        guard_path = self._guard_path(actor)
        if record_path.exists() or guard_path.exists():
            raise AuthorizationError(
                "Actor capability bootstrap is already provisioned"
            )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "workspace_id": self.workspace_id,
            "actor": actor,
            "guard_digest": _b64encode(self._guard_digest(actor, secret)),
            "created_at_epoch": int(time.time()),
            "one_time": True,
        }
        self._secure_directory(actor_dir)
        try:
            descriptor = os.open(
                guard_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as exc:
            raise AuthorizationError(
                "Actor capability bootstrap is already provisioned"
            ) from exc
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            guard_path.unlink(missing_ok=True)
            raise
        return self.status(actor=actor)

    def bootstrap(self, *, actor: str, bootstrap_secret: str | bytes) -> dict[str, Any]:
        """Consume a pre-provisioned guard and create the actor verifier key."""

        secret = _secret_bytes(bootstrap_secret, label="Bootstrap secret")
        guard_path = self._guard_path(actor)
        record_path = self._record_path(actor)
        if record_path.exists():
            raise AuthorizationError("Actor capability is already bootstrapped")
        if not guard_path.is_file():
            raise AuthorizationError(
                "Actor capability bootstrap guard is unavailable; OS-admin provisioning is required"
            )
        guard = read_json(guard_path)
        if (
            guard.get("schema_version") != SCHEMA_VERSION
            or guard.get("workspace_id") != self.workspace_id
            or guard.get("actor") != actor
            or guard.get("one_time") is not True
        ):
            raise IntegrityError("Actor capability bootstrap guard is invalid")
        expected_guard = _b64decode(str(guard.get("guard_digest", "")))
        observed_guard = self._guard_digest(actor, secret)
        if not hmac.compare_digest(expected_guard, observed_guard):
            raise AuthorizationError("Actor capability bootstrap secret is incorrect")
        key = self._derive_key(actor, secret)
        protected = _dpapi_protect(key, self._entropy(actor))
        record = {
            "schema_version": SCHEMA_VERSION,
            "workspace_id": self.workspace_id,
            "actor": actor,
            "key_version": 1,
            "protected_key": _b64encode(protected),
            "retired_receipt_keys": [],
            "protector": "windows-dpapi-current-user"
            if os.name == "nt"
            else "mode-0600",
            "actor_os_isolation_proven": False,
            "created_at_epoch": int(time.time()),
        }
        # Atomic create prevents two bootstrap secrets from winning a race.
        self._secure_directory(record_path.parent)
        try:
            descriptor = os.open(
                record_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as exc:
            raise AuthorizationError(
                "Actor capability is already bootstrapped"
            ) from exc
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(record, handle, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            record_path.unlink(missing_ok=True)
            raise
        guard_path.unlink()
        return self.status(actor=actor)

    def _record(self, actor: str) -> dict[str, Any]:
        path = self._record_path(actor)
        if not path.is_file():
            raise AuthorizationError(
                "Actor capability is unprovisioned; privileged operation denied"
            )
        record = read_json(path)
        if (
            record.get("schema_version") != SCHEMA_VERSION
            or record.get("workspace_id") != self.workspace_id
            or record.get("actor") != actor
            or not isinstance(record.get("key_version"), int)
            or isinstance(record.get("key_version"), bool)
            or record["key_version"] < 1
            or not isinstance(record.get("retired_receipt_keys", []), list)
        ):
            raise IntegrityError("Actor capability key record is invalid")
        seen_versions: set[int] = set()
        for retired in record.get("retired_receipt_keys", []):
            if (
                not isinstance(retired, dict)
                or not isinstance(retired.get("key_version"), int)
                or isinstance(retired.get("key_version"), bool)
                or retired["key_version"] < 1
                or retired["key_version"] >= record["key_version"]
                or retired["key_version"] in seen_versions
                or not isinstance(retired.get("protected_key"), str)
                or not retired["protected_key"]
            ):
                raise IntegrityError("Actor capability retired verifier key is invalid")
            seen_versions.add(retired["key_version"])
        return record

    def _key(self, actor: str, record: dict[str, Any]) -> bytes:
        protected = _b64decode(str(record.get("protected_key", "")))
        key = _dpapi_unprotect(protected, self._entropy(actor))
        if len(key) != hashlib.sha256().digest_size:
            raise IntegrityError("Actor capability verifier key is invalid")
        return key

    def _receipt_key(
        self,
        actor: str,
        record: dict[str, Any],
        key_version: int,
    ) -> bytes:
        """Return the active or retired key used to verify a persisted receipt."""

        if record["key_version"] == key_version:
            return self._key(actor, record)
        retired = next(
            (
                item
                for item in record.get("retired_receipt_keys", [])
                if item.get("key_version") == key_version
            ),
            None,
        )
        if not isinstance(retired, dict):
            raise AuthorizationError(
                "Actor capability receipt key version is unavailable"
            )
        protected = _b64decode(str(retired.get("protected_key", "")))
        key = _dpapi_unprotect(protected, self._entropy(actor))
        if len(key) != hashlib.sha256().digest_size:
            raise IntegrityError("Actor capability retired verifier key is invalid")
        return key

    def mint(
        self,
        *,
        actor: str,
        operation: str,
        credential_secret: str | bytes,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now: int | None = None,
        nonce: str | None = None,
        task_id: str | None = None,
        run_id: str | None = None,
        task_attempt: int | None = None,
    ) -> str:
        """Mint a short-lived, one-time proof after constant-time credential check."""

        if not OPERATION_RE.fullmatch(operation):
            raise AuthorizationError("Actor capability operation is invalid")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise AuthorizationError("Actor capability lifetime is invalid")
        if ttl_seconds < 1 or ttl_seconds > MAX_TTL_SECONDS:
            raise AuthorizationError("Actor capability lifetime is outside policy")
        secret = _secret_bytes(credential_secret, label="Actor credential")
        record = self._record(actor)
        stored_key = self._key(actor, record)
        derived_key = self._derive_key(actor, secret)
        if not hmac.compare_digest(stored_key, derived_key):
            raise AuthorizationError("Actor capability credential is incorrect")
        issued_at = int(time.time()) if now is None else int(now)
        proof_nonce = nonce or secrets.token_hex(24)
        if not re.fullmatch(r"[0-9a-f]{48}", proof_nonce):
            raise AuthorizationError("Actor capability nonce is invalid")
        binding = _binding_fields(
            task_id=task_id,
            run_id=run_id,
            task_attempt=task_attempt,
        )
        payload = {
            "token_version": TOKEN_VERSION,
            "workspace_id": self.workspace_id,
            "actor": actor,
            "operation": operation,
            "nonce": proof_nonce,
            "key_version": record["key_version"],
            "issued_at_epoch": issued_at,
            "expires_at_epoch": issued_at + ttl_seconds,
            **binding,
        }
        body = canonical_json(payload)
        signature = hmac.new(stored_key, body, hashlib.sha256).digest()
        return f"{_b64encode(body)}.{_b64encode(signature)}"

    def verify_and_consume(
        self,
        *,
        expected_actor: str,
        expected_operation: str,
        token: str | None,
        now: int | None = None,
        expected_task_id: str | None = None,
        expected_run_id: str | None = None,
        expected_task_attempt: int | None = None,
    ) -> dict[str, Any]:
        """Validate and atomically consume one actor capability proof."""

        if not token or not isinstance(token, str):
            raise AuthorizationError("Actor capability proof is required")
        if len(token.encode("utf-8", errors="ignore")) > MAX_TOKEN_BYTES:
            raise AuthorizationError("Actor capability proof is malformed")
        if not OPERATION_RE.fullmatch(expected_operation):
            raise AuthorizationError("Actor capability operation is invalid")
        expected_binding = _binding_fields(
            task_id=expected_task_id,
            run_id=expected_run_id,
            task_attempt=expected_task_attempt,
        )
        parts = token.split(".")
        if len(parts) != 2:
            raise AuthorizationError("Actor capability proof is malformed")
        body = _b64decode(parts[0])
        signature = _b64decode(parts[1])
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorizationError("Actor capability proof is malformed") from exc
        if not isinstance(payload, dict) or canonical_json(payload) != body:
            raise AuthorizationError("Actor capability proof is not canonical")
        record = self._record(expected_actor)
        key = self._key(expected_actor, record)
        expected_signature = hmac.new(key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_signature, signature):
            raise AuthorizationError("Actor capability proof signature is invalid")
        if (
            payload.get("token_version") != TOKEN_VERSION
            or payload.get("workspace_id") != self.workspace_id
            or payload.get("actor") != expected_actor
            or payload.get("operation") != expected_operation
            or payload.get("key_version") != record["key_version"]
            or any(
                payload.get(name) != value for name, value in expected_binding.items()
            )
        ):
            raise AuthorizationError("Actor capability proof scope is invalid")
        issued_at = payload.get("issued_at_epoch")
        expires_at = payload.get("expires_at_epoch")
        if (
            not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at <= issued_at
            or expires_at - issued_at > MAX_TTL_SECONDS
        ):
            raise AuthorizationError("Actor capability proof lifetime is invalid")
        current = int(time.time()) if now is None else int(now)
        if issued_at > current + 5 or current >= expires_at:
            raise AuthorizationError(
                "Actor capability proof is expired or not yet valid"
            )
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{48}", nonce):
            raise AuthorizationError("Actor capability nonce is invalid")

        nonce_sha256 = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        principal_attestation = _os_principal_attestation()
        receipt_body = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "receipt_type": "actor-capability-consumption",
            "workspace_id": self.workspace_id,
            "actor": expected_actor,
            "operation": expected_operation,
            **expected_binding,
            "nonce_sha256": nonce_sha256,
            "key_version": record["key_version"],
            "issued_at_epoch": issued_at,
            "expires_at_epoch": expires_at,
            "consumed_at_epoch": current,
            "os_principal_attestation": principal_attestation,
            "independent_trust_root": False,
            "actor_os_isolation_proven": False,
            "signature_algorithm": RECEIPT_SIGNATURE_ALGORITHM,
        }
        receipt = {
            **receipt_body,
            "signature": _b64encode(
                hmac.new(key, canonical_json(receipt_body), hashlib.sha256).digest()
            ),
        }

        # Do not persist the bearer proof itself.  The signed receipt hash and
        # a scoped nonce digest make replay consumption auditable outside the
        # workspace without turning the receipt back into a bearer token.
        marker_digest = hashlib.sha256(
            canonical_json(
                {
                    "workspace_id": self.workspace_id,
                    "actor": expected_actor,
                    "operation": expected_operation,
                    "nonce_sha256": nonce_sha256,
                    "key_version": record["key_version"],
                }
            )
        ).hexdigest()
        used_dir = self._used_dir(expected_actor)
        self._secure_directory(used_dir)
        marker = used_dir / marker_digest
        try:
            descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise AuthorizationError(
                "Actor capability proof has already been consumed"
            ) from exc
        try:
            marker_payload = {
                "schema_version": 1,
                "receipt_sha256": hashlib.sha256(canonical_json(receipt)).hexdigest(),
                "consumed_at_epoch": current,
            }
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(marker_payload, handle, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            marker.unlink(missing_ok=True)
            raise
        return receipt

    def validate_receipt(
        self,
        receipt: Any,
        *,
        expected_actor: str,
        expected_operation: str,
        expected_task_id: str | None,
        expected_run_id: str | None,
        expected_task_attempt: int | None,
        require_independent_trust_root: bool = False,
    ) -> dict[str, Any]:
        """Cryptographically validate one persisted, context-bound receipt.

        Local HMAC validation detects plain, modified and mismatched receipts.
        It deliberately cannot upgrade a same-user key into an independent
        actor trust root; release-critical readers must request that stronger
        property and receive ``CAPABILITY_UNATTESTED`` until a broker exists.
        """

        expected_binding = _binding_fields(
            task_id=expected_task_id,
            run_id=expected_run_id,
            task_attempt=expected_task_attempt,
        )
        if not isinstance(receipt, dict):
            raise AuthorizationError("Actor capability receipt is missing")
        required = {
            "schema_version",
            "receipt_type",
            "workspace_id",
            "actor",
            "operation",
            "task_id",
            "run_id",
            "task_attempt",
            "nonce_sha256",
            "key_version",
            "issued_at_epoch",
            "expires_at_epoch",
            "consumed_at_epoch",
            "os_principal_attestation",
            "independent_trust_root",
            "actor_os_isolation_proven",
            "signature_algorithm",
            "signature",
        }
        if set(receipt) != required:
            raise AuthorizationError("Actor capability receipt schema is invalid")
        key_version = receipt.get("key_version")
        issued_at = receipt.get("issued_at_epoch")
        expires_at = receipt.get("expires_at_epoch")
        consumed_at = receipt.get("consumed_at_epoch")
        nonce_sha256 = receipt.get("nonce_sha256")
        if (
            receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION
            or receipt.get("receipt_type") != "actor-capability-consumption"
            or receipt.get("workspace_id") != self.workspace_id
            or receipt.get("actor") != expected_actor
            or receipt.get("operation") != expected_operation
            or any(
                receipt.get(name) != value for name, value in expected_binding.items()
            )
            or not isinstance(nonce_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", nonce_sha256)
            or not isinstance(key_version, int)
            or isinstance(key_version, bool)
            or key_version < 1
            or not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or not isinstance(consumed_at, int)
            or isinstance(consumed_at, bool)
            or not issued_at <= consumed_at < expires_at
            or expires_at - issued_at > MAX_TTL_SECONDS
            or receipt.get("signature_algorithm") != RECEIPT_SIGNATURE_ALGORITHM
            or receipt.get("independent_trust_root") is not False
            or receipt.get("actor_os_isolation_proven") is not False
            or receipt.get("os_principal_attestation") != _os_principal_attestation()
        ):
            raise AuthorizationError("Actor capability receipt scope is invalid")
        record = self._record(expected_actor)
        key = self._receipt_key(expected_actor, record, key_version)
        body = {name: value for name, value in receipt.items() if name != "signature"}
        observed_signature = _b64decode(str(receipt.get("signature", "")))
        expected_signature = hmac.new(
            key,
            canonical_json(body),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(observed_signature, expected_signature):
            raise AuthorizationError("Actor capability receipt signature is invalid")

        marker_digest = hashlib.sha256(
            canonical_json(
                {
                    "workspace_id": self.workspace_id,
                    "actor": expected_actor,
                    "operation": expected_operation,
                    "nonce_sha256": nonce_sha256,
                    "key_version": key_version,
                }
            )
        ).hexdigest()
        marker_path = self._used_dir(expected_actor) / marker_digest
        try:
            marker = read_json(marker_path)
        except (FileNotFoundError, ConfigurationError) as exc:
            raise AuthorizationError(
                "Actor capability receipt has no external consumption record"
            ) from exc
        if (
            marker.get("schema_version") != 1
            or marker.get("receipt_sha256")
            != hashlib.sha256(canonical_json(receipt)).hexdigest()
            or marker.get("consumed_at_epoch") != consumed_at
        ):
            raise AuthorizationError(
                "Actor capability receipt replay record is invalid"
            )
        if require_independent_trust_root:
            raise AuthorizationError(
                "CAPABILITY_UNATTESTED: local same-user HMAC receipts are not an "
                "independent actor trust root"
            )
        return dict(receipt)

    def rotate(
        self,
        *,
        actor: str,
        rotation_token: str,
        new_secret: str | bytes,
    ) -> dict[str, Any]:
        """Rotate the verifier key after consuming a dedicated old-key proof."""

        secret = _secret_bytes(new_secret, label="New actor credential")
        self._secure_directory(self._actor_dir(actor))
        with FileLock(self._rotation_lock_path(actor)):
            receipt = self.verify_and_consume(
                expected_actor=actor,
                expected_operation="capability.rotate",
                token=rotation_token,
            )
            record = self._record(actor)
            if record["key_version"] != receipt["key_version"]:
                raise AuthorizationError(
                    "Actor capability rotation lost its key-version compare-and-swap"
                )
            next_key = self._derive_key(actor, secret)
            protected = _dpapi_protect(next_key, self._entropy(actor))
            retired = [*record.get("retired_receipt_keys", [])]
            retired.append(
                {
                    "key_version": record["key_version"],
                    "protected_key": record["protected_key"],
                }
            )
            rotated = {
                **record,
                "key_version": record["key_version"] + 1,
                "protected_key": _b64encode(protected),
                "retired_receipt_keys": retired,
                "rotated_at_epoch": int(time.time()),
                "actor_os_isolation_proven": False,
            }
            self._secure_write(self._record_path(actor), rotated)
        return self.status(actor=actor)

    def status(self, *, actor: str) -> dict[str, Any]:
        record_path = self._record_path(actor)
        guard_path = self._guard_path(actor)
        if record_path.is_file():
            record = self._record(actor)
            return {
                "schema_version": SCHEMA_VERSION,
                "workspace_id": self.workspace_id,
                "actor": actor,
                "state": "provisioned",
                "key_version": record["key_version"],
                "protector": record.get("protector"),
                "actor_os_isolation_proven": False,
                "independent_trust_root": False,
                "receipt_signature_algorithm": RECEIPT_SIGNATURE_ALGORITHM,
                "capability_home_outside_workspace": True,
            }
        return {
            "schema_version": SCHEMA_VERSION,
            "workspace_id": self.workspace_id,
            "actor": actor,
            "state": "guard_pending" if guard_path.is_file() else "unprovisioned",
            "key_version": None,
            "protector": None,
            "actor_os_isolation_proven": False,
            "independent_trust_root": False,
            "receipt_signature_algorithm": None,
            "capability_home_outside_workspace": True,
        }


def authority_for_workspace(
    workspace: Any,
    *,
    home: str | Path | None = None,
) -> ActorCapabilityAuthority:
    """Create an authority from a loaded workspace without importing Workspace."""

    return ActorCapabilityAuthority(
        workspace_root=workspace.root,
        workspace_id=str(workspace.config["workspace_id"]),
        home=home,
    )


def platform_security_posture() -> dict[str, Any]:
    """Return explicit, non-inflated capability isolation claims."""

    return {
        "platform": sys.platform,
        "at_rest_protector": (
            "windows-dpapi-current-user" if os.name == "nt" else "mode-0600"
        ),
        # A same-user process can generally read the same profile and invoke
        # the same DPAPI principal.  Keeping the key outside the repository
        # prevents accidental disclosure and actor-label-only authorization,
        # but it is not an OS-enforced process boundary.  Never advertise the
        # weaker control as proof that an untrusted workspace process cannot
        # impersonate the conductor.
        "workspace_process_impersonation_blocked_without_credential": False,
        "actor_label_only_authorization_rejected": True,
        "operation_scoped_credential_check_enabled": True,
        "same_os_user_actor_isolation_proven": False,
        "strong_isolation_requires": (
            "distinct OS principals or an external secret broker with ACL-separated homes"
        ),
    }
