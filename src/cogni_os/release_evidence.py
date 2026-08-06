"""Conductor-only collection of immutable production release evidence.

This module deliberately does not accept caller-selected URLs, archive paths,
or expected response values.  It captures the two canonical production
endpoints over verified TLS, stores the exact bounded response bodies, and
binds the resulting content-addressed bundle to the signed workspace ledger.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePath, PurePosixPath
from typing import Any

from .actor_capability import authority_for_workspace
from .errors import (
    AuthorizationError,
    ConfigurationError,
    EvidenceError,
    IntegrityError,
    StateError,
)
from .independence import identity_snapshot
from .lock import FileLock
from .release_gate import (
    _open_directory_at as _open_archive_directory_at,
)
from .release_gate import (
    _read_descriptor_bounded as _read_archive_descriptor_bounded,
)
from .release_gate import (
    _secure_archive_directory as _secure_archive_directory_fd,
)
from .release_gate import (
    _secure_archive_primitives_available,
)
from .trusted_runner import trusted_git_source_commit
from .util import utc_now
from .workspace import Workspace

P01_TASK_ID = "P01-TRUTH"
PRODUCTION_ORIGIN = "https://cogni-os-orchestrator.pages.dev"
CLOUDFLARE_API_ORIGIN = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_ACCOUNT_TOKEN_ENV = "CLOUDFLARE_API_TOKEN"
CLOUDFLARE_PROJECT = "cogni-os-orchestrator"
PRODUCTION_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("health", f"{PRODUCTION_ORIGIN}/api/health"),
    ("snapshot", f"{PRODUCTION_ORIGIN}/api/snapshot"),
)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
HTTP_TIMEOUT_SECONDS = 15.0
MAX_HEADER_VALUE_BYTES = 4096
ARCHIVE_PREFIX = Path("archive") / "release-evidence" / P01_TASK_ID

_SELECTED_HEADERS = {
    "cache-control",
    "cf-cache-status",
    "cf-ray",
    "content-length",
    "content-type",
    "date",
    "etag",
    "last-modified",
    "x-cogni-body-sha256",
    "x-cogni-data-state",
    "x-cogni-sequence",
}
_SENSITIVE_JSON_KEYS = {
    "api_key",
    "authorization",
    "client_secret",
    "cookie",
    "password",
    "refresh_token",
    "secret",
    "set-cookie",
    "token",
}
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DEPLOYMENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_ACCOUNT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_BUNDLE_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_ARTIFACT_FILES = {
    "production-health-body": "production_health.body.json",
    "production-health-capture": "production_health.capture.json",
    "production-snapshot-body": "production_snapshot.body.json",
    "production-snapshot-capture": "production_snapshot.capture.json",
    "cloudflare-deployment-evidence": "cloudflare_deployment.json",
    "cloudflare-rollback-target-evidence": "cloudflare_rollback_target.json",
    "cloudflare-rollback-dry-run-receipt": "cloudflare_rollback_dry_run.json",
    "cloudflare-current-deployment-body": "cloudflare_current_deployment.body.json",
    "cloudflare-current-deployment-capture": "cloudflare_current_deployment.capture.json",
    "cloudflare-current-project-body": "cloudflare_current_project.body.json",
    "cloudflare-current-project-capture": "cloudflare_current_project.capture.json",
    "cloudflare-rollback-deployment-body": "cloudflare_rollback_deployment.body.json",
    "cloudflare-rollback-deployment-capture": "cloudflare_rollback_deployment.capture.json",
    "cloudflare-rollback-project-body": "cloudflare_rollback_project.body.json",
    "cloudflare-rollback-project-capture": "cloudflare_rollback_project.capture.json",
}


@dataclass(frozen=True)
class HttpCapture:
    """One exact, bounded HTTP response and its non-sensitive metadata."""

    body: bytes
    metadata: dict[str, Any]


@dataclass(frozen=True)
class CloudflareDeploymentCapture:
    """Derived deployment evidence plus both exact Cloudflare API responses."""

    evidence: dict[str, Any]
    deployment: HttpCapture
    project: HttpCapture


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise EvidenceError("Production evidence endpoint redirected")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).strip().lower()
            if normalized_key in _SENSITIVE_JSON_KEYS or any(
                marker in normalized_key
                for marker in (
                    "authorization",
                    "api_key",
                    "cookie",
                    "password",
                    "secret",
                    "token",
                )
            ):
                return True
            if normalized_key in {"env_vars", "environment_variables"} and child:
                return True
            if _contains_sensitive_key(child):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_key(child) for child in value)
    return False


def _selected_headers(headers: Any) -> dict[str, str]:
    selected: dict[str, str] = {}
    items = headers.items() if hasattr(headers, "items") else []
    for raw_name, raw_value in items:
        name = str(raw_name).strip().lower()
        if name not in _SELECTED_HEADERS:
            continue
        value = str(raw_value).strip()
        if "\r" in value or "\n" in value:
            raise EvidenceError(f"Unsafe response header value: {name}")
        if len(value.encode("utf-8")) > MAX_HEADER_VALUE_BYTES:
            raise EvidenceError(f"Response header is too large: {name}")
        if name in selected:
            selected[name] = f"{selected[name]}, {value}"
        else:
            selected[name] = value
    return selected


def _default_https_opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _RejectRedirects(),
    )


def fetch_production_json(
    url: str,
    *,
    opener: Any | None = None,
    timeout_seconds: float = HTTP_TIMEOUT_SECONDS,
    max_body_bytes: int = MAX_RESPONSE_BYTES,
) -> HttpCapture:
    """Fetch one pinned JSON endpoint with one bounded body read.

    ``url`` is accepted for internal endpoint iteration and tests, but anything
    outside the exact production allowlist is rejected before network access.
    """
    allowed_urls = {endpoint_url for _, endpoint_url in PRODUCTION_ENDPOINTS}
    if url not in allowed_urls:
        raise EvidenceError("Release evidence URL is not pinned")
    if not (0 < timeout_seconds <= HTTP_TIMEOUT_SECONDS):
        raise EvidenceError("HTTP timeout is outside the allowed bound")
    if not (0 < max_body_bytes <= MAX_RESPONSE_BYTES):
        raise EvidenceError("HTTP response bound is outside the allowed limit")

    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "Cogni-OS-Evidence/1"},
    )
    transport = opener if opener is not None else _default_https_opener()
    response: Any | None = None
    try:
        response = transport.open(request, timeout=timeout_seconds)
        status_value = getattr(response, "status", None)
        if status_value is None:
            status_value = response.getcode()
        status_code = int(status_value)
        final_url = str(response.geturl())
        if final_url != url:
            raise EvidenceError("Production evidence endpoint changed URL")
        if status_code != 200:
            raise EvidenceError(
                f"Production evidence endpoint returned HTTP {status_code}"
            )

        selected_headers = _selected_headers(response.headers)
        content_type = selected_headers.get("content-type", "")
        if not content_type.lower().startswith("application/json"):
            raise EvidenceError("Production evidence response is not JSON")
        content_length = selected_headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise EvidenceError("Invalid Content-Length response header") from exc
            if declared_length < 0 or declared_length > max_body_bytes:
                raise EvidenceError("Production evidence response exceeds size limit")

        # Deliberately one read: the returned bytes are both hashed and archived.
        body = response.read(max_body_bytes + 1)
        if len(body) > max_body_bytes:
            raise EvidenceError("Production evidence response exceeds size limit")
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceError(
                "Production evidence response is invalid UTF-8 JSON"
            ) from exc
        if not isinstance(decoded, dict):
            raise EvidenceError("Production evidence response must be a JSON object")
        if _contains_sensitive_key(decoded):
            raise EvidenceError("Production response contains a secret-bearing field")

        return HttpCapture(
            body=body,
            metadata={
                "schema_version": 1,
                "document_type": "cogni-production-http-capture",
                "method": "GET",
                "request_url": url,
                "final_url": final_url,
                "status": status_code,
                "fetched_at": utc_now(),
                "tls_verified": True,
                "tls_policy": "python-default-ca",
                "headers": selected_headers,
                "body_sha256": _sha256_bytes(body),
                "body_size_bytes": len(body),
            },
        )
    except EvidenceError:
        raise
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        raise EvidenceError(
            f"Production evidence fetch failed: {type(exc).__name__}"
        ) from exc
    finally:
        if response is not None:
            response.close()


def _cloudflare_deployment_url(account_id: str, deployment_id: str) -> str:
    return (
        f"{CLOUDFLARE_API_ORIGIN}/accounts/{account_id}/pages/projects/"
        f"{CLOUDFLARE_PROJECT}/deployments/{deployment_id}"
    )


def _cloudflare_project_url(account_id: str) -> str:
    return (
        f"{CLOUDFLARE_API_ORIGIN}/accounts/{account_id}/pages/projects/"
        f"{CLOUDFLARE_PROJECT}"
    )


def _fetch_cloudflare_api_result(
    url: str,
    *,
    token: str,
    transport: Any,
    resource: str,
) -> tuple[dict[str, Any], HttpCapture]:
    """Perform one bounded, redirect-intolerant Cloudflare API GET."""

    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "Cogni-OS-Evidence/1",
        },
    )
    response: Any | None = None
    try:
        response = transport.open(request, timeout=HTTP_TIMEOUT_SECONDS)
        status_value = getattr(response, "status", None)
        if status_value is None:
            status_value = response.getcode()
        status_code = int(status_value)
        final_url = str(response.geturl())
        if final_url != url:
            raise EvidenceError(f"Cloudflare {resource} endpoint changed URL")
        if status_code != 200:
            raise EvidenceError(
                f"Cloudflare {resource} API returned HTTP {status_code}"
            )
        selected_headers = _selected_headers(response.headers)
        content_type = selected_headers.get("content-type", "")
        if not content_type.lower().startswith("application/json"):
            raise EvidenceError(f"Cloudflare {resource} response is not JSON")
        content_length = selected_headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise EvidenceError(
                    f"Cloudflare {resource} Content-Length is invalid"
                ) from exc
            if declared_length < 0 or declared_length > MAX_RESPONSE_BYTES:
                raise EvidenceError(
                    f"Cloudflare {resource} response exceeds size limit"
                )
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise EvidenceError(f"Cloudflare {resource} response exceeds size limit")
        try:
            envelope = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceError(
                f"Cloudflare {resource} response is invalid JSON"
            ) from exc
        if not isinstance(envelope, dict) or envelope.get("success") is not True:
            raise EvidenceError(f"Cloudflare {resource} API did not attest success")
        if _contains_sensitive_key(envelope):
            raise EvidenceError(
                f"Cloudflare {resource} response contains a secret-bearing field"
            )
        result = envelope.get("result")
        if not isinstance(result, dict):
            raise EvidenceError(f"Cloudflare {resource} API result is missing")
        return result, HttpCapture(
            body=body,
            metadata={
                "schema_version": 1,
                "document_type": "cogni-cloudflare-http-capture",
                "method": "GET",
                "resource": resource,
                "request_url": url,
                "final_url": final_url,
                "status": status_code,
                "fetched_at": utc_now(),
                "tls_verified": True,
                "tls_policy": "python-default-ca",
                "headers": selected_headers,
                "body_sha256": _sha256_bytes(body),
                "body_size_bytes": len(body),
            },
        )
    except EvidenceError:
        raise
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        raise EvidenceError(
            f"Cloudflare {resource} fetch failed: {type(exc).__name__}"
        ) from exc
    finally:
        if response is not None:
            response.close()


def _safe_api_string(value: Any, *, label: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"Cloudflare deployment {label} is missing")
    normalized = value.strip()
    if "\r" in normalized or "\n" in normalized or len(normalized) > maximum:
        raise EvidenceError(f"Cloudflare deployment {label} is invalid")
    return normalized


def _normalized_pages_url(value: Any) -> str:
    raw_url = _safe_api_string(value, label="url")
    parsed = urllib.parse.urlsplit(raw_url)
    expected_suffix = f".{CLOUDFLARE_PROJECT}.pages.dev"
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme.lower() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not hostname.endswith(expected_suffix)
    ):
        raise EvidenceError(
            "Cloudflare deployment URL is outside the Pages project allowlist"
        )
    return f"https://{hostname}"


def _deployment_time(value: Any, *, label: str) -> datetime:
    normalized = _safe_api_string(value, label=label, maximum=64)
    # Python 3.10's fromisoformat does not accept the RFC 3339 ``Z`` suffix.
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise EvidenceError(f"Cloudflare deployment {label} is invalid") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"Cloudflare deployment {label} must include a timezone")
    return parsed


def _capture_cloudflare_deployment(
    account_id: str,
    deployment_id: str,
    *,
    api_token: str,
    opener: Any | None = None,
) -> CloudflareDeploymentCapture:
    """Read one deployment and the project's current production alias.

    Both API resources are required.  A deployment object alone proves that a
    build exists, but not that the canonical Pages hostname is serving it.  The
    bearer token remains memory-only. The exact bounded API responses are
    returned beside the independently derived document for immutable archival.
    """
    normalized_account = account_id.strip().lower()
    if not _ACCOUNT_ID_RE.fullmatch(normalized_account):
        raise EvidenceError("Cloudflare account id must be 32 hexadecimal characters")
    normalized_deployment = _validated_deployment_id(
        deployment_id,
        label="Cloudflare deployment id",
    )
    token = api_token.strip()
    if not token:
        raise EvidenceError(
            f"Missing {CLOUDFLARE_ACCOUNT_TOKEN_ENV} environment secret"
        )
    transport = opener if opener is not None else _default_https_opener()
    deployment_url = _cloudflare_deployment_url(
        normalized_account, normalized_deployment
    )
    project_url = _cloudflare_project_url(normalized_account)
    result, deployment_receipt = _fetch_cloudflare_api_result(
        deployment_url,
        token=token,
        transport=transport,
        resource="pages-deployment",
    )
    project_result, project_receipt = _fetch_cloudflare_api_result(
        project_url,
        token=token,
        transport=transport,
        resource="pages-project",
    )
    try:
        latest_stage = result.get("latest_stage")
        trigger = result.get("deployment_trigger")
        trigger_metadata = (
            trigger.get("metadata") if isinstance(trigger, dict) else None
        )
        if not isinstance(latest_stage, dict) or not isinstance(trigger_metadata, dict):
            raise EvidenceError("Cloudflare deployment provenance is incomplete")

        result_id = _safe_api_string(result.get("id"), label="id", maximum=64)
        if result_id != normalized_deployment:
            raise EvidenceError("Cloudflare deployment id does not match the request")
        project_name = _safe_api_string(
            result.get("project_name"),
            label="project_name",
            maximum=128,
        )
        if project_name != CLOUDFLARE_PROJECT:
            raise EvidenceError("Cloudflare deployment belongs to another project")
        environment = _safe_api_string(
            result.get("environment"),
            label="environment",
            maximum=32,
        )
        if environment != "production":
            raise EvidenceError("Cloudflare deployment is not a production deployment")
        stage_status = _safe_api_string(
            latest_stage.get("status"),
            label="latest_stage.status",
            maximum=32,
        )
        if stage_status != "success":
            raise EvidenceError("Cloudflare deployment is not successful")
        if result.get("is_skipped") is True:
            raise EvidenceError("Cloudflare deployment was skipped")

        commit_hash = _validated_commit(
            _safe_api_string(
                trigger_metadata.get("commit_hash"),
                label="commit_hash",
                maximum=64,
            ),
            label="Cloudflare deployment commit",
        )
        commit_dirty = trigger_metadata.get("commit_dirty")
        if commit_dirty is not False:
            raise EvidenceError(
                "Cloudflare deployment commit_dirty must be the boolean false"
            )
        branch = _safe_api_string(
            trigger_metadata.get("branch"),
            label="deployment_trigger.metadata.branch",
            maximum=256,
        )
        if branch != "main":
            raise EvidenceError(
                "Cloudflare deployment is not from production branch main"
            )
        direct_url = _normalized_pages_url(result.get("url"))

        project_name_from_alias = _safe_api_string(
            project_result.get("name"),
            label="project.name",
            maximum=128,
        )
        if project_name_from_alias != CLOUDFLARE_PROJECT:
            raise EvidenceError("Cloudflare project alias belongs to another project")
        canonical_hostname = _safe_api_string(
            project_result.get("subdomain"),
            label="project.subdomain",
            maximum=256,
        ).lower()
        if canonical_hostname != urllib.parse.urlsplit(PRODUCTION_ORIGIN).hostname:
            raise EvidenceError("Cloudflare project canonical hostname does not match")
        canonical = project_result.get("canonical_deployment")
        if not isinstance(canonical, dict):
            raise EvidenceError("Cloudflare canonical deployment is missing")
        canonical_trigger = canonical.get("deployment_trigger")
        canonical_metadata = (
            canonical_trigger.get("metadata")
            if isinstance(canonical_trigger, dict)
            else None
        )
        canonical_stage = canonical.get("latest_stage")
        if not isinstance(canonical_metadata, dict) or not isinstance(
            canonical_stage, dict
        ):
            raise EvidenceError(
                "Cloudflare canonical deployment provenance is incomplete"
            )
        canonical_id = _validated_deployment_id(
            _safe_api_string(
                canonical.get("id"),
                label="canonical_deployment.id",
                maximum=64,
            ),
            label="Cloudflare canonical deployment id",
        )
        canonical_direct_url = _normalized_pages_url(canonical.get("url"))
        canonical_commit = _validated_commit(
            _safe_api_string(
                canonical_metadata.get("commit_hash"),
                label="canonical_deployment.commit_hash",
                maximum=64,
            ),
            label="Cloudflare canonical deployment commit",
        )
        if canonical.get("environment") != "production":
            raise EvidenceError("Cloudflare canonical deployment is not production")
        if canonical_stage.get("status") != "success":
            raise EvidenceError("Cloudflare canonical deployment is not successful")
        if canonical.get("is_skipped") is True:
            raise EvidenceError("Cloudflare canonical deployment was skipped")
        if canonical_metadata.get("branch") != "main":
            raise EvidenceError("Cloudflare canonical deployment branch is not main")
        if canonical_metadata.get("commit_dirty") is not False:
            raise EvidenceError(
                "Cloudflare canonical deployment commit_dirty must be false"
            )
        evidence = {
            "schema_version": 1,
            "document_type": "cloudflare-pages-deployment-evidence",
            "attestation_level": "CLOUDFLARE_API_VERIFIED",
            "provider": "cloudflare-pages",
            "account_id": normalized_account,
            "project_name": project_name,
            "deployment_id": result_id,
            "short_id": str(result.get("short_id", ""))[:64],
            "environment": environment,
            "url": direct_url,
            "created_on": _safe_api_string(
                result.get("created_on"), label="created_on", maximum=64
            ),
            "modified_on": _safe_api_string(
                result.get("modified_on"), label="modified_on", maximum=64
            ),
            "is_skipped": bool(result.get("is_skipped", False)),
            "source_commit": commit_hash,
            "trigger": {
                "type": str(trigger.get("type", ""))[:64],
                "branch": branch,
                "commit_dirty": False,
            },
            "latest_stage": {
                "name": str(latest_stage.get("name", ""))[:64],
                "status": stage_status,
                "started_on": str(latest_stage.get("started_on", ""))[:64],
                "ended_on": str(latest_stage.get("ended_on", ""))[:64],
            },
            "api_request": deployment_receipt.metadata,
            "production_alias": {
                "api_verified": True,
                "canonical_url": PRODUCTION_ORIGIN,
                "deployment_id": canonical_id,
                "deployment_url": canonical_direct_url,
                "source_commit": canonical_commit,
                "api_request": project_receipt.metadata,
            },
        }
        return CloudflareDeploymentCapture(
            evidence=evidence,
            deployment=deployment_receipt,
            project=project_receipt,
        )
    except EvidenceError:  # noqa: TRY203 - normalize provider parsing boundary
        raise


def fetch_cloudflare_deployment(
    account_id: str,
    deployment_id: str,
    *,
    api_token: str,
    opener: Any | None = None,
) -> dict[str, Any]:
    """Return derived Cloudflare evidence for callers that do not archive it."""

    return _capture_cloudflare_deployment(
        account_id,
        deployment_id,
        api_token=api_token,
        opener=opener,
    ).evidence


def validate_archive_relative_path(value: str | Path) -> Path:
    """Reject absolute, traversal, ADS, and drive-qualified archive paths."""
    path = Path(value)
    raw = str(value)
    if path.is_absolute() or path.drive or raw.startswith(("/", "\\")):
        raise EvidenceError("Archive path must be workspace-relative")
    parts = PurePath(path).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise EvidenceError("Archive path contains an unsafe component")
    if any(":" in part for part in parts):
        raise EvidenceError("Archive path contains an ADS or drive separator")
    return Path(*parts)


def _validated_archive_filename(value: str) -> str:
    """Return one plain filename suitable for a descriptor-relative open."""

    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "\x00" in value
        or "/" in value
        or "\\" in value
        or ":" in value
        or Path(value).name != value
    ):
        raise EvidenceError("Archive filename is unsafe")
    return value


def _write_exclusive_at(directory_descriptor: int, filename: str, value: bytes) -> None:
    """Create and durably write one file below an already-held directory."""

    filename = _validated_archive_filename(filename)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    try:
        descriptor = os.open(
            filename,
            flags,
            0o600,
            dir_fd=directory_descriptor,
        )
    except FileExistsError as exc:
        raise EvidenceError(
            f"Immutable archive artifact already exists: {filename}"
        ) from exc
    except OSError as exc:
        raise EvidenceError("Archive artifact cannot be created safely") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise EvidenceError("Archive artifact is not a regular file")
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short archive write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_archive_file_at(
    directory_descriptor: int,
    filename: str,
    *,
    maximum: int,
) -> bytes:
    """Read one bounded regular file without releasing the parent descriptor."""

    filename = _validated_archive_filename(filename)
    flags = os.O_RDONLY
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NONBLOCK", 0))
    try:
        descriptor = os.open(filename, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        raise EvidenceError(
            f"Recoverable archive artifact cannot be opened safely: {filename}"
        ) from exc
    try:
        return _read_archive_descriptor_bounded(descriptor, maximum)
    finally:
        os.close(descriptor)


def _git_source_commit(root: Path) -> str:
    commit = trusted_git_source_commit(root)
    if not _COMMIT_RE.fullmatch(commit):
        raise EvidenceError("Trusted Git returned an invalid source commit")
    return commit


def _validated_commit(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if not _COMMIT_RE.fullmatch(normalized):
        raise EvidenceError(f"{label} must be a full 40-character Git commit")
    return normalized


def _validated_deployment_id(value: str, *, label: str) -> str:
    normalized = value.strip()
    if not _DEPLOYMENT_ID_RE.fullmatch(normalized):
        raise EvidenceError(f"{label} is invalid")
    return normalized


def _artifact(kind: str, filename: str, value: bytes) -> dict[str, Any]:
    return {
        "kind": kind,
        "filename": filename,
        "sha256": _sha256_bytes(value),
        "size_bytes": len(value),
    }


def _validate_capture(endpoint_url: str, capture: HttpCapture) -> dict[str, Any]:
    if len(capture.body) > MAX_RESPONSE_BYTES:
        raise EvidenceError("Release evidence capture exceeds size limit")
    metadata = capture.metadata
    if metadata.get("schema_version") != 1:
        raise EvidenceError("Release evidence capture schema is invalid")
    if metadata.get("method") != "GET":
        raise EvidenceError("Release evidence capture method is invalid")
    if metadata.get("request_url") != endpoint_url:
        raise EvidenceError(
            "Release evidence capture URL does not match pinned endpoint"
        )
    if metadata.get("final_url") != endpoint_url:
        raise EvidenceError("Release evidence capture final URL is invalid")
    if metadata.get("status") != 200:
        raise EvidenceError("Release evidence capture status is invalid")
    if metadata.get("tls_verified") is not True:
        raise EvidenceError("Release evidence capture is not TLS verified")
    headers = metadata.get("headers")
    if not isinstance(headers, dict):
        raise EvidenceError("Release evidence capture headers are invalid")
    for raw_name, raw_value in headers.items():
        name = str(raw_name).strip().lower()
        value = str(raw_value)
        if name not in _SELECTED_HEADERS:
            raise EvidenceError(
                "Release evidence capture contains a non-selected header"
            )
        if "\r" in value or "\n" in value:
            raise EvidenceError("Release evidence capture contains an unsafe header")
        if len(value.encode("utf-8")) > MAX_HEADER_VALUE_BYTES:
            raise EvidenceError("Release evidence capture header exceeds size limit")
    if metadata.get("body_sha256") != _sha256_bytes(capture.body):
        raise EvidenceError("Release evidence capture body hash mismatch")
    if metadata.get("body_size_bytes") != len(capture.body):
        raise EvidenceError("Release evidence capture body size mismatch")
    try:
        decoded = json.loads(capture.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("Release evidence capture body is invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise EvidenceError("Release evidence capture body must be an object")
    if _contains_sensitive_key(decoded):
        raise EvidenceError("Production response contains a secret-bearing field")
    return decoded


def _validate_cloudflare_capture(
    endpoint_url: str,
    capture: HttpCapture,
    *,
    resource: str,
) -> dict[str, Any]:
    """Validate and decode one archived Cloudflare response from raw bytes."""

    if not isinstance(capture, HttpCapture) or len(capture.body) > MAX_RESPONSE_BYTES:
        raise EvidenceError("Cloudflare raw capture is invalid or exceeds size limit")
    metadata = capture.metadata
    if (
        metadata.get("schema_version") != 1
        or metadata.get("document_type") != "cogni-cloudflare-http-capture"
        or metadata.get("method") != "GET"
        or metadata.get("resource") != resource
        or metadata.get("request_url") != endpoint_url
        or metadata.get("final_url") != endpoint_url
        or metadata.get("status") != 200
        or metadata.get("tls_verified") is not True
        or metadata.get("tls_policy") != "python-default-ca"
    ):
        raise EvidenceError("Cloudflare raw capture metadata is invalid")
    fetched_at = metadata.get("fetched_at")
    if not isinstance(fetched_at, str):
        raise EvidenceError("Cloudflare raw capture time is invalid")
    try:
        _deployment_time(fetched_at, label="API fetched_at")
    except EvidenceError as exc:
        raise EvidenceError("Cloudflare raw capture time is invalid") from exc
    headers = metadata.get("headers")
    if not isinstance(headers, dict):
        raise EvidenceError("Cloudflare raw capture headers are invalid")
    for raw_name, raw_value in headers.items():
        name = str(raw_name).strip().lower()
        value = str(raw_value)
        if name not in _SELECTED_HEADERS or "\r" in value or "\n" in value:
            raise EvidenceError("Cloudflare raw capture header is invalid")
        if len(value.encode("utf-8")) > MAX_HEADER_VALUE_BYTES:
            raise EvidenceError("Cloudflare raw capture header exceeds size limit")
    if not str(headers.get("content-type", "")).lower().startswith("application/json"):
        raise EvidenceError("Cloudflare raw capture content type is invalid")
    if metadata.get("body_sha256") != _sha256_bytes(capture.body) or metadata.get(
        "body_size_bytes"
    ) != len(capture.body):
        raise EvidenceError("Cloudflare raw capture body binding is invalid")
    try:
        envelope = json.loads(capture.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("Cloudflare raw capture body is invalid JSON") from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("success") is not True
        or not isinstance(envelope.get("result"), dict)
        or _contains_sensitive_key(envelope)
    ):
        raise EvidenceError("Cloudflare raw capture envelope is invalid")
    return envelope["result"]


def _rederive_cloudflare_evidence(
    *,
    account_id: str,
    deployment_id: str,
    deployment_capture: HttpCapture,
    project_capture: HttpCapture,
) -> dict[str, Any]:
    """Recompute the complete derived document from the archived raw bodies."""

    deployment_url = _cloudflare_deployment_url(account_id, deployment_id)
    project_url = _cloudflare_project_url(account_id)
    result = _validate_cloudflare_capture(
        deployment_url,
        deployment_capture,
        resource="pages-deployment",
    )
    project = _validate_cloudflare_capture(
        project_url,
        project_capture,
        resource="pages-project",
    )
    latest_stage = result.get("latest_stage")
    trigger = result.get("deployment_trigger")
    trigger_metadata = trigger.get("metadata") if isinstance(trigger, dict) else None
    canonical = project.get("canonical_deployment")
    canonical_trigger = (
        canonical.get("deployment_trigger") if isinstance(canonical, dict) else None
    )
    canonical_metadata = (
        canonical_trigger.get("metadata")
        if isinstance(canonical_trigger, dict)
        else None
    )
    canonical_stage = (
        canonical.get("latest_stage") if isinstance(canonical, dict) else None
    )
    if not all(
        isinstance(value, dict)
        for value in (
            latest_stage,
            trigger,
            trigger_metadata,
            canonical,
            canonical_metadata,
            canonical_stage,
        )
    ):
        raise EvidenceError("Cloudflare raw provenance is incomplete")
    result_id = _validated_deployment_id(
        _safe_api_string(result.get("id"), label="id", maximum=64),
        label="Cloudflare deployment id",
    )
    if result_id != deployment_id:
        raise EvidenceError("Cloudflare raw deployment id does not match")
    project_name = _safe_api_string(
        result.get("project_name"), label="project_name", maximum=128
    )
    environment = _safe_api_string(
        result.get("environment"), label="environment", maximum=32
    )
    stage_status = _safe_api_string(
        latest_stage.get("status"), label="latest_stage.status", maximum=32
    )
    commit_hash = _validated_commit(
        _safe_api_string(
            trigger_metadata.get("commit_hash"), label="commit_hash", maximum=64
        ),
        label="Cloudflare deployment commit",
    )
    branch = _safe_api_string(
        trigger_metadata.get("branch"),
        label="deployment_trigger.metadata.branch",
        maximum=256,
    )
    if (
        project_name != CLOUDFLARE_PROJECT
        or environment != "production"
        or stage_status != "success"
        or result.get("is_skipped") is True
        or trigger_metadata.get("commit_dirty") is not False
        or branch != "main"
    ):
        raise EvidenceError("Cloudflare raw deployment provenance is invalid")
    if project.get("name") != CLOUDFLARE_PROJECT:
        raise EvidenceError("Cloudflare raw project name is invalid")
    canonical_hostname = _safe_api_string(
        project.get("subdomain"), label="project.subdomain", maximum=256
    ).lower()
    if canonical_hostname != urllib.parse.urlsplit(PRODUCTION_ORIGIN).hostname:
        raise EvidenceError("Cloudflare raw canonical hostname is invalid")
    canonical_id = _validated_deployment_id(
        _safe_api_string(
            canonical.get("id"), label="canonical_deployment.id", maximum=64
        ),
        label="Cloudflare canonical deployment id",
    )
    canonical_commit = _validated_commit(
        _safe_api_string(
            canonical_metadata.get("commit_hash"),
            label="canonical_deployment.commit_hash",
            maximum=64,
        ),
        label="Cloudflare canonical deployment commit",
    )
    if (
        canonical.get("environment") != "production"
        or canonical_stage.get("status") != "success"
        or canonical.get("is_skipped") is True
        or canonical_metadata.get("branch") != "main"
        or canonical_metadata.get("commit_dirty") is not False
    ):
        raise EvidenceError("Cloudflare raw canonical deployment is invalid")
    return {
        "schema_version": 1,
        "document_type": "cloudflare-pages-deployment-evidence",
        "attestation_level": "CLOUDFLARE_API_VERIFIED",
        "provider": "cloudflare-pages",
        "account_id": account_id,
        "project_name": project_name,
        "deployment_id": result_id,
        "short_id": str(result.get("short_id", ""))[:64],
        "environment": environment,
        "url": _normalized_pages_url(result.get("url")),
        "created_on": _safe_api_string(
            result.get("created_on"), label="created_on", maximum=64
        ),
        "modified_on": _safe_api_string(
            result.get("modified_on"), label="modified_on", maximum=64
        ),
        "is_skipped": bool(result.get("is_skipped", False)),
        "source_commit": commit_hash,
        "trigger": {
            "type": str(trigger.get("type", ""))[:64],
            "branch": branch,
            "commit_dirty": False,
        },
        "latest_stage": {
            "name": str(latest_stage.get("name", ""))[:64],
            "status": stage_status,
            "started_on": str(latest_stage.get("started_on", ""))[:64],
            "ended_on": str(latest_stage.get("ended_on", ""))[:64],
        },
        "api_request": deployment_capture.metadata,
        "production_alias": {
            "api_verified": True,
            "canonical_url": PRODUCTION_ORIGIN,
            "deployment_id": canonical_id,
            "deployment_url": _normalized_pages_url(canonical.get("url")),
            "source_commit": canonical_commit,
            "api_request": project_capture.metadata,
        },
    }


def _validate_production_deployment_binding(
    documents: dict[str, dict[str, Any]],
    deployment_evidence: dict[str, Any],
    *,
    deployment_id: str,
    source_commit: str,
) -> None:
    """Bind canonical responses to the exact direct Pages deployment."""

    production_alias = deployment_evidence.get("production_alias")
    if not isinstance(production_alias, dict):
        raise EvidenceError("Production alias binding is missing")
    expected_direct_url = production_alias.get("deployment_url")
    if (
        production_alias.get("deployment_id") != deployment_id
        or production_alias.get("source_commit") != source_commit
        or expected_direct_url != deployment_evidence.get("url")
    ):
        raise EvidenceError("Production alias is not the selected deployment")
    for endpoint_name in ("health", "snapshot"):
        document = documents.get(endpoint_name)
        deployment = document.get("deployment") if isinstance(document, dict) else None
        if not isinstance(deployment, dict):
            raise EvidenceError(
                f"Production {endpoint_name} response has no deployment attribution"
            )
        if (
            deployment.get("attribution") != "BUILD_BOUND"
            or deployment.get("provider") != "cloudflare-pages"
            or deployment.get("project") != CLOUDFLARE_PROJECT
            or deployment.get("environment") != "production"
            or deployment.get("source_commit") != source_commit
            or deployment.get("branch") != "main"
            or deployment.get("url") != PRODUCTION_ORIGIN
            or deployment.get("deployment_url") != expected_direct_url
        ):
            raise EvidenceError(
                f"Production {endpoint_name} response is not bound to the selected deployment"
            )


def _artifact_filename_inventory(
    artifact_values: list[tuple[str, str, bytes]],
) -> set[str]:
    filenames = [filename for _, filename, _ in artifact_values]
    expected = set(_REQUIRED_ARTIFACT_FILES.values())
    if len(filenames) != len(expected) or set(filenames) != expected:
        raise EvidenceError("Release evidence artifact filename inventory is invalid")
    for filename in filenames:
        _validated_archive_filename(filename)
    return expected


def _store_release_bundle(
    workspace: Workspace,
    *,
    destination_relative: Path,
    artifact_values: list[tuple[str, str, bytes]],
    bundle_bytes: bytes,
) -> None:
    """Store one content-addressed bundle through held no-follow descriptors."""

    destination = validate_archive_relative_path(destination_relative)
    if not destination.parts or destination.parts[0] != "archive":
        raise EvidenceError("Release evidence destination must be below archive")
    artifact_names = _artifact_filename_inventory(artifact_values)
    expected_names = {"bundle.json", *artifact_names}

    if not _secure_archive_primitives_available():
        raise EvidenceError(
            "Release evidence archive requires descriptor-relative no-follow "
            "directory primitives; this platform is fail-closed"
        )
    secure_relative = PurePosixPath(destination.as_posix())
    with _secure_archive_directory_fd(
        workspace.root,
        secure_relative,
        create=True,
    ) as directory_descriptor:
        if os.listdir(directory_descriptor):
            raise EvidenceError("Immutable release evidence destination is not empty")
        for _, filename, value in artifact_values:
            _write_exclusive_at(directory_descriptor, filename, value)
        _write_exclusive_at(directory_descriptor, "bundle.json", bundle_bytes)
        os.fsync(directory_descriptor)
        if set(os.listdir(directory_descriptor)) != expected_names:
            raise EvidenceError("Release evidence archive inventory is not exact")


def _load_recovery_archive_files(
    workspace: Workspace,
    *,
    attempt_relative: Path,
) -> tuple[str, dict[str, bytes]] | None:
    """Load one orphan bundle while holding every production directory handle."""

    attempt = validate_archive_relative_path(attempt_relative)
    expected_names = {"bundle.json", *_REQUIRED_ARTIFACT_FILES.values()}
    if not _secure_archive_primitives_available():
        raise EvidenceError(
            "Release evidence archive requires descriptor-relative no-follow "
            "directory primitives; this platform is fail-closed"
        )
    secure_attempt = PurePosixPath((Path("archive") / attempt).as_posix())
    # This is only a missing-directory hint. Every trusted read below is made
    # through the held no-follow descriptor chain, so a positive result grants
    # no authority and a later exchange fails closed.
    try:
        (workspace.root / Path(secure_attempt.as_posix())).lstat()
    except FileNotFoundError:
        return None
    with _secure_archive_directory_fd(
        workspace.root,
        secure_attempt,
        create=False,
    ) as attempt_descriptor:
        children = os.listdir(attempt_descriptor)
        if len(children) != 1 or not _BUNDLE_SHA_RE.fullmatch(children[0]):
            raise EvidenceError(
                "Release evidence recovery requires exactly one valid bundle"
            )
        bundle_name = children[0]
        bundle_descriptor = _open_archive_directory_at(
            attempt_descriptor,
            bundle_name,
        )
        try:
            if set(os.listdir(bundle_descriptor)) != expected_names:
                raise EvidenceError(
                    "Release evidence recovery directory has extra or missing files"
                )
            values = {
                filename: _read_archive_file_at(
                    bundle_descriptor,
                    filename,
                    maximum=MAX_RESPONSE_BYTES,
                )
                for filename in expected_names
            }
            if set(os.listdir(bundle_descriptor)) != expected_names:
                raise EvidenceError(
                    "Release evidence recovery directory changed during read"
                )
        finally:
            os.close(bundle_descriptor)
        if os.listdir(attempt_descriptor) != [bundle_name]:
            raise EvidenceError(
                "Release evidence recovery attempt directory changed during read"
            )
        return bundle_name, values


def _json_object(value: bytes, *, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"Recoverable {label} is invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise EvidenceError(f"Recoverable {label} must be a JSON object")
    return decoded


def _validate_cloudflare_receipt_metadata(
    receipt: Any,
    *,
    endpoint_url: str,
    resource: str,
    label: str,
) -> None:
    """Validate the public receipt fields copied from one raw API capture."""

    if not isinstance(receipt, dict):
        raise EvidenceError(f"Cloudflare {label} API receipt is invalid")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("document_type") != "cogni-cloudflare-http-capture"
        or receipt.get("method") != "GET"
        or receipt.get("resource") != resource
        or receipt.get("request_url") != endpoint_url
        or receipt.get("final_url") != endpoint_url
        or receipt.get("status") != 200
        or receipt.get("tls_verified") is not True
        or receipt.get("tls_policy") != "python-default-ca"
        or not isinstance(receipt.get("body_sha256"), str)
        or not _BUNDLE_SHA_RE.fullmatch(receipt["body_sha256"])
        or not isinstance(receipt.get("body_size_bytes"), int)
        or isinstance(receipt.get("body_size_bytes"), bool)
        or receipt["body_size_bytes"] <= 0
        or receipt["body_size_bytes"] > MAX_RESPONSE_BYTES
    ):
        raise EvidenceError(f"Cloudflare {label} API receipt is invalid")
    fetched_at = receipt.get("fetched_at")
    if not isinstance(fetched_at, str):
        raise EvidenceError(f"Cloudflare {label} API receipt is invalid")
    try:
        _deployment_time(fetched_at, label="API fetched_at")
    except EvidenceError as exc:
        raise EvidenceError(f"Cloudflare {label} API receipt is invalid") from exc
    headers = receipt.get("headers")
    if not isinstance(headers, dict):
        raise EvidenceError(f"Cloudflare {label} API receipt is invalid")
    for raw_name, raw_value in headers.items():
        name = str(raw_name).strip().lower()
        value = str(raw_value)
        if (
            name not in _SELECTED_HEADERS
            or "\r" in value
            or "\n" in value
            or len(value.encode("utf-8")) > MAX_HEADER_VALUE_BYTES
        ):
            raise EvidenceError(f"Cloudflare {label} API receipt is invalid")
    if not str(headers.get("content-type", "")).lower().startswith("application/json"):
        raise EvidenceError(f"Cloudflare {label} API receipt is invalid")


def _validate_deployment_evidence(
    evidence: dict[str, Any],
    *,
    account_id: str,
    deployment_id: str,
    source_commit: str,
    require_current_alias: bool = False,
) -> None:
    if (
        evidence.get("schema_version") != 1
        or evidence.get("document_type") != "cloudflare-pages-deployment-evidence"
        or evidence.get("provider") != "cloudflare-pages"
        or evidence.get("attestation_level") != "CLOUDFLARE_API_VERIFIED"
    ):
        raise EvidenceError("Cloudflare deployment evidence is not API verified")
    if evidence.get("account_id") != account_id:
        raise EvidenceError("Cloudflare deployment account does not match")
    if evidence.get("project_name") != CLOUDFLARE_PROJECT:
        raise EvidenceError("Cloudflare deployment project does not match")
    if evidence.get("environment") != "production":
        raise EvidenceError("Cloudflare deployment environment does not match")
    if evidence.get("deployment_id") != deployment_id:
        raise EvidenceError("Cloudflare deployment id does not match")
    if evidence.get("source_commit") != source_commit:
        raise EvidenceError("Cloudflare deployment commit does not match")
    if evidence.get("is_skipped") is not False:
        raise EvidenceError("Cloudflare deployment was skipped or is unmeasured")
    _normalized_pages_url(evidence.get("url"))
    _deployment_time(evidence.get("created_on"), label="created_on")
    latest_stage = evidence.get("latest_stage")
    if not isinstance(latest_stage, dict) or latest_stage.get("status") != "success":
        raise EvidenceError("Cloudflare deployment is not successful")
    trigger = evidence.get("trigger")
    if (
        not isinstance(trigger, dict)
        or trigger.get("branch") != "main"
        or trigger.get("commit_dirty") is not False
    ):
        raise EvidenceError("Cloudflare deployment trigger provenance is invalid")
    api_request = evidence.get("api_request")
    _validate_cloudflare_receipt_metadata(
        api_request,
        endpoint_url=_cloudflare_deployment_url(account_id, deployment_id),
        resource="pages-deployment",
        label="deployment",
    )
    production_alias = evidence.get("production_alias")
    if not isinstance(production_alias, dict):
        raise EvidenceError("Cloudflare production alias evidence is missing")
    alias_receipt = production_alias.get("api_request")
    if (
        production_alias.get("api_verified") is not True
        or production_alias.get("canonical_url") != PRODUCTION_ORIGIN
    ):
        raise EvidenceError("Cloudflare production alias API receipt is invalid")
    _validate_cloudflare_receipt_metadata(
        alias_receipt,
        endpoint_url=_cloudflare_project_url(account_id),
        resource="pages-project",
        label="production alias",
    )
    alias_deployment_id = _validated_deployment_id(
        str(production_alias.get("deployment_id", "")),
        label="Cloudflare production alias deployment id",
    )
    alias_deployment_url = _normalized_pages_url(production_alias.get("deployment_url"))
    alias_source_commit = _validated_commit(
        str(production_alias.get("source_commit", "")),
        label="Cloudflare production alias commit",
    )
    if require_current_alias and (
        alias_deployment_id != deployment_id
        or alias_deployment_url != evidence.get("url")
        or alias_source_commit != source_commit
    ):
        raise EvidenceError(
            "Cloudflare canonical production alias is not serving the selected deployment"
        )


def _recover_complete_bundle(
    workspace: Workspace,
    *,
    producer: dict[str, Any],
    source_commit: str,
    task_attempt: int,
    account_id: str,
    deployment_id: str,
    rollback_deployment_id: str,
    rollback_source_commit: str,
) -> tuple[str, list[dict[str, Any]], dict[str, Any]] | None:
    attempt_relative = (
        Path("release-evidence") / P01_TASK_ID / f"attempt-{task_attempt}"
    )
    loaded_archive = _load_recovery_archive_files(
        workspace,
        attempt_relative=attempt_relative,
    )
    if loaded_archive is None:
        return None
    archive_bundle_name, archive_files = loaded_archive
    bundle_bytes = archive_files["bundle.json"]
    bundle_sha256 = _sha256_bytes(bundle_bytes)
    if bundle_sha256 != archive_bundle_name:
        raise EvidenceError("Release evidence recovery bundle hash mismatch")
    bundle = _json_object(bundle_bytes, label="release evidence bundle")
    if (
        bundle.get("schema_version") != 1
        or bundle.get("kind") != "production-release-evidence"
        or bundle.get("task_id") != P01_TASK_ID
        or bundle.get("task_attempt") != task_attempt
        or bundle.get("source_commit") != source_commit
        or bundle.get("producer") != producer
        or bundle.get("deployment_attestation") != "CLOUDFLARE_API_VERIFIED"
        or bundle.get("rollback_mutation_performed") is not False
    ):
        raise EvidenceError("Release evidence recovery bundle provenance mismatch")
    capability_receipt = _validated_collection_capability_receipt(
        bundle.get("actor_capability"),
        workspace=workspace,
        actor=str(producer.get("actor", "")),
        task_attempt=task_attempt,
    )

    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(
        _REQUIRED_ARTIFACT_FILES
    ):
        raise EvidenceError("Release evidence recovery artifact inventory is invalid")
    artifact_by_kind: dict[str, dict[str, Any]] = {}
    artifact_values: dict[str, bytes] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise EvidenceError("Release evidence recovery artifact is invalid")
        kind = artifact.get("kind")
        if not isinstance(kind, str) or kind in artifact_by_kind:
            raise EvidenceError("Release evidence recovery artifact kind is invalid")
        expected_filename = _REQUIRED_ARTIFACT_FILES.get(kind)
        if artifact.get("filename") != expected_filename:
            raise EvidenceError(
                "Release evidence recovery artifact filename is invalid"
            )
        sha256 = artifact.get("sha256")
        size_bytes = artifact.get("size_bytes")
        if (
            not isinstance(sha256, str)
            or not _BUNDLE_SHA_RE.fullmatch(sha256)
            or not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or size_bytes < 0
            or size_bytes > MAX_RESPONSE_BYTES
        ):
            raise EvidenceError("Release evidence recovery artifact digest is invalid")
        value = archive_files[expected_filename]
        if len(value) != size_bytes or _sha256_bytes(value) != sha256:
            raise EvidenceError("Release evidence recovery artifact hash mismatch")
        artifact_by_kind[kind] = artifact
        artifact_values[kind] = value
    if set(artifact_by_kind) != set(_REQUIRED_ARTIFACT_FILES):
        raise EvidenceError("Release evidence recovery artifact set is incomplete")
    replay_results = bundle.get("replay_results")
    if not isinstance(replay_results, list) or len(replay_results) != 2:
        raise EvidenceError("Release evidence recovery replay inventory is invalid")
    replay_by_endpoint = {
        replay.get("endpoint"): replay
        for replay in replay_results
        if isinstance(replay, dict)
    }
    production_documents: dict[str, dict[str, Any]] = {}
    for endpoint_name, endpoint_url in PRODUCTION_ENDPOINTS:
        body = artifact_values[f"production-{endpoint_name}-body"]
        capture_document = _json_object(
            artifact_values[f"production-{endpoint_name}-capture"],
            label=f"{endpoint_name} capture",
        )
        production_documents[endpoint_name] = _validate_capture(
            endpoint_url,
            HttpCapture(body=body, metadata=capture_document),
        )
        replay = replay_by_endpoint.get(endpoint_name)
        if not isinstance(replay, dict) or replay != {
            "endpoint": endpoint_name,
            "url": endpoint_url,
            "status": capture_document["status"],
            "body_sha256": capture_document["body_sha256"],
            "body_size_bytes": capture_document["body_size_bytes"],
        }:
            raise EvidenceError("Release evidence recovery replay result mismatch")

    current_evidence = _json_object(
        artifact_values["cloudflare-deployment-evidence"],
        label="Cloudflare deployment evidence",
    )
    rollback_evidence = _json_object(
        artifact_values["cloudflare-rollback-target-evidence"],
        label="Cloudflare rollback target evidence",
    )
    current_raw = CloudflareDeploymentCapture(
        evidence=current_evidence,
        deployment=HttpCapture(
            body=artifact_values["cloudflare-current-deployment-body"],
            metadata=_json_object(
                artifact_values["cloudflare-current-deployment-capture"],
                label="Cloudflare current deployment capture",
            ),
        ),
        project=HttpCapture(
            body=artifact_values["cloudflare-current-project-body"],
            metadata=_json_object(
                artifact_values["cloudflare-current-project-capture"],
                label="Cloudflare current project capture",
            ),
        ),
    )
    rollback_raw = CloudflareDeploymentCapture(
        evidence=rollback_evidence,
        deployment=HttpCapture(
            body=artifact_values["cloudflare-rollback-deployment-body"],
            metadata=_json_object(
                artifact_values["cloudflare-rollback-deployment-capture"],
                label="Cloudflare rollback deployment capture",
            ),
        ),
        project=HttpCapture(
            body=artifact_values["cloudflare-rollback-project-body"],
            metadata=_json_object(
                artifact_values["cloudflare-rollback-project-capture"],
                label="Cloudflare rollback project capture",
            ),
        ),
    )
    for expected_id, capture in (
        (deployment_id, current_raw),
        (rollback_deployment_id, rollback_raw),
    ):
        if capture.evidence != _rederive_cloudflare_evidence(
            account_id=account_id,
            deployment_id=expected_id,
            deployment_capture=capture.deployment,
            project_capture=capture.project,
        ):
            raise EvidenceError(
                "Release evidence recovery raw Cloudflare binding mismatch"
            )
    _validate_deployment_evidence(
        current_evidence,
        account_id=account_id,
        deployment_id=deployment_id,
        source_commit=source_commit,
        require_current_alias=True,
    )
    _validate_deployment_evidence(
        rollback_evidence,
        account_id=account_id,
        deployment_id=rollback_deployment_id,
        source_commit=rollback_source_commit,
    )
    _validate_production_deployment_binding(
        production_documents,
        current_evidence,
        deployment_id=deployment_id,
        source_commit=source_commit,
    )
    if _deployment_time(
        rollback_evidence.get("created_on"),
        label="rollback created_on",
    ) >= _deployment_time(
        current_evidence.get("created_on"),
        label="current created_on",
    ):
        raise EvidenceError("Recoverable rollback deployment is not prior")
    rollback_receipt = _json_object(
        artifact_values["cloudflare-rollback-dry-run-receipt"],
        label="Cloudflare rollback dry-run receipt",
    )
    if (
        rollback_receipt.get("attestation_level") != "CLOUDFLARE_API_VERIFIED"
        or rollback_receipt.get("mutation_performed") is not False
        or rollback_receipt.get("account_id") != account_id
        or rollback_receipt.get("project_name") != CLOUDFLARE_PROJECT
        or rollback_receipt.get("current_deployment_id") != deployment_id
        or rollback_receipt.get("current_source_commit") != source_commit
        or rollback_receipt.get("target_deployment_id") != rollback_deployment_id
        or rollback_receipt.get("target_source_commit") != rollback_source_commit
    ):
        raise EvidenceError("Release evidence recovery rollback receipt mismatch")
    return bundle_sha256, artifacts, capability_receipt


def _validated_collection_capability_receipt(
    value: Any,
    *,
    workspace: Workspace,
    actor: str,
    task_attempt: int,
) -> dict[str, Any]:
    """Validate the audit binding emitted by the external capability check.

    The receipt is evidence that the collector passed the one-time capability
    boundary; it is not itself accepted as a reusable authorization token.
    Release evidence is fail-closed unless the receipt is bound to this
    workspace, conductor and operation and records an attested OS boundary.
    """

    try:
        return authority_for_workspace(workspace).validate_receipt(
            value,
            expected_actor=actor,
            expected_operation="release.evidence.collect",
            expected_task_id=P01_TASK_ID,
            expected_run_id=None,
            expected_task_attempt=task_attempt,
            require_independent_trust_root=True,
        )
    except (
        AuthorizationError,
        ConfigurationError,
        IntegrityError,
        OSError,
        ValueError,
    ) as exc:
        raise EvidenceError(
            "Release evidence actor capability receipt is not independently trusted"
        ) from exc


def _collection_payload(
    *,
    producer: dict[str, Any],
    actor_capability: dict[str, Any],
    source_commit: str,
    task_attempt: int,
    destination_relative: Path,
    bundle_sha256: str,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "producer": producer,
        "actor_capability": actor_capability,
        "source_commit": source_commit,
        "task_attempt": task_attempt,
        "collection": {
            "kind": "production-release-evidence",
            "bundle_path": (destination_relative / "bundle.json").as_posix(),
            "bundle_sha256": bundle_sha256,
            "artifacts": [
                {
                    "kind": artifact["kind"],
                    "archive_path": (
                        destination_relative / artifact["filename"]
                    ).as_posix(),
                    "sha256": artifact["sha256"],
                    "size_bytes": artifact["size_bytes"],
                }
                for artifact in artifacts
            ],
        },
    }


def _collection_result(
    event: dict[str, Any],
    payload: dict[str, Any],
    *,
    recovered: bool,
) -> dict[str, Any]:
    return {
        "event_sequence": event["sequence"],
        "event_hash": event["event_hash"],
        "task_id": P01_TASK_ID,
        "task_attempt": payload["task_attempt"],
        "source_commit": payload["source_commit"],
        "recovered_complete_archive": recovered,
        "collection": payload["collection"],
    }


def _already_collected(
    workspace: Workspace,
    *,
    source_commit: str,
    task_attempt: int,
) -> bool:
    for event in workspace.ledger.read():
        payload = event.get("payload", {})
        if (
            event.get("action") == "release.evidence_collected"
            and event.get("task_id") == P01_TASK_ID
            and payload.get("source_commit") == source_commit
            and payload.get("task_attempt") == task_attempt
        ):
            return True
    return False


def _collection_authority_snapshot(
    workspace: Workspace,
    actor: str,
) -> dict[str, Any]:
    """Read the exact authority and task state that a collection is bound to."""

    if actor != workspace.orchestrator:
        raise AuthorizationError(
            "Only the accountable workspace orchestrator can collect release evidence"
        )
    agent = workspace.get_agent(actor)
    if agent.get("id") != actor or agent.get("role") != "orchestrator":
        raise AuthorizationError(
            "Release evidence collector must be the registered orchestrator"
        )
    producer_identity = identity_snapshot(actor, agent.get("identity"))
    if producer_identity is None:
        raise AuthorizationError("Release evidence collector identity is missing")
    task = workspace.get_task(P01_TASK_ID)
    state = task.get("state")
    if state not in {"running", "submitted"}:
        raise StateError("P01 release evidence requires a running or submitted task")
    attempt = task.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise StateError("P01 release evidence requires a positive task attempt")
    return {
        "orchestrator": workspace.orchestrator,
        "producer": {**producer_identity, "role": "orchestrator"},
        "task_state": state,
        "task_attempt": attempt,
    }


def _collect_p01_production_evidence_core(
    workspace: Workspace,
    *,
    actor: str,
    cloudflare_account_id: str,
    deployment_id: str,
    deployment_source_commit: str,
    rollback_deployment_id: str,
    rollback_source_commit: str,
    capability_secret: str | bytes | None = None,
) -> dict[str, Any]:
    """Collect evidence through fixed transports and the secure archive policy."""
    # First consume and independently validate an unbound admission capability.
    # No task/Git/network/lock/ledger/archive read is permitted before this
    # authorization. A second receipt is minted below with the exact attempt.
    admission_receipt = workspace.authorize_actor_capability(
        actor=actor,
        operation="release.evidence.collect",
        capability_secret=capability_secret,
        require_actor_os_isolation=True,
        task_id=None,
        run_id=None,
        task_attempt=None,
    )
    authority_for_workspace(workspace).validate_receipt(
        admission_receipt,
        expected_actor=actor,
        expected_operation="release.evidence.collect",
        expected_task_id=None,
        expected_run_id=None,
        expected_task_attempt=None,
        require_independent_trust_root=True,
    )
    if not _secure_archive_primitives_available():
        raise EvidenceError(
            "Release evidence archive requires descriptor-relative no-follow "
            "directory primitives; this platform is fail-closed"
        )
    preliminary_authority = _collection_authority_snapshot(workspace, actor)
    preliminary_attempt = int(preliminary_authority["task_attempt"])
    capability_receipt = workspace.authorize_actor_capability(
        actor=actor,
        operation="release.evidence.collect",
        capability_secret=capability_secret,
        require_actor_os_isolation=True,
        task_id=P01_TASK_ID,
        run_id=None,
        task_attempt=preliminary_attempt,
    )
    capability_receipt = _validated_collection_capability_receipt(
        capability_receipt,
        workspace=workspace,
        actor=actor,
        task_attempt=preliminary_attempt,
    )
    declared_deployment_commit = _validated_commit(
        deployment_source_commit,
        label="deployment source commit",
    )
    rollback_commit = _validated_commit(
        rollback_source_commit,
        label="rollback source commit",
    )
    current_deployment = _validated_deployment_id(
        deployment_id,
        label="deployment id",
    )
    rollback_deployment = _validated_deployment_id(
        rollback_deployment_id,
        label="rollback deployment id",
    )
    if current_deployment == rollback_deployment:
        raise EvidenceError("Rollback deployment must differ from current deployment")
    normalized_account_id = cloudflare_account_id.strip().lower()
    if not _ACCOUNT_ID_RE.fullmatch(normalized_account_id):
        raise EvidenceError("Cloudflare account id must be 32 hexadecimal characters")

    lock = FileLock(workspace.control_dir / "locks" / "release-evidence.lock")
    with lock:
        workspace.ledger.verify()
        initial_authority = _collection_authority_snapshot(workspace, actor)
        if initial_authority != preliminary_authority:
            raise StateError("Release evidence authority changed before collection")
        producer = initial_authority["producer"]
        attempt = int(initial_authority["task_attempt"])
        source_commit = _git_source_commit(workspace.root)
        if declared_deployment_commit != source_commit:
            raise EvidenceError(
                "Deployment source commit does not match workspace HEAD"
            )
        if rollback_commit == source_commit:
            raise EvidenceError(
                "Rollback source commit must differ from current source"
            )
        if _already_collected(
            workspace,
            source_commit=source_commit,
            task_attempt=attempt,
        ):
            raise StateError("Release evidence is already bound for this P01 attempt")
        recovered_bundle = _recover_complete_bundle(
            workspace,
            producer=producer,
            source_commit=source_commit,
            task_attempt=attempt,
            account_id=normalized_account_id,
            deployment_id=current_deployment,
            rollback_deployment_id=rollback_deployment,
            rollback_source_commit=rollback_commit,
        )
        if recovered_bundle is not None:
            (
                recovered_sha256,
                recovered_artifacts,
                recovered_capability_receipt,
            ) = recovered_bundle
            recovered_destination = (
                ARCHIVE_PREFIX / f"attempt-{attempt}" / recovered_sha256
            )
            recovered_payload = _collection_payload(
                producer=producer,
                actor_capability=recovered_capability_receipt,
                source_commit=source_commit,
                task_attempt=attempt,
                destination_relative=recovered_destination,
                bundle_sha256=recovered_sha256,
                artifacts=recovered_artifacts,
            )
            recovered_event = workspace.ledger.append(
                actor=workspace.orchestrator,
                action="release.evidence_collected",
                task_id=P01_TASK_ID,
                payload=recovered_payload,
            )
            return _collection_result(
                recovered_event,
                recovered_payload,
                recovered=True,
            )

    captures: dict[str, HttpCapture] = {}
    production_documents: dict[str, dict[str, Any]] = {}
    for endpoint_name, endpoint_url in PRODUCTION_ENDPOINTS:
        capture = fetch_production_json(endpoint_url)
        if not isinstance(capture, HttpCapture):
            raise EvidenceError(
                "Release evidence transport returned an invalid capture"
            )
        production_documents[endpoint_name] = _validate_capture(endpoint_url, capture)
        captures[endpoint_name] = capture

    api_token = os.environ.get(CLOUDFLARE_ACCOUNT_TOKEN_ENV, "")
    if not api_token.strip():
        raise EvidenceError(
            f"Missing {CLOUDFLARE_ACCOUNT_TOKEN_ENV} environment secret"
        )
    current_cloudflare_capture = _capture_cloudflare_deployment(
        normalized_account_id,
        current_deployment,
        api_token=api_token,
    )
    rollback_cloudflare_capture = _capture_cloudflare_deployment(
        normalized_account_id,
        rollback_deployment,
        api_token=api_token,
    )
    for capture in (current_cloudflare_capture, rollback_cloudflare_capture):
        if not isinstance(capture, CloudflareDeploymentCapture):
            raise EvidenceError(
                "Cloudflare deployment transport returned an invalid capture"
            )
    current_deployment_evidence = current_cloudflare_capture.evidence
    rollback_deployment_evidence = rollback_cloudflare_capture.evidence
    for expected_id, capture in (
        (current_deployment, current_cloudflare_capture),
        (rollback_deployment, rollback_cloudflare_capture),
    ):
        independently_derived = _rederive_cloudflare_evidence(
            account_id=normalized_account_id,
            deployment_id=expected_id,
            deployment_capture=capture.deployment,
            project_capture=capture.project,
        )
        if capture.evidence != independently_derived:
            raise EvidenceError(
                "Cloudflare derived evidence does not match archived raw responses"
            )
    for expected_id, expected_commit, evidence, require_current_alias in (
        (current_deployment, source_commit, current_deployment_evidence, True),
        (rollback_deployment, rollback_commit, rollback_deployment_evidence, False),
    ):
        if not isinstance(evidence, dict):
            raise EvidenceError(
                "Cloudflare deployment transport returned invalid evidence"
            )
        _validate_deployment_evidence(
            evidence,
            account_id=normalized_account_id,
            deployment_id=expected_id,
            source_commit=expected_commit,
            require_current_alias=require_current_alias,
        )
    _validate_production_deployment_binding(
        production_documents,
        current_deployment_evidence,
        deployment_id=current_deployment,
        source_commit=source_commit,
    )
    current_created = _deployment_time(
        current_deployment_evidence.get("created_on"),
        label="current created_on",
    )
    rollback_created = _deployment_time(
        rollback_deployment_evidence.get("created_on"),
        label="rollback created_on",
    )
    if rollback_created >= current_created:
        raise EvidenceError("Rollback deployment is not prior to current deployment")

    collected_at = utc_now()
    rollback_receipt = {
        "schema_version": 1,
        "document_type": "cloudflare-pages-rollback-dry-run-receipt",
        "attestation_level": "CLOUDFLARE_API_VERIFIED",
        "validated_at": collected_at,
        "validated_by": actor,
        "provider": "cloudflare-pages",
        "project_name": CLOUDFLARE_PROJECT,
        "account_id": normalized_account_id,
        "operation": "rollback-plan-validation",
        "mutation_performed": False,
        "current_deployment_id": current_deployment,
        "current_source_commit": source_commit,
        "target_deployment_id": rollback_deployment,
        "target_source_commit": rollback_commit,
        "checks": {
            "current_deployment_api_verified": True,
            "target_deployment_api_verified": True,
            "target_is_prior_distinct_deployment": True,
            "target_is_successful_production": True,
            "commits_are_distinct": True,
        },
    }

    artifact_values: list[tuple[str, str, bytes]] = []
    for endpoint_name, _ in PRODUCTION_ENDPOINTS:
        capture = captures[endpoint_name]
        body_filename = f"production_{endpoint_name}.body.json"
        metadata_filename = f"production_{endpoint_name}.capture.json"
        capture_metadata = {**capture.metadata, "body_file": body_filename}
        artifact_values.extend(
            [
                (f"production-{endpoint_name}-body", body_filename, capture.body),
                (
                    f"production-{endpoint_name}-capture",
                    metadata_filename,
                    _json_bytes(capture_metadata),
                ),
            ]
        )
    for deployment_label, cloudflare_capture in (
        ("current", current_cloudflare_capture),
        ("rollback", rollback_cloudflare_capture),
    ):
        for resource_label, http_capture in (
            ("deployment", cloudflare_capture.deployment),
            ("project", cloudflare_capture.project),
        ):
            body_filename = f"cloudflare_{deployment_label}_{resource_label}.body.json"
            metadata_filename = (
                f"cloudflare_{deployment_label}_{resource_label}.capture.json"
            )
            artifact_values.extend(
                [
                    (
                        f"cloudflare-{deployment_label}-{resource_label}-body",
                        body_filename,
                        http_capture.body,
                    ),
                    (
                        f"cloudflare-{deployment_label}-{resource_label}-capture",
                        metadata_filename,
                        _json_bytes(http_capture.metadata),
                    ),
                ]
            )
    artifact_values.extend(
        [
            (
                "cloudflare-deployment-evidence",
                "cloudflare_deployment.json",
                _json_bytes(current_deployment_evidence),
            ),
            (
                "cloudflare-rollback-target-evidence",
                "cloudflare_rollback_target.json",
                _json_bytes(rollback_deployment_evidence),
            ),
            (
                "cloudflare-rollback-dry-run-receipt",
                "cloudflare_rollback_dry_run.json",
                _json_bytes(rollback_receipt),
            ),
        ]
    )
    artifacts = [
        _artifact(kind, filename, value) for kind, filename, value in artifact_values
    ]
    bundle_document = {
        "schema_version": 1,
        "kind": "production-release-evidence",
        "task_id": P01_TASK_ID,
        "task_attempt": attempt,
        "producer": producer,
        "actor_capability": capability_receipt,
        "source_commit": source_commit,
        "collected_at": collected_at,
        "replay_results": [
            {
                "endpoint": endpoint_name,
                "url": captures[endpoint_name].metadata["request_url"],
                "status": captures[endpoint_name].metadata["status"],
                "body_sha256": captures[endpoint_name].metadata["body_sha256"],
                "body_size_bytes": captures[endpoint_name].metadata["body_size_bytes"],
            }
            for endpoint_name, _ in PRODUCTION_ENDPOINTS
        ],
        "deployment_attestation": "CLOUDFLARE_API_VERIFIED",
        "rollback_mutation_performed": False,
        "artifacts": artifacts,
    }
    bundle_bytes = _json_bytes(bundle_document)
    bundle_sha256 = _sha256_bytes(bundle_bytes)
    attempt_path = ARCHIVE_PREFIX / f"attempt-{attempt}"
    destination_relative = attempt_path / bundle_sha256

    with lock:
        workspace.ledger.verify()
        if _collection_authority_snapshot(workspace, actor) != initial_authority:
            raise StateError(
                "Release evidence authority or P01 task state changed during collection"
            )
        if _git_source_commit(workspace.root) != source_commit:
            raise StateError(
                "Workspace HEAD changed during release evidence collection"
            )
        if _already_collected(
            workspace,
            source_commit=source_commit,
            task_attempt=attempt,
        ):
            raise StateError("Release evidence is already bound for this P01 attempt")
        _store_release_bundle(
            workspace,
            destination_relative=destination_relative,
            artifact_values=artifact_values,
            bundle_bytes=bundle_bytes,
        )

        payload = _collection_payload(
            producer=producer,
            actor_capability=capability_receipt,
            source_commit=source_commit,
            task_attempt=attempt,
            destination_relative=destination_relative,
            bundle_sha256=bundle_sha256,
            artifacts=artifacts,
        )
        event = workspace.ledger.append(
            actor=workspace.orchestrator,
            action="release.evidence_collected",
            task_id=P01_TASK_ID,
            payload=payload,
        )

    return _collection_result(event, payload, recovered=False)


def collect_p01_production_evidence(
    workspace: Workspace,
    *,
    actor: str,
    cloudflare_account_id: str,
    deployment_id: str,
    deployment_source_commit: str,
    rollback_deployment_id: str,
    rollback_source_commit: str,
    capability_secret: str | bytes | None = None,
) -> dict[str, Any]:
    """Production entrypoint with fixed network transports and archive policy."""

    return _collect_p01_production_evidence_core(
        workspace,
        actor=actor,
        cloudflare_account_id=cloudflare_account_id,
        deployment_id=deployment_id,
        deployment_source_commit=deployment_source_commit,
        rollback_deployment_id=rollback_deployment_id,
        rollback_source_commit=rollback_source_commit,
        capability_secret=capability_secret,
    )


__all__ = [
    "ARCHIVE_PREFIX",
    "CLOUDFLARE_ACCOUNT_TOKEN_ENV",
    "CLOUDFLARE_API_ORIGIN",
    "CLOUDFLARE_PROJECT",
    "HTTP_TIMEOUT_SECONDS",
    "MAX_RESPONSE_BYTES",
    "P01_TASK_ID",
    "PRODUCTION_ENDPOINTS",
    "PRODUCTION_ORIGIN",
    "HttpCapture",
    "collect_p01_production_evidence",
    "fetch_cloudflare_deployment",
    "fetch_production_json",
    "validate_archive_relative_path",
]
