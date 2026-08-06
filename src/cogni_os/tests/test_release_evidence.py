"""Tests for conductor-only immutable production release evidence."""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from cogni_os.errors import AuthorizationError, EvidenceError, StateError
from cogni_os.release_evidence import (
    CLOUDFLARE_PROJECT,
    MAX_RESPONSE_BYTES,
    PRODUCTION_ENDPOINTS,
    CloudflareDeploymentCapture,
    HttpCapture,
    _git_source_commit,
    _normalized_pages_url,
    _rederive_cloudflare_evidence,
    collect_p01_production_evidence,
    fetch_cloudflare_deployment,
    fetch_production_json,
    validate_archive_relative_path,
)
from cogni_os.tests._actor_capability_test_support import (
    install_legacy_capability_fixture,
)
from cogni_os.tests._release_evidence_test_support import (
    portable_load_recovery_archive_files,
    portable_store_release_bundle,
)
from cogni_os.workspace import Workspace

from cogni_os import release_evidence
from cogni_os.cli import build_parser

_DEFAULT_TRANSPORT = object()


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        url: str,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.body = body
        self.url = url
        self.status = status
        self.headers = headers or {"Content-Type": "application/json"}
        self.read_calls = 0
        self.closed = False

    def read(self, limit: int) -> bytes:
        self.read_calls += 1
        return self.body[:limit]

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return self.status

    def close(self) -> None:
        self.closed = True


class _FakeOpener:
    def __init__(self, response_factory):
        self.response_factory = response_factory
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append((request, timeout))
        return self.response_factory(request)


class TestReleaseEvidence(unittest.TestCase):
    def setUp(self) -> None:
        install_legacy_capability_fixture(self)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.workspace = Workspace.initialize(
            self.root,
            name="release evidence test",
            orchestrator="codex",
            preset="cogni-codex-antigravity",
        )
        self.workspace.add_task(
            actor="codex",
            task_id="P01-TRUTH",
            title="Release truth",
            description="Collect production release truth.",
            owner="antigravity",
        )
        claimed = self.workspace.claim(actor="antigravity", task_id="P01-TRUTH")
        self.workspace.start(
            actor="antigravity",
            task_id="P01-TRUTH",
            lease_token=claimed["lease_token"],
        )
        self._commit_fixture()
        self.account_id = "1" * 32
        self.deployment_id = "deployment-current"
        self.rollback_deployment_id = "deployment-previous"
        self.rollback_commit = "a" * 40
        if self.rollback_commit == self.head:
            self.rollback_commit = "b" * 40

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _commit_fixture(self) -> None:
        subprocess.run(
            ["git", "init"],
            cwd=self.root,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "tests@cogni.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Cogni Tests"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "core.autocrlf", "false"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(
            ["git", "commit", "-m", "release fixture"],
            cwd=self.root,
            check=True,
            capture_output=True,
        )
        self.head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _capture(self, url: str, *, payload: dict | None = None) -> HttpCapture:
        document = payload or {
            "ok": True,
            "deployment": {
                "attribution": "BUILD_BOUND",
                "provider": "cloudflare-pages",
                "project": CLOUDFLARE_PROJECT,
                "environment": "production",
                "source_commit": self.head,
                "branch": "main",
                "url": "https://cogni-os-orchestrator.pages.dev",
                "deployment_url": (
                    f"https://{self.deployment_id}.cogni-os-orchestrator.pages.dev"
                ),
            },
        }
        body = json.dumps(document, sort_keys=True).encode("utf-8")
        return HttpCapture(
            body=body,
            metadata={
                "schema_version": 1,
                "document_type": "cogni-production-http-capture",
                "method": "GET",
                "request_url": url,
                "final_url": url,
                "status": 200,
                "fetched_at": "2026-08-01T00:00:00Z",
                "tls_verified": True,
                "tls_policy": "python-default-ca",
                "headers": {"content-type": "application/json"},
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_size_bytes": len(body),
            },
        )

    def _cloudflare_api_capture(
        self,
        *,
        url: str,
        resource: str,
        result: dict,
    ) -> HttpCapture:
        body = json.dumps({"success": True, "result": result}, sort_keys=True).encode(
            "utf-8"
        )
        return HttpCapture(
            body=body,
            metadata={
                "schema_version": 1,
                "document_type": "cogni-cloudflare-http-capture",
                "method": "GET",
                "resource": resource,
                "request_url": url,
                "final_url": url,
                "status": 200,
                "fetched_at": "2026-08-01T00:00:00Z",
                "tls_verified": True,
                "tls_policy": "python-default-ca",
                "headers": {"content-type": "application/json"},
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_size_bytes": len(body),
            },
        )

    def _cloudflare_evidence(
        self, account_id: str, deployment_id: str
    ) -> CloudflareDeploymentCapture:
        source_commit = (
            self.head if deployment_id == self.deployment_id else self.rollback_commit
        )
        created_on = (
            "2026-08-01T01:00:00Z"
            if deployment_id == self.deployment_id
            else "2026-07-31T01:00:00Z"
        )
        result = {
            "project_name": CLOUDFLARE_PROJECT,
            "id": deployment_id,
            "short_id": deployment_id[:8],
            "environment": "production",
            "url": (f"https://{deployment_id}.cogni-os-orchestrator.pages.dev"),
            "created_on": created_on,
            "modified_on": created_on,
            "is_skipped": False,
            "deployment_trigger": {
                "type": "github:push",
                "metadata": {
                    "branch": "main",
                    "commit_dirty": False,
                    "commit_hash": source_commit,
                },
            },
            "latest_stage": {
                "name": "deploy",
                "status": "success",
                "started_on": created_on,
                "ended_on": created_on,
            },
        }
        canonical_created = "2026-08-01T01:00:00Z"
        canonical = {
            "id": self.deployment_id,
            "environment": "production",
            "url": (f"https://{self.deployment_id}.cogni-os-orchestrator.pages.dev"),
            "is_skipped": False,
            "deployment_trigger": {
                "metadata": {
                    "branch": "main",
                    "commit_dirty": False,
                    "commit_hash": self.head,
                },
            },
            "latest_stage": {
                "name": "deploy",
                "status": "success",
                "started_on": canonical_created,
                "ended_on": canonical_created,
            },
        }
        project = {
            "name": CLOUDFLARE_PROJECT,
            "subdomain": "cogni-os-orchestrator.pages.dev",
            "canonical_deployment": canonical,
        }
        deployment_url = (
            f"https://api.cloudflare.com/client/v4/accounts/{account_id}/pages/"
            f"projects/{CLOUDFLARE_PROJECT}/deployments/{deployment_id}"
        )
        project_url = (
            f"https://api.cloudflare.com/client/v4/accounts/{account_id}/pages/"
            f"projects/{CLOUDFLARE_PROJECT}"
        )
        deployment_capture = self._cloudflare_api_capture(
            url=deployment_url,
            resource="pages-deployment",
            result=result,
        )
        project_capture = self._cloudflare_api_capture(
            url=project_url,
            resource="pages-project",
            result=project,
        )
        evidence = _rederive_cloudflare_evidence(
            account_id=account_id,
            deployment_id=deployment_id,
            deployment_capture=deployment_capture,
            project_capture=project_capture,
        )
        return CloudflareDeploymentCapture(
            evidence=evidence,
            deployment=deployment_capture,
            project=project_capture,
        )

    def _collect(
        self,
        *,
        fetcher=_DEFAULT_TRANSPORT,
        cloudflare_fetcher=_DEFAULT_TRANSPORT,
        **overrides,
    ):
        values = {
            "actor": "codex",
            "cloudflare_account_id": self.account_id,
            "deployment_id": self.deployment_id,
            "deployment_source_commit": self.head,
            "rollback_deployment_id": self.rollback_deployment_id,
            "rollback_source_commit": self.rollback_commit,
            "capability_secret": "unit-test-capability",
        }
        values.update(overrides)
        production_transport = (
            self._capture if fetcher is _DEFAULT_TRANSPORT else fetcher
        )
        cloudflare_transport = (
            self._cloudflare_evidence
            if cloudflare_fetcher is _DEFAULT_TRANSPORT
            else cloudflare_fetcher
        )
        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "cogni_os.release_evidence._secure_archive_primitives_available",
                    return_value=True,
                )
            )
            stack.enter_context(
                patch(
                    "cogni_os.release_evidence._store_release_bundle",
                    side_effect=portable_store_release_bundle,
                )
            )
            stack.enter_context(
                patch(
                    "cogni_os.release_evidence._load_recovery_archive_files",
                    side_effect=portable_load_recovery_archive_files,
                )
            )
            stack.enter_context(
                patch(
                    "cogni_os.release_evidence.fetch_production_json",
                    side_effect=production_transport,
                )
            )
            if cloudflare_transport is not None:

                def capture_cloudflare(
                    account_id: str,
                    deployment_id: str,
                    *,
                    api_token: str,
                ) -> CloudflareDeploymentCapture:
                    self.assertEqual(api_token, "unit-test-cloudflare-token")
                    return cloudflare_transport(account_id, deployment_id)

                stack.enter_context(
                    patch(
                        "cogni_os.release_evidence._capture_cloudflare_deployment",
                        side_effect=capture_cloudflare,
                    )
                )
                stack.enter_context(
                    patch.dict(
                        os.environ,
                        {"CLOUDFLARE_API_TOKEN": "unit-test-cloudflare-token"},
                    )
                )
            return collect_p01_production_evidence(self.workspace, **values)

    def test_git_commit_is_delegated_to_trusted_runner(self) -> None:
        with patch(
            "cogni_os.release_evidence.trusted_git_source_commit",
            return_value=self.head,
        ) as trusted_git:
            self.assertEqual(_git_source_commit(self.root), self.head)
        trusted_git.assert_called_once_with(self.root)

    def test_collects_content_addressed_archive_and_exact_signed_event(self) -> None:
        os.environ["CLOUDFLARE_API_TOKEN"] = "must-never-be-persisted"
        try:
            result = self._collect()
        finally:
            os.environ.pop("CLOUDFLARE_API_TOKEN", None)

        events = self.workspace.ledger.read()
        event = events[-1]
        self.assertEqual(event["action"], "release.evidence_collected")
        self.assertEqual(event["actor"], "codex")
        self.assertEqual(event["task_id"], "P01-TRUTH")
        self.assertEqual(
            set(event["payload"]),
            {
                "schema_version",
                "producer",
                "actor_capability",
                "source_commit",
                "task_attempt",
                "collection",
            },
        )
        self.assertEqual(event["payload"]["schema_version"], 1)
        self.assertEqual(event["payload"]["source_commit"], self.head)
        self.assertEqual(event["payload"]["task_attempt"], 1)
        self.assertEqual(event["payload"]["producer"]["role"], "orchestrator")
        self.assertTrue(self.workspace.ledger.verify()["signed"])

        collection = result["collection"]
        bundle_path = self.root / Path(collection["bundle_path"])
        self.assertTrue(bundle_path.is_file())
        self.assertIn(
            "archive/release-evidence/P01-TRUTH/attempt-1/", collection["bundle_path"]
        )
        bundle_bytes = bundle_path.read_bytes()
        self.assertEqual(
            hashlib.sha256(bundle_bytes).hexdigest(), collection["bundle_sha256"]
        )
        self.assertEqual(bundle_path.parent.name, collection["bundle_sha256"])
        bundle = json.loads(bundle_bytes)
        self.assertEqual(
            bundle["actor_capability"],
            event["payload"]["actor_capability"],
        )
        self.assertEqual(
            bundle["actor_capability"]["operation"],
            "release.evidence.collect",
        )
        self.assertTrue(bundle["actor_capability"]["actor_os_isolation_proven"])
        self.assertEqual(bundle["deployment_attestation"], "CLOUDFLARE_API_VERIFIED")
        self.assertFalse(bundle["rollback_mutation_performed"])
        self.assertEqual(len(bundle["replay_results"]), 2)

        for artifact in collection["artifacts"]:
            path = self.root / Path(artifact["archive_path"])
            value = path.read_bytes()
            self.assertEqual(len(value), artifact["size_bytes"])
            self.assertEqual(hashlib.sha256(value).hexdigest(), artifact["sha256"])
            self.assertTrue(artifact["archive_path"].startswith("archive/"))
        archived_bytes = (
            b"".join(
                (self.root / Path(artifact["archive_path"])).read_bytes()
                for artifact in collection["artifacts"]
            )
            + bundle_bytes
        )
        self.assertNotIn(b"must-never-be-persisted", archived_bytes)
        rollback_receipt = json.loads(
            (bundle_path.parent / "cloudflare_rollback_dry_run.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(rollback_receipt["mutation_performed"])

    def test_worker_is_rejected_before_git_network_archive_or_ledger_write(
        self,
    ) -> None:
        initial_events = len(self.workspace.ledger.read())
        calls = []

        def forbidden(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("fetch must not run")

        with patch("cogni_os.release_evidence._git_source_commit") as git_commit:
            with self.assertRaises(AuthorizationError):
                self._collect(
                    actor="antigravity",
                    fetcher=forbidden,
                    cloudflare_fetcher=forbidden,
                )
            git_commit.assert_not_called()
        self.assertEqual(calls, [])
        self.assertEqual(len(self.workspace.ledger.read()), initial_events)
        self.assertFalse((self.root / "archive" / "release-evidence").exists())

    def test_complete_archive_recovers_after_crash_before_ledger_append(self) -> None:
        with (
            patch.object(
                self.workspace.ledger,
                "append",
                side_effect=RuntimeError("simulated crash before ledger append"),
            ),
            self.assertRaisesRegex(RuntimeError, "simulated crash"),
        ):
            self._collect()
        self.assertFalse(
            any(
                event["action"] == "release.evidence_collected"
                for event in self.workspace.ledger.read()
            )
        )

        def forbidden(*args, **kwargs):
            raise AssertionError("recovery must not re-fetch network evidence")

        result = self._collect(fetcher=forbidden, cloudflare_fetcher=forbidden)
        self.assertTrue(result["recovered_complete_archive"])
        events = [
            event
            for event in self.workspace.ledger.read()
            if event["action"] == "release.evidence_collected"
        ]
        self.assertEqual(len(events), 1)
        self.assertEqual(
            Path(result["collection"]["bundle_path"]).parent.name,
            result["collection"]["bundle_sha256"],
        )

    def test_partial_or_extra_orphan_archive_is_fail_closed(self) -> None:
        attempt = (
            self.root
            / "archive"
            / "release-evidence"
            / "P01-TRUTH"
            / "attempt-1"
            / ("b" * 64)
        )
        attempt.mkdir(parents=True)
        (attempt / "partial.txt").write_text("partial", encoding="utf-8")
        with self.assertRaises(EvidenceError):
            self._collect(
                fetcher=lambda *args: self.fail("partial recovery must precede fetch"),
                cloudflare_fetcher=lambda *args: self.fail(
                    "partial recovery must precede fetch"
                ),
            )

    def test_extra_file_blocks_recovery_of_otherwise_complete_archive(self) -> None:
        with (
            patch.object(
                self.workspace.ledger,
                "append",
                side_effect=RuntimeError("simulated crash"),
            ),
            self.assertRaises(RuntimeError),
        ):
            self._collect()
        attempt_directory = (
            self.root / "archive" / "release-evidence" / "P01-TRUTH" / "attempt-1"
        )
        bundle_directory = next(attempt_directory.iterdir())
        (bundle_directory / "unexpected.txt").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "extra or missing"):
            self._collect()

    def test_capture_hash_mismatch_fails_before_cloudflare_and_archive(self) -> None:
        cloudflare_calls = []

        def bad_capture(url: str) -> HttpCapture:
            capture = self._capture(url)
            return HttpCapture(
                body=capture.body,
                metadata={**capture.metadata, "body_sha256": "0" * 64},
            )

        with self.assertRaises(EvidenceError):
            self._collect(
                fetcher=bad_capture,
                cloudflare_fetcher=lambda *args: cloudflare_calls.append(args),
            )
        self.assertEqual(cloudflare_calls, [])
        self.assertFalse((self.root / "archive" / "release-evidence").exists())
        self.assertFalse(
            any(
                event["action"] == "release.evidence_collected"
                for event in self.workspace.ledger.read()
            )
        )

    def test_cloudflare_identity_commit_environment_and_status_must_match(self) -> None:
        variants = (
            ("account_id", "2" * 32),
            ("project_name", "another-project"),
            ("environment", "preview"),
            ("source_commit", "f" * 40),
            ("attestation_level", "CONDUCTOR_DECLARED"),
            ("latest_stage", {"name": "deploy", "status": "failure"}),
            (
                "trigger",
                {"type": "github:push", "branch": "preview", "commit_dirty": False},
            ),
            (
                "trigger",
                {"type": "github:push", "branch": "main", "commit_dirty": True},
            ),
        )
        for field, invalid_value in variants:

            def invalid_cloudflare(
                account_id,
                deployment_id,
                field=field,
                invalid_value=invalid_value,
            ):
                capture = self._cloudflare_evidence(account_id, deployment_id)
                evidence = dict(capture.evidence)
                if deployment_id == self.deployment_id:
                    evidence[field] = invalid_value
                return CloudflareDeploymentCapture(
                    evidence=evidence,
                    deployment=capture.deployment,
                    project=capture.project,
                )

            with self.subTest(field=field), self.assertRaises(EvidenceError):
                self._collect(cloudflare_fetcher=invalid_cloudflare)
        self.assertFalse((self.root / "archive" / "release-evidence").exists())

    def test_same_commit_different_canonical_deployment_is_rejected(self) -> None:
        def wrong_alias(account_id, deployment_id):
            capture = self._cloudflare_evidence(account_id, deployment_id)
            evidence = dict(capture.evidence)
            if deployment_id == self.deployment_id:
                evidence["production_alias"] = {
                    **evidence["production_alias"],
                    "deployment_id": "deployment-other",
                    "deployment_url": (
                        "https://deployment-other.cogni-os-orchestrator.pages.dev"
                    ),
                    # A matching source commit is deliberately insufficient.
                    "source_commit": self.head,
                }
            return CloudflareDeploymentCapture(
                evidence=evidence,
                deployment=capture.deployment,
                project=capture.project,
            )

        with self.assertRaisesRegex(
            EvidenceError, "does not match archived raw responses"
        ):
            self._collect(cloudflare_fetcher=wrong_alias)
        self.assertFalse((self.root / "archive" / "release-evidence").exists())

    def test_canonical_response_from_other_direct_deployment_is_rejected(self) -> None:
        def wrong_endpoint_binding(url: str) -> HttpCapture:
            capture = self._capture(url)
            document = json.loads(capture.body)
            document["deployment"]["deployment_url"] = (
                "https://deployment-other.cogni-os-orchestrator.pages.dev"
            )
            return self._capture(url, payload=document)

        with self.assertRaisesRegex(EvidenceError, "selected deployment"):
            self._collect(fetcher=wrong_endpoint_binding)
        self.assertFalse((self.root / "archive" / "release-evidence").exists())

    def test_missing_cloudflare_token_is_fail_closed(self) -> None:
        with (
            patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": ""}, clear=False),
            self.assertRaisesRegex(EvidenceError, "CLOUDFLARE_API_TOKEN"),
        ):
            self._collect(cloudflare_fetcher=None)
        self.assertFalse((self.root / "archive" / "release-evidence").exists())

    def test_production_fetch_is_pinned_single_read_bounded_and_redacted(self) -> None:
        url = PRODUCTION_ENDPOINTS[0][1]
        body = b'{"ok":true}'
        response = _FakeResponse(
            body,
            url,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": str(len(body)),
                "Set-Cookie": "must-not-be-captured",
                "CF-Ray": "ray-id",
            },
        )
        opener = _FakeOpener(lambda request: response)
        capture = fetch_production_json(url, opener=opener)
        self.assertEqual(response.read_calls, 1)
        self.assertTrue(response.closed)
        self.assertEqual(capture.body, body)
        self.assertNotIn("set-cookie", capture.metadata["headers"])
        self.assertEqual(capture.metadata["headers"]["cf-ray"], "ray-id")
        self.assertEqual(opener.requests[0][0].full_url, url)

        oversized = _FakeResponse(
            b"x" * (MAX_RESPONSE_BYTES + 1),
            url,
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaisesRegex(EvidenceError, "size limit"):
            fetch_production_json(url, opener=_FakeOpener(lambda request: oversized))
        self.assertEqual(oversized.read_calls, 1)
        with self.assertRaisesRegex(EvidenceError, "not pinned"):
            fetch_production_json("https://example.invalid/api/health", opener=opener)

    def test_production_fetch_rejects_redirect_and_secret_body(self) -> None:
        url = PRODUCTION_ENDPOINTS[1][1]
        redirected = _FakeResponse(
            b'{"ok":true}',
            "https://example.invalid/redirected",
        )
        with self.assertRaisesRegex(EvidenceError, "changed URL"):
            fetch_production_json(url, opener=_FakeOpener(lambda request: redirected))
        secret = _FakeResponse(b'{"token":"do-not-store"}', url)
        with self.assertRaisesRegex(EvidenceError, "secret-bearing"):
            fetch_production_json(url, opener=_FakeOpener(lambda request: secret))

    def test_cloudflare_fetch_binds_selected_deployment_to_production_alias(
        self,
    ) -> None:
        deployment_id = self.deployment_id
        url_suffix = f"/deployments/{deployment_id}"
        body = json.dumps(
            {
                "success": True,
                "errors": [],
                "result": {
                    "id": deployment_id,
                    "short_id": "deadbeef",
                    "project_name": CLOUDFLARE_PROJECT,
                    "environment": "production",
                    "url": (f"https://{deployment_id}.cogni-os-orchestrator.pages.dev"),
                    "created_on": "2026-08-01T00:00:00Z",
                    "modified_on": "2026-08-01T00:01:00Z",
                    "is_skipped": False,
                    "latest_stage": {
                        "name": "deploy",
                        "status": "success",
                        "started_on": "2026-08-01T00:00:00Z",
                        "ended_on": "2026-08-01T00:01:00Z",
                    },
                    "deployment_trigger": {
                        "type": "github:push",
                        "metadata": {
                            "branch": "main",
                            "commit_dirty": False,
                            "commit_hash": self.head,
                        },
                    },
                },
            },
            sort_keys=True,
        ).encode("utf-8")

        project_body = json.dumps(
            {
                "success": True,
                "errors": [],
                "result": {
                    "name": CLOUDFLARE_PROJECT,
                    "subdomain": "cogni-os-orchestrator.pages.dev",
                    "canonical_deployment": json.loads(body)["result"],
                },
            },
            sort_keys=True,
        ).encode("utf-8")
        response_box = []

        def response_factory(request):
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(
                request.get_header("Authorization"), "Bearer memory-only-token"
            )
            response_body = (
                body if request.full_url.endswith(url_suffix) else project_body
            )
            response = _FakeResponse(response_body, request.full_url)
            response_box.append(response)
            return response

        evidence = fetch_cloudflare_deployment(
            self.account_id,
            deployment_id,
            api_token="memory-only-token",
            opener=_FakeOpener(response_factory),
        )
        self.assertEqual(len(response_box), 2)
        self.assertTrue(all(response.read_calls == 1 for response in response_box))
        self.assertTrue(all(response.closed for response in response_box))
        serialized = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("memory-only-token", serialized)
        self.assertEqual(evidence["attestation_level"], "CLOUDFLARE_API_VERIFIED")
        self.assertEqual(evidence["source_commit"], self.head)
        self.assertEqual(evidence["production_alias"]["deployment_id"], deployment_id)
        self.assertEqual(
            evidence["production_alias"]["deployment_url"], evidence["url"]
        )

        secret_envelope = json.loads(body)
        secret_envelope["result"]["env_vars"] = {
            "PRIVATE": {"type": "secret_text", "value": "hidden-value"}
        }
        secret_body = json.dumps(secret_envelope, sort_keys=True).encode("utf-8")
        with self.assertRaisesRegex(EvidenceError, "secret-bearing"):
            fetch_cloudflare_deployment(
                self.account_id,
                deployment_id,
                api_token="memory-only-token",
                opener=_FakeOpener(
                    lambda request: _FakeResponse(secret_body, request.full_url)
                ),
            )

        envelope = json.loads(body)
        for label, bad_value in (
            ("missing", object()),
            ("true", True),
            ("integer-zero", 0),
            ("string-false", "false"),
        ):
            invalid = json.loads(json.dumps(envelope))
            metadata = invalid["result"]["deployment_trigger"]["metadata"]
            if label == "missing":
                metadata.pop("commit_dirty")
            else:
                metadata["commit_dirty"] = bad_value
            invalid_body = json.dumps(invalid, sort_keys=True).encode("utf-8")
            invalid_project = json.loads(project_body)
            invalid_project["result"]["canonical_deployment"] = invalid["result"]
            invalid_project_body = json.dumps(invalid_project, sort_keys=True).encode(
                "utf-8"
            )
            invalid_opener = _FakeOpener(
                lambda request, deployment_value=invalid_body, project_value=invalid_project_body: (
                    _FakeResponse(
                        deployment_value
                        if request.full_url.endswith(url_suffix)
                        else project_value,
                        request.full_url,
                    )
                )
            )
            with (
                self.subTest(commit_dirty=label),
                self.assertRaisesRegex(EvidenceError, "commit_dirty"),
            ):
                fetch_cloudflare_deployment(
                    self.account_id,
                    deployment_id,
                    api_token="memory-only-token",
                    opener=invalid_opener,
                )

    def test_task_state_change_during_network_collection_is_rejected(self) -> None:
        initial_events = len(self.workspace.ledger.read())
        changed = False

        def mutating_fetcher(url: str) -> HttpCapture:
            nonlocal changed
            if not changed:
                task_path = self.root / "tasks" / "P01-TRUTH.json"
                task = json.loads(task_path.read_text(encoding="utf-8"))
                task["state"] = "submitted"
                task_path.write_text(json.dumps(task), encoding="utf-8")
                changed = True
            return self._capture(url)

        with self.assertRaisesRegex(StateError, "task state changed"):
            self._collect(fetcher=mutating_fetcher)
        self.assertEqual(len(self.workspace.ledger.read()), initial_events)
        self.assertFalse((self.root / "archive" / "release-evidence").exists())

    def test_orchestrator_identity_change_during_network_collection_is_rejected(
        self,
    ) -> None:
        initial_events = len(self.workspace.ledger.read())
        changed = False

        def mutating_fetcher(url: str) -> HttpCapture:
            nonlocal changed
            if not changed:
                agent_path = self.root / "agents" / "codex.json"
                agent = json.loads(agent_path.read_text(encoding="utf-8"))
                agent["identity"]["model_family"] = "tampered-family"
                agent_path.write_text(json.dumps(agent), encoding="utf-8")
                changed = True
            return self._capture(url)

        with self.assertRaisesRegex(StateError, "authority or P01 task state"):
            self._collect(fetcher=mutating_fetcher)
        self.assertEqual(len(self.workspace.ledger.read()), initial_events)
        self.assertFalse((self.root / "archive" / "release-evidence").exists())

    def test_head_change_during_network_collection_is_rejected(self) -> None:
        initial_events = len(self.workspace.ledger.read())
        changed = False

        def mutating_fetcher(url: str) -> HttpCapture:
            nonlocal changed
            if not changed:
                (self.root / "head-change.txt").write_text("changed", encoding="utf-8")
                subprocess.run(
                    ["git", "add", "head-change.txt"], cwd=self.root, check=True
                )
                subprocess.run(
                    ["git", "commit", "-m", "change during collection"],
                    cwd=self.root,
                    check=True,
                    capture_output=True,
                )
                changed = True
            return self._capture(url)

        with self.assertRaisesRegex(StateError, "HEAD changed"):
            self._collect(fetcher=mutating_fetcher)
        self.assertEqual(len(self.workspace.ledger.read()), initial_events)
        self.assertFalse((self.root / "archive" / "release-evidence").exists())

    def test_archive_path_rejects_absolute_ads_traversal_and_reparse(self) -> None:
        unsafe = [
            str(self.root / "absolute"),
            "C:\\absolute\\path",
            "\\\\server\\share",
            "safe:ads",
            "../escape",
            "safe/../escape",
        ]
        for value in unsafe:
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                validate_archive_relative_path(value)
        for unsafe_url in (
            "http://hash.cogni-os-orchestrator.pages.dev",
            "https://user:pass@hash.cogni-os-orchestrator.pages.dev",
            "https://hash.other-project.pages.dev",
            "https://hash.cogni-os-orchestrator.pages.dev?token=secret",
            "https://hash.cogni-os-orchestrator.pages.dev/#fragment",
        ):
            with self.subTest(url=unsafe_url), self.assertRaises(EvidenceError):
                _normalized_pages_url(unsafe_url)

    def test_cli_has_no_secret_url_or_bundle_override_arguments(self) -> None:
        parser = build_parser()
        valid = [
            "release",
            "evidence",
            "collect",
            str(self.root),
            "--actor",
            "codex",
            "--cloudflare-account-id",
            self.account_id,
            "--deployment-id",
            self.deployment_id,
            "--deployment-source-commit",
            self.head,
            "--rollback-deployment-id",
            self.rollback_deployment_id,
            "--rollback-source-commit",
            self.rollback_commit,
        ]
        args = parser.parse_args(valid)
        self.assertEqual(args.release_evidence_command, "collect")
        for forbidden in ("--token", "--secret", "--url", "--bundle", "--bundle-sha"):
            with (
                self.subTest(forbidden=forbidden),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                parser.parse_args([*valid, forbidden, "forbidden-value"])

    def test_production_entrypoint_has_no_transport_injection(self) -> None:
        for entrypoint in (
            collect_p01_production_evidence,
            release_evidence._collect_p01_production_evidence_core,
        ):
            parameters = inspect.signature(entrypoint).parameters
            self.assertNotIn("fetcher", parameters)
            self.assertNotIn("cloudflare_fetcher", parameters)
            self.assertNotIn("allow_unsafe_test_archive", parameters)
        self.assertFalse(
            hasattr(release_evidence, "_collect_p01_production_evidence_test_only")
        )

    def test_injected_transport_cannot_append_release_evidence_event(self) -> None:
        initial_events = len(self.workspace.ledger.read())
        arguments = {
            "actor": "codex",
            "cloudflare_account_id": self.account_id,
            "deployment_id": self.deployment_id,
            "deployment_source_commit": self.head,
            "rollback_deployment_id": self.rollback_deployment_id,
            "rollback_source_commit": self.rollback_commit,
            "capability_secret": "unit-test-capability",
        }
        for injected in (
            {"fetcher": self._capture},
            {"cloudflare_fetcher": self._cloudflare_evidence},
            {"allow_unsafe_test_archive": True},
        ):
            with (
                self.subTest(injected=next(iter(injected))),
                self.assertRaises(TypeError),
            ):
                release_evidence._collect_p01_production_evidence_core(
                    self.workspace,
                    **arguments,
                    **injected,
                )
        self.assertEqual(len(self.workspace.ledger.read()), initial_events)
        self.assertFalse(
            any(
                event["action"] == "release.evidence_collected"
                for event in self.workspace.ledger.read()
            )
        )

    def test_production_archive_policy_fails_closed_before_state_git_or_network(
        self,
    ) -> None:
        with (
            patch(
                "cogni_os.release_evidence._secure_archive_primitives_available",
                return_value=False,
            ),
            patch(
                "cogni_os.release_evidence._collection_authority_snapshot"
            ) as authority_snapshot,
            patch("cogni_os.release_evidence._git_source_commit") as git_commit,
            patch("cogni_os.release_evidence.fetch_production_json") as network,
            self.assertRaisesRegex(
                EvidenceError,
                "descriptor-relative no-follow.*fail-closed",
            ),
        ):
            collect_p01_production_evidence(
                self.workspace,
                actor="codex",
                cloudflare_account_id=self.account_id,
                deployment_id=self.deployment_id,
                deployment_source_commit=self.head,
                rollback_deployment_id=self.rollback_deployment_id,
                rollback_source_commit=self.rollback_commit,
                capability_secret="unit-test-capability",
            )
        authority_snapshot.assert_not_called()
        git_commit.assert_not_called()
        network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
