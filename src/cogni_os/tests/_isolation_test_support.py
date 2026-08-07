"""Test-only adapter for exercising post-sandbox receipt logic on any OS.

Production code has no bypass flag.  Unit tests patch the private backend and
launcher at the Python object boundary so Windows CI can still cover receipt,
archive, and state-transition behavior.  Security regressions intentionally do
not install this adapter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from cogni_os import trusted_runner


def install_direct_isolation_fixture(testcase: Any) -> None:
    """Install a deterministic direct executor scoped to one unittest case."""

    backend = {
        "id": trusted_runner.TRUSTED_ISOLATION_BACKEND_ID,
        "path": "/usr/bin/bwrap",
        "sha256": "a" * 64,
        "filesystem_enforcement": "private-mount-namespace-committed-snapshot-ro",
        "network_enforcement": "private-network-namespace",
        "system_roots": ["/usr", "/lib"],
    }
    original_run = trusted_runner._run_bounded_command

    def test_runtime_binding(
        *,
        command_kind: str,
        supplied_value: str,
    ) -> dict[str, str]:
        runtime = Path(supplied_value)
        if not runtime.is_absolute():
            raise AssertionError("test runtime binding must be absolute")
        return {
            "policy_id": trusted_runner.TRUSTED_RUNTIME_POLICY_ID,
            "kind": command_kind,
            "path": str(runtime),
            "sha256": trusted_runner.sha256_file(runtime),
            "provenance": "test-only-fixture",
        }

    def direct_run(**kwargs: Any) -> dict[str, Any]:
        wrapped = list(kwargs["argv"])
        snapshot_root = None
        for index, value in enumerate(wrapped[:-2]):
            if value == "--ro-bind" and wrapped[index + 2] == "/workspace":
                snapshot_root = wrapped[index + 1]
                break
        if snapshot_root is None:
            raise AssertionError("test isolation plan omitted the committed snapshot")
        separator = wrapped.index("--")
        command = wrapped[separator + 1 :]
        kwargs["argv"] = [
            (
                snapshot_root + value.removeprefix("/workspace")
                if value.startswith("/workspace/")
                else value
            )
            for value in command
        ]
        kwargs["workspace_root"] = snapshot_root
        return original_run(**kwargs)

    backend_patch = patch(
        "cogni_os.trusted_runner._require_isolation_backend",
        return_value=backend,
    )
    broker_contract_patch = patch(
        "cogni_os.trusted_runner._require_external_snapshot_broker_contract",
        return_value=None,
    )
    run_patch = patch(
        "cogni_os.trusted_runner._run_bounded_command",
        side_effect=direct_run,
    )
    snapshot_protection_patch = patch(
        "cogni_os.trusted_runner._require_broker_protected_snapshot",
        return_value={
            "policy_id": trusted_runner.SNAPSHOT_PROTECTION_POLICY_ID,
            "platform": "linux",
            "broker": "external-privileged-owner",
            "runner_euid": 1000,
            "owner_uid": 0,
            "actor_write_access": False,
            "path_chain_root_owned": True,
            "path_chain_actor_nonwritable": True,
            "entries_root_owned": True,
            "entries_actor_nonwritable": True,
            "links_rejected": True,
            "checked_ancestor_count": 3,
            "checked_entry_count": 1,
            "proof": "root-owner-mode-access-probe",
        },
    )
    snapshot_writer_patch = patch(
        "cogni_os.trusted_runner._test_snapshot_path_writer_enabled",
        return_value=True,
    )
    runtime_binding_patch = patch(
        "cogni_os.trusted_runner._trusted_runtime_binding",
        side_effect=test_runtime_binding,
    )
    runtime_projection_patch = patch(
        "cogni_os.trust_projection._runtime_binding_semantically_valid",
        return_value=True,
    )
    broker_signature_projection_patch = patch(
        "cogni_os.trust_projection.EXTERNAL_BROKER_SIGNATURE_VERIFICATION_AVAILABLE",
        True,
    )
    executor_attestation_projection_patch = patch(
        "cogni_os.trust_projection._separate_executor_attestation_valid",
        return_value=True,
    )
    verification_run_binding_patch = patch(
        "cogni_os.trust_projection._verification_run_binding_valid",
        return_value=True,
    )
    workspace_attestation_client_patch = patch(
        "cogni_os.workspace.request_executor_attestation",
        return_value={"schema_version": 0, "test_only": True},
    )
    workspace_attestation_patch = patch(
        "cogni_os.workspace.verify_executor_attestation",
        return_value={"schema_version": 0, "test_only": True},
    )
    backend_patch.start()
    broker_contract_patch.start()
    run_patch.start()
    snapshot_protection_patch.start()
    snapshot_writer_patch.start()
    runtime_binding_patch.start()
    runtime_projection_patch.start()
    broker_signature_projection_patch.start()
    executor_attestation_projection_patch.start()
    verification_run_binding_patch.start()
    workspace_attestation_client_patch.start()
    workspace_attestation_patch.start()
    testcase.addCleanup(workspace_attestation_patch.stop)
    testcase.addCleanup(workspace_attestation_client_patch.stop)
    testcase.addCleanup(verification_run_binding_patch.stop)
    testcase.addCleanup(executor_attestation_projection_patch.stop)
    testcase.addCleanup(broker_signature_projection_patch.stop)
    testcase.addCleanup(runtime_projection_patch.stop)
    testcase.addCleanup(runtime_binding_patch.stop)
    testcase.addCleanup(snapshot_writer_patch.stop)
    testcase.addCleanup(snapshot_protection_patch.stop)
    testcase.addCleanup(run_patch.stop)
    testcase.addCleanup(backend_patch.stop)
    testcase.addCleanup(broker_contract_patch.stop)
