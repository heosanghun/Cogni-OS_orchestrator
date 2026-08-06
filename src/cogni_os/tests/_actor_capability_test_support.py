"""Legacy unit-fixture isolation for pre-capability behavior tests.

These helpers do not test authorization.  They keep older state-machine tests
focused on their original subject while ``test_actor_capability`` and the new
CLI mutation regressions exercise the real fail-closed boundary.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from cogni_os.actor_capability import ActorCapabilityAuthority
from cogni_os.workspace import Workspace


def install_legacy_capability_fixture(test_case: Any) -> None:
    """Stub only the authorization hook for legacy unit tests."""

    def authorize_fixture(
        _workspace: Workspace,
        *,
        actor: str,
        operation: str,
        task_id: str | None = None,
        run_id: str | None = None,
        task_attempt: int | None = None,
        **_ignored: Any,
    ) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "receipt_type": "actor-capability-consumption",
            "workspace_id": str(_workspace.config["workspace_id"]),
            "actor": actor,
            "operation": operation,
            "task_id": task_id,
            "run_id": run_id,
            "task_attempt": task_attempt,
            "nonce_sha256": "a" * 64,
            "key_version": 1,
            "issued_at_epoch": 1,
            "expires_at_epoch": 3,
            "consumed_at_epoch": 1,
            "os_principal_attestation": {
                "schema_version": 1,
                "provider": "unit-test-fixture",
                "principal_sha256": "b" * 64,
                "trust_root": "unit-test-fixture",
                "independent_trust_root": True,
                "actor_os_isolation_proven": True,
            },
            "independent_trust_root": True,
            "test_fixture_only": True,
            "actor_os_isolation_proven": True,
            "signature_algorithm": "unit-test-fixture",
            "signature": "unit-test-fixture",
        }

    def validate_fixture(
        _authority: ActorCapabilityAuthority,
        receipt: Any,
        *,
        expected_actor: str,
        expected_operation: str,
        expected_task_id: str | None,
        expected_run_id: str | None,
        expected_task_attempt: int | None,
        **_ignored: Any,
    ) -> dict[str, Any]:
        if (
            not isinstance(receipt, dict)
            or receipt.get("test_fixture_only") is not True
            or receipt.get("actor") != expected_actor
            or receipt.get("operation") != expected_operation
            or receipt.get("task_id") != expected_task_id
            or receipt.get("run_id") != expected_run_id
            or receipt.get("task_attempt") != expected_task_attempt
        ):
            raise AssertionError("legacy capability fixture scope mismatch")
        return dict(receipt)

    capability_patch = patch.object(
        Workspace,
        "authorize_actor_capability",
        autospec=True,
        side_effect=authorize_fixture,
    )
    capability_patch.start()
    test_case.addCleanup(capability_patch.stop)
    receipt_patch = patch.object(
        ActorCapabilityAuthority,
        "validate_receipt",
        autospec=True,
        side_effect=validate_fixture,
    )
    receipt_patch.start()
    test_case.addCleanup(receipt_patch.stop)
    posture_patch = patch(
        "cogni_os.doctor.authority_for_workspace",
        return_value=SimpleNamespace(
            status=lambda **_: {
                "schema_version": 1,
                "state": "provisioned",
                "actor_os_isolation_proven": True,
                "independent_trust_root": True,
            }
        ),
    )
    posture_patch.start()
    test_case.addCleanup(posture_patch.stop)
