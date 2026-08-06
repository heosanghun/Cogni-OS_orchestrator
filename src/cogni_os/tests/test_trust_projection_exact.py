from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from cogni_os.trusted_runner import (
    TRUSTED_RECEIPT_RESULT_KEYS,
    TRUSTED_RUNNER_ID,
    _canonical_isolation_argv,
)

from cogni_os import trust_projection


class TrustProjectionExactReceiptTestCase(unittest.TestCase):
    def test_verification_run_binding_requires_canonical_lowercase_hex(self) -> None:
        valid = "1" * 32
        self.assertTrue(
            trust_projection._verification_run_binding_valid(
                {"run_id": valid},
                {"run_id": valid},
            )
        )
        for invalid in ("A" * 32, "workspace-run", "1" * 31, "1" * 33):
            with self.subTest(run_id=invalid):
                self.assertFalse(
                    trust_projection._verification_run_binding_valid(
                        {"run_id": invalid},
                        {"run_id": invalid},
                    )
                )

    def test_receipt_shape_rejects_legacy_versions_and_unknown_fields(self) -> None:
        receipt = dict.fromkeys(TRUSTED_RECEIPT_RESULT_KEYS)
        receipt["schema_version"] = 3
        receipt["runner"] = TRUSTED_RUNNER_ID
        self.assertTrue(trust_projection._trusted_receipt_shape_valid(receipt))

        for legacy_version in (1, 2):
            legacy = dict(receipt)
            legacy["schema_version"] = legacy_version
            self.assertFalse(trust_projection._trusted_receipt_shape_valid(legacy))

        unknown = dict(receipt)
        unknown["unexpected"] = "field"
        self.assertFalse(trust_projection._trusted_receipt_shape_valid(unknown))

    def _valid_command_fixture(
        self, workspace: Path
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, str]]:
        code_path = workspace / "tests" / "example.mjs"
        runtime_sha256 = "a" * 64
        code_sha256 = "b" * 64
        output_sha256 = "c" * 64
        binding = {
            "policy_id": "fixed-admin-runtime-readonly-v1",
            "kind": "node",
            "path": "/usr/bin/node",
            "sha256": runtime_sha256,
            "provenance": "fixed-admin-path-chain",
        }
        command_argv = ["/usr/bin/node", "--test", str(code_path)]
        command_policy = {
            "schema_version": 1,
            "kind": "node",
            "executable_path": "/usr/bin/node",
            "executable_sha256": runtime_sha256,
            "executable_binding": binding,
            "executed_argv": list(command_argv),
            "code_path": str(code_path),
            "code_paths": [{"path": str(code_path), "sha256": code_sha256}],
        }
        backend = {
            "id": "linux-bubblewrap-v1",
            "path": "/usr/bin/bwrap",
            "sha256": "d" * 64,
            "filesystem_enforcement": ("private-mount-namespace-committed-snapshot-ro"),
            "network_enforcement": "private-network-namespace",
            "system_roots": ["/usr", "/lib"],
        }
        sandbox_environment = trust_projection._expected_sandbox_environment(
            cuda_visible_devices="",
            has_python_source=False,
        )
        run_directory = (
            workspace
            / "runs"
            / "trusted-verifier"
            / "T-EXACT"
            / "attempt-001"
            / ("1" * 32)
        )
        isolation_argv = _canonical_isolation_argv(
            backend=backend,
            command_argv=list(command_argv),
            workspace_root=workspace,
            snapshot_root=run_directory / "committed-input",
            scratch_root=run_directory / "sandbox-home",
            sandbox_environment=sandbox_environment,
            network_allowed=False,
        )
        validation = {
            "index": 0,
            "command_argv": list(command_argv),
            "executed_argv": list(command_argv),
            "isolation_launch_argv": isolation_argv,
            "command_policy": command_policy,
            "started_at": "2026-08-01T00:00:00Z",
            "completed_at": "2026-08-01T00:00:01Z",
            "duration_ms": 1.0,
            "timeout_seconds": 30,
            "timed_out": False,
            "output_truncated": False,
            "exit_code": 0,
            "output_path": str(run_directory / "validation-000.log"),
            "output_sha256": output_sha256,
            "output_size_bytes": 1,
            "executable_sha256_after": runtime_sha256,
        }
        manifest_validation = {
            "command_argv": list(command_argv),
            "exit_code": 0,
            "raw_output_sha256": output_sha256,
        }
        snapshot_files = {
            "tests/example.mjs": {
                "path": "tests/example.mjs",
                "sha256": code_sha256,
            }
        }
        return validation, manifest_validation, snapshot_files, sandbox_environment

    def _assert_valid(self, workspace: Path, validation: dict[str, object]) -> bool:
        _, manifest, snapshot_files, sandbox_environment = self._valid_command_fixture(
            workspace
        )
        return trust_projection._valid_command_receipt(
            manifest,
            validation,
            expected_index=0,
            isolation_backend={
                "id": "linux-bubblewrap-v1",
                "path": "/usr/bin/bwrap",
                "sha256": "d" * 64,
                "filesystem_enforcement": (
                    "private-mount-namespace-committed-snapshot-ro"
                ),
                "network_enforcement": "private-network-namespace",
                "system_roots": ["/usr", "/lib"],
            },
            sandbox_environment=sandbox_environment,
            snapshot_files=snapshot_files,
            workspace_root=workspace,
            task_id="T-EXACT",
            attempt=1,
            network_allowed=False,
            maximum_output_bytes=4 * 1024 * 1024,
            output_evidence={"c" * 64: {1}},
            expected_run_directory=(
                workspace
                / "runs"
                / "trusted-verifier"
                / "T-EXACT"
                / "attempt-001"
                / ("1" * 32)
            ),
        )

    def test_command_receipt_rejects_extra_bind_unknown_and_unpinned_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            validation, _, _, _ = self._valid_command_fixture(workspace)
            self.assertTrue(self._assert_valid(workspace, validation))

            extra_bind = copy.deepcopy(validation)
            separator = extra_bind["isolation_launch_argv"].index("--")
            extra_bind["isolation_launch_argv"][separator:separator] = [
                "--bind",
                "/etc",
                "/workspace",
            ]
            self.assertFalse(self._assert_valid(workspace, extra_bind))

            unknown = copy.deepcopy(validation)
            unknown["unexpected"] = True
            self.assertFalse(self._assert_valid(workspace, unknown))

            wrong_output_size = copy.deepcopy(validation)
            wrong_output_size["output_size_bytes"] = 2
            self.assertFalse(self._assert_valid(workspace, wrong_output_size))

            unpinned = copy.deepcopy(validation)
            unpinned_path = str(workspace / "tests" / "evil.mjs")
            unpinned["command_policy"]["code_path"] = unpinned_path
            unpinned["command_policy"]["code_paths"] = [
                {"path": unpinned_path, "sha256": "b" * 64}
            ]
            self.assertFalse(self._assert_valid(workspace, unpinned))

    def test_command_receipt_rejects_actor_runtime_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            validation, _, _, _ = self._valid_command_fixture(workspace)
            validation["command_argv"][0] = "/tmp/actor-node"
            self.assertFalse(self._assert_valid(workspace, validation))

    def test_python_projection_rejects_interpreter_option_bypasses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            code_path = workspace / "tests" / "test_probe.py"
            snapshot_files = {
                "tests/test_probe.py": {
                    "path": "tests/test_probe.py",
                    "sha256": "b" * 64,
                }
            }
            for option in ("--help", "--version", "-X", "-S"):
                policy = {
                    "kind": "python",
                    "executed_argv": [
                        "/usr/bin/python3.12",
                        option,
                        "-m",
                        "pytest",
                        str(code_path),
                    ],
                    "code_path": None,
                    "code_paths": [{"path": str(code_path), "sha256": "b" * 64}],
                }
                with self.subTest(option=option):
                    self.assertFalse(
                        trust_projection._valid_code_path_bindings(
                            policy,
                            workspace_root=workspace,
                            snapshot_files=snapshot_files,
                        )
                    )
            module_bypass = {
                "kind": "python",
                "executed_argv": [
                    "/usr/bin/python3.12",
                    "-m",
                    "pytest",
                    "--version",
                    str(code_path),
                ],
                "code_path": None,
                "code_paths": [{"path": str(code_path), "sha256": "b" * 64}],
            }
            self.assertFalse(
                trust_projection._valid_code_path_bindings(
                    module_bypass,
                    workspace_root=workspace,
                    snapshot_files=snapshot_files,
                )
            )

    def test_projection_enforces_fixed_output_and_snapshot_resource_caps(self) -> None:
        self.assertTrue(trust_projection._fixed_output_limit_valid(4 * 1024 * 1024))
        self.assertFalse(trust_projection._fixed_output_limit_valid(8 * 1024 * 1024))
        zero_byte_snapshot = {
            "file_count": 1,
            "directories": [],
            "size_bytes": 0,
            "files": [{"path": "empty.txt", "size": 0}],
        }
        self.assertTrue(
            trust_projection._snapshot_resource_caps_valid(zero_byte_snapshot)
        )
        oversized = copy.deepcopy(zero_byte_snapshot)
        oversized["size_bytes"] = 64 * 1024 * 1024 + 1
        oversized["files"][0]["size"] = oversized["size_bytes"]
        self.assertFalse(trust_projection._snapshot_resource_caps_valid(oversized))

    def test_output_paths_share_one_canonical_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            validation, _, _, _ = self._valid_command_fixture(workspace)
            expected = (
                workspace
                / "runs"
                / "trusted-verifier"
                / "T-EXACT"
                / "attempt-001"
                / ("1" * 32)
            )
            self.assertTrue(self._assert_valid(workspace, validation))
            self.assertTrue(
                trust_projection._canonical_receipt_path_valid(
                    str(expected / "receipt.json"), expected
                )
            )
            self.assertFalse(
                trust_projection._canonical_receipt_path_valid(
                    str(expected / "receipt-copy.json"), expected
                )
            )
            other_run = copy.deepcopy(validation)
            other_run["output_path"] = str(
                expected.parent / ("2" * 32) / "validation-000.log"
            )
            self.assertFalse(self._assert_valid(workspace, other_run))
            self.assertIsNone(
                trust_projection._receipt_run_directory(
                    str(expected / "not-receipt.log"),
                    workspace_root=workspace,
                    task_id="T-EXACT",
                    attempt=1,
                    index=0,
                )
            )

    def test_retained_output_lstat_size_matches_bundle_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            bundle_directory = workspace / "archive" / "bundle"
            files_directory = bundle_directory / "files"
            files_directory.mkdir(parents=True)
            output = files_directory / "validation-000.log"
            output.write_bytes(b"x")
            digest = hashlib.sha256(b"x").hexdigest()
            item = {
                "kind": "trusted_runner_output",
                "retained": True,
                "archive_path": str(output),
                "sha256": digest,
                "size_bytes": 2,
            }
            bundle = {"files": [item]}
            self.assertEqual(
                trust_projection._retained_bundle_evidence(
                    bundle,
                    "trusted_runner_output",
                    workspace_root=workspace,
                    bundle_directory=bundle_directory,
                    maximum_bytes=4 * 1024 * 1024,
                ),
                {},
            )
            item["size_bytes"] = 1
            self.assertEqual(
                trust_projection._retained_bundle_evidence(
                    bundle,
                    "trusted_runner_output",
                    workspace_root=workspace,
                    bundle_directory=bundle_directory,
                    maximum_bytes=4 * 1024 * 1024,
                ),
                {digest: {1}},
            )


if __name__ == "__main__":
    unittest.main()
