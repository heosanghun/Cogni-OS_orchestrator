"""Security regressions for preemptive trusted-runner confinement."""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cogni_os.errors import EvidenceError
from cogni_os.trusted_runner import (
    FIXED_POWERSHELL_RUNTIME_ROOT,
    FIXED_RUNTIME_PATHS,
    _canonical_isolation_argv,
    _committed_snapshot_postcheck,
    _isolated_argv,
    _materialize_committed_snapshot,
    _require_isolation_backend,
    _require_plain_directory,
    _run_git,
    _runtime_path_is_lexically_canonical,
    _sandbox_environment,
    _snapshot_directory_inventory,
    _validate_command_argv,
    run_trusted_validations,
)


class TrustedRunnerIsolationTests(unittest.TestCase):
    def _git(
        self, root: Path, *arguments: str, input_bytes: bytes | None = None
    ) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            input=input_bytes,
        )
        return result.stdout.decode("utf-8", errors="replace").strip()

    def _committed_attack_workspace(
        self,
        root: Path,
        source: str,
    ) -> tuple[Path, dict[str, object]]:
        workspace = root / "workspace"
        workspace.mkdir()
        script = workspace / "attack.py"
        script.write_text(source, encoding="utf-8")
        (workspace / "runs").mkdir()
        self._git(workspace, "init")
        self._git(workspace, "config", "core.autocrlf", "false")
        self._git(workspace, "config", "user.email", "tests@cogni.invalid")
        self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
        self._git(workspace, "add", "attack.py")
        self._git(workspace, "commit", "-m", "committed attack fixture")
        expected = b"must not execute\n"
        return workspace, {
            "manifest_sha256": "a" * 64,
            "validations": [
                {
                    "command_argv": [sys.executable, str(script)],
                    "exit_code": 0,
                    "raw_output": {"sha256": hashlib.sha256(expected).hexdigest()},
                }
            ],
        }

    def test_unsupported_platform_refuses_before_all_attack_classes(self) -> None:
        """No proxy/env-only fallback may execute unconfined verifier code."""

        attacks = {
            "raw-socket": (
                "import socket\n"
                "from pathlib import Path\n"
                "Path(r'{marker}').write_text('executed')\n"
                "socket.socket().connect(('1.1.1.1', 53))\n"
            ),
            "external-read-write": (
                "from pathlib import Path\n"
                "secret = Path(r'{secret}').read_text()\n"
                "Path(r'{outside_write}').write_text(secret)\n"
                "Path(r'{marker}').write_text('executed')\n"
            ),
            "workspace-ledger": (
                "from pathlib import Path\n"
                "ledger = Path(r'{ledger}')\n"
                "ledger.write_bytes(ledger.read_bytes() + b'tamper')\n"
                "Path(r'{marker}').write_text('executed')\n"
            ),
        }
        for name, template in attacks.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / "attack-executed.txt"
                secret = root / "host-secret.txt"
                outside_write = root / "host-write.txt"
                secret.write_text("sensitive", encoding="utf-8")
                ledger = root / "workspace" / "ledger" / "events.jsonl"
                source = template.format(
                    marker=marker,
                    secret=secret,
                    outside_write=outside_write,
                    ledger=ledger,
                )
                workspace, manifest = self._committed_attack_workspace(root, source)
                ledger.parent.mkdir(parents=True, exist_ok=True)
                ledger.write_text("immutable\n", encoding="utf-8")
                with (
                    patch(
                        "cogni_os.trusted_runner.sys.platform",
                        "win32",
                    ),
                    self.assertRaisesRegex(
                        EvidenceError,
                        r"(?i)(isolation|unavailable|refusing|attestation)",
                    ),
                ):
                    run_trusted_validations(
                        workspace_root=workspace,
                        runs_root=workspace / "runs",
                        task_id=f"T-{name.upper()}",
                        attempt=1,
                        actor="codex",
                        run_id="1" * 32,
                        manifest=manifest,
                        gpu_allowed=False,
                        network_allowed=False,
                    )
                self.assertFalse(marker.exists())
                self.assertFalse(outside_write.exists())
                self.assertEqual(secret.read_text(encoding="utf-8"), "sensitive")
                self.assertEqual(ledger.read_text(encoding="utf-8"), "immutable\n")

    def test_pre_sandbox_git_ignores_hostile_path_config_and_secrets(self) -> None:
        """Only a fixed absolute Git and a newly built minimal env may execute."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            trusted_git = root / "policy" / "git.exe"
            trusted_git.parent.mkdir()
            trusted_git.write_bytes(b"fixed trusted git fixture")
            trusted_git.chmod(0o755)
            fake_path = root / "attacker-bin"
            fake_path.mkdir()
            poisoned = {
                "ALL_PROXY": "http://attacker.invalid:1",
                "CLOUDFLARE_API_TOKEN": "cloudflare-secret",
                "COGNI_ACTOR_CAPABILITY_SECRET": "cogni-secret",
                "COGNI_TRUSTED_GIT_EXECUTABLE": str(fake_path / "git.exe"),
                "GIT_CONFIG": str(root / "malicious.gitconfig"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_GLOBAL": str(root / "malicious-global.gitconfig"),
                "GIT_CONFIG_KEY_0": "alias.rev-parse",
                "GIT_CONFIG_VALUE_0": "!echo compromised",
                "GIT_SSH_COMMAND": "malicious-ssh --steal",
                "HTTPS_PROXY": "http://attacker.invalid:2",
                "HTTP_PROXY": "http://attacker.invalid:3",
                "NO_PROXY": "*",
                "PATH": str(fake_path),
                "PYTHONINSPECT": "1",
                "PYTHONPATH": str(root / "malicious-python"),
                "SSH_ASKPASS": str(root / "malicious-askpass"),
                "SSH_AUTH_SOCK": str(root / "malicious-agent"),
            }
            captured: dict[str, object] = {}

            class FakeProcess:
                def __init__(self, argv: list[str], **kwargs: object) -> None:
                    self.args = argv
                    self.returncode: int | None = None
                    self.stdout = io.BytesIO(b"trusted-output\n")
                    self.stderr = io.BytesIO(b"")
                    self.stdin = None
                    captured["argv"] = list(argv)
                    captured["kwargs"] = dict(kwargs)
                    self.assert_cwd(kwargs)

                def assert_cwd(self, kwargs: dict[str, object]) -> None:
                    if not Path(str(kwargs["cwd"])).is_dir():
                        raise AssertionError("trusted Git scratch cwd was not created")

                def poll(self) -> int | None:
                    return self.returncode

                def wait(self, timeout: float | None = None) -> int:
                    del timeout
                    self.returncode = 0
                    return 0

                def kill(self) -> None:
                    self.returncode = -9

            def fake_popen(argv: list[str], **kwargs: object) -> FakeProcess:
                captured["argv"] = list(argv)
                captured["kwargs"] = dict(kwargs)
                self.assertTrue(Path(str(kwargs["cwd"])).is_dir())
                return FakeProcess(argv, **kwargs)

            binding = {
                "policy_id": "test-fixed-policy",
                "path": str(trusted_git.resolve()),
                "sha256": hashlib.sha256(trusted_git.read_bytes()).hexdigest(),
                "provenance": "test-only",
            }
            with (
                patch.dict(os.environ, poisoned, clear=False),
                patch(
                    "cogni_os.trusted_runner._trusted_git_binding",
                    return_value=binding,
                ),
                patch(
                    "cogni_os.trusted_runner.subprocess.Popen",
                    side_effect=fake_popen,
                ),
            ):
                output = _run_git(workspace, ["rev-parse", "--verify", "HEAD"])

            self.assertEqual(output, b"trusted-output\n")
            argv = captured["argv"]
            kwargs = captured["kwargs"]
            self.assertIsInstance(argv, list)
            self.assertIsInstance(kwargs, dict)
            assert isinstance(argv, list)
            assert isinstance(kwargs, dict)
            self.assertEqual(argv[0], str(trusted_git.resolve()))
            self.assertTrue(Path(argv[0]).is_absolute())
            self.assertNotIn(str(fake_path), argv[0])
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertTrue(kwargs["close_fds"])
            self.assertNotEqual(Path(str(kwargs["cwd"])), workspace)
            child_environment = kwargs["env"]
            self.assertIsInstance(child_environment, dict)
            assert isinstance(child_environment, dict)
            self.assertEqual(child_environment["PATH"], str(trusted_git.parent))
            self.assertEqual(child_environment["GIT_CONFIG_COUNT"], "0")
            self.assertEqual(child_environment["GIT_CONFIG_GLOBAL"], os.devnull)
            for key in (
                "ALL_PROXY",
                "CLOUDFLARE_API_TOKEN",
                "COGNI_ACTOR_CAPABILITY_SECRET",
                "COGNI_TRUSTED_GIT_EXECUTABLE",
                "GIT_CONFIG",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
                "GIT_SSH_COMMAND",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "NO_PROXY",
                "PYTHONINSPECT",
                "PYTHONPATH",
                "SSH_ASKPASS",
                "SSH_AUTH_SOCK",
            ):
                self.assertNotIn(key, child_environment)
            self.assertNotIn("cloudflare-secret", repr(captured))
            self.assertNotIn("cogni-secret", repr(captured))

    def test_pre_sandbox_git_fails_closed_without_fixed_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            with (
                patch(
                    "cogni_os.trusted_runner._trusted_git_candidate_paths",
                    return_value=(Path(temporary) / "missing-git",),
                ),
                patch("cogni_os.trusted_runner.subprocess.run") as run,
                self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(Git executable|fixed-path|refusing)",
                ),
            ):
                _run_git(workspace, ["rev-parse", "HEAD"])
            run.assert_not_called()

    def test_gpu_request_is_rejected_before_any_device_is_exposed(self) -> None:
        with self.assertRaisesRegex(
            EvidenceError,
            r"(?i)(GPU isolation is unsupported|devices 6-7|refusing)",
        ):
            _require_isolation_backend(
                gpu_allowed=True,
                network_allowed=False,
            )

    def test_python_interpreter_option_bypasses_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            target = workspace / "test_probe.py"
            target.write_text("def test_probe():\n    assert True\n", encoding="utf-8")
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            self._git(workspace, "add", "test_probe.py")
            self._git(workspace, "commit", "-m", "Python option bypass fixture")
            for option in ("--help", "--version", "-X", "-S"):
                with (
                    self.subTest(option=option),
                    self.assertRaisesRegex(
                        EvidenceError,
                        r"(?i)(interpreter options|committed script|Python)",
                    ),
                ):
                    _validate_command_argv(
                        workspace,
                        [sys.executable, option, "-m", "pytest", str(target)],
                    )

    def test_runtime_alias_and_dot_segment_are_not_lexically_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixed = root / "bin" / "runtime.exe"
            fixed.parent.mkdir()
            fixed.write_bytes(b"runtime")
            alias = root / "bin" / "runtime-alias.exe"
            dot_segment = root / "bin" / ".." / "bin" / "runtime.exe"
            self.assertTrue(_runtime_path_is_lexically_canonical(fixed, fixed))
            self.assertFalse(_runtime_path_is_lexically_canonical(alias, fixed))
            self.assertFalse(_runtime_path_is_lexically_canonical(dot_segment, fixed))

    def test_snapshot_ancestor_inventory_is_bounded_during_expansion(self) -> None:
        with (
            patch("cogni_os.trusted_runner.MAX_SNAPSHOT_TREE_NODE_COUNT", 3),
            self.assertRaisesRegex(EvidenceError, r"(?i)(ancestor|tree-node|limit)"),
        ):
            _snapshot_directory_inventory([{"path": "a/b/c/payload.txt"}])

    def test_canonical_runtime_mounts_reject_full_opt_and_bind_minimal_pwsh_root(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            scratch = root / "scratch"
            snapshot.mkdir()
            scratch.mkdir()
            environment = _sandbox_environment(
                snapshot_root=snapshot,
                cuda_visible_devices="",
            )
            backend = {
                "path": "/usr/bin/bwrap",
                "system_roots": ["/usr", "/lib", "/opt"],
            }
            with self.assertRaisesRegex(EvidenceError, r"(?i)(system roots|invalid)"):
                _canonical_isolation_argv(
                    backend=backend,
                    command_argv=["/usr/bin/python3.12", "/workspace/probe.py"],
                    workspace_root=snapshot,
                    snapshot_root=snapshot,
                    scratch_root=scratch,
                    sandbox_environment=environment,
                    network_allowed=False,
                )

            backend["system_roots"] = [
                "/usr",
                "/lib",
                FIXED_POWERSHELL_RUNTIME_ROOT,
            ]
            python_plan = _canonical_isolation_argv(
                backend=backend,
                command_argv=["/usr/bin/python3.12", "/workspace/probe.py"],
                workspace_root=snapshot,
                snapshot_root=snapshot,
                scratch_root=scratch,
                sandbox_environment=environment,
                network_allowed=False,
            )
            self.assertNotIn(FIXED_POWERSHELL_RUNTIME_ROOT, python_plan)
            powershell_plan = _canonical_isolation_argv(
                backend=backend,
                command_argv=[
                    "/opt/microsoft/powershell/7/pwsh",
                    "-File",
                    "/workspace/probe.ps1",
                ],
                workspace_root=snapshot,
                snapshot_root=snapshot,
                scratch_root=scratch,
                sandbox_environment=environment,
                network_allowed=False,
            )
            self.assertIn(FIXED_POWERSHELL_RUNTIME_ROOT, powershell_plan)
            self.assertNotIn("/opt", powershell_plan)

    def test_real_bubblewrap_executes_fixed_python_with_loader_roots(self) -> None:
        if not sys.platform.startswith("linux"):
            with self.assertRaisesRegex(EvidenceError, "unavailable on this platform"):
                _require_isolation_backend(
                    gpu_allowed=False,
                    network_allowed=False,
                )
            return
        runtime = next(
            (
                Path(value)
                for value in FIXED_RUNTIME_PATHS["python"]
                if Path(value).is_file()
            ),
            None,
        )
        if runtime is None:
            self.assertFalse(
                any(Path(value).is_file() for value in FIXED_RUNTIME_PATHS["python"])
            )
            return
        if not Path("/usr/bin/bwrap").is_file():
            with self.assertRaisesRegex(EvidenceError, "/usr/bin/bwrap"):
                _require_isolation_backend(
                    gpu_allowed=False,
                    network_allowed=False,
                )
            return
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            scratch = root / "scratch"
            snapshot.mkdir()
            scratch.mkdir()
            probe = snapshot / "probe.py"
            probe.write_text("print('bwrap-loader-ok')\n", encoding="utf-8")
            environment = _sandbox_environment(
                snapshot_root=snapshot,
                cuda_visible_devices="",
            )
            backend = _require_isolation_backend(
                gpu_allowed=False,
                network_allowed=False,
            )
            argv = _canonical_isolation_argv(
                backend=backend,
                command_argv=[str(runtime), "/workspace/probe.py"],
                workspace_root=snapshot,
                snapshot_root=snapshot,
                scratch_root=scratch,
                sandbox_environment=environment,
                network_allowed=False,
            )
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            restriction = (completed.stdout + completed.stderr).lower()
            if completed.returncode != 0 and any(
                marker in restriction
                for marker in (
                    "operation not permitted",
                    "no permissions to create new namespace",
                    "user namespaces are not enabled",
                )
            ):
                self.assertNotEqual(completed.returncode, 0)
                return
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "bwrap-loader-ok")

    def test_powershell_file_form_is_reconstructed_from_canonical_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            script = workspace / "verify.ps1"
            script.write_text("Write-Output 'verified'\n", encoding="utf-8")
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            self._git(workspace, "add", "verify.ps1")
            self._git(workspace, "commit", "-m", "PowerShell fixture")
            pinned = root / "policy" / "powershell.exe"
            pinned.parent.mkdir()
            pinned.write_bytes(b"pinned PowerShell fixture")
            binding = {
                "source": "fixed-os-powershell-policy",
                "path": str(pinned.resolve()),
                "sha256": hashlib.sha256(pinned.read_bytes()).hexdigest(),
            }
            with patch(
                "cogni_os.trusted_runner._trusted_powershell_binding",
                return_value=binding,
            ):
                policy = _validate_command_argv(
                    workspace,
                    [
                        "powershell.exe",
                        "-NonInteractive",
                        "-NoProfile",
                        "-File",
                        str(script),
                        "-Mode",
                        "verify",
                        r"C:\Data\input.json",
                    ],
                )
            self.assertEqual(policy["kind"], "powershell-file")
            self.assertEqual(
                policy["executed_argv"],
                [
                    str(pinned.resolve()),
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(script.resolve()),
                    "-Mode",
                    "verify",
                    r"C:\Data\input.json",
                ],
            )

    def test_powershell_abbreviations_aliases_colons_and_inline_forms_fail(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            script = workspace / "verify.ps1"
            script.write_text("Write-Output 'verified'\n", encoding="utf-8")
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            self._git(workspace, "add", "verify.ps1")
            self._git(workspace, "commit", "-m", "PowerShell adversarial fixture")
            pinned = root / "policy" / "powershell.exe"
            pinned.parent.mkdir()
            pinned.write_bytes(b"pinned PowerShell fixture")
            binding = {
                "source": "fixed-os-powershell-policy",
                "path": str(pinned.resolve()),
                "sha256": hashlib.sha256(pinned.read_bytes()).hexdigest(),
            }
            adversarial = (
                ["powershell", "-File", str(script)],
                ["powershell.exe", "-F", str(script)],
                ["powershell.exe", "-Fi", str(script)],
                ["powershell.exe", f"-File:{script}"],
                ["powershell.exe", "/File", str(script)],
                ["powershell.exe", "--File", str(script)],
                ["powershell.exe", "-C", "Write-Output compromised"],
                ["powershell.exe", "-Co", "Write-Output compromised"],
                ["powershell.exe", "-Command:Write-Output compromised"],
                ["powershell.exe", "-E", "YQBiAGMA"],
                ["powershell.exe", "-EC", "YQBiAGMA"],
                ["powershell.exe", "-Enc", "YQBiAGMA"],
                ["powershell.exe", "-EncodedCommand:YQBiAGMA"],
                ["powershell.exe", "-NoP", "-File", str(script)],
                ["powershell.exe", "-NonI", "-File", str(script)],
                [
                    "powershell.exe",
                    "-ExecutionPolicy:Bypass",
                    "-File",
                    str(script),
                ],
                ["powershell.exe", "-"],
                ["powershell.exe", "--%", "-File", str(script)],
                ["powershell.exe", "-File", "-"],
                ["powershell.exe", "-File", str(script), "--%"],
                ["powershell.exe", "-File", str(script), "-Enc", "YQBiAGMA"],
                ["powershell.exe", "-File", str(script), "-Mode:value"],
                ["powershell.exe", "-File", str(script), "@args"],
                ["powershell.exe", "-File", str(script), "$(Get-Secret)"],
            )
            with patch(
                "cogni_os.trusted_runner._trusted_powershell_binding",
                return_value=binding,
            ):
                for argv in adversarial:
                    with (
                        self.subTest(argv=argv),
                        self.assertRaisesRegex(
                            EvidenceError,
                            r"(?i)(PowerShell|executable|allowlisted)",
                        ),
                    ):
                        _validate_command_argv(workspace, argv)

    def test_user_owned_snapshot_is_no_go_before_verifier_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "must-not-run.txt"
            workspace, manifest = self._committed_attack_workspace(
                root,
                "from pathlib import Path\n"
                f"Path(r'{marker}').write_text('executed')\n"
                "print('must not execute')\n",
            )
            backend = {
                "id": "linux-bubblewrap-v1",
                "path": "/usr/bin/bwrap",
                "sha256": "a" * 64,
                "filesystem_enforcement": (
                    "private-mount-namespace-committed-snapshot-ro"
                ),
                "network_enforcement": "private-network-namespace",
                "system_roots": ["/usr", "/lib"],
            }
            with (
                patch(
                    "cogni_os.trusted_runner._require_isolation_backend",
                    return_value=backend,
                ),
                patch(
                    "cogni_os.trusted_runner._test_snapshot_path_writer_enabled",
                    return_value=True,
                ),
                patch(
                    "cogni_os.trusted_runner._materialize_committed_snapshot"
                ) as materialize,
                patch("cogni_os.trusted_runner._run_bounded_command") as execute,
                self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(snapshot|broker|root-owned|write access|immutab)",
                ),
            ):
                run_trusted_validations(
                    workspace_root=workspace,
                    runs_root=workspace / "runs",
                    task_id="T-USER-SNAPSHOT",
                    attempt=1,
                    actor="codex",
                    run_id="2" * 32,
                    manifest=manifest,
                    gpu_allowed=False,
                    network_allowed=False,
                )
            execute.assert_not_called()
            materialize.assert_not_called()
            self.assertFalse(marker.exists())

    def test_concurrent_snapshot_swap_restore_cannot_reach_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "must-not-run.txt"
            workspace, manifest = self._committed_attack_workspace(
                root,
                "print('must not execute')\n",
            )
            backend = {
                "id": "linux-bubblewrap-v1",
                "path": "/usr/bin/bwrap",
                "sha256": "a" * 64,
                "filesystem_enforcement": (
                    "private-mount-namespace-committed-snapshot-ro"
                ),
                "network_enforcement": "private-network-namespace",
                "system_roots": ["/usr", "/lib"],
            }
            swap_observed = threading.Event()
            postcheck_restored = threading.Event()
            original_materialize = _materialize_committed_snapshot

            def swap_restore(
                workspace_root: Path,
                snapshot_root: Path,
                source_commit: str,
            ) -> dict[str, object]:
                expected = original_materialize(
                    workspace_root,
                    snapshot_root,
                    source_commit,
                )
                victim = snapshot_root / "attack.py"
                original_bytes = victim.read_bytes()

                def attacker() -> None:
                    backup = snapshot_root / "attack.py.safe"
                    victim.chmod(0o600)
                    victim.replace(backup)
                    victim.write_text(
                        "from pathlib import Path\n"
                        f"Path(r'{marker}').write_text('executed')\n",
                        encoding="utf-8",
                    )
                    swap_observed.set()
                    victim.unlink()
                    backup.replace(victim)
                    victim.chmod(0o444)
                    if victim.read_bytes() == original_bytes:
                        postcheck_restored.set()

                worker = threading.Thread(target=attacker, daemon=True)
                worker.start()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(
                    _committed_snapshot_postcheck(snapshot_root, expected),
                    expected,
                )
                return expected

            with (
                patch(
                    "cogni_os.trusted_runner._require_isolation_backend",
                    return_value=backend,
                ),
                patch(
                    "cogni_os.trusted_runner._require_external_snapshot_broker_contract",
                    return_value=None,
                ),
                patch(
                    "cogni_os.trusted_runner._materialize_committed_snapshot",
                    side_effect=swap_restore,
                ),
                patch(
                    "cogni_os.trusted_runner._test_snapshot_path_writer_enabled",
                    return_value=True,
                ),
                patch("cogni_os.trusted_runner._run_bounded_command") as execute,
                self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(snapshot|broker|root-owned|write access|immutab)",
                ),
            ):
                run_trusted_validations(
                    workspace_root=workspace,
                    runs_root=workspace / "runs",
                    task_id="T-SWAP-RESTORE",
                    attempt=1,
                    actor="codex",
                    run_id="3" * 32,
                    manifest=manifest,
                    gpu_allowed=False,
                    network_allowed=False,
                )
            self.assertTrue(swap_observed.is_set())
            self.assertTrue(postcheck_restored.is_set())
            execute.assert_not_called()
            self.assertFalse(marker.exists())

    def test_committed_symlink_is_rejected_before_snapshot_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            blob = self._git(
                workspace,
                "hash-object",
                "-w",
                "--stdin",
                input_bytes=b"../../host-secret.txt",
            )
            self._git(
                workspace,
                "update-index",
                "--add",
                "--cacheinfo",
                f"120000,{blob},escape-link",
            )
            (workspace / ".gitattributes").write_text(
                "escape-link export-ignore\n",
                encoding="utf-8",
            )
            self._git(workspace, "add", ".gitattributes")
            self._git(workspace, "commit", "-m", "symlink escape fixture")
            source_commit = self._git(workspace, "rev-parse", "HEAD")
            with (
                patch(
                    "cogni_os.trusted_runner._test_snapshot_path_writer_enabled",
                    return_value=True,
                ),
                self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(symlink|hardlink|special|snapshot)",
                ),
            ):
                _materialize_committed_snapshot(
                    workspace,
                    root / "snapshot",
                    source_commit,
                )

    def test_committed_submodule_is_rejected_before_snapshot_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            (workspace / "seed.txt").write_text("seed\n", encoding="utf-8")
            self._git(workspace, "add", "seed.txt")
            self._git(workspace, "commit", "-m", "submodule seed")
            commit = self._git(workspace, "rev-parse", "HEAD")
            self._git(
                workspace,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{commit},nested-module",
            )
            self._git(workspace, "commit", "-m", "submodule fixture")
            source_commit = self._git(workspace, "rev-parse", "HEAD")
            with (
                patch(
                    "cogni_os.trusted_runner._test_snapshot_path_writer_enabled",
                    return_value=True,
                ),
                patch("cogni_os.trusted_runner._stream_committed_blobs") as blobs,
                self.assertRaisesRegex(EvidenceError, r"(?i)submodule"),
            ):
                _materialize_committed_snapshot(
                    workspace,
                    root / "snapshot",
                    source_commit,
                )
            blobs.assert_not_called()

    def test_zero_byte_tree_entry_limit_is_no_go_before_blob_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            for name in ("a.txt", "b.txt", "c.txt"):
                (workspace / name).write_bytes(b"")
            self._git(workspace, "add", ".")
            self._git(workspace, "commit", "-m", "zero-byte count fixture")
            source_commit = self._git(workspace, "rev-parse", "HEAD")
            with (
                patch("cogni_os.trusted_runner.MAX_SNAPSHOT_ENTRY_COUNT", 2),
                patch("cogni_os.trusted_runner._stream_committed_blobs") as blobs,
                self.assertRaisesRegex(EvidenceError, r"(?i)entry-count"),
            ):
                _materialize_committed_snapshot(
                    workspace,
                    root / "snapshot",
                    source_commit,
                )
            blobs.assert_not_called()
            self.assertFalse((root / "snapshot").exists())

    def test_actor_node_path_or_environment_override_is_no_go(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            script = workspace / "check.mjs"
            script.write_text("console.log('ok');\n", encoding="utf-8")
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            self._git(workspace, "add", "check.mjs")
            self._git(workspace, "commit", "-m", "node runtime fixture")
            actor_bin = root / "actor-bin"
            actor_bin.mkdir()
            fake_node = actor_bin / "node.exe"
            fake_node.write_bytes(b"actor selected runtime")
            with (
                patch.dict(
                    os.environ,
                    {
                        "PATH": str(actor_bin),
                        "COGNI_TRUSTED_NODE_EXECUTABLE": str(fake_node),
                    },
                    clear=False,
                ),
                self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(actor PATH|relative executable|fixed administrator)",
                ),
            ):
                _validate_command_argv(
                    workspace,
                    ["node", str(script)],
                )

    def test_ref_round_trip_materializes_only_the_initial_commit_oid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            payload = workspace / "payload.txt"
            payload.write_text("commit-a\n", encoding="utf-8")
            self._git(workspace, "add", "payload.txt")
            self._git(workspace, "commit", "-m", "commit A")
            commit_a = self._git(workspace, "rev-parse", "HEAD")
            tree_a = self._git(workspace, "rev-parse", f"{commit_a}^{{tree}}")
            payload.write_text("commit-b\n", encoding="utf-8")
            self._git(workspace, "add", "payload.txt")
            self._git(workspace, "commit", "-m", "commit B")
            commit_b = self._git(workspace, "rev-parse", "HEAD")
            self._git(workspace, "reset", "--hard", commit_a)

            from cogni_os import trusted_runner

            original_manifest = trusted_runner._committed_tree_manifest

            def round_trip_ref(
                workspace_root: Path,
                source_commit: str,
            ) -> dict[str, object]:
                self.assertEqual(source_commit, commit_a)
                self._git(workspace_root, "update-ref", "HEAD", commit_b)
                try:
                    return original_manifest(workspace_root, source_commit)
                finally:
                    self._git(workspace_root, "update-ref", "HEAD", commit_a)

            with (
                patch(
                    "cogni_os.trusted_runner._test_snapshot_path_writer_enabled",
                    return_value=True,
                ),
                patch(
                    "cogni_os.trusted_runner._committed_tree_manifest",
                    side_effect=round_trip_ref,
                ),
            ):
                snapshot = _materialize_committed_snapshot(
                    workspace,
                    root / "snapshot-a",
                    commit_a,
                )

            self.assertEqual(
                (root / "snapshot-a" / "payload.txt").read_bytes(), b"commit-a\n"
            )
            self.assertEqual(snapshot["source_commit"], commit_a)
            self.assertEqual(snapshot["tree_oid"], tree_a)
            self.assertEqual(self._git(workspace, "rev-parse", "HEAD"), commit_a)

    def test_export_attributes_cannot_omit_or_rewrite_committed_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            (workspace / ".gitattributes").write_text(
                "ignored.txt export-ignore\ntemplate.txt export-subst\n",
                encoding="utf-8",
            )
            (workspace / "ignored.txt").write_text(
                "must remain\n",
                encoding="utf-8",
            )
            literal = b"commit=$Format:%H$\n"
            (workspace / "template.txt").write_bytes(literal)
            self._git(workspace, "add", ".")
            self._git(workspace, "commit", "-m", "archive attribute fixture")
            source_commit = self._git(workspace, "rev-parse", "HEAD")

            with patch(
                "cogni_os.trusted_runner._test_snapshot_path_writer_enabled",
                return_value=True,
            ):
                snapshot = _materialize_committed_snapshot(
                    workspace,
                    root / "snapshot",
                    source_commit,
                )

            self.assertEqual(
                (root / "snapshot" / "ignored.txt").read_text(encoding="utf-8"),
                "must remain\n",
            )
            self.assertEqual(
                (root / "snapshot" / "template.txt").read_bytes(),
                literal,
            )
            objects = {entry["path"]: entry["object"] for entry in snapshot["files"]}
            self.assertEqual(
                objects["ignored.txt"],
                self._git(workspace, "rev-parse", f"{source_commit}:ignored.txt"),
            )
            self.assertEqual(
                objects["template.txt"],
                self._git(workspace, "rev-parse", f"{source_commit}:template.txt"),
            )

    def test_snapshot_manifest_mismatch_is_no_go_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, manifest = self._committed_attack_workspace(
                root,
                "print('must not execute')\n",
            )
            from cogni_os import trusted_runner

            original_materialize = trusted_runner._materialize_committed_snapshot

            def tampered_materialize(
                workspace_root: Path,
                snapshot_root: Path,
                source_commit: str,
            ) -> dict[str, object]:
                expected = original_materialize(
                    workspace_root,
                    snapshot_root,
                    source_commit,
                )
                victim = snapshot_root / "attack.py"
                victim.chmod(0o600)
                victim.write_text("print('tampered')\n", encoding="utf-8")
                return expected

            backend = {
                "id": "linux-bubblewrap-v1",
                "path": "/usr/bin/bwrap",
                "sha256": "a" * 64,
                "filesystem_enforcement": (
                    "private-mount-namespace-committed-snapshot-ro"
                ),
                "network_enforcement": "private-network-namespace",
                "system_roots": ["/usr", "/lib"],
            }
            with (
                patch(
                    "cogni_os.trusted_runner._require_isolation_backend",
                    return_value=backend,
                ),
                patch(
                    "cogni_os.trusted_runner._require_external_snapshot_broker_contract",
                    return_value=None,
                ),
                patch(
                    "cogni_os.trusted_runner._test_snapshot_path_writer_enabled",
                    return_value=True,
                ),
                patch(
                    "cogni_os.trusted_runner._materialize_committed_snapshot",
                    side_effect=tampered_materialize,
                ),
                patch("cogni_os.trusted_runner._run_bounded_command") as execute,
                self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(snapshot|Git object|manifest|bytes differ)",
                ),
            ):
                run_trusted_validations(
                    workspace_root=workspace,
                    runs_root=workspace / "runs",
                    task_id="T-SNAPSHOT-MISMATCH",
                    attempt=1,
                    actor="codex",
                    run_id="4" * 32,
                    manifest=manifest,
                    gpu_allowed=False,
                    network_allowed=False,
                )
            execute.assert_not_called()

    def test_snapshot_postcheck_rejects_mode_only_and_extra_directory_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            self._git(workspace, "init")
            self._git(workspace, "config", "user.email", "tests@cogni.invalid")
            self._git(workspace, "config", "user.name", "Cogni Isolation Tests")
            payload = workspace / "pkg" / "payload.txt"
            payload.parent.mkdir()
            payload.write_text("payload\n", encoding="utf-8")
            self._git(workspace, "add", ".")
            self._git(workspace, "commit", "-m", "postcheck fixture")
            source_commit = self._git(workspace, "rev-parse", "HEAD")
            snapshot_root = root / "snapshot"
            with patch(
                "cogni_os.trusted_runner._test_snapshot_path_writer_enabled",
                return_value=True,
            ):
                snapshot = _materialize_committed_snapshot(
                    workspace,
                    snapshot_root,
                    source_commit,
                )

            victim = snapshot_root / "pkg" / "payload.txt"
            victim.chmod(0o600)
            with (
                patch("cogni_os.trusted_runner.os.name", "posix"),
                self.assertRaisesRegex(EvidenceError, r"(?i)(mode|Git tree)"),
            ):
                _committed_snapshot_postcheck(snapshot_root, snapshot)
            victim.chmod(0o444)

            extra = snapshot_root / "unexpected"
            extra.mkdir()
            extra.chmod(0o555)
            with self.assertRaisesRegex(
                EvidenceError,
                r"(?i)(directory set|Git tree)",
            ):
                _committed_snapshot_postcheck(snapshot_root, snapshot)
            extra.chmod(0o700)
            extra.rmdir()

    def test_runs_root_reparse_is_rejected_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runs_root = Path(temporary) / "runs"
            runs_root.mkdir()
            with (
                patch(
                    "cogni_os.trusted_runner._is_reparse_or_symlink",
                    return_value=True,
                ),
                self.assertRaisesRegex(
                    EvidenceError,
                    r"(?i)(link|reparse)",
                ),
            ):
                _require_plain_directory(runs_root, label="runs root")

    def test_bubblewrap_plan_exposes_only_snapshot_and_scratch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            snapshot = root / "snapshot"
            scratch = root / "scratch"
            for directory in (workspace, snapshot, scratch):
                directory.mkdir()
            (snapshot / "src").mkdir()
            external_secret = root / "host-secret.txt"
            external_secret.write_text("secret", encoding="utf-8")
            backend = {
                "id": "linux-bubblewrap-v1",
                "path": "/usr/bin/bwrap",
                "sha256": "a" * 64,
                "filesystem_enforcement": (
                    "private-mount-namespace-committed-snapshot-ro"
                ),
                "network_enforcement": "private-network-namespace",
                "system_roots": ["/usr", "/lib"],
            }
            plan = _isolated_argv(
                backend=backend,
                command_argv=["/usr/bin/python3", "tests/check.py"],
                workspace_root=workspace,
                snapshot_root=snapshot,
                scratch_root=scratch,
                environment={"CUDA_VISIBLE_DEVICES": ""},
                network_allowed=False,
            )
            self.assertEqual(plan[0], "/usr/bin/bwrap")
            self.assertIn("--unshare-all", plan)
            self.assertNotIn("--share-net", plan)
            self.assertIn(str(snapshot), plan)
            self.assertIn(str(scratch), plan)
            self.assertNotIn(str(workspace), plan)
            self.assertNotIn(str(external_secret), plan)
            scratch_index = plan.index(str(scratch))
            snapshot_index = plan.index(str(snapshot))
            self.assertEqual(plan[snapshot_index - 1], "--ro-bind")
            self.assertEqual(plan[scratch_index - 1], "--bind")


if __name__ == "__main__":
    unittest.main()
