"""Bounded, shell-free execution of independent verifier commands."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .errors import EvidenceError
from .util import atomic_write_json, sha256_file, utc_now

MAX_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
ALLOWED_GPU_IDS = tuple(range(6))
OPERATIONAL_PATH_PREFIXES = (
    ".cogni/",
    ".efo/",
    "agents/",
    "archive/",
    "ledger/",
    "reports/",
    "runs/",
    "submissions/",
    "tasks/",
)
SAFE_ENVIRONMENT_KEYS = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATH",
    "PATHEXT",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "WINDIR",
)
ALLOWED_PYTHON_MODULES = {
    "pytest",
    "unittest",
}
SAFE_DOTTED_TEST = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$"
)
SAFE_PYTEST_FLAGS = {
    "-q",
    "-x",
    "--disable-warnings",
    "--strict-config",
    "--strict-markers",
}
SAFE_UNITTEST_FLAGS = {
    "-b",
    "-c",
    "-f",
    "-q",
    "-v",
    "--buffer",
    "--catch",
    "--failfast",
    "--locals",
    "--verbose",
}
SAFE_NODE_FLAGS = {
    "--no-warnings",
    "--test",
    "--test-only",
}
TRUSTED_EXECUTABLE_ENV = {
    "node": "COGNI_TRUSTED_NODE_EXECUTABLE",
    "powershell-file": "COGNI_TRUSTED_POWERSHELL_EXECUTABLE",
}


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _run_git(workspace_root: Path, arguments: list[str]) -> bytes:
    environment = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={workspace_root.as_posix()}",
                "-C",
                str(workspace_root),
                *arguments,
            ],
            shell=False,
            check=False,
            capture_output=True,
            env=environment,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError(f"Cannot inspect trusted source state: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceError(f"Trusted source inspection failed: {detail}")
    return result.stdout


def _source_state(workspace_root: Path) -> dict[str, Any]:
    commit = (
        _run_git(workspace_root, ["rev-parse", "--verify", "HEAD"])
        .decode("ascii", errors="ignore")
        .strip()
        .lower()
    )
    if len(commit) != 40:
        raise EvidenceError("Trusted verifier source commit is unknown")
    try:
        int(commit, 16)
    except ValueError as exc:
        raise EvidenceError("Trusted verifier source commit is invalid") from exc

    tracked = _run_git(
        workspace_root,
        ["diff", "--name-only", "-z", "HEAD", "--"],
    )
    untracked = _run_git(
        workspace_root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
    )
    dirty_paths = sorted(
        {
            value.decode("utf-8", errors="surrogateescape").replace("\\", "/")
            for value in (*tracked.split(b"\0"), *untracked.split(b"\0"))
            if value
        }
    )
    source_dirty = [
        path
        for path in dirty_paths
        if not any(path.startswith(prefix) for prefix in OPERATIONAL_PATH_PREFIXES)
    ]
    if source_dirty:
        preview = ", ".join(source_dirty[:8])
        suffix = "" if len(source_dirty) <= 8 else f" (+{len(source_dirty) - 8})"
        raise EvidenceError(
            "Trusted verifier refuses a dirty source tree; commit or remove "
            f"source-bearing changes first: {preview}{suffix}"
        )
    operational_fingerprint = hashlib.sha256(
        "\0".join(dirty_paths).encode("utf-8", errors="surrogateescape")
    ).hexdigest()
    return {
        "commit": commit,
        "source_clean": True,
        "operational_change_count": len(dirty_paths),
        "operational_paths_sha256": operational_fingerprint,
    }


def _tracked_workspace_file(
    workspace_root: Path,
    value: str,
    *,
    allow_operational: bool = False,
) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = workspace_root / candidate
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(workspace_root.resolve()).as_posix()
    except ValueError as exc:
        raise EvidenceError(
            f"Trusted verifier code path escapes the committed workspace: {resolved}"
        ) from exc
    if not resolved.is_file():
        raise EvidenceError(f"Trusted verifier code file does not exist: {resolved}")
    if not allow_operational and any(
        relative.startswith(prefix) for prefix in OPERATIONAL_PATH_PREFIXES
    ):
        raise EvidenceError(
            "Trusted verifier cannot execute code from an operational evidence "
            f"directory: {relative}"
        )
    _run_git(
        workspace_root,
        ["ls-files", "--error-unmatch", "--", relative],
    )
    return resolved


def _tracked_dotted_test(workspace_root: Path, target: str) -> Path:
    """Resolve a dotted unittest target to its committed module without imports."""
    components = target.split(".")
    for length in range(len(components), 0, -1):
        module_parts = components[:length]
        for source_root in (workspace_root / "src", workspace_root):
            module_file = source_root.joinpath(*module_parts).with_suffix(".py")
            if module_file.is_file():
                return _tracked_workspace_file(workspace_root, str(module_file))
            package_file = source_root.joinpath(*module_parts, "__init__.py")
            if package_file.is_file():
                return _tracked_workspace_file(workspace_root, str(package_file))
    raise EvidenceError(
        f"Trusted unittest target does not resolve to committed source: {target}"
    )


def _validate_python_module_arguments(
    workspace_root: Path,
    module: str,
    arguments: list[str],
) -> list[Path]:
    if module == "unittest":
        if "discover" in arguments:
            raise EvidenceError(
                "Trusted unittest discovery must be wrapped by a committed "
                "validation script; implicit filesystem discovery is forbidden"
            )
        targets: list[str] = []
        for argument in arguments:
            if argument.startswith("-"):
                if argument not in SAFE_UNITTEST_FLAGS:
                    raise EvidenceError(
                        f"Trusted unittest option is not allowlisted: {argument}"
                    )
                continue
            targets.append(argument)
        if not targets or any(
            SAFE_DOTTED_TEST.fullmatch(target) is None for target in targets
        ):
            raise EvidenceError(
                "Trusted unittest requires explicit dotted test targets"
            )
        return [
            _tracked_dotted_test(workspace_root, target)
            for target in targets
        ]

    if module == "pytest":
        test_targets: list[str] = []
        for argument in arguments:
            if argument in SAFE_PYTEST_FLAGS:
                continue
            if argument.startswith("--maxfail="):
                value = argument.partition("=")[2]
                if not value.isdigit() or not 1 <= int(value) <= 10:
                    raise EvidenceError("Trusted pytest --maxfail is invalid")
                continue
            if argument.startswith("--tb="):
                if argument.partition("=")[2] not in {
                    "auto",
                    "long",
                    "short",
                    "line",
                    "native",
                    "no",
                }:
                    raise EvidenceError("Trusted pytest traceback mode is invalid")
                continue
            if argument.startswith("-"):
                raise EvidenceError(
                    f"Trusted pytest option is not allowlisted: {argument}"
                )
            test_targets.append(argument)
        if not test_targets:
            raise EvidenceError(
                "Trusted pytest requires explicit committed test file targets"
            )
        tracked_targets: list[Path] = []
        for target in test_targets:
            source_path = target.split("::", 1)[0]
            tracked_targets.append(
                _tracked_workspace_file(workspace_root, source_path)
            )
        return tracked_targets

    raise EvidenceError(f"Trusted Python module is not supported: {module}")


def _trusted_executable_binding(
    *,
    command_kind: str,
    executable_name: str,
    supplied_path: Path,
) -> dict[str, str]:
    """Bind actor-supplied argv[0] to a control-plane selected runtime."""
    if command_kind == "python":
        configured = sys.executable
        binding_source = "current-python-runtime"
    else:
        environment_key = TRUSTED_EXECUTABLE_ENV[command_kind]
        configured = os.environ.get(environment_key, "")
        if configured:
            binding_source = environment_key
        else:
            lookup = (
                "node"
                if command_kind == "node"
                else ("pwsh" if executable_name.startswith("pwsh") else "powershell")
            )
            configured = shutil.which(lookup) or ""
            binding_source = f"parent-path:{lookup}"
    if not configured:
        raise EvidenceError(
            f"Trusted {command_kind} executable is not configured by the control plane"
        )
    configured_candidate = Path(configured)
    if not configured_candidate.is_absolute():
        located = shutil.which(configured)
        if located is None:
            raise EvidenceError(
                f"Configured trusted {command_kind} executable is unavailable"
            )
        configured_candidate = Path(located)
    configured_path = configured_candidate.resolve()
    if not configured_path.is_file():
        raise EvidenceError(
            f"Configured trusted {command_kind} executable is not a file"
        )
    if os.path.normcase(str(configured_path)) != os.path.normcase(
        str(supplied_path.resolve())
    ):
        raise EvidenceError(
            "Verifier-selected executable does not match the control-plane "
            f"trusted {command_kind} runtime"
        )
    return {
        "source": binding_source,
        "path": str(configured_path),
        "sha256": sha256_file(configured_path),
    }


def _validate_command_argv(
    workspace_root: Path,
    argv: list[str],
) -> dict[str, Any]:
    executable = shutil.which(argv[0])
    if executable is None:
        candidate = Path(argv[0])
        if candidate.is_file():
            executable = str(candidate.resolve())
    if executable is None:
        raise EvidenceError(
            f"Trusted verifier executable is not available: {argv[0]}"
        )
    executable_path = Path(executable).resolve()
    executable_name = executable_path.name.lower()
    code_path: Path | None = None
    code_paths: list[Path] = []
    command_kind: str

    if executable_name.startswith(("python", "py.exe")):
        command_kind = "python"
        arguments = argv[1:]
        if any(argument in {"-c", "-"} for argument in arguments):
            raise EvidenceError(
                "Trusted Python validation must use an allowlisted module or "
                "a committed script; inline/stdin code is forbidden"
            )
        if "-m" in arguments:
            module_index = arguments.index("-m") + 1
            if module_index >= len(arguments):
                raise EvidenceError("Trusted Python -m requires a module")
            module = arguments[module_index]
            if module not in ALLOWED_PYTHON_MODULES:
                raise EvidenceError(
                    f"Trusted Python module is not allowlisted: {module}"
                )
            code_paths = _validate_python_module_arguments(
                workspace_root,
                module,
                arguments[module_index + 1 :],
            )
        else:
            positional = [
                argument
                for argument in arguments
                if argument and not argument.startswith("-")
            ]
            if not positional:
                raise EvidenceError(
                    "Trusted Python validation requires a committed script"
            )
            code_path = _tracked_workspace_file(workspace_root, positional[0])
            code_paths = [code_path]
    elif executable_name in {"node", "node.exe"}:
        command_kind = "node"
        arguments = argv[1:]
        for argument in arguments:
            if argument.startswith("-") and argument not in SAFE_NODE_FLAGS:
                raise EvidenceError(
                    f"Trusted Node option is not allowlisted: {argument}"
                )
        positional = [
            argument
            for argument in arguments
            if argument and not argument.startswith("-")
        ]
        if not positional:
            raise EvidenceError(
                "Trusted Node validation requires explicit committed code targets"
            )
        values_to_validate = positional if "--test" in arguments else positional[:1]
        for value in values_to_validate:
            code_paths.append(_tracked_workspace_file(workspace_root, value))
        code_path = code_paths[0]
    elif executable_name in {"powershell.exe", "pwsh.exe", "pwsh"}:
        command_kind = "powershell-file"
        lowered = [argument.lower() for argument in argv[1:]]
        if "-command" in lowered or "-encodedcommand" in lowered:
            raise EvidenceError(
                "Trusted PowerShell validation forbids command strings"
            )
        try:
            file_index = lowered.index("-file") + 1
            script = argv[file_index]
        except (ValueError, IndexError) as exc:
            raise EvidenceError(
                "Trusted PowerShell validation requires -File and a committed script"
            ) from exc
        code_path = _tracked_workspace_file(workspace_root, script)
        code_paths = [code_path]
    else:
        raise EvidenceError(
            "Trusted verifier executable is not allowlisted; use Python, Node, "
            "or PowerShell with committed validation code"
        )

    trust_binding = _trusted_executable_binding(
        command_kind=command_kind,
        executable_name=executable_name,
        supplied_path=executable_path,
    )
    return {
        "kind": command_kind,
        "executable_path": trust_binding["path"],
        "executable_sha256": trust_binding["sha256"],
        "executable_binding": trust_binding["source"],
        "executed_argv": [trust_binding["path"], *argv[1:]],
        "code_path": str(code_path) if code_path else None,
        "code_paths": [
            {
                "path": str(path),
                "sha256": sha256_file(path),
            }
            for path in code_paths
        ],
    }


def _trusted_environment(
    *,
    workspace_root: Path,
    scratch_root: Path,
    gpu_allowed: bool,
    network_allowed: bool,
) -> dict[str, str]:
    environment = {
        key: value
        for key in SAFE_ENVIRONMENT_KEYS
        if isinstance((value := os.environ.get(key)), str)
    }
    if "PATH" not in environment:
        environment["PATH"] = os.defpath
    scratch_root.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "APPDATA": str(scratch_root / "appdata"),
            "HOME": str(scratch_root),
            "LOCALAPPDATA": str(scratch_root / "localappdata"),
            "PYTHONPATH": (
                str(workspace_root / "src")
                if (workspace_root / "src").is_dir()
                else ""
            ),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "TEMP": str(scratch_root / "tmp"),
            "TMP": str(scratch_root / "tmp"),
            "USERPROFILE": str(scratch_root),
        }
    )
    for path in (
        Path(environment["APPDATA"]),
        Path(environment["LOCALAPPDATA"]),
        Path(environment["TEMP"]),
    ):
        path.mkdir(parents=True, exist_ok=True)
    environment["CUDA_VISIBLE_DEVICES"] = _bounded_cuda_visible_devices(
        gpu_allowed=gpu_allowed,
    )
    if not network_allowed:
        offline_proxy = "http://127.0.0.1:9"
        environment.update(
            {
                "ALL_PROXY": offline_proxy,
                "HTTP_PROXY": offline_proxy,
                "HTTPS_PROXY": offline_proxy,
                "NO_PROXY": "",
                "HF_HUB_OFFLINE": "1",
                "PIP_NO_INDEX": "1",
                "TRANSFORMERS_OFFLINE": "1",
            }
        )
    return environment


def _numeric_device_list(value: str, *, variable: str) -> list[int]:
    normalized = value.strip()
    if normalized in {"", "-1"}:
        return []
    tokens = [token.strip() for token in normalized.split(",")]
    if (
        not tokens
        or any(re.fullmatch(r"(?:0|[1-9][0-9]*)", token) is None for token in tokens)
    ):
        raise EvidenceError(
            f"{variable} must contain only unambiguous numeric GPU indices"
        )
    devices = [int(token) for token in tokens]
    if len(devices) != len(set(devices)):
        raise EvidenceError(f"{variable} contains duplicate GPU indices")
    return devices


def _bounded_cuda_visible_devices(*, gpu_allowed: bool) -> str:
    """Return a physical GPU 0-5 subset or fail on UUID/remapping ambiguity."""
    if not gpu_allowed:
        return ""

    physical_allowlist = list(ALLOWED_GPU_IDS)
    nvidia_visible = os.environ.get("NVIDIA_VISIBLE_DEVICES")
    if nvidia_visible is not None:
        exposed = _numeric_device_list(
            nvidia_visible,
            variable="NVIDIA_VISIBLE_DEVICES",
        )
        if exposed != list(range(len(exposed))) or any(
            device not in ALLOWED_GPU_IDS for device in exposed
        ):
            raise EvidenceError(
                "NVIDIA_VISIBLE_DEVICES introduces an ambiguous or denied GPU remap"
            )
        physical_allowlist = exposed

    existing = os.environ.get("CUDA_VISIBLE_DEVICES")
    if existing is None:
        selected = physical_allowlist
    else:
        requested = _numeric_device_list(
            existing,
            variable="CUDA_VISIBLE_DEVICES",
        )
        allowed = set(physical_allowlist)
        selected = [device for device in requested if device in allowed]
    return ",".join(str(device) for device in selected)


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                shell=False,
                check=False,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            process.kill()
    else:
        try:
            os.killpg(process.pid, 9)
        except (OSError, ProcessLookupError):
            process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def _run_bounded_command(
    *,
    argv: list[str],
    workspace_root: Path,
    environment: dict[str, str],
    output_path: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    temporary_path = output_path.with_suffix(output_path.suffix + ".part")
    timed_out = False
    output_truncated = False
    start_error: str | None = None
    exit_code: int | None = None
    started = time.monotonic()
    creation: dict[str, Any] = {}
    if os.name == "nt":
        creation["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        creation["start_new_session"] = True
    try:
        with temporary_path.open("wb") as output:
            process = subprocess.Popen(
                argv,
                cwd=workspace_root,
                env=environment,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                **creation,
            )
            while True:
                exit_code = process.poll()
                output.flush()
                size = temporary_path.stat().st_size
                elapsed = time.monotonic() - started
                if size > MAX_OUTPUT_BYTES:
                    output_truncated = True
                    _terminate_process_tree(process)
                    exit_code = process.poll()
                    break
                if elapsed > timeout_seconds:
                    timed_out = True
                    _terminate_process_tree(process)
                    exit_code = process.poll()
                    break
                if exit_code is not None:
                    break
                time.sleep(0.025)
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        start_error = str(exc)
        _atomic_write_bytes(temporary_path, start_error.encode("utf-8", errors="replace"))
    if temporary_path.stat().st_size > MAX_OUTPUT_BYTES:
        with temporary_path.open("r+b") as output:
            output.truncate(MAX_OUTPUT_BYTES)
            output.flush()
            os.fsync(output.fileno())
    os.replace(temporary_path, output_path)
    return {
        "exit_code": exit_code,
        "timed_out": timed_out,
        "output_truncated": output_truncated,
        "start_error": start_error,
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
    }


def run_trusted_validations(
    *,
    workspace_root: Path,
    runs_root: Path,
    task_id: str,
    attempt: int,
    actor: str,
    manifest: dict[str, Any],
    gpu_allowed: bool,
    network_allowed: bool,
    timeout_seconds: int = MAX_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Execute every validated verifier argv and bind results to raw bytes."""
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise EvidenceError(
            f"Trusted verifier timeout must be 1..{MAX_TIMEOUT_SECONDS} seconds"
        )
    source = _source_state(workspace_root)
    started_at = utc_now()
    run_directory = (
        runs_root
        / "trusted-verifier"
        / task_id
        / f"attempt-{attempt:03d}"
        / (
            started_at.replace(":", "").replace("-", "")
            + "-"
            + secrets.token_hex(4)
        )
    ).resolve()
    run_directory.mkdir(parents=True, exist_ok=False)
    environment = _trusted_environment(
        workspace_root=workspace_root,
        scratch_root=run_directory / "sandbox-home",
        gpu_allowed=gpu_allowed,
        network_allowed=network_allowed,
    )
    environment_sha256 = hashlib.sha256(
        json.dumps(
            environment,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    receipts: list[dict[str, Any]] = []
    failure: str | None = None
    for index, validation in enumerate(manifest.get("validations", [])):
        argv = validation.get("command_argv")
        if not isinstance(argv, list) or not argv:
            raise EvidenceError(
                f"validations[{index}].command_argv was not validated"
            )
        command_policy = _validate_command_argv(workspace_root, argv)
        command_started_at = utc_now()
        output_path = run_directory / f"validation-{index:03d}.log"
        execution = _run_bounded_command(
            argv=command_policy["executed_argv"],
            workspace_root=workspace_root,
            environment=environment,
            output_path=output_path,
            timeout_seconds=timeout_seconds,
        )
        output_sha256 = sha256_file(output_path)
        executable_path = Path(command_policy["executable_path"])
        executable_sha256_after = (
            sha256_file(executable_path)
            if executable_path.is_file()
            else None
        )
        receipt = {
            "index": index,
            "command_argv": list(argv),
            "executed_argv": list(command_policy["executed_argv"]),
            "command_policy": command_policy,
            "started_at": command_started_at,
            "completed_at": utc_now(),
            "duration_ms": execution["duration_ms"],
            "timeout_seconds": timeout_seconds,
            "timed_out": execution["timed_out"],
            "output_truncated": execution["output_truncated"],
            "exit_code": execution["exit_code"],
            "output_path": str(output_path),
            "output_sha256": output_sha256,
            "output_size_bytes": output_path.stat().st_size,
            "executable_sha256_after": executable_sha256_after,
        }
        receipts.append(receipt)
        if execution["start_error"]:
            failure = (
                "Trusted verifier command could not start: "
                + execution["start_error"]
            )
        elif execution["timed_out"]:
            failure = f"Trusted verifier validation {index} timed out"
        elif execution["output_truncated"]:
            failure = (
                f"Trusted verifier validation {index} exceeded the "
                f"{MAX_OUTPUT_BYTES}-byte output limit"
            )
        elif executable_sha256_after != command_policy["executable_sha256"]:
            failure = (
                f"Trusted verifier executable changed during validation {index}"
            )
        elif execution["exit_code"] != 0:
            failure = (
                f"Trusted verifier validation {index} failed with "
                f"exit code {execution['exit_code']}"
            )
        elif execution["exit_code"] != validation.get("exit_code"):
            failure = f"Trusted verifier validation {index} exit code was forged"
        elif output_sha256 != validation["raw_output"]["sha256"]:
            failure = f"Trusted verifier validation {index} output was forged"
        if failure:
            break

    source_postcheck_error: str | None = None
    try:
        completed_source = _source_state(workspace_root)
        if completed_source["commit"] != source["commit"]:
            source_postcheck_error = (
                "Trusted verifier changed the source commit during validation"
            )
    except EvidenceError as exc:
        source_postcheck_error = (
            f"Trusted verifier source postcheck failed: {exc}"
        )
    if source_postcheck_error and failure is None:
        failure = source_postcheck_error

    receipt_document = {
        "schema_version": 1,
        "runner": "cogni-os-trusted-runner-v1",
        "task_id": task_id,
        "attempt": attempt,
        "actor": actor,
        "source_commit": source["commit"],
        "source_clean": source["source_clean"],
        "source_postcheck_passed": source_postcheck_error is None,
        "source_postcheck_error": source_postcheck_error,
        "operational_change_count": source["operational_change_count"],
        "operational_paths_sha256": source["operational_paths_sha256"],
        "started_at": started_at,
        "completed_at": utc_now(),
        "gpu_allowed": gpu_allowed,
        "cuda_visible_devices": environment["CUDA_VISIBLE_DEVICES"],
        "network_allowed": network_allowed,
        "network_enforcement": (
            "task-permitted"
            if network_allowed
            else "offline-environment-and-loopback-proxy"
        ),
        "environment_sha256": environment_sha256,
        "max_output_bytes": MAX_OUTPUT_BYTES,
        "validations": receipts,
        "passed": failure is None and len(receipts) == len(manifest.get("validations", [])),
        "failure": failure,
    }
    receipt_path = run_directory / "receipt.json"
    atomic_write_json(receipt_path, receipt_document)
    result = {
        **receipt_document,
        "receipt_path": str(receipt_path),
        "receipt_sha256": sha256_file(receipt_path),
    }
    if failure:
        raise EvidenceError(
            f"{failure}; receipt={result['receipt_sha256']}"
        )
    return result
