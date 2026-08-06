#!/usr/bin/env python3
"""Validate and, on the dedicated Linux job, run the root-broker inventory.

The broker integration is intentionally absent from the portable unit-test
suite.  This file makes that separation explicit and fail-closed: the exact
test IDs are pinned here and the normal validator checks that the dedicated
``linux-root-broker`` job invokes this script.  A successful run proves only
the privileged snapshot transport, signed provenance, FD transfer and
cleanup.  It is not Phase 1 release evidence and does not establish trusted
validator execution.  The separate signing-oracle code correction does not
promote this broker-only proof into a verifier receipt or release decision.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import io
import json
import os
import re
import sys
import unittest
from collections.abc import Iterator
from pathlib import Path

INTEGRATION_TEST_RELATIVE_PATH = Path(
    "src/cogni_os/tests/test_snapshot_broker_linux_integration.py"
)
WORKFLOW_RELATIVE_PATH = Path(".github/workflows/monitoring-ci.yml")
INSTALLER_RELATIVE_PATH = Path("scripts/install_snapshot_broker.sh")
INTEGRATION_JOB_ID = "linux-root-broker"
BROKER_PROOF_SCOPE = "broker-snapshot-only"
EXPECTED_INTEGRATION_TEST_IDS = (
    (
        "test_snapshot_broker_linux_integration."
        "InstalledSnapshotBrokerIntegrationTests.test_fixed_root_broker_preflight"
    ),
    (
        "test_snapshot_broker_linux_integration."
        "InstalledSnapshotBrokerIntegrationTests."
        "test_real_fd_lease_ed25519_scm_rights_and_cleanup"
    ),
)
EXPECTED_INTEGRATION_TESTS = 2
EXPECTED_INTEGRATION_INVENTORY_SHA256 = (
    "7ae2eeaaf958f14ac1b639fd234f76e24e48600dccb9ecb4f251b35780908fea"
)
MAX_POLICY_FILE_BYTES = 512 * 1024
ACTION_PIN = re.compile(r"^\s*-\s+uses:\s*[^@\s]+@([0-9a-f]{40})\s*(?:#.*)?$")


class InventoryError(RuntimeError):
    """Raised when the delegated integration contract is not exact."""


def _sha256_lines(values: list[str] | tuple[str, ...]) -> str:
    return hashlib.sha256(("\n".join(values) + "\n").encode("utf-8")).hexdigest()


def _bounded_text(path: Path) -> str:
    metadata = path.stat()
    if (
        not path.is_file()
        or metadata.st_size < 1
        or metadata.st_size > MAX_POLICY_FILE_BYTES
    ):
        raise InventoryError(f"policy file is absent or unbounded: {path}")
    return path.read_text(encoding="utf-8")


def _ast_inventory(root: Path) -> list[str]:
    path = root / INTEGRATION_TEST_RELATIVE_PATH
    source = _bounded_text(path)
    tree = ast.parse(source, filename=str(path))
    discovered: list[str] = []
    test_classes = 0
    module = path.stem
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        methods = [
            child.name
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test_")
        ]
        if methods:
            test_classes += 1
            discovered.extend(f"{module}.{node.name}.{name}" for name in methods)
    if test_classes != 1:
        raise InventoryError("integration file must contain exactly one test class")
    return sorted(discovered)


def validate_static_contract(root: Path) -> dict[str, object]:
    root = root.resolve()
    identifiers = _ast_inventory(root)
    inventory_sha256 = _sha256_lines(identifiers)
    if (
        identifiers != list(EXPECTED_INTEGRATION_TEST_IDS)
        or len(identifiers) != EXPECTED_INTEGRATION_TESTS
        or inventory_sha256 != EXPECTED_INTEGRATION_INVENTORY_SHA256
    ):
        raise InventoryError("root-broker integration inventory changed")

    workflow = _bounded_text(root / WORKFLOW_RELATIVE_PATH)
    required_tokens = (
        f"  {INTEGRATION_JOB_ID}:",
        "runs-on: ubuntu-24.04",
        'BROKER_CLIENT_ROLE: "adversarial-transport-client-not-verifier"',
        'BROKER_PROOF_SCOPE: "broker-snapshot-only"',
        'PHASE1_RELEASE_ELIGIBLE: "false"',
        'COGNI_RUN_ROOT_BROKER_INTEGRATION: "1"',
        "validate_snapshot_broker_integration_inventory.py",
        "--run",
        "docs/SNAPSHOT_BROKER_DEPLOYMENT_KO.md",
        "docs/TRUSTED_RUNNER_ISOLATION_KO.md",
        "src/cogni_os/tests/test_snapshot_broker_linux_integration.py",
        "scripts/install_snapshot_broker.sh",
        "deploy/**",
        "--no-build-isolation",
        "--no-deps",
        "--no-index",
        "git clone --no-local --no-checkout",
        "/usr/bin/timeout",
        "0:0:755",
        "0:0:600",
        "0:0:644",
        'for word in ("private","secret","token","credential")',
    )
    missing = [token for token in required_tokens if token not in workflow]
    if missing:
        raise InventoryError("mandatory Linux broker delegation is incomplete")
    if re.search(r"PHASE1_RELEASE_ELIGIBLE:\s*[\"']?true", workflow, re.IGNORECASE):
        raise InventoryError("broker-only CI may not claim Phase 1 release eligibility")

    broker_job = workflow.partition(f"  {INTEGRATION_JOB_ID}:")[2]
    if any(
        token in broker_job
        for token in ("apt-get", " apt ", "curl ", "wget ", "pip install")
    ):
        raise InventoryError(
            "root-broker CI may not install dependencies from a network"
        )
    if re.search(r"\bbwrap\b", broker_job):
        raise InventoryError(
            "broker-snapshot-only CI may not impersonate the future bwrap gate"
        )
    if "--no-hardlinks" in broker_job:
        raise InventoryError("cross-UID local clone must use Git's --no-local boundary")

    uses_lines = [line for line in workflow.splitlines() if "uses:" in line]
    if not uses_lines or any(ACTION_PIN.fullmatch(line) is None for line in uses_lines):
        raise InventoryError("every GitHub Action must use an exact 40-hex pin")

    installer = _bounded_text(root / INSTALLER_RELATIVE_PATH)
    approved_install = re.compile(
        r'"\$PYTHON" -I -m pip --isolated install \\\s*'
        r'--no-deps --no-index --only-binary=:all: "\$WHEEL"'
    )
    if len(re.findall(r"-m\s+pip\b", installer)) != 1 or not approved_install.search(
        installer
    ):
        raise InventoryError("broker installer must perform one offline wheel install")
    if any(
        token in installer.lower()
        for token in (
            "http://",
            "https://",
            "ftp://",
            "apt-get",
            "curl ",
            "wget ",
            "git clone",
            "pip download",
        )
    ):
        raise InventoryError("broker installer contains a network acquisition path")
    installer_mode_tokens = (
        '-m 0755 "$KEY_ROOT"',
        '/usr/bin/chmod 0600 "$PRIVATE_KEY"',
        '/usr/bin/chmod 0644 "$PUBLIC_KEY"',
        '/usr/bin/chmod 0644 "$OPENSSL_DIGEST"',
        '/usr/bin/chmod 0644 "$RUNTIME_MANIFEST"',
    )
    if any(token not in installer for token in installer_mode_tokens):
        raise InventoryError("broker installer trust-material modes are incomplete")
    return {
        "delegated": True,
        "job": INTEGRATION_JOB_ID,
        "client_role": "adversarial-transport-client-not-verifier",
        "proof_scope": BROKER_PROOF_SCOPE,
        "phase1_release_eligible": False,
        "validator_execution_trusted": False,
        "tests": len(identifiers),
        "test_ids": identifiers,
        "inventory_sha256": inventory_sha256,
    }


def build_portable_suite(root: Path) -> unittest.TestSuite:
    """Load every portable test file while excluding exactly one delegated file."""

    test_root = root.resolve() / "src" / "cogni_os" / "tests"
    delegated = (root.resolve() / INTEGRATION_TEST_RELATIVE_PATH).resolve()
    files = sorted(test_root.glob("test_*.py"))
    if delegated not in [path.resolve() for path in files]:
        raise InventoryError("delegated integration test file is missing")
    suite = unittest.TestSuite()
    for path in files:
        if path.resolve() == delegated:
            continue
        loader = unittest.TestLoader()
        suite.addTests(loader.discover(str(test_root), pattern=path.name))
    return suite


def _iter_tests(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_tests(item)
        else:
            yield item


def _run_integration(root: Path) -> dict[str, object]:
    if not (
        os.name == "posix"
        and sys.platform.startswith("linux")
        and hasattr(os, "geteuid")
        and os.geteuid() != 0
        and os.environ.get("COGNI_RUN_ROOT_BROKER_INTEGRATION") == "1"
        and os.environ.get("BROKER_CLIENT_ROLE")
        == "adversarial-transport-client-not-verifier"
        and os.environ.get("BROKER_PROOF_SCOPE") == BROKER_PROOF_SCOPE
        and os.environ.get("PHASE1_RELEASE_ELIGIBLE") == "false"
    ):
        raise InventoryError("root-broker integration execution context is invalid")
    for prerequisite in (Path("/usr/bin/python3.12"),):
        if not prerequisite.is_file() or not os.access(prerequisite, os.X_OK):
            raise InventoryError(
                f"mandatory runner-image prerequisite is absent: {prerequisite}"
            )

    test_root = root / "src" / "cogni_os" / "tests"
    suite = unittest.TestLoader().discover(
        str(test_root), pattern=INTEGRATION_TEST_RELATIVE_PATH.name
    )
    identifiers = sorted(test.id() for test in _iter_tests(suite))
    if identifiers != list(EXPECTED_INTEGRATION_TEST_IDS):
        raise InventoryError("runtime integration inventory differs from its AST pin")
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    return {
        "errors": len(result.errors),
        "failures": len(result.failures),
        "skipped": len(result.skipped),
        "tests_run": result.testsRun,
        "error_ids": sorted(test.id() for test, _ in result.errors)[:8],
        "failure_ids": sorted(test.id() for test, _ in result.failures)[:8],
        "passed": bool(
            not result.errors
            and not result.failures
            and not result.skipped
            and result.testsRun == EXPECTED_INTEGRATION_TESTS
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if sys.flags.isolated != 1 or Path.cwd().resolve() != root:
        print(json.dumps({"passed": False, "reason": "non-isolated-preflight"}))
        return 1
    try:
        contract = validate_static_contract(root)
        runtime = _run_integration(root) if args.run else None
        passed = runtime is None or runtime["passed"] is True
        record = {"passed": passed, "contract": contract, "runtime": runtime}
    except (InventoryError, OSError, SyntaxError) as exc:
        record = {"passed": False, "reason": str(exc)}
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
