#!/usr/bin/env python3
"""Run the fixed Python trust-test inventory under an isolated interpreter."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import unittest
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType


def _load_policy(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("p01_validation_policy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("P01 validation policy could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _iter_tests(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_tests(item)
        else:
            yield item


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    if sys.flags.isolated != 1 or Path.cwd().resolve() != root:
        print(json.dumps({"passed": False, "reason": "non-isolated-preflight"}))
        return 1
    if sys.version_info[:2] not in {(3, 10), (3, 12)}:
        print(json.dumps({"passed": False, "reason": "unsupported-python"}))
        return 1

    policy = _load_policy(root / "scripts" / "validate_p01_python.py")
    integration_policy = _load_policy(
        root / "scripts" / "validate_snapshot_broker_integration_inventory.py"
    )
    sys.path.insert(0, str(root / "src"))
    integration = integration_policy.validate_static_contract(root)
    suite = integration_policy.build_portable_suite(root)
    identifiers = sorted(test.id() for test in _iter_tests(suite))
    inventory_sha256 = hashlib.sha256(
        ("\n".join(identifiers) + "\n").encode("utf-8")
    ).hexdigest()

    stream = io.StringIO()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    record = {
        "passed": False,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "errors": len(result.errors),
        "failures": len(result.failures),
        "error_ids": sorted(test.id() for test, _ in result.errors)[:16],
        "failure_ids": sorted(test.id() for test, _ in result.failures)[:16],
        "skipped": len(result.skipped),
        "tests_run": result.testsRun,
        "inventory_sha256": inventory_sha256,
        "expected_tests": policy.EXPECTED_PYTHON_TESTS,
        "expected_inventory_sha256": policy.EXPECTED_TEST_INVENTORY_SHA256,
        "delegated_integration": integration,
    }
    record["passed"] = bool(
        record["errors"] == 0
        and record["failures"] == 0
        and record["skipped"] == 0
        and record["tests_run"] == record["expected_tests"]
        and record["inventory_sha256"] == record["expected_inventory_sha256"]
        and integration["delegated"] is True
        and integration["proof_scope"] == "broker-snapshot-only"
        and integration["phase1_release_eligible"] is False
        and integration["validator_execution_trusted"] is False
    )
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
