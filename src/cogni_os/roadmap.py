"""Evidence-gated Cogni-OS Phase 1-11 execution roadmap."""

from __future__ import annotations

import subprocess
from copy import deepcopy
from typing import Any

from .errors import ConfigurationError
from .trust_projection import task_trust_state
from .workspace import Workspace


_STRICT_GATES = {
    "require_validation": True,
    "allow_skips": False,
    "require_known_answer_check": True,
    "require_independent_verification": True,
}


ROADMAP_PHASES: tuple[dict[str, Any], ...] = (
    {
        "id": "P01-TRUTH",
        "title": "Phase 1 - Release truth baseline",
        "description": (
            "Establish one authoritative source commit, preserve historical evidence, "
            "record disputes instead of rewriting history, reconcile the shared "
            "workspace, capability Fact-book, and deployment identity. Acceptance: "
            "workspace doctor passes; source, ledger, projection, and deployment "
            "commit are attributable; the historical same-family T-001 verification "
            "is not counted as trusted; exact replay and rollback commands are retained."
        ),
        "prerequisites": [],
        "allowed_write_roots": [
            "src",
            "tests",
            "docs",
            "scripts",
            ".github",
            "README.md",
            "START_HERE_KO.md",
            "wrangler.toml",
        ],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
        },
    },
    {
        "id": "P02-ORCHESTRATION",
        "title": "Phase 2 - Trusted orchestration and live evidence channel",
        "description": (
            "Operate Codex task contracts, Antigravity leases, trusted reruns, signed "
            "D1 monitoring ingest, publisher restart recovery, and fail-closed status. "
            "The worker task remains network-denied; connected deployment and secret "
            "provisioning are conductor-only operations after enforcement is verified. "
            "Acceptance: before any worker process starts, the runner applies "
            "preemptive filesystem confinement and OS-level deny-by-default network "
            "isolation; post-run filesystem diffs are only secondary detection. A "
            "fresh signed snapshot contains the source commit and task states; stale, "
            "corrupt, replayed, or unsigned data is rejected; GPU telemetry accepts "
            "only devices 0-5 and always rejects 6-7."
        ),
        "prerequisites": ["P01-TRUTH"],
        "allowed_write_roots": [
            "src",
            "tests",
            "docs",
            "scripts",
            "functions",
            "public",
            "migrations",
            ".github",
            "package.json",
            "wrangler.toml",
        ],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
        },
    },
    {
        "id": "P03-EVIDENCE",
        "title": "Phase 3 - Evidence kernel",
        "description": (
            "Create typed Evidence Capsules for every execution: requirement, input, "
            "model, code, environment, world, policy, command, output, verifier, "
            "replay, and rollback provenance. Acceptance: any missing, skipped, "
            "unmeasured, wrong-commit, or unverifiable field makes the release NO_GO."
        ),
        "prerequisites": ["P02-ORCHESTRATION"],
        "allowed_write_roots": ["src", "tests", "docs", "schemas", "scripts"],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
        },
    },
    {
        "id": "P04-WORLD",
        "title": "Phase 4 - ESTC world kernel",
        "description": (
            "Implement Entity-State-Transition-Constraint schemas, World DSL, "
            "belief versus committed state separation, policy verdicts, SSOT commit, "
            "human escalation, and rollback. Acceptance: forbidden transitions never "
            "commit, deterministic state hashes replay, and all verdicts cite evidence."
        ),
        "prerequisites": ["P03-EVIDENCE"],
        "allowed_write_roots": ["src", "tests", "docs", "schemas", "worldpacks"],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
        },
    },
    {
        "id": "P05-FINANCE",
        "title": "Phase 5 - Financial investment World Pack",
        "description": (
            "Implement the first reference World Pack for regime detection, signals, "
            "strategy, portfolio, order proposal, paper execution, reconciliation, "
            "and risk limits. Acceptance: point-in-time and look-ahead guards, fees "
            "and slippage, exposure limits, known-answer backtests, and deterministic "
            "paper-trading reconciliation pass. Live trading is out of scope."
        ),
        "prerequisites": ["P04-WORLD"],
        "allowed_write_roots": [
            "src",
            "tests",
            "docs",
            "schemas",
            "worldpacks/finance",
            "fixtures/finance",
        ],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
        },
    },
    {
        "id": "P06-TWIN",
        "title": "Phase 6 - Agentic Twin and adversarial validation",
        "description": (
            "Build a production-isolated twin with golden scenarios, fault injection, "
            "prompt and tool poisoning tests, policy bypass tests, and rollback drills. "
            "Acceptance: zero critical forbidden commits and reproducible recovery "
            "evidence for every injected failure."
        ),
        "prerequisites": ["P05-FINANCE"],
        "allowed_write_roots": ["src", "tests", "docs", "twin", "fixtures"],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
        },
    },
    {
        "id": "P07-WORKSPACE",
        "title": "Phase 7 - Local agent workspace",
        "description": (
            "Integrate natural conversation, local tools, file/PDF/image attachments, "
            "local RAG, voice, model selection, cancellation, continuation, and bounded "
            "history. Acceptance: no hard-coded answer path, no unbounded repetition, "
            "no silent truncation, explicit capability truth, and offline tool policy."
        ),
        "prerequisites": ["P06-TWIN"],
        "allowed_write_roots": [
            "src",
            "tests",
            "docs",
            "cogniboard",
            "cogni_agent",
            "assets",
        ],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
        },
    },
    {
        "id": "P08-CORE",
        "title": "Phase 8 - Cogni-Core measured integration",
        "description": (
            "Integrate the attested local Gemma backbone in the required order: "
            "DEQ/CTS, System 1.5 Fast Weight, System 2.5 FP-EWC and C-FIRE, "
            "System 3 sparse experts, then System 4 tensor collaboration. Acceptance: "
            "each module remains gated until target-hardware memory, convergence, "
            "latency, finite-value, and fallback evidence passes on GPUs 0-5 only."
        ),
        "prerequisites": ["P07-WORKSPACE"],
        "allowed_write_roots": [
            "src",
            "tests",
            "docs",
            "cogni_core",
            "benchmarks",
            "config",
        ],
        "permissions": {
            "gpu": True,
            "performance_metrics": True,
            "network": False,
        },
    },
    {
        "id": "P09-HARNESS",
        "title": "Phase 9 - Governed Self-Harness",
        "description": (
            "Implement failure collection, bounded patch proposals, isolated regression "
            "and security tests, independent verification, canary promotion, and signed "
            "rollback. Acceptance: inference and evolution are mutually exclusive and "
            "no model or worker can mutate production directly."
        ),
        "prerequisites": ["P08-CORE"],
        "allowed_write_roots": [
            "src",
            "tests",
            "docs",
            "cogni_flow",
            "self_harness",
            "proposals",
        ],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
        },
    },
    {
        "id": "P10-COGNIBOARD",
        "title": "Phase 10 - CogniBoard evidence operations",
        "description": (
            "Deliver operator, developer, and executive views of proposal, verdict, "
            "execution, commit, evidence, replay, rollback, cost, and domain state. "
            "The worker task remains network-denied; connected deployment is a "
            "conductor-only operation after the signed evidence channel and isolation "
            "controls pass. "
            "Acceptance: the UI never displays LIVE or VERIFIED without a fresh, "
            "signed, independently verified snapshot and shows exact blocking reasons."
        ),
        "prerequisites": ["P09-HARNESS"],
        "allowed_write_roots": [
            "src",
            "tests",
            "docs",
            "cogniboard",
            "public",
            "functions",
            "assets",
        ],
        "permissions": {
            "gpu": False,
            "performance_metrics": False,
            "network": False,
        },
    },
    {
        "id": "P11-RELEASE",
        "title": "Phase 11 - Appliance POC and verified release",
        "description": (
            "Package the offline Windows appliance, launcher preflight, SBOM, recovery "
            "image, operations manual, finance POC evidence pack, and reusable Bio and "
            "Defense World Pack contracts. Acceptance: target RTX 4090 runs, 30-run "
            "reproduction, restart recovery, rollback, offline network-zero, installer, "
            "GPU 0-5 enforcement, and customer replay drills all pass before release."
        ),
        "prerequisites": ["P10-COGNIBOARD"],
        "allowed_write_roots": [
            "src",
            "tests",
            "docs",
            "release",
            "launcher",
            "worldpacks",
            "scripts",
        ],
        "permissions": {
            "gpu": True,
            "performance_metrics": True,
            "network": False,
        },
    },
)


def phase_contracts(owner: str = "antigravity") -> list[dict[str, Any]]:
    """Return independent copies of the Phase 1-11 task contracts."""

    contracts = deepcopy(list(ROADMAP_PHASES))
    for contract in contracts:
        contract["owner"] = owner
        contract["gates"] = deepcopy(_STRICT_GATES)
    return contracts


def bootstrap_roadmap(
    workspace: Workspace,
    *,
    actor: str,
    owner: str = "antigravity",
) -> dict[str, Any]:
    """Idempotently register the canonical Phase 1-11 task graph."""

    created: list[str] = []
    existing: list[str] = []
    for contract in phase_contracts(owner):
        task_id = contract["id"]
        try:
            current = workspace.get_task(task_id)
        except ConfigurationError:
            workspace.add_task(
                actor=actor,
                task_id=task_id,
                title=contract["title"],
                description=contract["description"],
                owner=contract["owner"],
                prerequisites=contract["prerequisites"],
                allowed_write_roots=contract["allowed_write_roots"],
                permissions=contract["permissions"],
                gates=contract["gates"],
                idempotency_key=f"cogni-os-roadmap-v1:{task_id}",
            )
            created.append(task_id)
            continue

        expected = {
            "title": contract["title"],
            "description": contract["description"],
            "owner": contract["owner"],
            "prerequisites": contract["prerequisites"],
            "allowed_write_roots": contract["allowed_write_roots"],
            "permissions": contract["permissions"],
            "gates": contract["gates"],
            "idempotency_key": f"cogni-os-roadmap-v1:{task_id}",
        }
        mismatches = [
            key for key, value in expected.items() if current.get(key) != value
        ]
        if mismatches:
            raise ConfigurationError(
                f"Roadmap task {task_id} exists with a different contract: "
                + ", ".join(mismatches)
            )
        existing.append(task_id)

    return {
        "schema_version": 1,
        "roadmap": "Cogni-OS Phase 1-11",
        "created": created,
        "existing": existing,
        "status": roadmap_status(workspace),
    }


def _current_commit(workspace: Workspace) -> str | None:
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={workspace.root.as_posix()}",
                "-C",
                str(workspace.root),
                "rev-parse",
                "HEAD",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = result.stdout.strip().lower()
    if len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit
    ):
        return None
    return commit


def roadmap_status(workspace: Workspace) -> dict[str, Any]:
    """Project evidence-gated roadmap progress without inventing percentages."""

    tasks_by_id = {task["id"]: task for task in workspace.list_tasks()}
    current_commit = _current_commit(workspace)
    phases: list[dict[str, Any]] = []
    trusted_complete = 0
    for contract in phase_contracts():
        task = tasks_by_id.get(contract["id"])
        if task is None:
            state = "missing"
        elif current_commit is None and task.get("state") in {
            "verified",
            "archived",
        }:
            state = "verification_disputed"
        else:
            state = task_trust_state(
                task,
                current_commit=current_commit,
                workspace_root=workspace.root,
            )
        complete = state in {"verified", "archived"}
        if complete:
            trusted_complete += 1
        phases.append(
            {
                "id": contract["id"],
                "title": contract["title"],
                "state": state,
                "trusted_complete": complete,
                "prerequisites": contract["prerequisites"],
            }
        )
    return _roadmap_projection(phases, trusted_complete)


def roadmap_snapshot(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    """Project the canonical roadmap from already trust-normalized task records."""

    tasks_by_id = {str(task.get("id")): task for task in tasks}
    phases: list[dict[str, Any]] = []
    trusted_complete = 0
    for contract in phase_contracts():
        task = tasks_by_id.get(contract["id"])
        state = str(task.get("state", "missing")) if task else "missing"
        complete = state in {"verified", "archived"}
        if complete:
            trusted_complete += 1
        phases.append(
            {
                "id": contract["id"],
                "title": contract["title"],
                "state": state,
                "trusted_complete": complete,
                "prerequisites": contract["prerequisites"],
            }
        )
    return _roadmap_projection(phases, trusted_complete)


def _roadmap_projection(
    phases: list[dict[str, Any]],
    trusted_complete: int,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "total": len(phases),
        "trusted_complete": trusted_complete,
        "progress_percent": round(trusted_complete * 100 / len(phases), 1),
        "progress_basis": "trusted-roadmap-task-states",
        "phases": phases,
    }
