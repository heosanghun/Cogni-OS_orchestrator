"""Command-line interface for Cogni-OS Orchestrator."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .actor_capability import (
    CAPABILITY_BOOTSTRAP_ENV,
    CAPABILITY_NEW_SECRET_ENV,
    CAPABILITY_SECRET_ENV,
    authority_for_workspace,
)
from .adapter import run_once
from .dashboard import serve_dashboard
from .doctor import audit_workspace
from .errors import CogniError
from .release_evidence import collect_p01_production_evidence
from .release_gate import issue_release_gate, release_gate_status
from .roadmap import bootstrap_roadmap, roadmap_status
from .workspace import Workspace


def _emit(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _read_description(args: argparse.Namespace) -> str:
    if args.description_file:
        return Path(args.description_file).read_text(encoding="utf-8")
    if args.description:
        return args.description
    raise ValueError("Either --description or --description-file is required")


def _parse_command(value: str | None) -> list[str] | None:
    if value is None:
        return None
    parsed = json.loads(value)
    if not isinstance(parsed, list) or not all(
        isinstance(item, str) and item for item in parsed
    ):
        raise ValueError("--command-json must be a JSON array of non-empty strings")
    return parsed


def _workspace(path: str) -> Workspace:
    return Workspace(Path(path))


def _secret_argument(args: argparse.Namespace, name: str) -> bytes | None:
    value = getattr(args, name, None)
    return value if isinstance(value, bytes) else None


def _cmd_init(args: argparse.Namespace) -> None:
    workspace = Workspace.initialize(
        args.path,
        name=args.name,
        orchestrator=args.orchestrator,
        orchestrator_control_principal=args.control_principal,
        orchestrator_model_family=args.model_family,
        preset=args.preset,
    )
    _emit(workspace.status())


def _cmd_status(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit({"status": workspace.status(), "tasks": workspace.list_tasks()})


def _cmd_agent_add(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    record = workspace.add_agent(
        actor=args.actor,
        capability_secret=_secret_argument(args, "_capability_secret"),
        agent_id=args.id,
        role=args.role,
        mode=args.mode,
        command=_parse_command(args.command_json),
        write_roots=args.write_root,
        control_principal=args.control_principal,
        model_family=args.model_family,
        alias_of=args.alias_of,
    )
    _emit(record)


def _cmd_agent_list(args: argparse.Namespace) -> None:
    _emit(_workspace(args.path).list_agents())


def _cmd_task_add(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    permissions = {
        "gpu": args.allow_gpu,
        "performance_metrics": args.allow_performance_metrics,
        "network": args.allow_network,
    }
    gates = {
        "require_validation": not args.skip_validation_gate,
        "allow_skips": args.allow_skipped_checks,
        "require_known_answer_check": not args.skip_known_answer_gate,
        "require_independent_verification": not args.skip_independent_gate,
    }
    task = workspace.add_task(
        actor=args.actor,
        capability_secret=_secret_argument(args, "_capability_secret"),
        task_id=args.id,
        title=args.title,
        description=_read_description(args),
        owner=args.owner,
        prerequisites=args.prerequisite,
        allowed_write_roots=args.allow_write,
        permissions=permissions,
        gates=gates,
    )
    _emit(task)


def _cmd_task_claim(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        workspace.claim(
            actor=args.actor,
            task_id=args.id,
            lease_seconds=args.lease_seconds,
        )
    )


def _cmd_task_recover_lease(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        workspace.recover_lease(
            actor=args.actor,
            task_id=args.id,
            reason=args.reason,
            force=args.force,
            capability_secret=_secret_argument(args, "_capability_secret"),
        )
    )


def _cmd_task_start(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        workspace.start(
            actor=args.actor,
            task_id=args.id,
            lease_token=args.lease_token,
        )
    )


def _cmd_task_heartbeat(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        workspace.heartbeat(
            actor=args.actor,
            task_id=args.id,
            lease_token=args.lease_token,
        )
    )


def _cmd_task_block(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        workspace.block(
            actor=args.actor,
            task_id=args.id,
            lease_token=args.lease_token,
            reason=args.reason,
        )
    )


def _cmd_task_submit(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        workspace.submit(
            actor=args.actor,
            task_id=args.id,
            lease_token=args.lease_token,
            report_path=args.report,
            evidence_path=args.evidence,
        )
    )


def _cmd_task_verify(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        workspace.verify(
            actor=args.actor,
            capability_secret=_secret_argument(args, "_capability_secret"),
            task_id=args.id,
            decision=args.decision,
            note=args.note,
            evidence_path=args.evidence,
            timeout_seconds=args.timeout_seconds,
        )
    )


def _cmd_task_reconcile_verification(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        workspace.reconcile_verification(
            actor=args.actor,
            capability_secret=_secret_argument(args, "_capability_secret"),
            task_id=args.id,
            run_id=args.run_id,
        )
    )


def _cmd_task_restate_verification(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        workspace.restate_verification(
            actor=args.actor,
            capability_secret=_secret_argument(args, "_capability_secret"),
            task_id=args.id,
            effective_status=args.status,
            reason=args.reason,
            target_sequence=args.target_sequence,
        )
    )


def _cmd_task_list(args: argparse.Namespace) -> None:
    _emit(_workspace(args.path).list_tasks())


def _cmd_task_show(args: argparse.Namespace) -> None:
    _emit(_workspace(args.path).get_task(args.id))


def _cmd_worker_run(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(
        run_once(
            workspace,
            agent_id=args.agent,
            task_id=args.task_id,
            timeout_seconds=args.timeout_seconds,
        )
    )


def _cmd_doctor(args: argparse.Namespace) -> None:
    _emit(
        audit_workspace(
            args.path,
            legacy_root=args.legacy_root,
            legacy_agent=args.legacy_agent,
            legacy_write_test=args.legacy_write_test,
        )
    )


def _cmd_dashboard(args: argparse.Namespace) -> None:
    serve_dashboard(args.path, host=args.host, port=args.port)


def _cmd_roadmap_bootstrap(args: argparse.Namespace) -> None:
    _emit(
        bootstrap_roadmap(
            _workspace(args.path),
            actor=args.actor,
            capability_secret=_secret_argument(args, "_capability_secret"),
            owner=args.owner,
        )
    )


def _cmd_roadmap_status(args: argparse.Namespace) -> None:
    _emit(roadmap_status(_workspace(args.path)))


def _cmd_release_evidence_collect(args: argparse.Namespace) -> None:
    _emit(
        collect_p01_production_evidence(
            _workspace(args.path),
            actor=args.actor,
            capability_secret=_secret_argument(args, "_capability_secret"),
            cloudflare_account_id=args.cloudflare_account_id,
            deployment_id=args.deployment_id,
            deployment_source_commit=args.deployment_source_commit,
            rollback_deployment_id=args.rollback_deployment_id,
            rollback_source_commit=args.rollback_source_commit,
        )
    )


def _cmd_release_gate_issue(args: argparse.Namespace) -> None:
    _emit(
        issue_release_gate(
            _workspace(args.path),
            actor=args.actor,
            capability_secret=_secret_argument(args, "_capability_secret"),
            attesting_agent_id=args.attesting_agent,
        )
    )


def _cmd_release_gate_status(args: argparse.Namespace) -> None:
    _emit(
        release_gate_status(
            _workspace(args.path),
            expected_source_commit=args.expected_source_commit,
        )
    )


def _cmd_capability_status(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    _emit(authority_for_workspace(workspace).status(actor=args.actor))


def _cmd_capability_bootstrap(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    secret = _secret_argument(args, "_capability_bootstrap_secret")
    if secret is None:
        # The authority emits a stable fail-closed error and never creates a
        # guard from an actor label alone.
        secret = b""
    _emit(
        authority_for_workspace(workspace).bootstrap(
            actor=args.actor,
            bootstrap_secret=secret,
        )
    )


def _cmd_capability_rotate(args: argparse.Namespace) -> None:
    workspace = _workspace(args.path)
    authority = authority_for_workspace(workspace)
    current_secret = _secret_argument(args, "_capability_secret")
    new_secret = _secret_argument(args, "_capability_new_secret")
    # mint() / rotate() fail closed before key replacement if either secret is
    # unavailable or wrong.
    rotation_token = authority.mint(
        actor=args.actor,
        operation="capability.rotate",
        credential_secret=current_secret or b"",
    )
    _emit(
        authority.rotate(
            actor=args.actor,
            rotation_token=rotation_token,
            new_secret=new_secret or b"",
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cogni",
        description="Cogni-OS: Evidence-First Multi-Agent Orchestrator CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Initialize a Cogni-OS workspace")
    p_init.add_argument("path", help="Path to workspace root")
    p_init.add_argument("--name", default="", help="Workspace display name")
    p_init.add_argument("--orchestrator", default="codex", help="Orchestrator agent ID")
    p_init.add_argument(
        "--control-principal",
        default="codex-conductor",
        help="Orchestrator control principal",
    )
    p_init.add_argument(
        "--model-family", default="openai-codex", help="Orchestrator model family"
    )
    p_init.add_argument(
        "--preset",
        default="cogni-codex-antigravity",
        help="Initial workspace preset topology",
    )
    p_init.set_defaults(func=_cmd_init)

    # status
    p_status = subparsers.add_parser("status", help="Display workspace status")
    p_status.add_argument("path", help="Path to workspace root")
    p_status.set_defaults(func=_cmd_status)

    # evidence-gated Phase 1-11 roadmap
    p_roadmap = subparsers.add_parser(
        "roadmap",
        help="Manage the canonical Cogni-OS Phase 1-11 task graph",
    )
    roadmap_subs = p_roadmap.add_subparsers(
        dest="roadmap_command",
        required=True,
    )
    p_roadmap_bootstrap = roadmap_subs.add_parser(
        "bootstrap",
        help="Idempotently register Phase 1-11 task contracts",
    )
    p_roadmap_bootstrap.add_argument("path", help="Path to workspace root")
    p_roadmap_bootstrap.add_argument(
        "--actor",
        default="codex",
        help="Accountable orchestrator actor",
    )
    p_roadmap_bootstrap.add_argument(
        "--owner",
        default="antigravity",
        help="Primary executant for roadmap tasks",
    )
    p_roadmap_bootstrap.set_defaults(func=_cmd_roadmap_bootstrap)

    p_roadmap_status = roadmap_subs.add_parser(
        "status",
        help="Show progress from verified or archived roadmap tasks only",
    )
    p_roadmap_status.add_argument("path", help="Path to workspace root")
    p_roadmap_status.set_defaults(func=_cmd_roadmap_status)

    # actor capability lifecycle. Guard provisioning is intentionally not
    # exposed here; it belongs to an ACL-isolated installer/OS-admin context.
    p_capability = subparsers.add_parser(
        "capability",
        help="Inspect or consume externally provisioned actor capabilities",
    )
    capability_subs = p_capability.add_subparsers(
        dest="capability_command",
        required=True,
    )
    p_cap_status = capability_subs.add_parser(
        "status",
        help="Report fail-closed capability provisioning state without secrets",
    )
    p_cap_status.add_argument("path", help="Path to workspace root")
    p_cap_status.add_argument("--actor", required=True, help="Registered actor ID")
    p_cap_status.set_defaults(func=_cmd_capability_status)

    p_cap_bootstrap = capability_subs.add_parser(
        "bootstrap",
        help=(
            "Consume a pre-provisioned OS-admin guard; secret is read only from "
            f"{CAPABILITY_BOOTSTRAP_ENV}"
        ),
    )
    p_cap_bootstrap.add_argument("path", help="Path to workspace root")
    p_cap_bootstrap.add_argument("--actor", required=True, help="Registered actor ID")
    p_cap_bootstrap.set_defaults(func=_cmd_capability_bootstrap)

    p_cap_rotate = capability_subs.add_parser(
        "rotate",
        help=(
            "Rotate an actor key using current/new secrets supplied through "
            f"{CAPABILITY_SECRET_ENV} and {CAPABILITY_NEW_SECRET_ENV}"
        ),
    )
    p_cap_rotate.add_argument("path", help="Path to workspace root")
    p_cap_rotate.add_argument("--actor", required=True, help="Registered actor ID")
    p_cap_rotate.set_defaults(func=_cmd_capability_rotate)

    # conductor-only production release evidence
    p_release = subparsers.add_parser(
        "release",
        help="Manage conductor-owned release operations",
    )
    release_subs = p_release.add_subparsers(
        dest="release_command",
        required=True,
    )
    p_release_evidence = release_subs.add_parser(
        "evidence",
        help="Manage immutable production release evidence",
    )
    release_evidence_subs = p_release_evidence.add_subparsers(
        dest="release_evidence_command",
        required=True,
    )
    p_release_collect = release_evidence_subs.add_parser(
        "collect",
        help="Capture pinned P01 production endpoints and bind the bundle to the ledger",
    )
    p_release_collect.add_argument("path", help="Path to workspace root")
    p_release_collect.add_argument(
        "--actor",
        required=True,
        help="Accountable workspace orchestrator",
    )
    p_release_collect.add_argument(
        "--cloudflare-account-id",
        required=True,
        help="Cloudflare account identifier (API token is read from the environment)",
    )
    p_release_collect.add_argument(
        "--deployment-id",
        required=True,
        help="Cloudflare Pages production deployment identifier",
    )
    p_release_collect.add_argument(
        "--deployment-source-commit",
        required=True,
        help="Full Git commit declared for the production deployment",
    )
    p_release_collect.add_argument(
        "--rollback-deployment-id",
        required=True,
        help="Previously known-good Cloudflare Pages deployment identifier",
    )
    p_release_collect.add_argument(
        "--rollback-source-commit",
        required=True,
        help="Full Git commit declared for the rollback deployment",
    )
    p_release_collect.set_defaults(func=_cmd_release_evidence_collect)

    p_release_gate = release_subs.add_parser(
        "gate",
        help="Issue or validate the immutable content-addressed release gate",
    )
    release_gate_subs = p_release_gate.add_subparsers(
        dest="release_gate_command",
        required=True,
    )
    p_release_gate_issue = release_gate_subs.add_parser(
        "issue",
        help="Bind the clean source, current task proofs, production evidence, and attestation",
    )
    p_release_gate_issue.add_argument("path", help="Path to workspace root")
    p_release_gate_issue.add_argument(
        "--actor",
        required=True,
        help="Accountable workspace orchestrator",
    )
    p_release_gate_issue.add_argument(
        "--attesting-agent",
        required=True,
        help="Registered agent with a fresh file-backed attestation",
    )
    p_release_gate_issue.set_defaults(func=_cmd_release_gate_issue)

    p_release_gate_status = release_gate_subs.add_parser(
        "status",
        help="Validate the current commit's signed release gate fail-closed",
    )
    p_release_gate_status.add_argument("path", help="Path to workspace root")
    p_release_gate_status.add_argument(
        "--expected-source-commit",
        help="Optional full commit expected at workspace HEAD",
    )
    p_release_gate_status.set_defaults(func=_cmd_release_gate_status)

    # agent subcommands
    p_agent = subparsers.add_parser("agent", help="Manage registered agents")
    agent_subs = p_agent.add_subparsers(dest="agent_command", required=True)

    p_agent_add = agent_subs.add_parser("add", help="Add a new agent")
    p_agent_add.add_argument("path", help="Path to workspace root")
    p_agent_add.add_argument(
        "--actor", required=True, help="Actor executing this command"
    )
    p_agent_add.add_argument("--id", required=True, help="Agent ID")
    p_agent_add.add_argument(
        "--role",
        default="worker",
        choices=["orchestrator", "worker", "verifier", "advisor"],
    )
    p_agent_add.add_argument("--mode", default="manual", choices=["manual", "command"])
    p_agent_add.add_argument("--command-json", help="JSON array of command arguments")
    p_agent_add.add_argument(
        "--write-root", action="append", default=[], help="Allowed write roots"
    )
    p_agent_add.add_argument(
        "--control-principal", help="Stable control principal identity"
    )
    p_agent_add.add_argument("--model-family", help="Stable model family identity")
    p_agent_add.add_argument("--alias-of", help="Agent ID this agent is an alias of")
    p_agent_add.set_defaults(func=_cmd_agent_add)

    p_agent_list = agent_subs.add_parser("list", help="List registered agents")
    p_agent_list.add_argument("path", help="Path to workspace root")
    p_agent_list.set_defaults(func=_cmd_agent_list)

    # task subcommands
    p_task = subparsers.add_parser("task", help="Manage task lifecycle")
    task_subs = p_task.add_subparsers(dest="task_command", required=True)

    p_task_add = task_subs.add_parser("add", help="Add a new task")
    p_task_add.add_argument("path", help="Path to workspace root")
    p_task_add.add_argument(
        "--actor", required=True, help="Actor executing this command"
    )
    p_task_add.add_argument("--id", required=True, help="Task ID")
    p_task_add.add_argument("--owner", required=True, help="Task owner agent ID")
    p_task_add.add_argument("--title", required=True, help="Task title")
    p_task_add.add_argument("--description", help="Task description string")
    p_task_add.add_argument(
        "--description-file", help="Path to file containing task description"
    )
    p_task_add.add_argument(
        "--prerequisite", action="append", default=[], help="Prerequisite task IDs"
    )
    p_task_add.add_argument(
        "--allow-write",
        action="append",
        default=[],
        help="Allowed write directory roots",
    )
    p_task_add.add_argument(
        "--allow-gpu", action="store_true", help="Grant GPU permission"
    )
    p_task_add.add_argument(
        "--allow-performance-metrics",
        action="store_true",
        help="Grant performance metrics permission",
    )
    p_task_add.add_argument(
        "--allow-network", action="store_true", help="Grant network permission"
    )
    p_task_add.add_argument(
        "--skip-validation-gate",
        action="store_true",
        help="Disable validation gate requirement",
    )
    p_task_add.add_argument(
        "--allow-skipped-checks", action="store_true", help="Allow skipped test checks"
    )
    p_task_add.add_argument(
        "--skip-known-answer-gate",
        action="store_true",
        help="Disable known answer gate",
    )
    p_task_add.add_argument(
        "--skip-independent-gate",
        action="store_true",
        help="Disable independent verifier gate",
    )
    p_task_add.set_defaults(func=_cmd_task_add)

    p_task_claim = task_subs.add_parser("claim", help="Claim a pending task")
    p_task_claim.add_argument("path", help="Path to workspace root")
    p_task_claim.add_argument("--actor", required=True, help="Actor claiming task")
    p_task_claim.add_argument("--id", help="Specific task ID to claim")
    p_task_claim.add_argument(
        "--lease-seconds", type=int, help="Lease duration in seconds"
    )
    p_task_claim.set_defaults(func=_cmd_task_claim)

    p_task_recover = task_subs.add_parser(
        "recover-lease",
        help="Conductor-only recovery of a lost active task lease",
    )
    p_task_recover.add_argument("path", help="Path to workspace root")
    p_task_recover.add_argument(
        "--actor",
        required=True,
        help="Accountable orchestrator recovering the lease",
    )
    p_task_recover.add_argument("--id", required=True, help="Task ID")
    p_task_recover.add_argument(
        "--reason",
        required=True,
        help="Non-empty operational reason for recovery",
    )
    p_task_recover.add_argument(
        "--force",
        action="store_true",
        help="Exceptional capability-gated recovery of a non-expired lease",
    )
    p_task_recover.set_defaults(func=_cmd_task_recover_lease)

    p_task_start = task_subs.add_parser("start", help="Start a claimed task")
    p_task_start.add_argument("path", help="Path to workspace root")
    p_task_start.add_argument("--actor", required=True, help="Actor starting task")
    p_task_start.add_argument("--id", required=True, help="Task ID")
    p_task_start.add_argument("--lease-token", required=True, help="Lease token")
    p_task_start.set_defaults(func=_cmd_task_start)

    p_task_hb = task_subs.add_parser("heartbeat", help="Heartbeat task lease")
    p_task_hb.add_argument("path", help="Path to workspace root")
    p_task_hb.add_argument("--actor", required=True, help="Actor heartbeating task")
    p_task_hb.add_argument("--id", required=True, help="Task ID")
    p_task_hb.add_argument("--lease-token", required=True, help="Lease token")
    p_task_hb.set_defaults(func=_cmd_task_heartbeat)

    p_task_block = task_subs.add_parser("block", help="Block a running task")
    p_task_block.add_argument("path", help="Path to workspace root")
    p_task_block.add_argument("--actor", required=True, help="Actor blocking task")
    p_task_block.add_argument("--id", required=True, help="Task ID")
    p_task_block.add_argument("--lease-token", required=True, help="Lease token")
    p_task_block.add_argument("--reason", required=True, help="Block reason")
    p_task_block.set_defaults(func=_cmd_task_block)

    p_task_submit = task_subs.add_parser(
        "submit", help="Submit task report and evidence"
    )
    p_task_submit.add_argument("path", help="Path to workspace root")
    p_task_submit.add_argument("--actor", required=True, help="Actor submitting task")
    p_task_submit.add_argument("--id", required=True, help="Task ID")
    p_task_submit.add_argument("--lease-token", required=True, help="Lease token")
    p_task_submit.add_argument(
        "--report", required=True, help="Path to report markdown file"
    )
    p_task_submit.add_argument(
        "--evidence", required=True, help="Path to evidence manifest JSON"
    )
    p_task_submit.set_defaults(func=_cmd_task_submit)

    p_task_verify = task_subs.add_parser(
        "verify", help="Independently verify a submitted task"
    )
    p_task_verify.add_argument("path", help="Path to workspace root")
    p_task_verify.add_argument("--actor", required=True, help="Actor verifying task")
    p_task_verify.add_argument("--id", required=True, help="Task ID")
    p_task_verify.add_argument(
        "--decision",
        required=True,
        choices=["accept", "reject"],
        help="Verification decision",
    )
    p_task_verify.add_argument(
        "--note", required=True, help="Verification rationale note"
    )
    p_task_verify.add_argument(
        "--evidence",
        required=True,
        help="Path to independently produced verifier evidence manifest JSON",
    )
    p_task_verify.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="Per-command trusted verifier timeout (1-300 seconds)",
    )
    p_task_verify.set_defaults(func=_cmd_task_verify)

    p_task_reconcile = task_subs.add_parser(
        "reconcile-verification",
        help="Close an orphan verification or rebuild its signed projection",
    )
    p_task_reconcile.add_argument("path", help="Path to workspace root")
    p_task_reconcile.add_argument(
        "--actor",
        required=True,
        help="Accountable orchestrator reconciling the run",
    )
    p_task_reconcile.add_argument("--id", required=True, help="Task ID")
    p_task_reconcile.add_argument(
        "--run-id",
        required=True,
        help="32-character verification run identifier",
    )
    p_task_reconcile.set_defaults(func=_cmd_task_reconcile_verification)

    p_task_restate = task_subs.add_parser(
        "restate-verification",
        help="Append a trust correction without rewriting verification history",
    )
    p_task_restate.add_argument("path", help="Path to workspace root")
    p_task_restate.add_argument(
        "--actor",
        required=True,
        help="Accountable orchestrator recording the correction",
    )
    p_task_restate.add_argument("--id", required=True, help="Task ID")
    p_task_restate.add_argument(
        "--status",
        required=True,
        choices=["verification_disputed", "verification_revoked"],
        help="Effective trust status after the correction",
    )
    p_task_restate.add_argument(
        "--reason",
        required=True,
        help="Evidence-based correction rationale",
    )
    p_task_restate.add_argument(
        "--target-sequence",
        type=int,
        help="Exact task.verified ledger sequence; defaults to the latest",
    )
    p_task_restate.set_defaults(func=_cmd_task_restate_verification)

    p_task_list = task_subs.add_parser("list", help="List all tasks")
    p_task_list.add_argument("path", help="Path to workspace root")
    p_task_list.set_defaults(func=_cmd_task_list)

    p_task_show = task_subs.add_parser("show", help="Show task details")
    p_task_show.add_argument("path", help="Path to workspace root")
    p_task_show.add_argument("--id", required=True, help="Task ID")
    p_task_show.set_defaults(func=_cmd_task_show)

    # worker
    p_worker = subparsers.add_parser("worker", help="Command worker actions")
    worker_subs = p_worker.add_subparsers(dest="worker_command", required=True)
    p_worker_run = worker_subs.add_parser("run", help="Run once using command adapter")
    p_worker_run.add_argument("path", help="Path to workspace root")
    p_worker_run.add_argument("--agent", required=True, help="Agent ID")
    p_worker_run.add_argument("--task-id", help="Task ID (optional)")
    p_worker_run.add_argument(
        "--timeout-seconds", type=int, default=3600, help="Command timeout in seconds"
    )
    p_worker_run.set_defaults(func=_cmd_worker_run)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run workspace health audit")
    p_doc.add_argument("path", help="Path to workspace root")
    p_doc.add_argument(
        "--legacy-root", help="Optional legacy markdown workspace root to audit"
    )
    p_doc.add_argument("--legacy-agent", help="Agent ID for legacy write test")
    p_doc.add_argument(
        "--legacy-write-test",
        action="store_true",
        help="Perform write permission check on legacy workspace",
    )
    p_doc.set_defaults(func=_cmd_doctor)

    # dashboard
    p_dash = subparsers.add_parser("dashboard", help="Start local web dashboard")
    p_dash.add_argument("path", help="Path to workspace root")
    p_dash.add_argument("--host", default="127.0.0.1", help="Dashboard listen host")
    p_dash.add_argument("--port", type=int, default=8484, help="Dashboard listen port")
    p_dash.set_defaults(func=_cmd_dashboard)

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Secrets are never accepted through argv.  Remove them before invoking any
    # operation that can spawn a child process; only private bytes on Namespace
    # remain for the duration of this command.
    capability_secret = os.environ.pop(CAPABILITY_SECRET_ENV, None)
    bootstrap_secret = os.environ.pop(CAPABILITY_BOOTSTRAP_ENV, None)
    new_secret = os.environ.pop(CAPABILITY_NEW_SECRET_ENV, None)
    args._capability_secret = (
        capability_secret.encode("utf-8") if capability_secret is not None else None
    )
    args._capability_bootstrap_secret = (
        bootstrap_secret.encode("utf-8") if bootstrap_secret is not None else None
    )
    args._capability_new_secret = (
        new_secret.encode("utf-8") if new_secret is not None else None
    )
    try:
        args.func(args)
    except CogniError as exc:
        print(f"Cogni-OS Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 - final CLI process boundary
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
