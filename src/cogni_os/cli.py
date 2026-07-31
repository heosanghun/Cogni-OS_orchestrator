"""Command-line interface for Cogni-OS Orchestrator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .adapter import run_once
from .dashboard import serve_dashboard
from .doctor import audit_legacy_workspace, audit_workspace
from .errors import CogniError
from .evidence import validate_submission
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
            task_id=args.id,
            decision=args.decision,
            note=args.note,
            evidence_path=args.evidence,
            timeout_seconds=args.timeout_seconds,
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
            owner=args.owner,
        )
    )


def _cmd_roadmap_status(args: argparse.Namespace) -> None:
    _emit(roadmap_status(_workspace(args.path)))


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
    p_init.add_argument("--control-principal", default="codex-conductor", help="Orchestrator control principal")
    p_init.add_argument("--model-family", default="openai-codex", help="Orchestrator model family")
    p_init.add_argument("--preset", default="cogni-codex-antigravity", help="Initial workspace preset topology")
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

    # agent subcommands
    p_agent = subparsers.add_parser("agent", help="Manage registered agents")
    agent_subs = p_agent.add_subparsers(dest="agent_command", required=True)

    p_agent_add = agent_subs.add_parser("add", help="Add a new agent")
    p_agent_add.add_argument("path", help="Path to workspace root")
    p_agent_add.add_argument("--actor", required=True, help="Actor executing this command")
    p_agent_add.add_argument("--id", required=True, help="Agent ID")
    p_agent_add.add_argument("--role", default="worker", choices=["orchestrator", "worker", "verifier", "advisor"])
    p_agent_add.add_argument("--mode", default="manual", choices=["manual", "command"])
    p_agent_add.add_argument("--command-json", help="JSON array of command arguments")
    p_agent_add.add_argument("--write-root", action="append", default=[], help="Allowed write roots")
    p_agent_add.add_argument("--control-principal", help="Stable control principal identity")
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
    p_task_add.add_argument("--actor", required=True, help="Actor executing this command")
    p_task_add.add_argument("--id", required=True, help="Task ID")
    p_task_add.add_argument("--owner", required=True, help="Task owner agent ID")
    p_task_add.add_argument("--title", required=True, help="Task title")
    p_task_add.add_argument("--description", help="Task description string")
    p_task_add.add_argument("--description-file", help="Path to file containing task description")
    p_task_add.add_argument("--prerequisite", action="append", default=[], help="Prerequisite task IDs")
    p_task_add.add_argument("--allow-write", action="append", default=[], help="Allowed write directory roots")
    p_task_add.add_argument("--allow-gpu", action="store_true", help="Grant GPU permission")
    p_task_add.add_argument("--allow-performance-metrics", action="store_true", help="Grant performance metrics permission")
    p_task_add.add_argument("--allow-network", action="store_true", help="Grant network permission")
    p_task_add.add_argument("--skip-validation-gate", action="store_true", help="Disable validation gate requirement")
    p_task_add.add_argument("--allow-skipped-checks", action="store_true", help="Allow skipped test checks")
    p_task_add.add_argument("--skip-known-answer-gate", action="store_true", help="Disable known answer gate")
    p_task_add.add_argument("--skip-independent-gate", action="store_true", help="Disable independent verifier gate")
    p_task_add.set_defaults(func=_cmd_task_add)

    p_task_claim = task_subs.add_parser("claim", help="Claim a pending task")
    p_task_claim.add_argument("path", help="Path to workspace root")
    p_task_claim.add_argument("--actor", required=True, help="Actor claiming task")
    p_task_claim.add_argument("--id", help="Specific task ID to claim")
    p_task_claim.add_argument("--lease-seconds", type=int, help="Lease duration in seconds")
    p_task_claim.set_defaults(func=_cmd_task_claim)

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

    p_task_submit = task_subs.add_parser("submit", help="Submit task report and evidence")
    p_task_submit.add_argument("path", help="Path to workspace root")
    p_task_submit.add_argument("--actor", required=True, help="Actor submitting task")
    p_task_submit.add_argument("--id", required=True, help="Task ID")
    p_task_submit.add_argument("--lease-token", required=True, help="Lease token")
    p_task_submit.add_argument("--report", required=True, help="Path to report markdown file")
    p_task_submit.add_argument("--evidence", required=True, help="Path to evidence manifest JSON")
    p_task_submit.set_defaults(func=_cmd_task_submit)

    p_task_verify = task_subs.add_parser("verify", help="Independently verify a submitted task")
    p_task_verify.add_argument("path", help="Path to workspace root")
    p_task_verify.add_argument("--actor", required=True, help="Actor verifying task")
    p_task_verify.add_argument("--id", required=True, help="Task ID")
    p_task_verify.add_argument("--decision", required=True, choices=["accept", "reject"], help="Verification decision")
    p_task_verify.add_argument("--note", required=True, help="Verification rationale note")
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
    p_worker_run.add_argument("--timeout-seconds", type=int, default=3600, help="Command timeout in seconds")
    p_worker_run.set_defaults(func=_cmd_worker_run)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run workspace health audit")
    p_doc.add_argument("path", help="Path to workspace root")
    p_doc.add_argument("--legacy-root", help="Optional legacy markdown workspace root to audit")
    p_doc.add_argument("--legacy-agent", help="Agent ID for legacy write test")
    p_doc.add_argument("--legacy-write-test", action="store_true", help="Perform write permission check on legacy workspace")
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
    try:
        args.func(args)
    except CogniError as exc:
        print(f"Cogni-OS Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
