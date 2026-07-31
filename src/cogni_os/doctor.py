"""Workspace and legacy-protocol diagnostics for Cogni-OS."""

from __future__ import annotations

import re
import secrets
import subprocess
from pathlib import Path
from typing import Any

from .errors import CogniError, ConfigurationError
from .independence import audit_verification_events
from .model import lease_expired
from .trust_projection import task_trust_state
from .workspace import Workspace

LEGACY_REQUIRED = (
    "README.md",
    "shared/RULES.md",
    "shared/ENV.md",
    "shared/FACTS.md",
    "tasks/INBOX_codex.md",
    "tasks/INBOX_antigravity.md",
    "logs/EVENTS.md",
)
EVENT_RE = re.compile(
    r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}\] "
    r"[a-z0-9_-]+ (?:START|DONE|BLOCKED|NOTE) \S+ .+$"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?ix)(?:^|[\s,{])"
    r"[\"']?(password|passwd|pass|token|secret|api[_-]?key)[\"']?"
    r"\s*[:=]\s*[\"']?([^\"'\s,}|`]+)"
)
SECRET_TABLE_RE = re.compile(
    r"(?ix)\|\s*(password|passwd|pass|token|secret|api[_-]?key)"
    r"\s*\|\s*([^|\s`]+)"
)


def _scan_secrets(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return findings
    for line_number, line in enumerate(lines, start=1):
        matches = (
            *SECRET_ASSIGNMENT_RE.finditer(line),
            *SECRET_TABLE_RE.finditer(line),
        )
        for match in matches:
            value = match.group(2)
            if value.lower() in {
                "none",
                "null",
                "[fill]",
                "[redacted]",
                "redacted",
                "false",
                "true",
                "environment",
            }:
                continue
            findings.append(
                {
                    "path": str(path),
                    "line": line_number,
                    "key": match.group(1).lower(),
                    "value": "[REDACTED]",
                }
            )
    return findings


def _current_commit(root: Path) -> str | None:
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={root.as_posix()}",
                "-C",
                str(root),
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


def audit_legacy_workspace(
    root: str | Path,
    *,
    agent_id: str | None = None,
    write_test: bool = False,
) -> dict[str, Any]:
    """Inspect the Markdown-only Antigravity/Codex protocol safely."""
    root_path = Path(root).resolve()
    checks: list[dict[str, Any]] = []
    secret_findings: list[dict[str, Any]] = []
    for relative in LEGACY_REQUIRED:
        path = root_path / relative
        exists = path.is_file()
        readable = False
        error = None
        if exists:
            try:
                path.read_text(encoding="utf-8")
                readable = True
                secret_findings.extend(_scan_secrets(path))
            except (OSError, UnicodeDecodeError) as exc:
                error = str(exc)
        checks.append(
            {
                "path": relative,
                "exists": exists,
                "readable": readable,
                "error": error,
            }
        )

    malformed_events: list[dict[str, Any]] = []
    events_path = root_path / "logs" / "EVENTS.md"
    if events_path.is_file():
        for line_number, line in enumerate(
            events_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not re.match(r"^\[\d{4}-\d{2}-\d{2}", line):
                continue
            if not EVENT_RE.fullmatch(line):
                malformed_events.append({"line": line_number, "text": line})

    write_result: dict[str, Any] = {"tested": False}
    if write_test:
        if not agent_id:
            raise ConfigurationError("agent_id is required for a write test")
        report_dir = root_path / "reports" / agent_id
        if not report_dir.is_dir():
            raise ConfigurationError(
                f"Report directory does not exist for {agent_id}: {report_dir}"
            )
        ping = report_dir / f".cogni-write-test-{secrets.token_hex(6)}.tmp"
        try:
            ping.write_text("write-test\n", encoding="utf-8")
            observed = ping.read_text(encoding="utf-8")
            write_result = {
                "tested": True,
                "writable": observed == "write-test\n",
                "path": str(report_dir),
            }
        except OSError as exc:
            write_result = {
                "tested": True,
                "writable": False,
                "path": str(report_dir),
                "error": str(exc),
            }
        finally:
            try:
                ping.unlink()
            except (FileNotFoundError, OSError):
                pass

    all_readable = all(check["exists"] and check["readable"] for check in checks)
    risks: list[str] = []
    if secret_findings:
        risks.append(
            "Plaintext secret-like values were found; move credentials to environment "
            "variables or an OS secret store before publishing or mirroring this workspace."
        )
    risks.extend(
        [
            "Markdown ownership rules are cooperative, not OS-enforced.",
            "The shared EVENTS.md file has no atomic multi-writer lock or tamper signature.",
            "DONE entries do not mechanically require independent verification.",
            "There is no lease, heartbeat, or stale-worker recovery mechanism.",
        ]
    )
    return {
        "root": str(root_path),
        "compatible": all_readable and not malformed_events,
        "checks": checks,
        "malformed_events": malformed_events,
        "write_test": write_result,
        "secret_findings": secret_findings,
        "risks": risks,
    }


def audit_workspace(
    root: str | Path,
    *,
    legacy_root: str | Path | None = None,
    legacy_agent: str | None = None,
    legacy_write_test: bool = False,
) -> dict[str, Any]:
    """Run integrity and configuration checks for a broker workspace."""
    result: dict[str, Any] = {
        "root": str(Path(root).resolve()),
        "healthy": False,
        "release_ready": False,
        "checks": {},
    }
    try:
        workspace = Workspace(root)
        projection = workspace.audit_projections()
        result["checks"]["integrity"] = projection
        result["checks"]["status"] = workspace.status()
        result["checks"]["agent_directories"] = {
            agent["id"]: {
                "reports": (workspace.reports_dir / agent["id"]).is_dir(),
                "runs": (workspace.runs_dir / agent["id"]).is_dir(),
            }
            for agent in workspace.list_agents()
        }
        expired = [
            task["id"]
            for task in workspace.list_tasks()
            if task["state"] in {"claimed", "running"}
            and lease_expired(task)
        ]
        result["checks"]["expired_leases"] = expired
        broker_secret_findings: list[dict[str, Any]] = []
        for path in (
            [workspace.config_path]
            + sorted(workspace.agents_dir.glob("*.json"))
            + sorted(workspace.tasks_dir.glob("*.json"))
        ):
            broker_secret_findings.extend(_scan_secrets(path))
        result["checks"]["secret_findings"] = broker_secret_findings
        events = workspace.ledger.read()
        agents = {agent["id"]: agent for agent in workspace.list_agents()}
        verification_audit = audit_verification_events(
            events,
            agents,
            orchestrator=workspace.orchestrator,
        )
        result["checks"]["verification_semantics"] = verification_audit

        latest_verification = {
            item["task_id"]: item
            for item in verification_audit["verifications"]
        }
        current_commit = _current_commit(workspace.root)
        current_claims: list[dict[str, Any]] = []
        unacknowledged_claims: list[str] = []
        release_blockers: list[str] = []
        for task in workspace.list_tasks():
            raw_state = str(task.get("state", "pending"))
            if raw_state not in {"verified", "archived"}:
                continue
            audit_record = latest_verification.get(task["id"])
            restatement = (
                audit_record.get("restatement")
                if isinstance(audit_record, dict)
                else None
            )
            if isinstance(restatement, dict):
                effective_state = str(restatement["effective_status"])
                acknowledged = True
            elif current_commit is None:
                effective_state = "verification_disputed"
                acknowledged = False
            else:
                effective_state = task_trust_state(
                    task,
                    current_commit=current_commit,
                    workspace_root=workspace.root,
                )
                acknowledged = effective_state in {"verified", "archived"}
            trusted = effective_state in {"verified", "archived"}
            if not trusted:
                release_blockers.append(task["id"])
                if not acknowledged:
                    unacknowledged_claims.append(task["id"])
            current_claims.append(
                {
                    "task_id": task["id"],
                    "recorded_state": raw_state,
                    "effective_state": effective_state,
                    "trusted": trusted,
                    "restated": isinstance(restatement, dict),
                }
            )

        result["checks"]["current_verification_claims"] = {
            "valid": not unacknowledged_claims,
            "source_commit": current_commit,
            "claims": current_claims,
            "unacknowledged_claims": unacknowledged_claims,
            "release_blockers": release_blockers,
        }
        result["healthy"] = (
            projection["valid"]
            and not broker_secret_findings
            and verification_audit["valid"]
            and not unacknowledged_claims
        )
        result["release_ready"] = result["healthy"] and not release_blockers
    except Exception as exc:
        result["error"] = str(exc)
        result["healthy"] = False

    if legacy_root:
        result["legacy_audit"] = audit_legacy_workspace(
            legacy_root,
            agent_id=legacy_agent,
            write_test=legacy_write_test,
        )
    return result
