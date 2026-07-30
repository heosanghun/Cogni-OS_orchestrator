"""Workspace and legacy-protocol diagnostics for Cogni-OS."""

from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any

from .errors import CogniError, ConfigurationError
from .model import lease_expired
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
SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pass|token|secret|api[_-]?key)\b"
    r"\s*(?:[:=|]\s*|\s+)([^\s|`]+)"
)


def _scan_secrets(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return findings
    for line_number, line in enumerate(lines, start=1):
        for match in SECRET_RE.finditer(line):
            value = match.group(2)
            if value.lower() in {
                "none",
                "null",
                "[fill]",
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
        result["healthy"] = projection["valid"] and not broker_secret_findings
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
