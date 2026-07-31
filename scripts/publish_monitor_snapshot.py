#!/usr/bin/env python3
"""Publish a signed, metadata-only Cogni-OS operations snapshot.

This process is an optional outbound monitoring gateway. It is deliberately
separate from Cogni-Core inference, never accepts inbound control, and exports
only the allowlisted operational schema consumed by Cloudflare Pages.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cogni_os.lock import FileLock
from cogni_os.roadmap import roadmap_snapshot
from cogni_os.trust_projection import task_trust_state
from cogni_os.workspace import Workspace

COLLECTOR_VERSION = "1.0.0"
INGEST_PROTOCOL = "COGNI-SNAPSHOT-V2"
DEFAULT_ENDPOINT = "https://cogni-os-orchestrator.pages.dev/api/ingest"
DEFAULT_ENDPOINT_HOST = "cogni-os-orchestrator.pages.dev"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def signature_message(
    *,
    key_id: str,
    workspace_id: str,
    sequence: int,
    observed_at: str,
    nonce: str,
    body_sha256: str,
) -> bytes:
    return "\n".join(
        (
            INGEST_PROTOCOL,
            key_id,
            workspace_id,
            str(sequence),
            observed_at,
            nonce,
            body_sha256,
        )
    ).encode("utf-8")


def hmac_signature(secret: str, message: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def validate_publish_endpoint(
    endpoint: str,
    *,
    allowed_hosts: set[str] | None = None,
) -> str:
    parsed = urlsplit(endpoint)
    allowed = {
        host.strip().lower()
        for host in (allowed_hosts or {DEFAULT_ENDPOINT_HOST})
        if isinstance(host, str) and host.strip()
    }
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or not hostname
        or hostname not in allowed
        or parsed.port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/api/ingest"
    ):
        raise RuntimeError(
            "Monitoring endpoint must be an allowlisted HTTPS host on "
            "port 443 with the exact /api/ingest path"
        )
    return parsed.geturl()


def collector_host_id(workspace_id: str) -> str:
    """Return a stable pseudonym without publishing the machine hostname."""

    material = f"{workspace_id}\0{socket.gethostname()}".encode("utf-8")
    return "host-" + hashlib.sha256(material).hexdigest()[:16]


def git_commit(root: Path) -> str:
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
        value = result.stdout.strip().lower()
        if 7 <= len(value) <= 64:
            return value
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def git_tree_status(root: Path) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={root.as_posix()}",
                "-C",
                str(root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        normalized = "\n".join(
            line.rstrip() for line in result.stdout.splitlines() if line.strip()
        )
        changes = normalized.splitlines() if normalized else []
        return {
            "clean": not changes,
            "change_count": len(changes),
            "fingerprint": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        }
    except (OSError, subprocess.SubprocessError):
        return {
            "clean": False,
            "change_count": 1,
            "fingerprint": hashlib.sha256(b"git-status-unavailable").hexdigest(),
        }


def export_tasks(
    tasks: list[dict[str, Any]],
    *,
    current_commit: str | None = None,
    workspace_root: Path | None = None,
) -> list[dict[str, Any]]:
    exported: list[dict[str, Any]] = []
    for task in tasks:
        trust_state = task_trust_state(
            task,
            current_commit=current_commit,
            workspace_root=workspace_root,
        )
        measured_progress = task.get("measured_progress")
        if not isinstance(measured_progress, (int, float)) or not math.isfinite(
            float(measured_progress)
        ):
            measured_progress = (
                100 if trust_state in {"verified", "archived"} else None
            )
        exported.append(
            {
                "id": str(task.get("id", "unknown"))[:128],
                "title": str(task.get("title", "제목 없음"))[:1024],
                "owner": str(task.get("owner", "unassigned"))[:128],
                "state": trust_state,
                "raw_state": str(task.get("state", "unknown"))[:64],
                "progress": measured_progress,
                "next_step": _next_step(trust_state),
                "updated_at": str(task.get("updated_at") or utc_now()),
                "attempt": int(task.get("attempt", 0) or 0),
            }
        )
    return exported


def _next_step(state: str) -> str:
    return {
        "pending": "작업 선점 대기",
        "claimed": "실행 시작",
        "running": "증거 포함 구현 계속",
        "blocked": "차단 원인 해소",
        "submitted": "독립 검증 대기",
        "verified": "검증 증거 보관",
        "verification_disputed": "신뢰 실행기로 재검증",
        "rejected": "수정 후 재제출",
        "archived": "보관",
        "invalidated": "교정 태스크 생성",
    }.get(state, "상태 확인")


def task_summary(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(task["state"] for task in tasks)
    total = len(tasks)
    trusted_complete = counts["verified"] + counts["archived"]
    completion = (trusted_complete / total * 100.0) if total else None
    return {
        "total": total,
        "pending": counts["pending"],
        "claimed": counts["claimed"],
        "running": counts["running"],
        "blocked": counts["blocked"],
        "submitted": counts["submitted"],
        "trusted_verified": counts["verified"] + counts["archived"],
        "verification_disputed": counts["verification_disputed"],
        "rejected": counts["rejected"],
        "completion_percentage": round(completion, 1) if completion is not None else None,
        "progress_basis": "trusted-ledger-task-states",
    }


def export_agents(
    workspace: Workspace,
    tasks: list[dict[str, Any]],
    commit: str,
) -> list[dict[str, Any]]:
    active_states = {"claimed", "running", "submitted"}
    result: list[dict[str, Any]] = []
    for path in sorted(workspace.agents_dir.glob("*.json")):
        try:
            agent = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        agent_id = str(agent.get("id", path.stem))
        current = next(
            (
                task
                for task in sorted(
                    tasks,
                    key=lambda item: str(item.get("updated_at", "")),
                    reverse=True,
                )
                if task.get("owner") == agent_id and task.get("state") in active_states
            ),
            None,
        )
        attestation = agent.get("runtime_attestation")
        status = "UNATTESTED"
        attestation_evidence_sha256 = None
        attested_at = None
        attested_source_commit = None
        if agent.get("mode") == "command" and agent.get("command"):
            status = "CONFIGURED"
        if isinstance(attestation, dict) and attestation.get("ready") is True:
            observed = _parse_timestamp(attestation.get("observed_at"))
            evidence_hash = str(attestation.get("evidence_sha256", "")).lower()
            commit_matches = attestation.get("source_commit") == commit
            evidence_valid = len(evidence_hash) == 64 and all(
                char in "0123456789abcdef" for char in evidence_hash
            )
            evidence_path_value = attestation.get("evidence_path")
            evidence_file_valid = False
            if isinstance(evidence_path_value, str) and evidence_path_value:
                candidate = (workspace.root / evidence_path_value).resolve()
                try:
                    candidate.relative_to(workspace.root.resolve())
                    evidence_file_valid = (
                        candidate.is_file() and _sha256_file(candidate) == evidence_hash
                    )
                except ValueError:
                    evidence_file_valid = False
            if (
                observed
                and 0 <= (datetime.now(UTC) - observed).total_seconds() <= 90
                and evidence_valid
                and evidence_file_valid
                and commit_matches
            ):
                status = "READY"
                attestation_evidence_sha256 = evidence_hash
                attested_at = str(attestation.get("observed_at"))
                attested_source_commit = commit
        result.append(
            {
                "id": agent_id[:128],
                "role": str(agent.get("role", "unknown"))[:128],
                "status": status,
                "current_task": str(current.get("title"))[:1024] if current else None,
                "task_progress": current.get("progress") if current else None,
                "next_step": current.get("next_step") if current else "실행 주체 attestation 대기",
                "mode": str(agent.get("mode", "unknown"))[:64],
                "attestation_evidence_sha256": attestation_evidence_sha256,
                "attested_at": attested_at,
                "attested_source_commit": attested_source_commit,
            }
        )
    return result


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _finite_float(value: str, default: float = 0.0) -> float:
    try:
        parsed = float(value)
        return parsed if math.isfinite(parsed) else default
    except (TypeError, ValueError):
        return default


def collect_gpus(
    enabled: bool,
) -> tuple[list[dict[str, Any]], str, list[int]]:
    if not enabled:
        return [], "DISABLED", []
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=index,uuid,name,utilization.gpu,memory.used,memory.total,"
                "temperature.gpu,power.draw",
                "--format=csv,noheader,nounits",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return [], "UNAVAILABLE", []
    gpus: list[dict[str, Any]] = []
    violating_ids: set[int] = set()
    for line in result.stdout.splitlines():
        fields = [field.strip() for field in line.split(",")]
        if len(fields) != 8:
            continue
        try:
            gpu_id = int(fields[0])
        except ValueError:
            continue
        utilization = _finite_float(fields[3])
        memory_used_mib = _finite_float(fields[4])
        if gpu_id in {6, 7}:
            if utilization > 0 or memory_used_mib > 128:
                violating_ids.add(gpu_id)
            continue
        if gpu_id < 0 or gpu_id > 5:
            continue
        gpus.append(
            {
                "id": gpu_id,
                "name": fields[2][:256],
                "utilization": utilization,
                "vram_used_gib": round(memory_used_mib / 1024, 3),
                "vram_total_gib": round(_finite_float(fields[5]) / 1024, 3),
                "temperature_c": _finite_float(fields[6]),
                "power_w": _finite_float(fields[7]),
            }
        )
    visible = os.environ.get("CUDA_VISIBLE_DEVICES", "")
    for token in visible.split(","):
        token = token.strip()
        if token in {"6", "7"}:
            violating_ids.add(int(token))
    state = "POLICY_VIOLATION" if violating_ids else "MEASURED"
    return sorted(gpus, key=lambda item: item["id"]), state, sorted(violating_ids)


def collect_resources(root: Path) -> dict[str, Any]:
    disk = shutil.disk_usage(root)
    resources: dict[str, Any] = {
        "disk": {
            "used_gib": round(disk.used / (1024**3), 2),
            "total_gib": round(disk.total / (1024**3), 2),
            "percent": round(disk.used / disk.total * 100, 1) if disk.total else None,
        },
        "memory": None,
        "load_average_1m": None,
        "uptime_seconds": None,
    }
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        values: dict[str, int] = {}
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            key, _, raw = line.partition(":")
            if raw:
                values[key] = int(raw.strip().split()[0]) * 1024
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        resources["memory"] = {
            "used_gib": round((total - available) / (1024**3), 2),
            "total_gib": round(total / (1024**3), 2),
            "percent": round((total - available) / total * 100, 1) if total else None,
        }
    try:
        resources["load_average_1m"] = round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):
        pass
    uptime = Path("/proc/uptime")
    if uptime.is_file():
        resources["uptime_seconds"] = int(float(uptime.read_text().split()[0]))
    return resources


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_gate(
    root: Path,
    commit: str,
    tasks: list[dict[str, Any]],
    agents: list[dict[str, Any]],
    ledger: dict[str, Any],
    tree: dict[str, Any],
    projection_audit: dict[str, Any],
    gpu_violations: list[int],
) -> dict[str, Any]:
    reasons: list[str] = []
    if any(task["state"] == "verification_disputed" for task in tasks):
        reasons.append("증거가 부족한 VERIFIED 태스크가 있습니다.")
    if any(task["state"] not in {"verified", "archived"} for task in tasks):
        reasons.append("모든 릴리스 태스크가 신뢰 검증을 완료하지 않았습니다.")
    if not ledger.get("valid") or not ledger.get("signed"):
        reasons.append("원장이 서명 검증을 통과하지 않았습니다.")
    if not tree.get("clean"):
        reasons.append("소스 트리에 커밋되지 않은 변경이 있습니다.")
    if not projection_audit.get("valid"):
        reasons.append("태스크 원장과 projection 파일이 일치하지 않습니다.")
    if gpu_violations:
        reasons.append(
            "사용 금지 GPU가 활성 상태입니다: "
            + ", ".join(f"GPU {gpu_id}" for gpu_id in gpu_violations)
        )
    contract_path = root / "release" / "RELEASE_GATE.json"
    contract: dict[str, Any] | None = None
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        reasons.append("서명된 RELEASE_GATE.json이 없습니다.")
    evidence_hash = None
    if contract:
        evidence_hash = str(contract.get("evidence_sha256", "")).lower()
        if contract.get("status") != "PASS":
            reasons.append("릴리스 계약 상태가 PASS가 아닙니다.")
        if contract.get("source_commit") != commit:
            reasons.append("릴리스 계약의 소스 커밋이 현재 커밋과 다릅니다.")
        if len(evidence_hash) != 64 or any(
            char not in "0123456789abcdef" for char in evidence_hash
        ):
            reasons.append("릴리스 계약의 증거 SHA-256이 유효하지 않습니다.")
        evidence_path_value = contract.get("evidence_path")
        evidence_path: Path | None = None
        if not isinstance(evidence_path_value, str) or not evidence_path_value:
            reasons.append("릴리스 계약의 evidence_path가 없습니다.")
        else:
            candidate = (root / evidence_path_value).resolve()
            try:
                candidate.relative_to(root.resolve())
                evidence_path = candidate
            except ValueError:
                reasons.append("릴리스 증거 경로가 workspace 밖을 가리킵니다.")
        if evidence_path is not None:
            if not evidence_path.is_file():
                reasons.append("릴리스 증거 파일이 존재하지 않습니다.")
            elif _sha256_file(evidence_path) != evidence_hash:
                reasons.append("릴리스 증거 파일의 SHA-256이 계약과 다릅니다.")
        if contract.get("ledger_head") != ledger.get("head"):
            reasons.append("릴리스 계약의 원장 head가 현재 원장과 다릅니다.")
        if contract.get("source_tree_sha256") != tree.get("fingerprint"):
            reasons.append("릴리스 계약의 소스 트리 지문이 현재 트리와 다릅니다.")
        expected_tasks = sorted(
            task["id"] for task in tasks if task["state"] in {"verified", "archived"}
        )
        contract_tasks = contract.get("trusted_verified_task_ids")
        if not isinstance(contract_tasks, list) or sorted(contract_tasks) != expected_tasks:
            reasons.append("릴리스 계약의 신뢰 검증 태스크 집합이 현재 상태와 다릅니다.")
        if not any(
            agent.get("status") in {"READY", "BUSY"}
            and agent.get("attestation_evidence_sha256") == evidence_hash
            and agent.get("attested_source_commit") == commit
            for agent in agents
        ):
            reasons.append(
                "현재 소스와 릴리스 증거에 결합된 실행 주체 attestation이 없습니다."
            )
    return {
        "status": "PASS" if not reasons else "NO_GO",
        "reasons": reasons,
        "evidence_sha256": evidence_hash if not reasons else None,
    }


def build_snapshot(
    workspace: Workspace,
    *,
    sequence: int,
    include_gpu: bool,
) -> dict[str, Any]:
    observed_at = utc_now()
    raw_tasks = workspace.list_tasks()
    ledger = workspace.ledger.verify()
    events = workspace.ledger.read()
    commit = git_commit(workspace.root)
    tasks = export_tasks(
        raw_tasks,
        current_commit=commit,
        workspace_root=workspace.root,
    )
    tree = git_tree_status(workspace.root)
    raw_projection_audit = workspace.audit_projections()
    projection_audit = {
        "valid": bool(raw_projection_audit.get("valid")),
        "events_count": int(raw_projection_audit.get("events_count", 0) or 0),
        "projected_count": int(raw_projection_audit.get("projected_count", 0) or 0),
        "actual_count": int(raw_projection_audit.get("actual_count", 0) or 0),
        "mismatch_count": len(raw_projection_audit.get("mismatches", []) or []),
    }
    agents = export_agents(workspace, tasks, commit)
    gpus, telemetry_state, gpu_violations = collect_gpus(include_gpu)
    gate = release_gate(
        workspace.root,
        commit,
        tasks,
        agents,
        ledger,
        tree,
        projection_audit,
        gpu_violations,
    )
    alerts: list[dict[str, Any]] = []
    disputed = [task["id"] for task in tasks if task["state"] == "verification_disputed"]
    if disputed:
        alerts.append(
            {
                "severity": "critical",
                "code": "UNTRUSTED_VERIFICATION",
                "message": "독립 재현 증거가 없는 VERIFIED 태스크: " + ", ".join(disputed),
                "observed_at": observed_at,
            }
        )
    if gpu_violations:
        alerts.append(
            {
                "severity": "critical",
                "code": "GPU_POLICY_VIOLATION",
                "message": "사용 금지 GPU가 활성 상태입니다: "
                + ", ".join(f"GPU {gpu_id}" for gpu_id in gpu_violations),
                "observed_at": observed_at,
            }
        )
    if not tree["clean"]:
        alerts.append(
            {
                "severity": "critical",
                "code": "DIRTY_SOURCE_TREE",
                "message": "커밋되지 않은 소스 변경 때문에 릴리스 증거가 무효입니다.",
                "observed_at": observed_at,
            }
        )
    resources = collect_resources(workspace.root)
    disk = resources.get("disk") or {}
    if isinstance(disk.get("percent"), (int, float)) and disk["percent"] >= 90:
        alerts.append(
            {
                "severity": "warning",
                "code": "DISK_PRESSURE",
                "message": f"저장공간 사용률 {disk['percent']}%",
                "observed_at": observed_at,
            }
        )
    title_by_id = {task["id"]: task["title"] for task in tasks}
    return {
        "schema_version": "1.0",
        "system": "Cogni-OS Operations",
        "workspace_id": str(workspace.config["workspace_id"]),
        "workspace_name": str(workspace.config["name"]),
        "sequence": sequence,
        "observed_at": observed_at,
        "collector": {
            "id": "cogni-monitor-publisher",
            "version": COLLECTOR_VERSION,
            "host": collector_host_id(str(workspace.config["workspace_id"])),
            "platform": platform.system(),
        },
        "data_classification": "operational-metadata-only",
        "orchestrator": {
            "id": workspace.orchestrator,
            "role": "conductor",
            "status": "ACCOUNTABLE_NOT_ATTESTED",
        },
        "tasks_summary": task_summary(tasks),
        "roadmap": roadmap_snapshot(tasks),
        "agents": agents,
        "tasks": tasks,
        "ledger_events": [
            {
                "timestamp": event.get("timestamp"),
                "actor": str(event.get("actor", "unknown"))[:128],
                "action": str(event.get("action", "unknown"))[:128],
                "task_id": event.get("task_id"),
                "task_title": title_by_id.get(str(event.get("task_id"))),
                "event_hash": event.get("event_hash"),
            }
            for event in events[-100:]
        ],
        "ledger": {
            "status": "VERIFIED" if ledger["valid"] else "NOT_VERIFIED",
            "valid": bool(ledger["valid"]),
            "events": int(ledger["events"]),
            "head": str(ledger["head"]),
            "signed": bool(ledger.get("signed", False)),
        },
        "gpus": gpus,
        "gpu_policy": {
            "allowed_ids": [0, 1, 2, 3, 4, 5],
            "denied_ids": [6, 7],
            "telemetry_state": telemetry_state,
            "violating_ids": gpu_violations,
        },
        "resources": resources,
        "alerts": alerts,
        "release_gate": gate,
        "source": {
            "git_commit": commit,
            "tree_clean": bool(tree["clean"]),
            "tree_fingerprint": str(tree["fingerprint"]),
            "change_count": int(tree["change_count"]),
            "task_projection_audit": projection_audit,
        },
    }


def _state_path(workspace: Workspace, state_dir: Path | None = None) -> Path:
    root = state_dir if state_dir is not None else workspace.control_dir
    return root / "monitor_publish_state.json"


def next_sequence(
    workspace: Workspace,
    *,
    state_dir: Path | None = None,
) -> int:
    state_path = _state_path(workspace, state_dir)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    sequence = peek_next_sequence(workspace, state_dir=state_dir)
    temporary = state_path.with_suffix(f".tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(
            {"last_sequence": sequence, "reserved_at": utc_now()},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, state_path)
    return sequence


def peek_next_sequence(
    workspace: Workspace,
    *,
    state_dir: Path | None = None,
) -> int:
    """Read the next sequence without mutating the workspace."""

    state_path = _state_path(workspace, state_dir)
    try:
        current = json.loads(state_path.read_text(encoding="utf-8"))
        return int(current.get("last_sequence", 0)) + 1
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 1


def publish(
    *,
    endpoint: str,
    allowed_hosts: set[str] | None = None,
    key_id: str,
    secret: str,
    snapshot: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    endpoint = validate_publish_endpoint(
        endpoint,
        allowed_hosts=allowed_hosts,
    )
    if not math.isfinite(timeout) or timeout < 1 or timeout > 60:
        raise RuntimeError("Publisher timeout must be between 1 and 60 seconds")
    body = canonical_json(snapshot)
    body_sha256 = hashlib.sha256(body).hexdigest()
    nonce = secrets.token_urlsafe(24)
    message = signature_message(
        key_id=key_id,
        workspace_id=snapshot["workspace_id"],
        sequence=snapshot["sequence"],
        observed_at=snapshot["observed_at"],
        nonce=nonce,
        body_sha256=body_sha256,
    )
    signature = hmac_signature(secret, message)
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": f"Cogni-Monitor-Publisher/{COLLECTOR_VERSION}",
            "X-Cogni-Key-Id": key_id,
            "X-Cogni-Workspace": snapshot["workspace_id"],
            "X-Cogni-Sequence": str(snapshot["sequence"]),
            "X-Cogni-Observed-At": snapshot["observed_at"],
            "X-Cogni-Nonce": nonce,
            "X-Cogni-Signature": f"sha256={signature}",
        },
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            response_bytes = response.read(64 * 1024 + 1)
            if len(response_bytes) > 64 * 1024:
                raise RuntimeError("ingest response exceeded the 64 KiB limit")
            payload = json.loads(response_bytes.decode("utf-8"))
            if response.status != 202 or payload.get("ok") is not True:
                raise RuntimeError(f"ingest rejected with HTTP {response.status}")
            return payload
    except urllib.error.HTTPError as error:
        body_text = error.read().decode("utf-8", errors="replace")[:2048]
        raise RuntimeError(f"ingest failed HTTP {error.code}: {body_text}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"ingest connection failed: {error.reason}") from error


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Publish a signed Cogni-OS monitoring snapshot.",
    )
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument(
        "--allowed-endpoint-host",
        action="append",
        default=[],
        help=(
            "Explicit additional HTTPS hostname allowed to receive operational "
            "metadata. The production Pages host is always allowed."
        ),
    )
    parser.add_argument(
        "--secret-env",
        default="COGNI_MONITOR_INGEST_SECRET",
        help="Environment variable that holds the HMAC secret.",
    )
    parser.add_argument(
        "--key-id",
        default=os.environ.get("COGNI_MONITOR_KEY_ID", ""),
        help="Publisher key id registered in the Cloudflare secret keyring.",
    )
    parser.add_argument("--include-gpu", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--state-dir",
        type=Path,
        help=(
            "Writable publisher-only sequence and lock directory. "
            "Defaults to the Cogni workspace control directory."
        ),
    )
    parser.add_argument("--interval-seconds", type=float, default=0.0)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    return parser.parse_args(argv)


def run_once(args: argparse.Namespace, workspace: Workspace) -> None:
    if args.dry_run:
        snapshot = build_snapshot(
            workspace,
            sequence=peek_next_sequence(
                workspace,
                state_dir=args.state_dir,
            ),
            include_gpu=args.include_gpu,
        )
        print(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return
    lock_root = args.state_dir or workspace.control_dir
    with FileLock(lock_root / "locks" / "monitor-publisher.lock"):
        sequence = next_sequence(
            workspace,
            state_dir=args.state_dir,
        )
        snapshot = build_snapshot(
            workspace,
            sequence=sequence,
            include_gpu=args.include_gpu,
        )
    secret = os.environ.get(args.secret_env, "")
    if len(secret) < 32:
        raise RuntimeError(
            f"{args.secret_env} must contain an HMAC secret of at least 32 characters"
        )
    if (
        not 3 <= len(args.key_id) <= 64
        or any(
            not (char.isalnum() or char in "._:-")
            for char in args.key_id
        )
    ):
        raise RuntimeError(
            "--key-id or COGNI_MONITOR_KEY_ID must be a safe 3-64 character id"
        )
    accepted = publish(
        endpoint=args.endpoint,
        allowed_hosts={
            DEFAULT_ENDPOINT_HOST,
            *args.allowed_endpoint_host,
        },
        key_id=args.key_id,
        secret=secret,
        snapshot=snapshot,
        timeout=args.timeout_seconds,
    )
    acknowledgement = accepted["accepted"]
    print(
        "accepted "
        f"sequence={acknowledgement['sequence']} "
        f"sha256={acknowledgement['body_sha256']}"
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    workspace = Workspace(args.workspace.resolve())
    while True:
        try:
            run_once(args, workspace)
        except Exception as error:
            print(f"monitor publisher error: {error}", file=sys.stderr)
            if args.interval_seconds <= 0:
                return 1
        if args.interval_seconds <= 0:
            return 0
        time.sleep(max(5.0, args.interval_seconds))


if __name__ == "__main__":
    raise SystemExit(main())
