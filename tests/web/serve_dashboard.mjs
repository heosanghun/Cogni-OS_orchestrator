import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";

import { failClosedSnapshot } from "../../functions/_lib/monitoring.js";

const root = normalize(new URL("../../public/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const port = Number(process.env.PORT || 8789);
const testState = process.env.TEST_STATE || "UNCONFIGURED";
const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const server = createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  if (url.pathname === "/api/snapshot") {
    response.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    });
    response.end(JSON.stringify(snapshotFixture(testState)));
    return;
  }
  if (url.pathname === "/api/history") {
    response.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    response.end(
      JSON.stringify({
        ok: testState === "LIVE",
        state: testState,
        history: [],
      }),
    );
    return;
  }
  const requested = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const path = normalize(join(root, requested));
  if (!path.startsWith(root)) {
    response.writeHead(403);
    response.end("forbidden");
    return;
  }
  try {
    const body = await readFile(path);
    response.writeHead(200, {
      "Content-Type": contentTypes[extname(path)] || "application/octet-stream",
    });
    response.end(body);
  } catch {
    response.writeHead(404);
    response.end("not found");
  }
});

function snapshotFixture(state) {
  if (state === "LIVE") return liveFixture();
  if (state === "STALE") {
    return failClosedSnapshot(
      "STALE",
      "마지막 서명 스냅샷이 허용된 최신성 한계를 초과했습니다.",
      {
        workspaceId: "visual-test",
      },
    );
  }
  if (state === "CORRUPT") {
    return failClosedSnapshot(
      "CORRUPT",
      "저장된 스냅샷의 본문 해시 또는 서명 검증에 실패했습니다.",
      {
        workspaceId: "visual-test",
      },
    );
  }
  return failClosedSnapshot(
    "UNCONFIGURED",
    "로컬 시각 검증: D1과 publisher를 연결하기 전 상태입니다.",
  );
}

function liveFixture() {
  const now = new Date().toISOString();
  return {
    schema_version: "1.0",
    system: "Cogni-OS Operations",
    timestamp: now,
    workspace_id: "visual-test",
    workspace_name: "Cogni-OS Visual Test",
    sequence: 42,
    observed_at: now,
    collector: {
      id: "visual-test-publisher",
      version: "1.0",
      host: "visual-test-host",
      platform: "win32",
    },
    data_classification: "operational-metadata-only",
    orchestrator: {
      id: "codex",
      role: "orchestrator",
      status: "READY",
    },
    monitoring: {
      state: "LIVE",
      reason: "로컬 시각 검증용 서명 fixture",
      signature_verified: true,
      sequence: 42,
      age_seconds: 1.2,
      observed_at: now,
      received_at: now,
      body_sha256: "a".repeat(64),
    },
    tasks_summary: {
      total: 2,
      pending: 0,
      claimed: 0,
      running: 1,
      blocked: 0,
      submitted: 0,
      trusted_verified: 0,
      verification_disputed: 1,
      rejected: 0,
      completion_percentage: 0,
      progress_basis: "trusted-ledger-task-states",
    },
    agents: [
      {
        id: "codex",
        role: "orchestrator",
        status: "READY",
        mode: "conductor",
        current_task: "신뢰 검증 커널",
        task_progress: 55,
        next_step: "독립 재현",
        attestation_evidence_sha256: "c".repeat(64),
        attested_at: now,
        attested_source_commit: "abcdef0123456789",
      },
      {
        id: "antigravity",
        role: "worker",
        status: "UNATTESTED",
        mode: "manual",
        current_task: null,
        task_progress: null,
        next_step: "실행 주체 attestation",
      },
    ],
    tasks: [
      {
        id: "T-001",
        title: "Release Truth",
        owner: "antigravity",
        state: "verification_disputed",
        progress: null,
        next_step: "신뢰 실행기로 재검증",
        updated_at: now,
      },
      {
        id: "T-002",
        title: "Trusted Monitoring",
        owner: "codex",
        state: "running",
        progress: 55,
        next_step: "부정 테스트",
        updated_at: now,
      },
    ],
    ledger_events: [
      {
        timestamp: now,
        actor: "codex",
        action: "task.started",
        task_id: "T-002",
        task_title: "Trusted Monitoring",
        event_hash: "d".repeat(64),
      },
    ],
    ledger: {
      status: "VERIFIED",
      valid: true,
      events: 42,
      head: "b".repeat(64),
      signed: true,
    },
    gpus: [
      {
        id: 0,
        name: "NVIDIA RTX A6000",
        utilization: 27,
        vram_used_gib: 12.5,
        vram_total_gib: 48,
        temperature_c: 48,
        power_w: 92,
      },
      {
        id: 5,
        name: "NVIDIA RTX A6000",
        utilization: 0,
        vram_used_gib: 0.02,
        vram_total_gib: 48,
        temperature_c: 34,
        power_w: 24,
      },
    ],
    gpu_policy: {
      allowed_ids: [0, 1, 2, 3, 4, 5],
      denied_ids: [6, 7],
      telemetry_state: "MEASURED",
      violating_ids: [],
    },
    resources: {
      memory: { used_gib: 31.2, total_gib: 251.5, percent: 12.4 },
      disk: { used_gib: 3203.6, total_gib: 3666.4, percent: 87.4 },
      load_average_1m: 2.14,
      uptime_seconds: 4406400,
    },
    alerts: [
      {
        severity: "critical",
        code: "UNTRUSTED_VERIFICATION",
        message: "T-001은 독립 재현 증거가 부족합니다.",
        observed_at: now,
      },
    ],
    release_gate: {
      status: "NO_GO",
      reasons: ["T-001 재검증 필요"],
      evidence_sha256: null,
    },
    source: {
      git_commit: "abcdef0123456789",
      tree_clean: false,
      tree_fingerprint: "e".repeat(64),
      change_count: 1,
      task_projection_audit: {
        valid: false,
        events_count: 1,
        projected_count: 1,
        actual_count: 2,
        mismatch_count: 1,
      },
    },
  };
}

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`dashboard-test-server http://127.0.0.1:${port}\n`);
});
