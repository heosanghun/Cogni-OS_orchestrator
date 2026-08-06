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
    schema_version: "1.2",
    system: "Cogni-OS Operations",
    timestamp: now,
    workspace_id: "visual-test",
    workspace_name: "Cogni-OS Evidence Operations",
    sequence: 42,
    observed_at: now,
    collector: {
      id: "visual-test-publisher",
      version: "1.0",
      host: "visual-test-host",
      platform: "win32",
      attribution: {
        source_commit: "a".repeat(40),
        source_tree_clean: false,
        source_tree_fingerprint: "b".repeat(64),
        entrypoint_sha256: "c".repeat(64),
      },
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
      verification_revoked: 0,
      rejected: 0,
      current_release_validated: 0,
      completion_percentage: 0,
      progress_basis: "historically-trusted-ledger-task-states",
    },
    roadmap: {
      schema_version: 1,
      total: 11,
      trusted_complete: 0,
      current_release_validated: 0,
      progress_percent: 0,
      progress_basis: "historically-trusted-roadmap-task-states",
      phases: [
        "P01-TRUTH",
        "P02-ORCHESTRATION",
        "P03-EVIDENCE",
        "P04-WORLD",
        "P05-FINANCE",
        "P06-TWIN",
        "P07-WORKSPACE",
        "P08-CORE",
        "P09-HARNESS",
        "P10-COGNIBOARD",
        "P11-RELEASE",
      ].map((id, index, phaseIds) => ({
        id,
        title: `Phase ${index + 1}`,
        state: "missing",
        trusted_complete: false,
        verified_source_commit: null,
        current_release_state: "missing",
        current_release_validated: false,
        prerequisites: index === 0 ? [] : [phaseIds[index - 1]],
      })),
    },
    agents: [
      {
        id: "codex",
        role: "orchestrator",
        status: "READY",
        mode: "conductor",
        current_task: "T-002",
        task_progress: 55,
        next_step: "독립 재현",
        attestation_evidence_sha256: "c".repeat(64),
        attested_at: now,
        attested_source_commit: "a".repeat(40),
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
        title: "Legacy trust audit",
        owner: "antigravity",
        state: "verification_disputed",
        raw_state: "verified",
        historical_state: "verification_disputed",
        historical_trusted: false,
        verified_source_commit: null,
        current_release_state: "verification_disputed",
        current_release_validated: false,
        progress: null,
        next_step: "신뢰 실행기로 재검증",
        updated_at: now,
      },
      {
        id: "T-002",
        title: "Operational task",
        owner: "codex",
        state: "running",
        raw_state: "running",
        historical_state: "running",
        historical_trusted: false,
        verified_source_commit: null,
        current_release_state: "running",
        current_release_validated: false,
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
        task_title: "Operational task",
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
      measurement_complete: true,
      source_states: {
        telemetry: "MEASURED",
        processes: "MEASURED",
        containers: "MEASURED",
        scheduler: "MEASURED",
      },
      evidence_counts: {
        processes: 0,
        container_claims: 0,
        scheduler_reservations: 0,
      },
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
    release_deployment: {
      provider: "cloudflare-pages",
      api_verified: true,
      deployment_id: "deployment-current",
      deployment_url:
        "https://deployment-current.cogni-os-orchestrator.pages.dev",
      canonical_url: "https://cogni-os-orchestrator.pages.dev",
      source_commit: "a".repeat(40),
    },
    source: {
      git_commit: "a".repeat(40),
      status_scope: "trusted-source-v1",
      tree_clean: false,
      tree_fingerprint: "e".repeat(64),
      change_count: 1,
      operational_state: {
        valid: false,
        change_count: 1,
        fingerprint: "f".repeat(64),
        unclassified_count: 1,
        unclassified_fingerprint: "1".repeat(64),
        unbound_count: 0,
        hash_mismatch_count: 0,
        reference_count: 0,
        conflict_count: 0,
        missing_count: 0,
        audit_fingerprint: "2".repeat(64),
      },
      task_projection_audit: {
        valid: false,
        events_count: 1,
        projected_count: 1,
        actual_count: 2,
        mismatch_count: 1,
      },
    },
    deployment: {
      provider: "cloudflare-pages",
      project: "cogni-os-orchestrator",
      environment: "production",
      source_commit: "a".repeat(40),
      branch: "main",
      url: "https://cogni-os-orchestrator.pages.dev",
      deployment_url:
        "https://deployment-current.cogni-os-orchestrator.pages.dev",
      attribution: "BUILD_BOUND",
    },
  };
}

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`dashboard-test-server http://127.0.0.1:${port}\n`);
});
