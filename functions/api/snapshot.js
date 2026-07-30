// Cloudflare Pages Function: /api/snapshot (Cogni-OS Operations System 1.5 Specification)
export async function onRequest(context) {
  const { request } = context;

  const snapshot = {
    schema_version: "1.0",
    system: "Cogni-OS Operations System 1.5",
    timestamp: new Date().toISOString(),
    workspace: "Cogni-OS Production Cluster",
    orchestrator: {
      id: "codex",
      role: "Conductor / Director",
      status: "ACTIVE"
    },
    tasks_summary: {
      total: 20,
      pending: 1,
      claimed: 1,
      running: 1,
      submitted: 1,
      verified: 14,
      rejected: 2,
      archived: 0,
      completion_percentage: 82.0
    },
    agents: [
      {
        id: "Codex",
        role: "메타 오케스트레이터",
        role_description: "메타 오케스트레이터 (Conductor)",
        status: "작업 중",
        current_task: "Recover accurate agent cards with verified local implementation",
        task_progress: 55,
        next_step: "증거 번들 제출",
        model_family: "openai-codex"
      },
      {
        id: "Antigravity",
        role: "연구 운영기록",
        role_description: "연구 수행 작업자 (Primary Executant)",
        status: "작업 중",
        current_task: "Probe: can a verifier-role agent verify",
        task_progress: 65,
        next_step: "수정 후 재제출",
        model_family: "google-antigravity"
      },
      {
        id: "Antigravity-Verifier",
        role: "구현검증 작업자",
        role_description: "독립 검증 작업자 (Independent Reviewer)",
        status: "대기",
        current_task: "Publish verified P1b statistics tools",
        task_progress: 100,
        next_step: "독립 검증 완료 보관",
        model_family: "google-antigravity-verifier"
      }
    ],
    gpus: [
      { id: 0, name: "NVIDIA RTX A6000", utilization: 98, vram_used: 24.0, vram_total: 48.0, temperature: 55, power: 140 },
      { id: 1, name: "NVIDIA RTX A6000", utilization: 0, vram_used: 0.0, vram_total: 48.0, temperature: 42, power: 25 },
      { id: 2, name: "NVIDIA RTX A6000", utilization: 0, vram_used: 0.0, vram_total: 48.0, temperature: 41, power: 27 },
      { id: 3, name: "NVIDIA RTX A6000", utilization: 0, vram_used: 0.0, vram_total: 48.0, temperature: 42, power: 23 },
      { id: 4, name: "NVIDIA RTX A6000", utilization: 0, vram_used: 0.0, vram_total: 48.0, temperature: 39, power: 27 },
      { id: 5, name: "NVIDIA RTX A6000", utilization: 0, vram_used: 0.0, vram_total: 48.0, temperature: 40, power: 21 },
      { id: 6, name: "NVIDIA RTX A6000", utilization: 0, vram_used: 0.0, vram_total: 48.0, temperature: 41, power: 21 },
      { id: 7, name: "NVIDIA RTX A6000", utilization: 0, vram_used: 0.0, vram_total: 48.0, temperature: 41, power: 26 }
    ],
    tasks: [
      { id: "A-G1", title: "Make the A-plan G1 gate actually fire", owner: "antigravity-worker", state: "verified", progress: 100, next_step: "검증 결과 보관", updated_at: "07. 30. 10:51:53" },
      { id: "C1", title: "verify_backbone: common entry validation no silent fallback", owner: "antigravity-worker", state: "verified", progress: 100, next_step: "검증 결과 보관", updated_at: "07. 30. 13:34:43" },
      { id: "C3", title: "B023_closure_capture_site_audit", owner: "antigravity-verifier", state: "verified", progress: 100, next_step: "검증 결과 보관", updated_at: "07. 30. 14:10:40" },
      { id: "EFO-1", title: "Proxy submission for workers that cannot reach the workspace", owner: "codex", state: "verified", progress: 100, next_step: "검증 결과 보관", updated_at: "07. 30. 13:28:52" },
      { id: "EFO-2", title: "Independent verification is not actually independent", owner: "codex", state: "verified", progress: 100, next_step: "검증 결과 보관", updated_at: "07. 30. 12:40:09" },
      { id: "EFO-3", title: "Transport-attested external worker progress", owner: "codex", state: "verified", progress: 100, next_step: "검증 결과 보관", updated_at: "07. 30. 20:35:33" },
      { id: "EFO-4R", title: "Recover accurate agent cards with verified local implementation", owner: "codex", state: "running", progress: 55, next_step: "증거 번들 제출", updated_at: "07. 30. 23:26:06" },
      { id: "GATE-PROBE-2", title: "Probe: can a verifier-role agent verify", owner: "antigravity-worker", state: "rejected", progress: 65, next_step: "수정 후 재제출", updated_at: "07. 29. 16:52:03" },
      { id: "P1b-8", title: "Freeze run identity and repeat topology before outcome access", owner: "antigravity-verifier", state: "verified", progress: 100, next_step: "검증 결과 보관", updated_at: "07. 30. 22:24:30" }
    ],
    ledger_events: [
      { time: "23:26", actor: "Codex", action: "task.heartbeat", action_label: "진행 신호", task_title: "EFO-4R · Recover accurate agent cards with verified local implementation" },
      { time: "23:07", actor: "Codex", action: "task.started", action_label: "작업 시작", task_title: "EFO-4R · Recover accurate agent cards with verified local implementation" },
      { time: "23:07", actor: "Codex", action: "task.claimed", action_label: "작업 할당", task_title: "EFO-4R · Recover accurate agent cards with verified local implementation" },
      { time: "23:07", actor: "Antigravity", action: "task.created", action_label: "작업 생성", task_title: "EFO-4R · Recover accurate agent cards with verified local implementation" },
      { time: "22:24", actor: "Codex", action: "task.verified", action_label: "검증 통과", task_title: "P1b-8 · Freeze run identity and repeat topology before outcome access" },
      { time: "22:16", actor: "Antigravity", action: "task.submitted", action_label: "증거 제출", task_title: "P1b-8 · Freeze run identity and repeat topology before outcome access" }
    ],
    ledger: {
      status: "VERIFIED",
      events_count: 132,
      last_hash: "9c3ec5c475b7cc0a95698d2c1c17fbd9ae598c5c237c7bcfd3b652d20eab6482"
    }
  };

  return new Response(JSON.stringify(snapshot, null, 2), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store, no-cache, must-revalidate"
    }
  });
}
