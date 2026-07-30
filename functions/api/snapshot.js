// Cloudflare Pages Function: /api/snapshot
export async function onRequest(context) {
  const { request, env } = context;

  const snapshot = {
    schema_version: 1,
    system: "Cogni-OS Operations",
    timestamp: new Date().toISOString(),
    workspace: "Cogni-OS Production Workspace",
    orchestrator: {
      id: "codex",
      role: "Conductor / Director",
      status: "ACTIVE"
    },
    agents: [
      {
        id: "codex",
        role: "orchestrator",
        model_family: "openai-codex",
        status: "ACTIVE"
      },
      {
        id: "antigravity",
        role: "worker",
        model_family: "google-antigravity",
        status: "RUNNING"
      },
      {
        id: "antigravity-verifier",
        role: "verifier",
        model_family: "google-antigravity-verifier",
        status: "ACTIVE"
      }
    ],
    tasks_summary: {
      total: 6,
      pending: 1,
      claimed: 1,
      running: 1,
      submitted: 1,
      verified: 2,
      rejected: 0,
      archived: 0,
      completion_percentage: 33.3
    },
    ledger: {
      status: "VERIFIED",
      events_count: 16,
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
