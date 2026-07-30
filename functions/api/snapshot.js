// Cloudflare Pages Function: /api/snapshot
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // Sample or dynamic workspace snapshot data
  const defaultSnapshot = {
    schema_version: 1,
    system: "Cogni-OS Orchestrator",
    timestamp: new Date().toISOString(),
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
        status: "IDLE"
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
        status: "STANDBY"
      }
    ],
    tasks_summary: {
      total: 5,
      pending: 1,
      claimed: 1,
      running: 1,
      submitted: 1,
      verified: 1,
      rejected: 0,
      archived: 0,
      completion_percentage: 40.0
    },
    ledger: {
      status: "VERIFIED",
      events_count: 12,
      last_hash: "8f3a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a"
    }
  };

  try {
    // Return snapshot with proper CORS and anti-caching headers
    return new Response(JSON.stringify(defaultSnapshot, null, 2), {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store, no-cache, must-revalidate"
      }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
