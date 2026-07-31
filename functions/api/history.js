import {
  errorResponse,
  jsonResponse,
  parseHmacKeys,
  verifyStoredRow,
} from "../_lib/monitoring.js";

function boundedLimit(request) {
  const url = new URL(request.url);
  const requested = Number(url.searchParams.get("limit") || 60);
  if (!Number.isInteger(requested)) return 60;
  return Math.min(240, Math.max(1, requested));
}

async function projectHistoryRow(row, hmacKeys) {
  const secret = hmacKeys.get(row.key_id);
  if (!secret) {
    throw new Error("stored snapshot publisher key is not active");
  }
  const payload = await verifyStoredRow(row, secret);
  return {
    sequence: Number(row.sequence),
    observed_at: row.observed_at,
    received_at: row.received_at,
    body_sha256: row.body_sha256,
    tasks_summary: payload.tasks_summary || {},
    roadmap: payload.roadmap || {},
    gpus: payload.gpus || [],
    resources: payload.resources || {},
    release_gate: payload.release_gate || { status: "NO_GO" },
  };
}

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "GET") {
    return errorResponse("METHOD_NOT_ALLOWED", "GET 요청만 허용됩니다.", 405);
  }
  const workspaceId =
    typeof env.COGNI_WORKSPACE_ID === "string" ? env.COGNI_WORKSPACE_ID : null;
  let hmacKeys;
  try {
    hmacKeys = parseHmacKeys(env.INGEST_HMAC_KEYS);
  } catch {
    hmacKeys = null;
  }
  if (!env.MONITOR_DB || !workspaceId || !hmacKeys) {
    return jsonResponse({
      ok: false,
      state: "UNCONFIGURED",
      history: [],
    });
  }
  try {
    const result = await env.MONITOR_DB.prepare(
      `SELECT workspace_id, sequence, observed_at, received_at, nonce,
              key_id, body_sha256, signature, payload
       FROM monitor_history
       WHERE workspace_id = ?1
       ORDER BY sequence DESC
       LIMIT ?2`,
    )
      .bind(workspaceId, boundedLimit(request))
      .all();
    const history = (
      await Promise.all(
        (result.results || []).map((row) =>
          projectHistoryRow(row, hmacKeys),
        ),
      )
    ).reverse();
    return jsonResponse({
      ok: true,
      state: "AVAILABLE",
      workspace_id: workspaceId,
      history,
    });
  } catch (error) {
    const message = String(error?.message || error);
    return jsonResponse({
      ok: false,
      state: /no such table/i.test(message)
        ? "UNCONFIGURED"
        : /stored snapshot|signature|hash|payload|JSON/i.test(message)
          ? "CORRUPT"
          : "STORAGE_ERROR",
      history: [],
    });
  }
}
