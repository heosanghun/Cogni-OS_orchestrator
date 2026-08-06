import {
  DEFAULT_MAX_AGE_SECONDS,
  bindDeploymentTruth,
  deploymentAttribution,
  errorResponse,
  failClosedSnapshot,
  jsonResponse,
  parseHmacKeys,
  verifyStoredRow,
  withMonitoringEnvelope,
} from "../_lib/monitoring.js";

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "GET" && request.method !== "HEAD") {
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
    const unavailable = failClosedSnapshot(
      "UNCONFIGURED",
      "Cloudflare D1 binding, workspace 식별자 또는 검증 비밀키가 설정되지 않았습니다.",
      { workspaceId },
    );
    return jsonResponse(
      { ...unavailable, deployment: deploymentAttribution(env) },
      200,
      { "X-Cogni-Data-State": "UNCONFIGURED" },
    );
  }

  let row;
  try {
    row = await env.MONITOR_DB.prepare(
      `SELECT workspace_id, sequence, observed_at, received_at,
              key_id, nonce, body_sha256, signature, payload
       FROM monitor_snapshots
       WHERE workspace_id = ?1`,
    )
      .bind(workspaceId)
      .first();
  } catch (error) {
    const isMigration = /no such table/i.test(String(error?.message || error));
    const state = isMigration ? "UNCONFIGURED" : "STORAGE_ERROR";
    return jsonResponse(
      {
        ...failClosedSnapshot(
          state,
          isMigration
            ? "모니터링 데이터베이스 마이그레이션이 필요합니다."
            : "모니터링 데이터 저장소를 읽을 수 없습니다.",
          { workspaceId },
        ),
        deployment: deploymentAttribution(env),
      },
      200,
      { "X-Cogni-Data-State": state },
    );
  }

  if (!row) {
    return jsonResponse(
      {
        ...failClosedSnapshot(
          "NO_DATA",
          "서명 검증된 운영 스냅샷이 아직 수신되지 않았습니다.",
          { workspaceId },
        ),
        deployment: deploymentAttribution(env),
      },
      200,
      { "X-Cogni-Data-State": "NO_DATA" },
    );
  }

  let payload;
  try {
    const secret = hmacKeys.get(row.key_id);
    if (!secret) {
      throw new Error("stored snapshot publisher key is not active");
    }
    payload = await verifyStoredRow(row, secret);
  } catch (error) {
    return jsonResponse(
      {
        ...failClosedSnapshot(
          "CORRUPT",
          "저장된 스냅샷의 구조 또는 무결성이 손상되었습니다.",
          { workspaceId },
        ),
        deployment: deploymentAttribution(env),
      },
      200,
      { "X-Cogni-Data-State": "CORRUPT" },
    );
  }

  const snapshot = withMonitoringEnvelope(payload, {
    ...row,
    max_age_seconds: Number(
      env.MAX_SNAPSHOT_AGE_SECONDS || DEFAULT_MAX_AGE_SECONDS,
    ),
  });
  const responseSnapshot = bindDeploymentTruth(
    snapshot,
    deploymentAttribution(env),
  );
  return jsonResponse(responseSnapshot, 200, {
    "X-Cogni-Data-State": snapshot.monitoring.state,
    "X-Cogni-Sequence": String(snapshot.monitoring.sequence),
    "X-Cogni-Body-SHA256": row.body_sha256,
  });
}
