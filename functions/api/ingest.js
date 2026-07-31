import {
  MAX_BODY_BYTES,
  assertFreshTimestamp,
  errorResponse,
  jsonResponse,
  parseHmacKeys,
  sha256Hex,
  signatureMessage,
  validateIngestHeaders,
  validateSnapshot,
  verifySignature,
} from "../_lib/monitoring.js";

function databaseError(error) {
  const message = String(error?.message || error);
  if (/no such table/i.test(message)) {
    return errorResponse(
      "DATABASE_NOT_MIGRATED",
      "모니터링 데이터베이스 마이그레이션이 필요합니다.",
      503,
    );
  }
  if (/unique|constraint/i.test(message)) {
    return errorResponse(
      "REPLAY_REJECTED",
      "이미 사용된 nonce 또는 sequence입니다.",
      409,
    );
  }
  return errorResponse("INGEST_STORAGE_FAILED", "스냅샷 저장에 실패했습니다.", 503);
}

async function readBoundedBody(request, maximumBytes) {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        throw new Error("request body stream returned invalid bytes");
      }
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel("body too large");
        const error = new Error("snapshot body exceeds the byte limit");
        error.code = "BODY_TOO_LARGE";
        throw error;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "POST") {
    return errorResponse("METHOD_NOT_ALLOWED", "POST 요청만 허용됩니다.", 405, {
      allow: ["POST"],
    });
  }
  if (!env.MONITOR_DB) {
    return errorResponse(
      "MONITORING_UNCONFIGURED",
      "MONITOR_DB D1 binding이 설정되지 않았습니다.",
      503,
    );
  }
  let hmacKeys;
  try {
    hmacKeys = parseHmacKeys(env.INGEST_HMAC_KEYS);
  } catch (error) {
    return errorResponse(
      "MONITORING_UNCONFIGURED",
      String(error.message || error),
      503,
    );
  }

  const contentType = request.headers.get("content-type") || "";
  const mediaType = contentType.split(";", 1)[0].trim().toLowerCase();
  if (mediaType !== "application/json") {
    return errorResponse(
      "UNSUPPORTED_MEDIA_TYPE",
      "application/json 요청만 허용됩니다.",
      415,
    );
  }

  const rawDeclaredLength = request.headers.get("content-length");
  const declaredLength =
    rawDeclaredLength === null ? null : Number(rawDeclaredLength);
  if (
    declaredLength !== null &&
    (!Number.isInteger(declaredLength) || declaredLength < 0)
  ) {
    return errorResponse(
      "INVALID_CONTENT_LENGTH",
      "Content-Length가 유효하지 않습니다.",
      400,
    );
  }
  if (declaredLength > MAX_BODY_BYTES) {
    return errorResponse("BODY_TOO_LARGE", "스냅샷 크기 제한을 초과했습니다.", 413);
  }

  let headers;
  try {
    headers = validateIngestHeaders(request.headers);
    assertFreshTimestamp(
      headers.observedAt,
      Date.now(),
      Number(env.MAX_CLOCK_SKEW_SECONDS || 300),
    );
  } catch (error) {
    return errorResponse("INVALID_HEADERS", String(error.message || error), 400);
  }

  if (
    typeof env.COGNI_WORKSPACE_ID !== "string" ||
    headers.workspaceId !== env.COGNI_WORKSPACE_ID
  ) {
    return errorResponse(
      "WORKSPACE_REJECTED",
      "허용된 Cogni-OS workspace가 아닙니다.",
      403,
    );
  }
  const hmacSecret = hmacKeys.get(headers.keyId);
  if (!hmacSecret) {
    return errorResponse(
      "PUBLISHER_KEY_REJECTED",
      "등록되지 않았거나 폐기된 publisher key id입니다.",
      403,
    );
  }

  let bodyBytes;
  try {
    bodyBytes = await readBoundedBody(request, MAX_BODY_BYTES);
  } catch (error) {
    if (error?.code === "BODY_TOO_LARGE") {
      return errorResponse(
        "BODY_TOO_LARGE",
        "스냅샷 크기 제한을 초과했습니다.",
        413,
      );
    }
    return errorResponse(
      "INVALID_SNAPSHOT",
      "스냅샷 본문을 읽을 수 없습니다.",
      400,
    );
  }

  const bodySha256 = await sha256Hex(bodyBytes);
  const message = signatureMessage({
    keyId: headers.keyId,
    workspaceId: headers.workspaceId,
    sequence: headers.sequence,
    observedAt: headers.observedAt,
    nonce: headers.nonce,
    bodySha256,
  });
  if (
    !(await verifySignature(
      hmacSecret,
      message,
      headers.signature,
    ))
  ) {
    return errorResponse(
      "SIGNATURE_REJECTED",
      "스냅샷 HMAC 서명 검증에 실패했습니다.",
      401,
    );
  }

  let rawBody;
  let payload;
  try {
    rawBody = new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes);
    payload = JSON.parse(rawBody);
    validateSnapshot(payload);
  } catch (error) {
    return errorResponse("INVALID_SNAPSHOT", String(error.message || error), 400);
  }

  if (
    payload.workspace_id !== headers.workspaceId ||
    payload.sequence !== headers.sequence ||
    payload.observed_at !== headers.observedAt
  ) {
    return errorResponse(
      "HEADER_BODY_MISMATCH",
      "서명 헤더와 스냅샷 본문 식별자가 일치하지 않습니다.",
      400,
    );
  }

  const receivedAt = new Date().toISOString();
  try {
    const results = await env.MONITOR_DB.batch([
      env.MONITOR_DB.prepare(
        `INSERT INTO monitor_nonces
          (workspace_id, key_id, nonce, sequence, received_at)
         SELECT ?1, ?2, ?3, ?4, ?5
         WHERE ?4 > COALESCE(
           (SELECT sequence FROM monitor_snapshots WHERE workspace_id = ?1),
           0
         )`,
      ).bind(
        headers.workspaceId,
        headers.keyId,
        headers.nonce,
        headers.sequence,
        receivedAt,
      ),
      env.MONITOR_DB.prepare(
        `INSERT INTO monitor_history
          (workspace_id, sequence, observed_at, received_at, key_id,
           nonce, body_sha256, signature, payload)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
         WHERE ?2 > COALESCE(
           (SELECT sequence FROM monitor_snapshots WHERE workspace_id = ?1),
           0
         )`,
      ).bind(
        headers.workspaceId,
        headers.sequence,
        headers.observedAt,
        receivedAt,
        headers.keyId,
        headers.nonce,
        bodySha256,
        headers.signature,
        rawBody,
      ),
      env.MONITOR_DB.prepare(
        `INSERT INTO monitor_snapshots
          (workspace_id, sequence, observed_at, received_at, key_id,
           nonce, body_sha256, signature, payload)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(workspace_id) DO UPDATE SET
           sequence = excluded.sequence,
           observed_at = excluded.observed_at,
           received_at = excluded.received_at,
           key_id = excluded.key_id,
           nonce = excluded.nonce,
           body_sha256 = excluded.body_sha256,
           signature = excluded.signature,
           payload = excluded.payload
         WHERE excluded.sequence > monitor_snapshots.sequence`,
      ).bind(
        headers.workspaceId,
        headers.sequence,
        headers.observedAt,
        receivedAt,
        headers.keyId,
        headers.nonce,
        bodySha256,
        headers.signature,
        rawBody,
      ),
      env.MONITOR_DB.prepare(
        `DELETE FROM monitor_history
         WHERE workspace_id = ?1
           AND sequence NOT IN (
             SELECT sequence FROM monitor_history
             WHERE workspace_id = ?1
             ORDER BY sequence DESC
             LIMIT 720
           )`,
      ).bind(headers.workspaceId),
      env.MONITOR_DB.prepare(
        `DELETE FROM monitor_nonces
         WHERE workspace_id = ?1
           AND received_at < datetime('now', '-2 days')`,
      ).bind(headers.workspaceId),
    ]);
    const latestWrite = results[2];
    if (Number(latestWrite?.meta?.changes || 0) !== 1) {
      return errorResponse(
        "STALE_SEQUENCE",
        "현재 저장된 sequence보다 큰 스냅샷만 허용됩니다.",
        409,
      );
    }
  } catch (error) {
    return databaseError(error);
  }

  return jsonResponse(
    {
      ok: true,
      accepted: {
        workspace_id: headers.workspaceId,
        sequence: headers.sequence,
        observed_at: headers.observedAt,
        received_at: receivedAt,
        body_sha256: bodySha256,
        signature_verified: true,
      },
    },
    202,
    {
      "X-Cogni-Sequence": String(headers.sequence),
      "X-Cogni-Body-SHA256": bodySha256,
    },
  );
}
