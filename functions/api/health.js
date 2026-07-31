import { jsonResponse, parseHmacKeys } from "../_lib/monitoring.js";

export async function onRequest(context) {
  const d1Bound = Boolean(context.env.MONITOR_DB);
  const workspaceConfigured = Boolean(context.env.COGNI_WORKSPACE_ID);
  let hmacKeys = null;
  try {
    hmacKeys = parseHmacKeys(context.env.INGEST_HMAC_KEYS);
  } catch {
    hmacKeys = null;
  }
  const secretConfigured = Boolean(hmacKeys);
  let storageReady = false;
  let storageState = d1Bound ? "NOT_CHECKED" : "UNBOUND";
  if (d1Bound) {
    try {
      for (const table of [
        "monitor_snapshots",
        "monitor_history",
        "monitor_nonces",
      ]) {
        await context.env.MONITOR_DB.prepare(
          `SELECT 1 AS ready FROM ${table} LIMIT 1`,
        ).first();
      }
      storageReady = true;
      storageState = "READY";
    } catch (error) {
      storageState = /no such table/i.test(String(error?.message || error))
        ? "NOT_MIGRATED"
        : "ERROR";
    }
  }
  const configured =
    d1Bound && workspaceConfigured && secretConfigured && storageReady;
  return jsonResponse(
    {
      ok: configured,
      service: "cogni-os-monitoring",
      state: configured ? "CONFIGURED" : "UNCONFIGURED",
      checks: {
        d1_binding: d1Bound,
        storage_state: storageState,
        workspace_id: workspaceConfigured,
        publisher_keyring: secretConfigured,
        publisher_keys: hmacKeys?.size || 0,
      },
      timestamp: new Date().toISOString(),
    },
    configured ? 200 : 503,
  );
}
