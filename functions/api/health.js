import {
  deploymentAttribution,
  jsonResponse,
  parseHmacKeys,
} from "../_lib/monitoring.js";

const REQUIRED_COLUMNS = Object.freeze({
  monitor_snapshots: [
    [0, "workspace_id", "TEXT", 0, null, 1],
    [1, "sequence", "INTEGER", 1, null, 0],
    [2, "observed_at", "TEXT", 1, null, 0],
    [3, "received_at", "TEXT", 1, null, 0],
    [4, "key_id", "TEXT", 1, null, 0],
    [5, "nonce", "TEXT", 1, null, 0],
    [6, "body_sha256", "TEXT", 1, null, 0],
    [7, "signature", "TEXT", 1, null, 0],
    [8, "payload", "TEXT", 1, null, 0],
  ],
  monitor_history: [
    [0, "workspace_id", "TEXT", 1, null, 1],
    [1, "sequence", "INTEGER", 1, null, 2],
    [2, "observed_at", "TEXT", 1, null, 0],
    [3, "received_at", "TEXT", 1, null, 0],
    [4, "key_id", "TEXT", 1, null, 0],
    [5, "nonce", "TEXT", 1, null, 0],
    [6, "body_sha256", "TEXT", 1, null, 0],
    [7, "signature", "TEXT", 1, null, 0],
    [8, "payload", "TEXT", 1, null, 0],
  ],
  monitor_nonces: [
    [0, "workspace_id", "TEXT", 1, null, 1],
    [1, "key_id", "TEXT", 1, null, 0],
    [2, "nonce", "TEXT", 1, null, 2],
    [3, "sequence", "INTEGER", 1, null, 0],
    [4, "received_at", "TEXT", 1, null, 0],
  ],
  monitor_schema_floors: [
    [0, "workspace_id", "TEXT", 0, null, 1],
    [1, "minimum_schema_rank", "INTEGER", 1, null, 0],
    [2, "minimum_schema_version", "TEXT", 1, null, 0],
    [3, "updated_at", "TEXT", 1, null, 0],
  ],
});

const REQUIRED_INDEX_SIGNATURES = Object.freeze({
  monitor_snapshots: ["1:pk:workspace_id", "1:u:nonce"],
  monitor_history: [
    "0:c:workspace_id,observed_at",
    "1:pk:workspace_id,sequence",
    "1:u:workspace_id,nonce",
  ],
  monitor_nonces: [
    "0:c:workspace_id,received_at",
    "1:pk:workspace_id,nonce",
  ],
  monitor_schema_floors: ["1:pk:workspace_id"],
});

const REQUIRED_DDL_FRAGMENTS = Object.freeze({
  monitor_snapshots: [
    "createtablemonitor_snapshots(",
    "check(sequence>0)",
    "noncetextnotnullunique",
    "check(length(body_sha256)=64)",
    "check(length(signature)=64)",
  ],
  monitor_history: [
    "createtablemonitor_history(",
    "check(sequence>0)",
    "primarykey(workspace_id,sequence)",
    "unique(workspace_id,nonce)",
    "check(length(body_sha256)=64)",
    "check(length(signature)=64)",
  ],
  monitor_nonces: [
    "createtablemonitor_nonces(",
    "primarykey(workspace_id,nonce)",
  ],
  monitor_schema_floors: [
    "createtablemonitor_schema_floors(",
    "check(minimum_schema_rankbetween100and199)",
  ],
});

const SAFE_INDEX_NAME = /^(?:sqlite_autoindex_monitor_(?:snapshots|history|nonces|schema_floors)_[1-9][0-9]*|monitor_history_observed|monitor_nonces_received)$/;
const MAX_SCHEMA_ROWS = 32;

function schemaMismatch(message) {
  const error = new Error(message);
  error.code = "SCHEMA_MISMATCH";
  return error;
}

function notMigrated(message) {
  const error = new Error(message);
  error.code = "NOT_MIGRATED";
  return error;
}

async function boundedRows(database, sql) {
  const response = await database.prepare(sql).all();
  const rows = response?.results;
  if (!Array.isArray(rows) || rows.length > MAX_SCHEMA_ROWS) {
    throw schemaMismatch("monitoring schema probe returned invalid rows");
  }
  return rows;
}

function normalizeDdl(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[\s"'`\[\]]+/g, "");
}

async function verifyStorageSchema(database) {
  for (const [table, expectedColumns] of Object.entries(REQUIRED_COLUMNS)) {
    const rows = await boundedRows(database, `PRAGMA table_info("${table}")`);
    if (rows.length === 0) {
      throw notMigrated(`monitoring table is missing: ${table}`);
    }
    const columns = rows.map((row) => [
      Number(row.cid),
      String(row.name || ""),
      String(row.type || "").toUpperCase(),
      Number(row.notnull),
      row.dflt_value ?? null,
      Number(row.pk),
    ]);
    if (JSON.stringify(columns) !== JSON.stringify(expectedColumns)) {
      throw schemaMismatch(`monitoring table schema mismatch: ${table}`);
    }

    const tableRecord = await database
      .prepare(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
      )
      .bind(table)
      .first();
    const normalizedDdl = normalizeDdl(tableRecord?.sql);
    if (
      REQUIRED_DDL_FRAGMENTS[table].some(
        (fragment) => !normalizedDdl.includes(fragment),
      )
    ) {
      throw schemaMismatch(`monitoring table constraints mismatch: ${table}`);
    }

    const indexRows = await boundedRows(
      database,
      `PRAGMA index_list("${table}")`,
    );
    const signatures = [];
    for (const index of indexRows) {
      const indexName = String(index.name || "");
      if (!SAFE_INDEX_NAME.test(indexName) || Number(index.partial) !== 0) {
        throw schemaMismatch(`monitoring index inventory mismatch: ${table}`);
      }
      const indexColumns = await boundedRows(
        database,
        `PRAGMA index_info("${indexName}")`,
      );
      const orderedColumns = [...indexColumns]
        .sort((left, right) => Number(left.seqno) - Number(right.seqno))
        .map((row) => String(row.name || ""));
      signatures.push(
        `${Number(index.unique)}:${String(index.origin || "")}:${orderedColumns.join(",")}`,
      );
    }
    signatures.sort();
    const expectedSignatures = [...REQUIRED_INDEX_SIGNATURES[table]].sort();
    if (JSON.stringify(signatures) !== JSON.stringify(expectedSignatures)) {
      throw schemaMismatch(`monitoring index definition mismatch: ${table}`);
    }
  }
}

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
      await verifyStorageSchema(context.env.MONITOR_DB);
      storageReady = true;
      storageState = "READY";
    } catch (error) {
      if (
        error?.code === "NOT_MIGRATED" ||
        /no such table/i.test(String(error?.message || error))
      ) {
        storageState = "NOT_MIGRATED";
      } else if (error?.code === "SCHEMA_MISMATCH") {
        storageState = "SCHEMA_MISMATCH";
      } else {
        storageState = "ERROR";
      }
    }
  }
  const configured =
    d1Bound && workspaceConfigured && secretConfigured && storageReady;
  const deployment = deploymentAttribution(context.env);
  const buildAttributionReady = deployment.attribution === "BUILD_BOUND";
  const operationalIngestReady = configured && buildAttributionReady;
  // A Pages build can bind commit telemetry, but Cloudflare does not expose a
  // deployment ID in the build environment. Release readiness therefore
  // remains fail-closed until separately archived Pages API evidence binds the
  // canonical deployment ID, direct URL, and commit.
  const releaseAttributionReady = false;
  const ready = operationalIngestReady;
  return jsonResponse(
    {
      ok: ready,
      service: "cogni-os-monitoring",
      state: ready ? "CONFIGURED" : "UNCONFIGURED",
      checks: {
        runtime_configuration_ready: configured,
        d1_binding: d1Bound,
        storage_state: storageState,
        storage_schema_verified: storageReady,
        workspace_id: workspaceConfigured,
        publisher_keyring: secretConfigured,
        publisher_keys: hmacKeys?.size || 0,
        deployment_attribution: deployment.attribution,
        build_attribution_ready: buildAttributionReady,
        operational_ingest_ready: operationalIngestReady,
        release_attribution_ready: releaseAttributionReady,
        release_evidence_state: "API_EVIDENCE_REQUIRED",
        minimum_release_snapshot_schema: "1.2",
      },
      deployment,
      timestamp: new Date().toISOString(),
    },
    ready ? 200 : 503,
  );
}
