import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { onRequest as health } from "../../functions/api/health.js";
import { onRequest as history } from "../../functions/api/history.js";
import { onRequest as ingest } from "../../functions/api/ingest.js";
import { onRequest as snapshot } from "../../functions/api/snapshot.js";
import {
  assertFreshTimestamp,
  failClosedSnapshot,
  hmacHex,
  sha256Hex,
  signatureMessage,
  validateSnapshot,
  withMonitoringEnvelope,
} from "../../functions/_lib/monitoring.js";

const SECRET = "test-secret-that-is-longer-than-thirty-two-characters";
const KEY_ID = "publisher-2026-07";
const WORKSPACE = "5988e0651ec1afcdeb87b58ccc8d68ea";

function payload(overrides = {}) {
  const observedAt = overrides.observed_at || new Date().toISOString();
  return {
    schema_version: "1.0",
    system: "Cogni-OS Operations",
    workspace_id: WORKSPACE,
    workspace_name: "Test Workspace",
    sequence: 1,
    observed_at: observedAt,
    collector: {
      id: "test",
      version: "1.0.0",
      host: "host-0123456789abcdef",
      platform: "test",
    },
    data_classification: "operational-metadata-only",
    orchestrator: { id: "codex", role: "conductor", status: "UNATTESTED" },
    tasks_summary: {
      total: 1,
      pending: 1,
      claimed: 0,
      running: 0,
      blocked: 0,
      submitted: 0,
      trusted_verified: 0,
      verification_disputed: 0,
      rejected: 0,
      completion_percentage: 0,
      progress_basis: "trusted-ledger-task-states",
    },
    agents: [
      {
        id: "codex",
        role: "orchestrator",
        status: "UNATTESTED",
      },
    ],
    tasks: [
      {
        id: "T-1",
        title: "Test",
        owner: "codex",
        state: "pending",
        progress: null,
        updated_at: observedAt,
      },
    ],
    ledger_events: [],
    ledger: {
      status: "VERIFIED",
      valid: true,
      signed: true,
      events: 1,
      head: "a".repeat(64),
    },
    gpus: [
      {
        id: 0,
        name: "GPU",
        utilization: 0,
        vram_used_gib: 0,
        vram_total_gib: 48,
        temperature_c: 40,
        power_w: 20,
      },
    ],
    gpu_policy: {
      allowed_ids: [0, 1, 2, 3, 4, 5],
      denied_ids: [6, 7],
      telemetry_state: "MEASURED",
      violating_ids: [],
    },
    resources: {},
    alerts: [],
    release_gate: {
      status: "NO_GO",
      reasons: ["test"],
      evidence_sha256: null,
    },
    source: {
      git_commit: "abcdef0",
      tree_clean: true,
      tree_fingerprint: "e".repeat(64),
      change_count: 0,
      task_projection_audit: {
        valid: true,
        events_count: 1,
        projected_count: 1,
        actual_count: 1,
        mismatch_count: 0,
      },
    },
    ...overrides,
  };
}

function canonical(value) {
  const keys = (input) => {
    if (Array.isArray(input)) return input.map(keys);
    if (input && typeof input === "object") {
      return Object.fromEntries(
        Object.keys(input)
          .sort()
          .map((key) => [key, keys(input[key])]),
      );
    }
    return input;
  };
  return JSON.stringify(keys(value));
}

class Statement {
  constructor(database, sql) {
    this.database = database;
    this.sql = sql;
    this.values = [];
  }

  bind(...values) {
    this.values = values;
    return this;
  }

  async first() {
    if (this.sql.includes("FROM monitor_snapshots")) {
      return this.database.latest;
    }
    return null;
  }

  async all() {
    if (this.sql.includes("FROM monitor_history")) {
      return { results: [...this.database.history] };
    }
    return { results: [] };
  }
}

class MemoryD1 {
  constructor() {
    this.latest = null;
    this.history = [];
    this.nonces = new Set();
  }

  prepare(sql) {
    return new Statement(this, sql);
  }

  async batch(statements) {
    const values = statements[2].values;
    const sequence = values[1];
    const changed = !this.latest || sequence > this.latest.sequence ? 1 : 0;
    if (changed) {
      const nonce = statements[0].values[2];
      if (this.nonces.has(nonce)) throw new Error("UNIQUE constraint failed");
      this.nonces.add(nonce);
      const historyValues = statements[1].values;
      this.history.push({
        workspace_id: historyValues[0],
        sequence: historyValues[1],
        observed_at: historyValues[2],
        received_at: historyValues[3],
        key_id: historyValues[4],
        nonce: historyValues[5],
        body_sha256: historyValues[6],
        signature: historyValues[7],
        payload: historyValues[8],
      });
      this.latest = {
        workspace_id: values[0],
        sequence,
        observed_at: values[2],
        received_at: values[3],
        key_id: values[4],
        nonce: values[5],
        body_sha256: values[6],
        signature: values[7],
        payload: values[8],
      };
    }
    return [
      { meta: { changes: 1 } },
      { meta: { changes: changed } },
      { meta: { changes: changed } },
      { meta: { changes: 0 } },
    ];
  }
}

async function signedRequest(
  value,
  nonce = "nonce_value_1234567890",
  { keyId = KEY_ID, secret = SECRET } = {},
) {
  const raw = canonical(value);
  const bodySha256 = await sha256Hex(new TextEncoder().encode(raw));
  const message = signatureMessage({
    keyId,
    workspaceId: value.workspace_id,
    sequence: value.sequence,
    observedAt: value.observed_at,
    nonce,
    bodySha256,
  });
  const signature = await hmacHex(secret, message);
  return new Request("https://example.test/api/ingest", {
    method: "POST",
    body: raw,
    headers: {
      "content-type": "application/json",
      "x-cogni-key-id": keyId,
      "x-cogni-workspace": value.workspace_id,
      "x-cogni-sequence": String(value.sequence),
      "x-cogni-observed-at": value.observed_at,
      "x-cogni-nonce": nonce,
      "x-cogni-signature": `sha256=${signature}`,
    },
  });
}

test("snapshot schema rejects GPU 6 and 7", () => {
  const value = payload();
  value.gpus[0].id = 6;
  assert.throws(() => validateSnapshot(value), /GPU 0-5 allowlist/);
});

test("JavaScript verifier matches the Python publisher HMAC contract", async () => {
  const message = signatureMessage({
    keyId: KEY_ID,
    workspaceId: "workspace",
    sequence: 7,
    observedAt: "2026-07-30T00:00:00Z",
    nonce: "nonce_1234567890abcdef",
    bodySha256: "a".repeat(64),
  });
  assert.equal(
    await hmacHex("0123456789abcdef0123456789abcdef", message),
    "e7e822dba04efc22745208c1a162c06ea712d4d2024427879d70c8e1801a478e",
  );
});

test("PASS release gate requires a valid evidence hash", () => {
  const value = payload({
    release_gate: { status: "PASS", reasons: [], evidence_sha256: null },
  });
  assert.throws(() => validateSnapshot(value), /evidence hash/);
});

test("PASS release gate is bound to a fresh agent attestation", () => {
  const value = payload();
  const evidence = "b".repeat(64);
  value.tasks[0].state = "verified";
  value.tasks_summary.pending = 0;
  value.tasks_summary.trusted_verified = 1;
  value.tasks_summary.completion_percentage = 100;
  value.agents[0] = {
    id: "antigravity-verifier",
    role: "independent-verifier",
    status: "READY",
    mode: "command",
    attestation_evidence_sha256: evidence,
    attested_at: value.observed_at,
    attested_source_commit: value.source.git_commit,
  };
  value.release_gate = {
    status: "PASS",
    reasons: [],
    evidence_sha256: evidence,
  };
  assert.doesNotThrow(() => validateSnapshot(value));

  value.release_gate.evidence_sha256 = "c".repeat(64);
  assert.throws(() => validateSnapshot(value), /attested agent/);
});

test("READY attestation must be fresh and match the source commit", () => {
  const value = payload();
  value.agents[0] = {
    id: "worker",
    role: "executant",
    status: "READY",
    mode: "command",
    attestation_evidence_sha256: "b".repeat(64),
    attested_at: "2026-01-01T00:00:00.000Z",
    attested_source_commit: value.source.git_commit,
  };
  assert.throws(() => validateSnapshot(value), /freshness window/);
  value.agents[0].attested_at = value.observed_at;
  value.agents[0].attested_source_commit = "1234567";
  assert.throws(() => validateSnapshot(value), /does not match/);
});

test("unsigned ledgers and nested metadata fields are rejected", () => {
  const unsigned = payload();
  unsigned.ledger.signed = false;
  assert.throws(() => validateSnapshot(unsigned), /valid ledger must be signed/);

  const leaked = payload();
  leaked.resources.leaked_secret = "TOP-SECRET";
  assert.throws(() => validateSnapshot(leaked), /unexpected fields/);
});

test("unconfigured snapshot fails closed without synthetic telemetry", async () => {
  const response = await snapshot({
    request: new Request("https://example.test/api/snapshot"),
    env: {},
  });
  const data = await response.json();
  assert.equal(response.status, 200);
  assert.equal(data.monitoring.state, "UNCONFIGURED");
  assert.equal(data.monitoring.signature_verified, false);
  assert.deepEqual(data.gpus, []);
  assert.deepEqual(data.tasks, []);
  assert.equal(data.release_gate.status, "NO_GO");
});

test("signed ingest becomes a LIVE snapshot", async () => {
  const database = new MemoryD1();
  const value = payload();
  const ingestResponse = await ingest({
    request: await signedRequest(value),
    env: {
      MONITOR_DB: database,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
      COGNI_WORKSPACE_ID: WORKSPACE,
    },
  });
  assert.equal(ingestResponse.status, 202);
  const snapshotResponse = await snapshot({
    request: new Request("https://example.test/api/snapshot"),
    env: {
      MONITOR_DB: database,
      COGNI_WORKSPACE_ID: WORKSPACE,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
      MAX_SNAPSHOT_AGE_SECONDS: "180",
    },
  });
  const data = await snapshotResponse.json();
  assert.equal(data.monitoring.state, "LIVE");
  assert.equal(data.monitoring.signature_verified, true);
  assert.equal(data.monitoring.sequence, 1);
  assert.equal(data.gpus.length, 1);
});

test("publisher key IDs support rotation and reject unknown keys", async () => {
  const database = new MemoryD1();
  const rotatedKeyId = "publisher-2026-08";
  const rotatedSecret =
    "rotated-test-secret-that-is-longer-than-thirty-two-characters";
  const environment = {
    MONITOR_DB: database,
    INGEST_HMAC_KEYS: JSON.stringify({
      [KEY_ID]: SECRET,
      [rotatedKeyId]: rotatedSecret,
    }),
    COGNI_WORKSPACE_ID: WORKSPACE,
  };
  const accepted = await ingest({
    request: await signedRequest(
      payload(),
      "rotated_nonce_1234567890",
      { keyId: rotatedKeyId, secret: rotatedSecret },
    ),
    env: environment,
  });
  assert.equal(accepted.status, 202);

  const unknownKeyId = "publisher-revoked";
  const unknown = await ingest({
    request: await signedRequest(
      payload({ sequence: 2 }),
      "unknown_key_nonce_123456",
      { keyId: unknownKeyId, secret: rotatedSecret },
    ),
    env: environment,
  });
  assert.equal(unknown.status, 403);
  assert.equal((await unknown.json()).error.code, "PUBLISHER_KEY_REJECTED");
});

test("health checks the storage schema instead of binding names only", async () => {
  const ready = await health({
    env: {
      MONITOR_DB: new MemoryD1(),
      COGNI_WORKSPACE_ID: WORKSPACE,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
    },
  });
  assert.equal(ready.status, 200);
  assert.equal((await ready.json()).checks.storage_state, "READY");

  const unconfigured = await health({ env: {} });
  assert.equal(unconfigured.status, 503);
  assert.equal((await unconfigured.json()).state, "UNCONFIGURED");
});

test("history rows are signature-verified before graph projection", async () => {
  const database = new MemoryD1();
  const environment = {
    MONITOR_DB: database,
    INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
    COGNI_WORKSPACE_ID: WORKSPACE,
  };
  assert.equal(
    (
      await ingest({
        request: await signedRequest(payload()),
        env: environment,
      })
    ).status,
    202,
  );
  const valid = await history({
    request: new Request("https://example.test/api/history?limit=60"),
    env: environment,
  });
  const validData = await valid.json();
  assert.equal(validData.state, "AVAILABLE");
  assert.equal(validData.history.length, 1);

  database.history[0].signature = "0".repeat(64);
  const corrupt = await history({
    request: new Request("https://example.test/api/history?limit=60"),
    env: environment,
  });
  const corruptData = await corrupt.json();
  assert.equal(corruptData.state, "CORRUPT");
  assert.deepEqual(corruptData.history, []);
});

test("tampered HMAC is rejected", async () => {
  const database = new MemoryD1();
  const request = await signedRequest(payload());
  request.headers.set("x-cogni-signature", `sha256=${"0".repeat(64)}`);
  const response = await ingest({
    request,
    env: {
      MONITOR_DB: database,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
      COGNI_WORKSPACE_ID: WORKSPACE,
    },
  });
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, "SIGNATURE_REJECTED");
});

test("nonce replay and non-monotonic sequence are rejected", async () => {
  const database = new MemoryD1();
  const environment = {
    MONITOR_DB: database,
    INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
    COGNI_WORKSPACE_ID: WORKSPACE,
  };
  const first = await ingest({
    request: await signedRequest(payload(), "replay_nonce_1234567890"),
    env: environment,
  });
  assert.equal(first.status, 202);
  const replay = await ingest({
    request: await signedRequest(payload(), "replay_nonce_1234567890"),
    env: environment,
  });
  assert.equal(replay.status, 409);

  const stale = await ingest({
    request: await signedRequest(payload(), "new_nonce_for_stale_1234"),
    env: environment,
  });
  assert.equal(stale.status, 409);
  assert.equal((await stale.json()).error.code, "STALE_SEQUENCE");

  const next = payload({ sequence: 2 });
  const reusedAfterStale = await ingest({
    request: await signedRequest(next, "new_nonce_for_stale_1234"),
    env: environment,
  });
  assert.equal(reusedAfterStale.status, 202);
});

test("stale snapshot is never labeled LIVE", async () => {
  const observedAt = "2026-07-30T00:00:00.000Z";
  const stale = withMonitoringEnvelope(
    payload({ observed_at: observedAt }),
    {
      sequence: 1,
      observed_at: observedAt,
      received_at: observedAt,
      body_sha256: "a".repeat(64),
      max_age_seconds: 180,
    },
    new Date("2026-07-30T00:10:00.000Z"),
  );
  assert.equal(stale.monitoring.state, "STALE");
  assert.equal(stale.monitoring.signature_verified, true);
  assert.ok(stale.monitoring.age_seconds > 180);
  assert.deepEqual(stale.agents, []);
  assert.deepEqual(stale.tasks, []);
  assert.deepEqual(stale.gpus, []);
  assert.equal(stale.gpu_policy.telemetry_state, "STALE");
  assert.equal(stale.ledger.status, "STALE");
  assert.equal(stale.ledger.valid, false);
  assert.equal(stale.release_gate.status, "NO_GO");
  assert.equal(stale.alerts[0].code, "STALE_SNAPSHOT");

  const closed = failClosedSnapshot("NO_DATA", "test");
  assert.equal(closed.monitoring.signature_verified, false);
  assert.equal(closed.release_gate.status, "NO_GO");
});

test("non-finite or oversized TTL cannot keep ancient data LIVE", () => {
  const observedAt = "2000-01-01T00:00:00.000Z";
  for (const maxAge of [Number.POSITIVE_INFINITY, 3601, -1]) {
    const value = withMonitoringEnvelope(
      payload({ observed_at: observedAt }),
      {
        sequence: 1,
        observed_at: observedAt,
        received_at: observedAt,
        body_sha256: "a".repeat(64),
        max_age_seconds: maxAge,
      },
      new Date("2026-07-31T00:00:00.000Z"),
    );
    assert.equal(value.monitoring.state, "STALE");
    assert.equal(value.monitoring.max_age_seconds, 180);
    assert.equal(value.release_gate.status, "NO_GO");
  }
});

test("non-finite clock skew cannot admit an ancient ingest timestamp", () => {
  assert.throws(
    () =>
      assertFreshTimestamp(
        "2000-01-01T00:00:00.000Z",
        Date.parse("2026-07-31T00:00:00.000Z"),
        Number.POSITIVE_INFINITY,
      ),
    /outside the accepted clock window/,
  );
});

test("stored payload tampering fails closed at read time", async () => {
  const database = new MemoryD1();
  const value = payload();
  const ingestResponse = await ingest({
    request: await signedRequest(value),
    env: {
      MONITOR_DB: database,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
      COGNI_WORKSPACE_ID: WORKSPACE,
    },
  });
  assert.equal(ingestResponse.status, 202);
  database.latest.payload = database.latest.payload.replace(
    '"pending":1',
    '"pending":0',
  );
  const response = await snapshot({
    request: new Request("https://example.test/api/snapshot"),
    env: {
      MONITOR_DB: database,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
      COGNI_WORKSPACE_ID: WORKSPACE,
    },
  });
  const data = await response.json();
  assert.equal(data.monitoring.state, "CORRUPT");
  assert.equal(data.monitoring.signature_verified, false);
  assert.deepEqual(data.tasks, []);
  assert.equal(data.release_gate.status, "NO_GO");
});

test("task summary must be derived from task records", () => {
  const value = payload();
  value.tasks_summary.trusted_verified = 1;
  assert.throws(
    () => validateSnapshot(value),
    /tasks_summary\.trusted_verified/,
  );
});

test("GPU telemetry rejects impossible VRAM and power values", () => {
  const value = payload();
  value.gpus[0].vram_used_gib = 49;
  assert.throws(() => validateSnapshot(value), /used VRAM above total/);
  value.gpus[0].vram_used_gib = 1;
  value.gpus[0].power_w = Number.NaN;
  assert.throws(() => validateSnapshot(value), /power_w/);
});

test("deployed UI contains no hard-coded GPU or VERIFIED defaults", async () => {
  const [snapshotSource, appSource, html] = await Promise.all([
    readFile(new URL("../../functions/api/snapshot.js", import.meta.url), "utf8"),
    readFile(new URL("../../public/assets/app.js", import.meta.url), "utf8"),
    readFile(new URL("../../public/index.html", import.meta.url), "utf8"),
  ]);
  assert.doesNotMatch(snapshotSource, /NVIDIA RTX A6000/);
  assert.doesNotMatch(snapshotSource, /tasks_summary:\s*\{\s*total:\s*20/);
  assert.doesNotMatch(appSource, /\.innerHTML\s*=/);
  assert.match(html, /서명된 운영 스냅샷 대기/);
  assert.doesNotMatch(html, /GPU 6 NVIDIA/);
});
