import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { onRequest as health } from "../../functions/api/health.js";
import { onRequest as history } from "../../functions/api/history.js";
import { onRequest as ingest } from "../../functions/api/ingest.js";
import { onRequest as snapshot } from "../../functions/api/snapshot.js";
import {
  assertFreshTimestamp,
  bindDeploymentTruth,
  deploymentAttribution,
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
const ROADMAP_PHASE_IDS = [
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
];

function roadmapFixture(tasks) {
  const byId = new Map(tasks.map((task) => [task.id, task]));
  const phases = ROADMAP_PHASE_IDS.map((id, index) => {
    const task = byId.get(id);
    const state = task?.state || "missing";
    return {
      id,
      title: `Phase ${index + 1}`,
      state,
      trusted_complete: state === "verified" || state === "archived",
      verified_source_commit: task?.verified_source_commit ?? null,
      current_release_state: task?.current_release_state ?? "missing",
      current_release_validated: Boolean(task?.current_release_validated),
      prerequisites: index === 0 ? [] : [ROADMAP_PHASE_IDS[index - 1]],
    };
  });
  const trusted = phases.filter((phase) => phase.trusted_complete).length;
  const currentReleaseValidated = phases.filter(
    (phase) => phase.current_release_validated,
  ).length;
  return {
    schema_version: 1,
    total: 11,
    trusted_complete: trusted,
    current_release_validated: currentReleaseValidated,
    progress_percent: Math.round((trusted / 11) * 1000) / 10,
    progress_basis: "historically-trusted-roadmap-task-states",
    phases,
  };
}

function payload(overrides = {}) {
  const observedAt = overrides.observed_at || new Date().toISOString();
  const tasks = overrides.tasks || [
    {
      id: "T-001",
      title: "Operational task",
      owner: "principal-0123456789abcdef",
      state: "pending",
      historical_state: "pending",
      historical_trusted: false,
      verified_source_commit: null,
      current_release_state: "pending",
      current_release_validated: false,
      progress: null,
      updated_at: observedAt,
    },
  ];
  return {
    schema_version: "1.2",
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
      attribution: {
        source_commit: "a".repeat(40),
        source_tree_clean: true,
        source_tree_fingerprint: "d".repeat(64),
        entrypoint_sha256: "c".repeat(64),
      },
    },
    data_classification: "operational-metadata-only",
    orchestrator: {
      id: "principal-0123456789abcdef",
      role: "conductor",
      status: "UNATTESTED",
    },
    tasks_summary: {
      total: 1,
      pending: 1,
      claimed: 0,
      running: 0,
      blocked: 0,
      submitted: 0,
      trusted_verified: 0,
      verification_disputed: 0,
      verification_revoked: 0,
      rejected: 0,
      current_release_validated: 0,
      completion_percentage: 0,
      progress_basis: "historically-trusted-ledger-task-states",
    },
    roadmap: overrides.roadmap || roadmapFixture(tasks),
    agents: [
      {
        id: "principal-0123456789abcdef",
        role: "conductor",
        status: "UNATTESTED",
      },
    ],
    tasks,
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
      measurement_complete: true,
      source_states: {
        telemetry: "MEASURED",
        processes: "MEASURED",
        containers: "MEASURED",
        scheduler: "MEASURED",
        boundary: "MEASURED",
      },
      evidence_counts: {
        processes: 0,
        container_claims: 0,
        scheduler_reservations: 0,
      },
      boundary_attestation: {
        state: "VERIFIED",
        issuer: "gpu-boundary-verifier",
        key_id: "gpu-boundary-key-1",
        observed_at: observedAt,
        expires_at: new Date(Date.parse(observedAt) + 60_000).toISOString(),
        evidence_sha256: "b".repeat(64),
        scope: [
          "host-inventory",
          "host-processes",
          "containers",
          "scheduler",
        ],
      },
    },
    resources: {},
    alerts: [],
    release_gate: {
      status: "NO_GO",
      reasons: ["test"],
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
      tree_clean: true,
      tree_fingerprint: "e".repeat(64),
      change_count: 0,
      operational_state: {
        valid: true,
        change_count: 0,
        fingerprint: "f".repeat(64),
        unclassified_count: 0,
        unclassified_fingerprint: "1".repeat(64),
        unbound_count: 0,
        hash_mismatch_count: 0,
        reference_count: 0,
        conflict_count: 0,
        missing_count: 0,
        audit_fingerprint: "2".repeat(64),
      },
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

function healthSchemaFixture() {
  return structuredClone({
    columns: {
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
    },
    ddl: {
      monitor_snapshots:
        "CREATE TABLE monitor_snapshots (workspace_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL CHECK (sequence > 0), observed_at TEXT NOT NULL, received_at TEXT NOT NULL, key_id TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64), signature TEXT NOT NULL CHECK (length(signature) = 64), payload TEXT NOT NULL)",
      monitor_history:
        "CREATE TABLE monitor_history (workspace_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK (sequence > 0), observed_at TEXT NOT NULL, received_at TEXT NOT NULL, key_id TEXT NOT NULL, nonce TEXT NOT NULL, body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64), signature TEXT NOT NULL CHECK (length(signature) = 64), payload TEXT NOT NULL, PRIMARY KEY (workspace_id, sequence), UNIQUE (workspace_id, nonce))",
      monitor_nonces:
        "CREATE TABLE monitor_nonces (workspace_id TEXT NOT NULL, key_id TEXT NOT NULL, nonce TEXT NOT NULL, sequence INTEGER NOT NULL, received_at TEXT NOT NULL, PRIMARY KEY (workspace_id, nonce))",
      monitor_schema_floors:
        "CREATE TABLE monitor_schema_floors (workspace_id TEXT PRIMARY KEY, minimum_schema_rank INTEGER NOT NULL CHECK (minimum_schema_rank BETWEEN 100 AND 199), minimum_schema_version TEXT NOT NULL, updated_at TEXT NOT NULL)",
    },
    indexes: {
      monitor_snapshots: [
        ["sqlite_autoindex_monitor_snapshots_2", 1, "u", ["nonce"]],
        ["sqlite_autoindex_monitor_snapshots_1", 1, "pk", ["workspace_id"]],
      ],
      monitor_history: [
        ["monitor_history_observed", 0, "c", ["workspace_id", "observed_at"]],
        ["sqlite_autoindex_monitor_history_2", 1, "u", ["workspace_id", "nonce"]],
        ["sqlite_autoindex_monitor_history_1", 1, "pk", ["workspace_id", "sequence"]],
      ],
      monitor_nonces: [
        ["monitor_nonces_received", 0, "c", ["workspace_id", "received_at"]],
        ["sqlite_autoindex_monitor_nonces_1", 1, "pk", ["workspace_id", "nonce"]],
      ],
      monitor_schema_floors: [
        ["sqlite_autoindex_monitor_schema_floors_1", 1, "pk", ["workspace_id"]],
      ],
    },
  });
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
    if (this.sql.includes("FROM sqlite_master")) {
      return { sql: this.database.healthSchema.ddl[this.values[0]] ?? null };
    }
    if (this.sql.includes("FROM monitor_schema_floors")) {
      let floor = this.database.schemaFloors.get(this.values[0]);
      if (floor === undefined && this.database.latest) {
        const schema = JSON.parse(this.database.latest.payload).schema_version;
        floor = { "1.0": 100, "1.1": 101, "1.2": 102 }[schema] || 0;
      }
      return floor === undefined ? null : { minimum_schema_rank: floor };
    }
    if (this.sql.includes("FROM monitor_snapshots")) {
      return this.database.latest;
    }
    return null;
  }

  async all() {
    const tableMatch = this.sql.match(/^PRAGMA table_info\("([a-z_]+)"\)$/);
    if (tableMatch) {
      const rows = this.database.healthSchema.columns[tableMatch[1]] || [];
      return {
        results: rows.map(([cid, name, type, notnull, dfltValue, pk]) => ({
          cid,
          name,
          type,
          notnull,
          dflt_value: dfltValue,
          pk,
        })),
      };
    }
    const listMatch = this.sql.match(/^PRAGMA index_list\("([a-z_]+)"\)$/);
    if (listMatch) {
      const indexes = this.database.healthSchema.indexes[listMatch[1]] || [];
      return {
        results: indexes.map(([name, unique, origin], seq) => ({
          seq,
          name,
          unique,
          origin,
          partial: 0,
        })),
      };
    }
    const infoMatch = this.sql.match(/^PRAGMA index_info\("([a-z0-9_]+)"\)$/);
    if (infoMatch) {
      const index = Object.values(this.database.healthSchema.indexes)
        .flat()
        .find(([name]) => name === infoMatch[1]);
      return {
        results: (index?.[3] || []).map((name, seqno) => ({
          seqno,
          cid: seqno,
          name,
        })),
      };
    }
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
    this.schemaFloors = new Map();
    this.healthSchema = healthSchemaFixture();
  }

  prepare(sql) {
    return new Statement(this, sql);
  }

  async batch(statements) {
    const floorValues = statements[0].values;
    const workspaceId = floorValues[0];
    const incomingSchemaRank = floorValues[1];
    const values = statements[3].values;
    const sequence = values[1];
    const existingSchema = this.latest
      ? JSON.parse(this.latest.payload).schema_version
      : null;
    const previousFloor =
      this.schemaFloors.get(workspaceId) ||
      { "1.0": 100, "1.1": 101, "1.2": 102 }[existingSchema] ||
      0;
    const schemaAllowed = incomingSchemaRank >= previousFloor;
    const changed =
      schemaAllowed && (!this.latest || sequence > this.latest.sequence) ? 1 : 0;
    if (changed) {
      this.schemaFloors.set(workspaceId, incomingSchemaRank);
      const nonce = statements[1].values[2];
      if (this.nonces.has(nonce)) throw new Error("UNIQUE constraint failed");
      this.nonces.add(nonce);
      const historyValues = statements[2].values;
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
      { meta: { changes: changed } },
      { meta: { changes: 0 } },
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
  value.tasks[0].historical_state = "verified";
  value.tasks[0].historical_trusted = true;
  value.tasks[0].verified_source_commit = value.source.git_commit;
  value.tasks[0].current_release_state = "verified";
  value.tasks[0].current_release_validated = true;
  value.tasks_summary.pending = 0;
  value.tasks_summary.trusted_verified = 1;
  value.tasks_summary.current_release_validated = 1;
  value.tasks_summary.completion_percentage = 100;
  value.agents[0] = {
    id: "principal-fedcba9876543210",
    role: "verifier",
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

  value.gpu_policy.telemetry_state = "UNMEASURED";
  value.gpu_policy.measurement_complete = false;
  value.gpu_policy.source_states.scheduler = "DISABLED";
  assert.throws(() => validateSnapshot(value), /GPU evidence/);
  value.gpu_policy.telemetry_state = "MEASURED";
  value.gpu_policy.measurement_complete = true;
  value.gpu_policy.source_states.scheduler = "MEASURED";

  value.release_gate.evidence_sha256 = "c".repeat(64);
  assert.throws(() => validateSnapshot(value), /attested agent/);
});

test("READY attestation must be fresh and match the source commit", () => {
  const value = payload();
  value.agents[0] = {
    id: "principal-fedcba9876543210",
    role: "worker",
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

test("source and collector provenance must align", () => {
  const value = payload();
  value.collector.attribution.source_commit = "b".repeat(40);
  assert.throws(() => validateSnapshot(value), /source and collector commits/);
});

test("schema 1.2 provenance requires full Git commit identities", () => {
  const value = payload();
  value.source.git_commit = "abcdef0";
  value.collector.attribution.source_commit = "abcdef0";
  assert.throws(() => validateSnapshot(value), /commit/);
});

test("operational evidence changes do not make the source tree dirty", () => {
  const value = payload();
  value.source.operational_state.change_count = 12;
  assert.doesNotThrow(() => validateSnapshot(value));

  value.source.operational_state.unclassified_count = 1;
  assert.throws(() => validateSnapshot(value), /untrusted changes/);

  value.source.operational_state.unclassified_count = 0;
  value.source.operational_state.conflict_count = 1;
  assert.throws(() => validateSnapshot(value), /untrusted changes/);

  value.source.operational_state.conflict_count = 0;
  value.source.operational_state.missing_count = 1;
  assert.throws(() => validateSnapshot(value), /untrusted changes/);
});

test("legacy 1.0 snapshots remain valid during the rolling migration", () => {
  const value = payload();
  value.schema_version = "1.0";
  delete value.collector.attribution;
  delete value.source.status_scope;
  delete value.source.operational_state;
  delete value.gpu_policy.source_states.boundary;
  delete value.gpu_policy.boundary_attestation;
  for (const task of value.tasks) {
    delete task.historical_state;
    delete task.historical_trusted;
    delete task.verified_source_commit;
    delete task.current_release_state;
    delete task.current_release_validated;
  }
  delete value.tasks_summary.current_release_validated;
  value.tasks_summary.progress_basis = "trusted-ledger-task-states";
  delete value.roadmap.current_release_validated;
  value.roadmap.progress_basis = "trusted-roadmap-task-states";
  for (const phase of value.roadmap.phases) {
    delete phase.verified_source_commit;
    delete phase.current_release_state;
    delete phase.current_release_validated;
  }
  assert.doesNotThrow(() => validateSnapshot(value));

  value.release_gate = {
    status: "PASS",
    reasons: [],
    evidence_sha256: "a".repeat(64),
  };
  assert.throws(() => validateSnapshot(value), /only snapshot schema 1.2/);
});

test("schema 1.1 is accepted only as fail-closed rolling input", () => {
  const value = payload({ schema_version: "1.1" });
  delete value.gpu_policy.source_states.boundary;
  delete value.gpu_policy.boundary_attestation;
  assert.doesNotThrow(() => validateSnapshot(value));
  value.release_gate = {
    status: "PASS",
    reasons: [],
    evidence_sha256: "a".repeat(64),
  };
  assert.throws(() => validateSnapshot(value), /only snapshot schema 1.2/);
});

test("schema 1.2 exposes verification_revoked without restoring trust", () => {
  const value = payload();
  value.tasks[0].state = "verification_revoked";
  value.tasks[0].historical_state = "verification_revoked";
  value.tasks[0].current_release_state = "verification_revoked";
  value.tasks_summary.pending = 0;
  value.tasks_summary.verification_revoked = 1;
  assert.doesNotThrow(() => validateSnapshot(value));

  value.tasks[0].current_release_validated = true;
  value.tasks_summary.current_release_validated = 1;
  assert.throws(() => validateSnapshot(value), /current release validation/);
});

test("legacy optional provenance cannot disagree with source", () => {
  const value = payload();
  value.schema_version = "1.0";
  delete value.source.status_scope;
  delete value.source.operational_state;
  delete value.release_deployment;
  delete value.gpu_policy.source_states.boundary;
  delete value.gpu_policy.boundary_attestation;
  value.collector.attribution.source_commit = "1234567";
  assert.throws(() => validateSnapshot(value), /source and collector commits/);
});

test("deployment attribution is server-owned and fail-closed", () => {
  const commit = "a".repeat(40);
  assert.equal(
    deploymentAttribution(
      {},
      {
        build_bound: true,
        source_commit: commit,
        branch: "main",
        url: "https://cogni-os-orchestrator.pages.dev",
        deployment_url: "https://a1b2c3d4.cogni-os-orchestrator.pages.dev",
        project: "cogni-os-orchestrator",
        environment: "production",
      },
    ).attribution,
    "BUILD_BOUND",
  );
  assert.equal(
    deploymentAttribution({ CF_PAGES_COMMIT_SHA: commit }).attribution,
    "UNAVAILABLE",
  );
  assert.equal(deploymentAttribution({}).attribution, "UNAVAILABLE");

  const claimedPass = {
    source: { git_commit: commit },
    alerts: [],
    release_deployment: {
      api_verified: true,
      provider: "cloudflare-pages",
      deployment_id: "deployment-current",
      deployment_url: "https://a1b2c3d4.cogni-os-orchestrator.pages.dev",
      canonical_url: "https://cogni-os-orchestrator.pages.dev",
      source_commit: commit,
    },
    release_gate: {
      status: "PASS",
      reasons: [],
      evidence_sha256: "b".repeat(64),
    },
  };
  const downgraded = bindDeploymentTruth(
    claimedPass,
    deploymentAttribution({ CF_PAGES_COMMIT_SHA: commit }),
  );
  assert.equal(downgraded.release_gate.status, "NO_GO");
  assert.equal(downgraded.release_gate.evidence_sha256, null);
  assert.equal(downgraded.alerts[0].code, "UNBOUND_DEPLOYMENT");

  const bound = bindDeploymentTruth(
    claimedPass,
    deploymentAttribution(
      {},
      {
        build_bound: true,
        source_commit: commit,
        branch: "main",
        url: "https://cogni-os-orchestrator.pages.dev",
        deployment_url: "https://a1b2c3d4.cogni-os-orchestrator.pages.dev",
        project: "cogni-os-orchestrator",
        environment: "production",
      },
    ),
  );
  assert.equal(bound.release_gate.status, "PASS");

  const wrongDirectDeployment = bindDeploymentTruth(
    {
      ...claimedPass,
      release_deployment: {
        ...claimedPass.release_deployment,
        deployment_id: "deployment-other",
        deployment_url:
          "https://deployment-other.cogni-os-orchestrator.pages.dev",
      },
    },
    deploymentAttribution(
      {},
      {
        build_bound: true,
        source_commit: commit,
        branch: "main",
        url: "https://cogni-os-orchestrator.pages.dev",
        deployment_url: "https://a1b2c3d4.cogni-os-orchestrator.pages.dev",
        project: "cogni-os-orchestrator",
        environment: "production",
      },
    ),
  );
  assert.equal(wrongDirectDeployment.release_gate.status, "NO_GO");

  for (const invalid of [
    { project: "other-project" },
    { branch: "feature/preview" },
    { environment: "preview" },
    { deployment_url: "https://other-project.pages.dev" },
  ]) {
    const attribution = deploymentAttribution({}, {
      build_bound: true,
      source_commit: commit,
      branch: "main",
      url: "https://cogni-os-orchestrator.pages.dev",
      deployment_url: "https://a1b2c3d4.cogni-os-orchestrator.pages.dev",
      project: "cogni-os-orchestrator",
      environment: "production",
      ...invalid,
    });
    assert.equal(attribution.attribution, "UNAVAILABLE");
  }

  const injected = payload({ deployment: { source_commit: commit } });
  assert.throws(() => validateSnapshot(injected), /unexpected fields/);
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
  const readyBody = await ready.json();
  assert.equal(readyBody.checks.storage_state, "READY");
  assert.equal(readyBody.checks.runtime_configuration_ready, true);
  assert.equal(readyBody.checks.minimum_release_snapshot_schema, "1.2");
  const buildBound = readyBody.checks.build_attribution_ready;
  assert.equal(readyBody.checks.operational_ingest_ready, buildBound);
  assert.equal(readyBody.checks.release_attribution_ready, false);
  assert.equal(readyBody.checks.release_evidence_state, "API_EVIDENCE_REQUIRED");
  assert.equal(ready.status, buildBound ? 200 : 503);
  assert.equal(readyBody.ok, buildBound);
  assert.equal(readyBody.state, buildBound ? "CONFIGURED" : "UNCONFIGURED");
  assert.equal(
    readyBody.deployment.attribution,
    buildBound ? "BUILD_BOUND" : "UNAVAILABLE",
  );

  const unconfigured = await health({ env: {} });
  assert.equal(unconfigured.status, 503);
  assert.equal((await unconfigured.json()).state, "UNCONFIGURED");
});

test("health rejects malformed same-name D1 schemas and constraints", async () => {
  const environmentFor = (database) => ({
    MONITOR_DB: database,
    COGNI_WORKSPACE_ID: WORKSPACE,
    INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
  });

  const missingColumn = new MemoryD1();
  missingColumn.healthSchema.columns.monitor_schema_floors.pop();
  const missingColumnResponse = await health({
    env: environmentFor(missingColumn),
  });
  const missingColumnBody = await missingColumnResponse.json();
  assert.equal(missingColumnResponse.status, 503);
  assert.equal(missingColumnBody.checks.storage_state, "SCHEMA_MISMATCH");
  assert.equal(missingColumnBody.checks.storage_schema_verified, false);
  assert.equal(missingColumnBody.checks.runtime_configuration_ready, false);

  const weakenedCheck = new MemoryD1();
  weakenedCheck.healthSchema.ddl.monitor_schema_floors =
    weakenedCheck.healthSchema.ddl.monitor_schema_floors.replace(
      "BETWEEN 100 AND 199",
      "BETWEEN 0 AND 999",
    );
  const weakenedCheckResponse = await health({
    env: environmentFor(weakenedCheck),
  });
  const weakenedCheckBody = await weakenedCheckResponse.json();
  assert.equal(weakenedCheckResponse.status, 503);
  assert.equal(weakenedCheckBody.checks.storage_state, "SCHEMA_MISMATCH");
  assert.equal(weakenedCheckBody.checks.storage_schema_verified, false);

  const missingIndex = new MemoryD1();
  missingIndex.healthSchema.indexes.monitor_history =
    missingIndex.healthSchema.indexes.monitor_history.filter(
      ([name]) => name !== "monitor_history_observed",
    );
  const missingIndexResponse = await health({
    env: environmentFor(missingIndex),
  });
  const missingIndexBody = await missingIndexResponse.json();
  assert.equal(missingIndexResponse.status, 503);
  assert.equal(missingIndexBody.checks.storage_state, "SCHEMA_MISMATCH");
  assert.equal(missingIndexBody.checks.storage_schema_verified, false);
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

test("schema floor rejects downgrade without ratcheting on stale input", async () => {
  const environmentFor = (database) => ({
    MONITOR_DB: database,
    INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
    COGNI_WORKSPACE_ID: WORKSPACE,
  });
  const downgradeDatabase = new MemoryD1();
  assert.equal(
    (
      await ingest({
        request: await signedRequest(payload(), "schema_floor_v12_nonce"),
        env: environmentFor(downgradeDatabase),
      })
    ).status,
    202,
  );
  const downgraded = payload({ schema_version: "1.1", sequence: 2 });
  delete downgraded.gpu_policy.source_states.boundary;
  delete downgraded.gpu_policy.boundary_attestation;
  const downgradeResponse = await ingest({
    request: await signedRequest(downgraded, "schema_floor_v11_nonce"),
    env: environmentFor(downgradeDatabase),
  });
  assert.equal(downgradeResponse.status, 409);
  assert.equal(
    (await downgradeResponse.json()).error.code,
    "SCHEMA_DOWNGRADE_REJECTED",
  );

  const staleDatabase = new MemoryD1();
  const initialLegacy = payload({ schema_version: "1.1" });
  delete initialLegacy.gpu_policy.source_states.boundary;
  delete initialLegacy.gpu_policy.boundary_attestation;
  assert.equal(
    (
      await ingest({
        request: await signedRequest(initialLegacy, "initial_v11_nonce_123"),
        env: environmentFor(staleDatabase),
      })
    ).status,
    202,
  );
  const staleHigher = await ingest({
    request: await signedRequest(
      payload(),
      "stale_higher_schema_nonce",
    ),
    env: environmentFor(staleDatabase),
  });
  assert.equal(staleHigher.status, 409);
  assert.equal((await staleHigher.json()).error.code, "STALE_SEQUENCE");
  const nextLegacy = payload({ schema_version: "1.1", sequence: 2 });
  delete nextLegacy.gpu_policy.source_states.boundary;
  delete nextLegacy.gpu_policy.boundary_attestation;
  assert.equal(
    (
      await ingest({
        request: await signedRequest(nextLegacy, "next_v11_nonce_123456"),
        env: environmentFor(staleDatabase),
      })
    ).status,
    202,
  );
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
  assert.equal(stale.gpu_policy.telemetry_state, "UNMEASURED");
  assert.equal(stale.gpu_policy.measurement_complete, false);
  assert.equal(stale.release_deployment, null);
  assert.equal(stale.ledger.status, "STALE");
  assert.equal(stale.ledger.valid, false);
  assert.equal(stale.release_gate.status, "NO_GO");
  assert.equal(stale.alerts[0].code, "STALE_SNAPSHOT");

  const closed = failClosedSnapshot("NO_DATA", "test");
  assert.equal(closed.document_type, "cogni-monitoring-fail-closed-response");
  assert.equal(closed.snapshot_schema_version, null);
  assert.equal(closed.schema_version, undefined);
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

test("future timestamps and unsafe integer sequences are rejected", async () => {
  const now = Date.parse("2026-08-01T00:00:00.000Z");
  assert.throws(
    () => assertFreshTimestamp("2026-08-01T00:00:06.000Z", now, 300),
    /outside the accepted clock window/,
  );
  assert.doesNotThrow(() =>
    assertFreshTimestamp("2026-08-01T00:00:05.000Z", now, 300),
  );
  const unsafe = payload({ sequence: Number.MAX_SAFE_INTEGER + 1 });
  assert.throws(() => validateSnapshot(unsafe), /positive safe integer/);
  const response = await ingest({
    request: await signedRequest(unsafe, "unsafe_sequence_nonce_12"),
    env: {
      MONITOR_DB: new MemoryD1(),
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
      COGNI_WORKSPACE_ID: WORKSPACE,
    },
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "INVALID_HEADERS");
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

test("roadmap progress must be derived from the canonical phase tasks", () => {
  const value = payload();
  value.roadmap.trusted_complete = 11;
  value.roadmap.progress_percent = 100;
  assert.throws(
    () => validateSnapshot(value),
    /roadmap\.trusted_complete/,
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
