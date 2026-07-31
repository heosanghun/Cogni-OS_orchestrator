export const SNAPSHOT_SCHEMA_VERSION = "1.0";
export const INGEST_PROTOCOL = "COGNI-SNAPSHOT-V2";
export const DEFAULT_MAX_AGE_SECONDS = 180;
export const DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300;
export const MAX_BODY_BYTES = 1024 * 1024;

const HEX_64 = /^[0-9a-f]{64}$/;
const WORKSPACE_ID = /^[A-Za-z0-9._:-]{3,128}$/;
const KEY_ID = /^[A-Za-z0-9._:-]{3,64}$/;
const NONCE = /^[A-Za-z0-9_-]{16,128}$/;
const ALERT_CODE = /^[A-Z0-9_:-]{2,128}$/;
const TASK_STATES = new Set([
  "pending",
  "claimed",
  "running",
  "blocked",
  "submitted",
  "verified",
  "rejected",
  "archived",
  "verification_disputed",
  "invalidated",
]);

export function jsonResponse(value, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(value, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      ...extraHeaders,
    },
  });
}

export function errorResponse(code, message, status = 400, details = undefined) {
  return jsonResponse(
    {
      ok: false,
      error: {
        code,
        message,
        ...(details === undefined ? {} : { details }),
      },
      timestamp: new Date().toISOString(),
    },
    status,
  );
}

function bytesToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256Hex(value) {
  const bytes =
    typeof value === "string" ? new TextEncoder().encode(value) : value;
  return bytesToHex(await crypto.subtle.digest("SHA-256", bytes));
}

export async function hmacHex(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value),
  );
  return bytesToHex(signature);
}

export function signatureMessage({
  keyId,
  workspaceId,
  sequence,
  observedAt,
  nonce,
  bodySha256,
}) {
  return [
    INGEST_PROTOCOL,
    keyId,
    workspaceId,
    String(sequence),
    observedAt,
    nonce,
    bodySha256,
  ].join("\n");
}

export function parseHmacKeys(value) {
  if (typeof value !== "string" || value.length < 2 || value.length > 8192) {
    throw new Error("INGEST_HMAC_KEYS is not configured");
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("INGEST_HMAC_KEYS must be valid JSON");
  }
  requireObject(parsed, "INGEST_HMAC_KEYS");
  const entries = Object.entries(parsed);
  if (entries.length < 1 || entries.length > 4) {
    throw new Error("INGEST_HMAC_KEYS must contain one to four keys");
  }
  const keys = new Map();
  for (const [keyId, secret] of entries) {
    if (!KEY_ID.test(keyId)) {
      throw new Error("INGEST_HMAC_KEYS contains an invalid key id");
    }
    if (
      typeof secret !== "string" ||
      secret.length < 32 ||
      secret.length > 256
    ) {
      throw new Error("INGEST_HMAC_KEYS contains an invalid HMAC secret");
    }
    keys.set(keyId, secret);
  }
  return keys;
}

export function normalizeSignature(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return normalized.startsWith("sha256=")
    ? normalized.slice("sha256=".length)
    : normalized;
}

export function constantTimeHexEqual(left, right) {
  const a = normalizeSignature(left);
  const b = normalizeSignature(right);
  if (!HEX_64.test(a) || !HEX_64.test(b)) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return difference === 0;
}

export async function verifySignature(secret, message, provided) {
  if (typeof secret !== "string" || secret.length < 32) return false;
  return constantTimeHexEqual(await hmacHex(secret, message), provided);
}

function requireObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function requireString(value, name, { min = 1, max = 8192 } = {}) {
  if (
    typeof value !== "string" ||
    value.length < min ||
    value.length > max ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)
  ) {
    throw new Error(`${name} must be a bounded printable string`);
  }
  return value;
}

function requireFiniteNumber(value, name, { min, max } = {}) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${name} must be a finite number`);
  }
  if (min !== undefined && value < min) {
    throw new Error(`${name} is below the minimum`);
  }
  if (max !== undefined && value > max) {
    throw new Error(`${name} is above the maximum`);
  }
  return value;
}

function requireIsoTimestamp(value, name) {
  requireString(value, name, { min: 20, max: 40 });
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${name} is not ISO-8601`);
  return parsed;
}

function rejectUnexpectedKeys(value, allowed, name) {
  const unexpected = Object.keys(value).filter((key) => !allowed.has(key));
  if (unexpected.length > 0) {
    throw new Error(`${name} contains unexpected fields: ${unexpected.join(", ")}`);
  }
}

function validateTask(task, index) {
  requireObject(task, `tasks[${index}]`);
  rejectUnexpectedKeys(
    task,
    new Set([
      "id",
      "title",
      "owner",
      "state",
      "raw_state",
      "progress",
      "next_step",
      "updated_at",
      "attempt",
    ]),
    `tasks[${index}]`,
  );
  requireString(task.id, `tasks[${index}].id`, { max: 128 });
  requireString(task.title, `tasks[${index}].title`, { max: 1024 });
  requireString(task.owner, `tasks[${index}].owner`, { max: 128 });
  if (!TASK_STATES.has(task.state)) {
    throw new Error(`tasks[${index}].state is not supported`);
  }
  if (task.progress !== null && task.progress !== undefined) {
    requireFiniteNumber(task.progress, `tasks[${index}].progress`, {
      min: 0,
      max: 100,
    });
  }
  requireIsoTimestamp(task.updated_at, `tasks[${index}].updated_at`);
}

function validateGpu(gpu, index, seen) {
  requireObject(gpu, `gpus[${index}]`);
  rejectUnexpectedKeys(
    gpu,
    new Set([
      "id",
      "name",
      "utilization",
      "vram_used_gib",
      "vram_total_gib",
      "temperature_c",
      "power_w",
    ]),
    `gpus[${index}]`,
  );
  if (!Number.isInteger(gpu.id) || gpu.id < 0 || gpu.id > 5) {
    throw new Error(`gpus[${index}].id violates the GPU 0-5 allowlist`);
  }
  if (seen.has(gpu.id)) throw new Error(`gpus[${index}].id is duplicated`);
  seen.add(gpu.id);
  requireString(gpu.name, `gpus[${index}].name`, { max: 256 });
  requireFiniteNumber(gpu.utilization, `gpus[${index}].utilization`, {
    min: 0,
    max: 100,
  });
  requireFiniteNumber(gpu.vram_used_gib, `gpus[${index}].vram_used_gib`, {
    min: 0,
    max: 1024,
  });
  requireFiniteNumber(gpu.vram_total_gib, `gpus[${index}].vram_total_gib`, {
    min: 0.001,
    max: 1024,
  });
  if (gpu.vram_used_gib > gpu.vram_total_gib) {
    throw new Error(`gpus[${index}] reports used VRAM above total VRAM`);
  }
  requireFiniteNumber(gpu.temperature_c, `gpus[${index}].temperature_c`, {
    min: -30,
    max: 150,
  });
  requireFiniteNumber(gpu.power_w, `gpus[${index}].power_w`, {
    min: 0,
    max: 2000,
  });
}

function validateResourceUsage(value, name) {
  if (value === null || value === undefined) return;
  requireObject(value, name);
  rejectUnexpectedKeys(
    value,
    new Set(["used_gib", "total_gib", "percent"]),
    name,
  );
  const used = requireFiniteNumber(value.used_gib, `${name}.used_gib`, {
    min: 0,
    max: 1024 * 1024,
  });
  const total = requireFiniteNumber(value.total_gib, `${name}.total_gib`, {
    min: 0.001,
    max: 1024 * 1024,
  });
  const percent = requireFiniteNumber(value.percent, `${name}.percent`, {
    min: 0,
    max: 100,
  });
  if (used > total) {
    throw new Error(`${name}.used_gib cannot exceed total_gib`);
  }
  const expected = Math.round((used / total) * 1000) / 10;
  if (Math.abs(percent - expected) > 0.2) {
    throw new Error(`${name}.percent is inconsistent with used and total`);
  }
}

export function validateSnapshot(payload) {
  requireObject(payload, "snapshot");
  rejectUnexpectedKeys(
    payload,
    new Set([
      "schema_version",
      "system",
      "workspace_id",
      "workspace_name",
      "sequence",
      "observed_at",
      "collector",
      "data_classification",
      "orchestrator",
      "tasks_summary",
      "agents",
      "tasks",
      "ledger_events",
      "ledger",
      "gpus",
      "gpu_policy",
      "resources",
      "alerts",
      "release_gate",
      "source",
    ]),
    "snapshot",
  );
  if (payload.schema_version !== SNAPSHOT_SCHEMA_VERSION) {
    throw new Error("snapshot.schema_version is unsupported");
  }
  if (payload.system !== "Cogni-OS Operations") {
    throw new Error("snapshot.system is unsupported");
  }
  requireString(payload.system, "snapshot.system", { max: 256 });
  requireString(payload.workspace_id, "snapshot.workspace_id", { max: 128 });
  if (!WORKSPACE_ID.test(payload.workspace_id)) {
    throw new Error("snapshot.workspace_id contains unsafe characters");
  }
  requireString(payload.workspace_name, "snapshot.workspace_name", { max: 256 });
  if (!Number.isInteger(payload.sequence) || payload.sequence < 1) {
    throw new Error("snapshot.sequence must be a positive integer");
  }
  const snapshotObservedMs = requireIsoTimestamp(
    payload.observed_at,
    "snapshot.observed_at",
  );
  if (payload.data_classification !== "operational-metadata-only") {
    throw new Error("snapshot.data_classification must be operational-metadata-only");
  }

  const collector = requireObject(payload.collector, "snapshot.collector");
  rejectUnexpectedKeys(
    collector,
    new Set(["id", "version", "host", "platform"]),
    "snapshot.collector",
  );
  requireString(collector.id, "snapshot.collector.id", { max: 128 });
  requireString(collector.version, "snapshot.collector.version", { max: 64 });
  requireString(collector.host, "snapshot.collector.host", { max: 256 });
  requireString(collector.platform, "snapshot.collector.platform", {
    max: 64,
  });

  const orchestrator = requireObject(
    payload.orchestrator,
    "snapshot.orchestrator",
  );
  rejectUnexpectedKeys(
    orchestrator,
    new Set(["id", "role", "status"]),
    "snapshot.orchestrator",
  );
  requireString(orchestrator.id, "snapshot.orchestrator.id", { max: 128 });
  requireString(orchestrator.role, "snapshot.orchestrator.role", {
    max: 128,
  });
  requireString(orchestrator.status, "snapshot.orchestrator.status", {
    max: 64,
  });

  const ledger = requireObject(payload.ledger, "snapshot.ledger");
  rejectUnexpectedKeys(
    ledger,
    new Set(["status", "valid", "events", "head", "signed"]),
    "snapshot.ledger",
  );
  if (typeof ledger.valid !== "boolean") {
    throw new Error("snapshot.ledger.valid must be boolean");
  }
  if (!Number.isInteger(ledger.events) || ledger.events < 0) {
    throw new Error("snapshot.ledger.events must be a non-negative integer");
  }
  if (typeof ledger.signed !== "boolean") {
    throw new Error("snapshot.ledger.signed must be boolean");
  }
  if (!HEX_64.test(String(ledger.head || "").toLowerCase())) {
    throw new Error("snapshot.ledger.head must be a SHA-256 hash");
  }
  if (ledger.valid && !ledger.signed) {
    throw new Error("a valid ledger must be signed");
  }
  if (ledger.status === "VERIFIED" && (!ledger.valid || !ledger.signed)) {
    throw new Error("a VERIFIED ledger must be valid and signed");
  }

  if (!Array.isArray(payload.tasks) || payload.tasks.length > 1000) {
    throw new Error("snapshot.tasks must be an array with at most 1000 items");
  }
  payload.tasks.forEach(validateTask);

  const summary = requireObject(
    payload.tasks_summary,
    "snapshot.tasks_summary",
  );
  rejectUnexpectedKeys(
    summary,
    new Set([
      "total",
      "pending",
      "claimed",
      "running",
      "blocked",
      "submitted",
      "trusted_verified",
      "verification_disputed",
      "rejected",
      "completion_percentage",
      "progress_basis",
    ]),
    "snapshot.tasks_summary",
  );
  const countFields = [
    "total",
    "pending",
    "claimed",
    "running",
    "blocked",
    "submitted",
    "trusted_verified",
    "verification_disputed",
    "rejected",
  ];
  for (const field of countFields) {
    if (!Number.isInteger(summary[field]) || summary[field] < 0) {
      throw new Error(`snapshot.tasks_summary.${field} must be non-negative`);
    }
  }
  if (summary.total !== payload.tasks.length) {
    throw new Error("snapshot.tasks_summary.total does not match snapshot.tasks");
  }
  const projected = {
    pending: 0,
    claimed: 0,
    running: 0,
    blocked: 0,
    submitted: 0,
    trusted_verified: 0,
    verification_disputed: 0,
    rejected: 0,
  };
  for (const task of payload.tasks) {
    if (task.state === "verified" || task.state === "archived") {
      projected.trusted_verified += 1;
    } else if (Object.hasOwn(projected, task.state)) {
      projected[task.state] += 1;
    }
  }
  for (const [field, expected] of Object.entries(projected)) {
    if (summary[field] !== expected) {
      throw new Error(
        `snapshot.tasks_summary.${field} does not match snapshot.tasks`,
      );
    }
  }
  if (summary.progress_basis !== "trusted-ledger-task-states") {
    throw new Error("snapshot.tasks_summary.progress_basis is unsupported");
  }
  if (
    summary.completion_percentage !== null &&
    summary.completion_percentage !== undefined
  ) {
    requireFiniteNumber(
      summary.completion_percentage,
      "snapshot.tasks_summary.completion_percentage",
      { min: 0, max: 100 },
    );
    const expected = summary.total
      ? Math.round((summary.trusted_verified / summary.total) * 1000) / 10
      : null;
    if (
      expected === null ||
      Math.abs(summary.completion_percentage - expected) > 0.05
    ) {
      throw new Error(
        "snapshot.tasks_summary.completion_percentage is not evidence-derived",
      );
    }
  }

  if (!Array.isArray(payload.agents) || payload.agents.length > 128) {
    throw new Error("snapshot.agents must be an array with at most 128 items");
  }
  const attestedAgentIndexes = [];
  payload.agents.forEach((agent, index) => {
    requireObject(agent, `agents[${index}]`);
    rejectUnexpectedKeys(
      agent,
      new Set([
        "id",
        "role",
        "status",
        "current_task",
        "task_progress",
        "next_step",
        "mode",
        "attestation_evidence_sha256",
        "attested_at",
        "attested_source_commit",
      ]),
      `agents[${index}]`,
    );
    requireString(agent.id, `agents[${index}].id`, { max: 128 });
    requireString(agent.role, `agents[${index}].role`, { max: 128 });
    requireString(agent.status, `agents[${index}].status`, { max: 64 });
    if (
      ![
        "UNATTESTED",
        "CONFIGURED",
        "READY",
        "BUSY",
        "BLOCKED",
        "OFFLINE",
      ].includes(agent.status)
    ) {
      throw new Error(`agents[${index}].status is not evidence-safe`);
    }
    if (agent.current_task !== null && agent.current_task !== undefined) {
      requireString(agent.current_task, `agents[${index}].current_task`, {
        max: 1024,
      });
    }
    if (agent.task_progress !== null && agent.task_progress !== undefined) {
      requireFiniteNumber(
        agent.task_progress,
        `agents[${index}].task_progress`,
        { min: 0, max: 100 },
      );
    }
    if (agent.next_step !== null && agent.next_step !== undefined) {
      requireString(agent.next_step, `agents[${index}].next_step`, {
        max: 2048,
      });
    }
    if (agent.mode !== null && agent.mode !== undefined) {
      requireString(agent.mode, `agents[${index}].mode`, { max: 64 });
    }

    const isAttested = agent.status === "READY" || agent.status === "BUSY";
    if (isAttested) {
      if (
        !HEX_64.test(
          String(agent.attestation_evidence_sha256 || "").toLowerCase(),
        )
      ) {
        throw new Error(
          `agents[${index}] READY/BUSY requires a SHA-256 attestation`,
        );
      }
      const attestedAtMs = requireIsoTimestamp(
        agent.attested_at,
        `agents[${index}].attested_at`,
      );
      const attestationAgeSeconds =
        (snapshotObservedMs - attestedAtMs) / 1000;
      if (attestationAgeSeconds < 0 || attestationAgeSeconds > 90) {
        throw new Error(
          `agents[${index}] attestation is outside the 90 second freshness window`,
        );
      }
      requireString(
        agent.attested_source_commit,
        `agents[${index}].attested_source_commit`,
        { min: 7, max: 64 },
      );
      if (!/^[0-9a-f]{7,64}$/.test(agent.attested_source_commit)) {
        throw new Error(
          `agents[${index}].attested_source_commit is not a commit hash`,
        );
      }
      attestedAgentIndexes.push(index);
    } else if (
      (agent.attestation_evidence_sha256 !== null &&
        agent.attestation_evidence_sha256 !== undefined) ||
      (agent.attested_at !== null && agent.attested_at !== undefined) ||
      (agent.attested_source_commit !== null &&
        agent.attested_source_commit !== undefined)
    ) {
      throw new Error(
        `agents[${index}] cannot expose attestation fields without READY/BUSY`,
      );
    }
  });

  if (!Array.isArray(payload.gpus) || payload.gpus.length > 6) {
    throw new Error("snapshot.gpus must contain at most GPU 0-5");
  }
  const seenGpuIds = new Set();
  payload.gpus.forEach((gpu, index) => validateGpu(gpu, index, seenGpuIds));

  const policy = requireObject(payload.gpu_policy, "snapshot.gpu_policy");
  rejectUnexpectedKeys(
    policy,
    new Set([
      "allowed_ids",
      "denied_ids",
      "telemetry_state",
      "violating_ids",
    ]),
    "snapshot.gpu_policy",
  );
  if (
    JSON.stringify(policy.allowed_ids) !== JSON.stringify([0, 1, 2, 3, 4, 5]) ||
    JSON.stringify(policy.denied_ids) !== JSON.stringify([6, 7])
  ) {
    throw new Error("snapshot.gpu_policy must enforce GPU 0-5 and deny GPU 6-7");
  }
  if (
    !["MEASURED", "DISABLED", "UNAVAILABLE", "POLICY_VIOLATION"].includes(
      policy.telemetry_state,
    )
  ) {
    throw new Error("snapshot.gpu_policy.telemetry_state is unsupported");
  }
  if (
    !Array.isArray(policy.violating_ids) ||
    policy.violating_ids.some((id) => id !== 6 && id !== 7)
  ) {
    throw new Error("snapshot.gpu_policy.violating_ids is malformed");
  }
  if (
    policy.telemetry_state === "POLICY_VIOLATION" &&
    policy.violating_ids.length === 0
  ) {
    throw new Error("GPU policy violation requires a denied GPU id");
  }
  if (
    policy.telemetry_state !== "POLICY_VIOLATION" &&
    policy.violating_ids.length !== 0
  ) {
    throw new Error("denied GPU ids require POLICY_VIOLATION state");
  }

  const resources = requireObject(payload.resources, "snapshot.resources");
  rejectUnexpectedKeys(
    resources,
    new Set(["memory", "disk", "load_average_1m", "uptime_seconds"]),
    "snapshot.resources",
  );
  validateResourceUsage(resources.memory, "snapshot.resources.memory");
  validateResourceUsage(resources.disk, "snapshot.resources.disk");
  if (
    resources.load_average_1m !== null &&
    resources.load_average_1m !== undefined
  ) {
    requireFiniteNumber(
      resources.load_average_1m,
      "snapshot.resources.load_average_1m",
      { min: 0, max: 100000 },
    );
  }
  if (
    resources.uptime_seconds !== null &&
    resources.uptime_seconds !== undefined
  ) {
    requireFiniteNumber(
      resources.uptime_seconds,
      "snapshot.resources.uptime_seconds",
      { min: 0, max: 100 * 365 * 24 * 60 * 60 },
    );
  }

  if (!Array.isArray(payload.alerts) || payload.alerts.length > 256) {
    throw new Error("snapshot.alerts must contain at most 256 items");
  }
  payload.alerts.forEach((alert, index) => {
    requireObject(alert, `alerts[${index}]`);
    rejectUnexpectedKeys(
      alert,
      new Set(["severity", "code", "message", "observed_at"]),
      `alerts[${index}]`,
    );
    if (!["info", "warning", "critical"].includes(alert.severity)) {
      throw new Error(`alerts[${index}].severity is unsupported`);
    }
    requireString(alert.code, `alerts[${index}].code`, { max: 128 });
    if (!ALERT_CODE.test(alert.code)) {
      throw new Error(`alerts[${index}].code is malformed`);
    }
    requireString(alert.message, `alerts[${index}].message`, { max: 2048 });
    requireIsoTimestamp(alert.observed_at, `alerts[${index}].observed_at`);
  });

  const releaseGate = requireObject(
    payload.release_gate,
    "snapshot.release_gate",
  );
  rejectUnexpectedKeys(
    releaseGate,
    new Set(["status", "reasons", "evidence_sha256"]),
    "snapshot.release_gate",
  );
  requireString(releaseGate.status, "snapshot.release_gate.status", {
    max: 64,
  });
  if (!["PASS", "NO_GO"].includes(releaseGate.status)) {
    throw new Error("snapshot.release_gate.status must be PASS or NO_GO");
  }
  if (
    !Array.isArray(releaseGate.reasons) ||
    releaseGate.reasons.length > 64 ||
    releaseGate.reasons.some(
      (reason) => typeof reason !== "string" || reason.length < 1 || reason.length > 2048,
    )
  ) {
    throw new Error("snapshot.release_gate.reasons must be bounded strings");
  }
  if (releaseGate.status === "PASS") {
    if (
      !ledger.valid ||
      !ledger.signed ||
      releaseGate.reasons.length !== 0 ||
      !HEX_64.test(String(releaseGate.evidence_sha256 || ""))
    ) {
      throw new Error("PASS release gate requires a valid ledger and evidence hash");
    }
  } else if (releaseGate.evidence_sha256 !== null) {
    throw new Error("NO_GO release gate must not expose an evidence hash");
  }

  const source = requireObject(payload.source, "snapshot.source");
  rejectUnexpectedKeys(
    source,
    new Set([
      "git_commit",
      "tree_clean",
      "tree_fingerprint",
      "change_count",
      "task_projection_audit",
    ]),
    "snapshot.source",
  );
  requireString(source.git_commit, "snapshot.source.git_commit", {
    min: 7,
    max: 64,
  });
  if (
    source.git_commit !== "unknown" &&
    !/^[0-9a-f]{7,64}$/.test(source.git_commit)
  ) {
    throw new Error("snapshot.source.git_commit is not a commit hash");
  }
  if (typeof source.tree_clean !== "boolean") {
    throw new Error("snapshot.source.tree_clean must be boolean");
  }
  if (!HEX_64.test(String(source.tree_fingerprint || ""))) {
    throw new Error("snapshot.source.tree_fingerprint must be SHA-256");
  }
  if (!Number.isInteger(source.change_count) || source.change_count < 0) {
    throw new Error("snapshot.source.change_count must be non-negative");
  }
  if (source.tree_clean !== (source.change_count === 0)) {
    throw new Error("snapshot.source tree state is inconsistent");
  }
  for (const index of attestedAgentIndexes) {
    if (payload.agents[index].attested_source_commit !== source.git_commit) {
      throw new Error(
        `agents[${index}] attestation does not match snapshot.source.git_commit`,
      );
    }
  }
  const projectionAudit = requireObject(
    source.task_projection_audit,
    "snapshot.source.task_projection_audit",
  );
  rejectUnexpectedKeys(
    projectionAudit,
    new Set([
      "valid",
      "events_count",
      "projected_count",
      "actual_count",
      "mismatch_count",
    ]),
    "snapshot.source.task_projection_audit",
  );
  if (typeof projectionAudit.valid !== "boolean") {
    throw new Error("snapshot.source.task_projection_audit.valid must be boolean");
  }
  for (const field of [
    "events_count",
    "projected_count",
    "actual_count",
    "mismatch_count",
  ]) {
    if (!Number.isInteger(projectionAudit[field]) || projectionAudit[field] < 0) {
      throw new Error(
        `snapshot.source.task_projection_audit.${field} must be non-negative`,
      );
    }
  }
  if (releaseGate.status === "PASS") {
    if (
      !source.tree_clean ||
      !projectionAudit.valid ||
      projectionAudit.mismatch_count !== 0 ||
      summary.total < 1 ||
      summary.trusted_verified !== summary.total ||
      summary.verification_disputed !== 0 ||
      policy.telemetry_state === "POLICY_VIOLATION" ||
      policy.violating_ids.length !== 0 ||
      attestedAgentIndexes.length < 1 ||
      !attestedAgentIndexes.some(
        (index) =>
          payload.agents[index].attestation_evidence_sha256 ===
          releaseGate.evidence_sha256,
      )
    ) {
      throw new Error(
        "PASS release gate requires clean source, trusted tasks, compliant GPUs, and an attested agent",
      );
    }
  }

  if (!Array.isArray(payload.ledger_events) || payload.ledger_events.length > 100) {
    throw new Error("snapshot.ledger_events must contain at most 100 items");
  }
  payload.ledger_events.forEach((event, index) => {
    requireObject(event, `ledger_events[${index}]`);
    rejectUnexpectedKeys(
      event,
      new Set([
        "timestamp",
        "actor",
        "action",
        "task_id",
        "task_title",
        "event_hash",
      ]),
      `ledger_events[${index}]`,
    );
    requireIsoTimestamp(event.timestamp, `ledger_events[${index}].timestamp`);
    requireString(event.actor, `ledger_events[${index}].actor`, { max: 128 });
    requireString(event.action, `ledger_events[${index}].action`, { max: 128 });
    if (event.task_id !== null && event.task_id !== undefined) {
      requireString(event.task_id, `ledger_events[${index}].task_id`, {
        max: 128,
      });
    }
    if (event.task_title !== null && event.task_title !== undefined) {
      requireString(event.task_title, `ledger_events[${index}].task_title`, {
        max: 1024,
      });
    }
    if (!HEX_64.test(String(event.event_hash || ""))) {
      throw new Error(`ledger_events[${index}].event_hash must be SHA-256`);
    }
  });
  return payload;
}

export function validateIngestHeaders(headers) {
  const keyId = requireString(
    headers.get("x-cogni-key-id"),
    "x-cogni-key-id",
    { min: 3, max: 64 },
  );
  if (!KEY_ID.test(keyId)) {
    throw new Error("x-cogni-key-id is malformed");
  }
  const workspaceId = requireString(
    headers.get("x-cogni-workspace"),
    "x-cogni-workspace",
    { max: 128 },
  );
  if (!WORKSPACE_ID.test(workspaceId)) {
    throw new Error("x-cogni-workspace contains unsafe characters");
  }
  const sequence = Number(headers.get("x-cogni-sequence"));
  if (!Number.isInteger(sequence) || sequence < 1) {
    throw new Error("x-cogni-sequence must be a positive integer");
  }
  const observedAt = requireString(
    headers.get("x-cogni-observed-at"),
    "x-cogni-observed-at",
    { min: 20, max: 40 },
  );
  requireIsoTimestamp(observedAt, "x-cogni-observed-at");
  const nonce = requireString(headers.get("x-cogni-nonce"), "x-cogni-nonce", {
    min: 16,
    max: 128,
  });
  if (!NONCE.test(nonce)) throw new Error("x-cogni-nonce is malformed");
  const signature = normalizeSignature(headers.get("x-cogni-signature"));
  if (!HEX_64.test(signature)) throw new Error("x-cogni-signature is malformed");
  return { keyId, workspaceId, sequence, observedAt, nonce, signature };
}

export async function verifyStoredRow(row, secret) {
  requireObject(row, "stored snapshot");
  const rawBody = requireString(row.payload, "stored snapshot.payload", {
    min: 2,
    max: MAX_BODY_BYTES,
  });
  const bodySha256 = normalizeSignature(row.body_sha256);
  if (!HEX_64.test(bodySha256)) {
    throw new Error("stored snapshot body hash is malformed");
  }
  const computedBodySha256 = await sha256Hex(
    new TextEncoder().encode(rawBody),
  );
  if (!constantTimeHexEqual(computedBodySha256, bodySha256)) {
    throw new Error("stored snapshot body hash does not match its payload");
  }

  const payload = JSON.parse(rawBody);
  validateSnapshot(payload);
  const sequence = Number(row.sequence);
  if (
    payload.workspace_id !== row.workspace_id ||
    payload.sequence !== sequence ||
    payload.observed_at !== row.observed_at
  ) {
    throw new Error("stored snapshot envelope does not match its payload");
  }

  const nonce = requireString(row.nonce, "stored snapshot.nonce", {
    min: 16,
    max: 128,
  });
  if (!NONCE.test(nonce)) {
    throw new Error("stored snapshot nonce is malformed");
  }
  const keyId = requireString(row.key_id, "stored snapshot.key_id", {
    min: 3,
    max: 64,
  });
  if (!KEY_ID.test(keyId)) {
    throw new Error("stored snapshot key id is malformed");
  }
  const message = signatureMessage({
    keyId,
    workspaceId: row.workspace_id,
    sequence,
    observedAt: row.observed_at,
    nonce,
    bodySha256,
  });
  if (!(await verifySignature(secret, message, row.signature))) {
    throw new Error("stored snapshot signature verification failed");
  }
  return payload;
}

export function assertFreshTimestamp(
  observedAt,
  now = Date.now(),
  maxSkewSeconds = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
) {
  const configuredSkew = Number(maxSkewSeconds);
  const boundedMaxSkew =
    Number.isFinite(configuredSkew) &&
    configuredSkew >= 30 &&
    configuredSkew <= 900
      ? configuredSkew
      : DEFAULT_MAX_CLOCK_SKEW_SECONDS;
  const observed = Date.parse(observedAt);
  const skewSeconds = Math.abs(now - observed) / 1000;
  if (!Number.isFinite(observed) || skewSeconds > boundedMaxSkew) {
    throw new Error("snapshot timestamp is outside the accepted clock window");
  }
  return skewSeconds;
}

export function failClosedSnapshot(
  state,
  reason,
  { workspaceId = null, now = new Date() } = {},
) {
  return {
    schema_version: SNAPSHOT_SCHEMA_VERSION,
    system: "Cogni-OS Operations",
    timestamp: now.toISOString(),
    workspace_id: workspaceId,
    workspace_name: "연결되지 않음",
    monitoring: {
      state,
      reason,
      signature_verified: false,
      sequence: null,
      age_seconds: null,
      observed_at: null,
      received_at: null,
    },
    tasks_summary: {
      total: 0,
      pending: 0,
      claimed: 0,
      running: 0,
      blocked: 0,
      submitted: 0,
      trusted_verified: 0,
      verification_disputed: 0,
      rejected: 0,
      completion_percentage: null,
      progress_basis: "unavailable",
    },
    agents: [],
    tasks: [],
    ledger_events: [],
    ledger: {
      status: "NOT_VERIFIED",
      valid: false,
      events: 0,
      head: null,
    },
    gpus: [],
    gpu_policy: {
      allowed_ids: [0, 1, 2, 3, 4, 5],
      denied_ids: [6, 7],
      telemetry_state: "UNAVAILABLE",
      violating_ids: [],
    },
    resources: {},
    alerts: [
      {
        severity: "critical",
        code: state,
        message: reason,
        observed_at: now.toISOString(),
      },
    ],
    release_gate: {
      status: "NO_GO",
      reasons: [reason],
      evidence_sha256: null,
    },
    source: {
      git_commit: "unknown",
    },
  };
}

export function withMonitoringEnvelope(payload, row, now = new Date()) {
  const configuredMaxAge = Number(row.max_age_seconds);
  const maxAge =
    Number.isFinite(configuredMaxAge) &&
    configuredMaxAge >= 15 &&
    configuredMaxAge <= 3600
      ? configuredMaxAge
      : DEFAULT_MAX_AGE_SECONDS;
  const observedMs = Date.parse(payload.observed_at);
  const ageSeconds = Math.max(0, (now.getTime() - observedMs) / 1000);
  const state = ageSeconds <= maxAge ? "LIVE" : "STALE";
  const copy = JSON.parse(JSON.stringify(payload));
  copy.timestamp = now.toISOString();
  copy.monitoring = {
    state,
    reason:
      state === "LIVE"
        ? "서명 검증된 최신 운영 스냅샷"
        : `마지막 스냅샷이 ${Math.round(ageSeconds)}초 경과했습니다`,
    signature_verified: true,
    sequence: Number(row.sequence),
    age_seconds: Math.round(ageSeconds * 10) / 10,
    observed_at: row.observed_at,
    received_at: row.received_at,
    body_sha256: row.body_sha256,
    max_age_seconds: maxAge,
  };
  if (state === "STALE") {
    copy.tasks_summary = {
      total: 0,
      pending: 0,
      claimed: 0,
      running: 0,
      blocked: 0,
      submitted: 0,
      trusted_verified: 0,
      verification_disputed: 0,
      rejected: 0,
      completion_percentage: null,
      progress_basis: "stale-unavailable",
    };
    copy.agents = [];
    copy.tasks = [];
    copy.ledger_events = [];
    copy.ledger = {
      status: "STALE",
      valid: false,
      events: 0,
      head: null,
      signed: false,
    };
    copy.gpus = [];
    copy.gpu_policy = {
      allowed_ids: [0, 1, 2, 3, 4, 5],
      denied_ids: [6, 7],
      telemetry_state: "STALE",
      violating_ids: [],
    };
    copy.resources = {};
    copy.release_gate = {
      status: "NO_GO",
      reasons: [copy.monitoring.reason],
      evidence_sha256: null,
    };
    copy.alerts = [
      {
        severity: "critical",
        code: "STALE_SNAPSHOT",
        message: copy.monitoring.reason,
        observed_at: now.toISOString(),
      },
    ];
  }
  return copy;
}
