#!/usr/bin/env node

import { createHash } from "node:crypto";
import { closeSync, openSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const PRODUCTION_ORIGIN = "https://cogni-os-orchestrator.pages.dev";
const PRODUCTION_PROJECT = "cogni-os-orchestrator";
const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;
const MODES = new Set(["configured", "live"]);
const CONFIGURED_SNAPSHOT_STATES = new Set(["LIVE", "NO_DATA", "STALE"]);
const CONFIGURED_HISTORY_STATES = new Set(["AVAILABLE", "NO_TRUSTED_DATA"]);
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const PHASE_REQUIREMENT_COUNTS = new Map([
  ["P01-TRUTH", 3],
  ["P02-ORCHESTRATION", 4],
  ["P03-EVIDENCE", 3],
  ["P04-WORLD", 3],
  ["P05-FINANCE", 3],
  ["P06-TWIN", 3],
  ["P07-WORKSPACE", 3],
  ["P08-CORE", 3],
  ["P09-HARNESS", 3],
  ["P10-COGNIBOARD", 3],
  ["P11-RELEASE", 4],
]);
const PHASE_IDS = [...PHASE_REQUIREMENT_COUNTS.keys()];
const AUDITOR_POLICY_PATHS = [
  "scripts/audit_phase_evidence.py",
  "src/cogni_os/phase_evidence.py",
];

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, expected) {
  if (!isObject(value)) return false;
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  return actual.length === required.length && actual.every((key, index) => key === required[index]);
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical JSON rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  throw new Error("canonical JSON rejects unsupported values");
}

export function phaseAuditSha256(audit) {
  return createHash("sha256").update(canonicalJson(audit), "utf8").digest("hex");
}

function releaseAndRoadmapFailures(snapshot, expectedCommit) {
  const failures = [];
  const releaseGate = snapshot?.release_gate;
  if (
    !hasExactKeys(releaseGate, ["status", "reasons", "evidence_sha256"]) ||
    releaseGate.status !== "PASS" ||
    !Array.isArray(releaseGate.reasons) ||
    releaseGate.reasons.length !== 0 ||
    !SHA256_PATTERN.test(String(releaseGate.evidence_sha256 || ""))
  ) {
    failures.push("snapshot.release_gate");
  }

  const roadmap = snapshot?.roadmap;
  if (
    !hasExactKeys(roadmap, [
      "schema_version",
      "total",
      "trusted_complete",
      "current_release_validated",
      "progress_percent",
      "progress_basis",
      "phases",
    ]) ||
    roadmap.schema_version !== 1 ||
    roadmap.total !== PHASE_IDS.length ||
    roadmap.trusted_complete !== PHASE_IDS.length ||
    roadmap.current_release_validated !== PHASE_IDS.length ||
    roadmap.progress_percent !== 100 ||
    roadmap.progress_basis !== "historically-trusted-roadmap-task-states" ||
    !Array.isArray(roadmap.phases) ||
    roadmap.phases.length !== PHASE_IDS.length
  ) {
    failures.push("snapshot.roadmap");
    return failures;
  }

  roadmap.phases.forEach((phase, index) => {
    const expectedId = PHASE_IDS[index];
    const expectedPrerequisites = index === 0 ? [] : [PHASE_IDS[index - 1]];
    if (
      !hasExactKeys(phase, [
        "id",
        "title",
        "state",
        "trusted_complete",
        "verified_source_commit",
        "current_release_state",
        "current_release_validated",
        "prerequisites",
      ]) ||
      phase.id !== expectedId ||
      typeof phase.title !== "string" ||
      !phase.title ||
      !["verified", "archived"].includes(phase.state) ||
      phase.trusted_complete !== true ||
      phase.verified_source_commit !== expectedCommit ||
      !["verified", "archived"].includes(phase.current_release_state) ||
      phase.current_release_validated !== true ||
      !Array.isArray(phase.prerequisites) ||
      phase.prerequisites.length !== expectedPrerequisites.length ||
      phase.prerequisites.some((value, prerequisiteIndex) => value !== expectedPrerequisites[prerequisiteIndex])
    ) {
      failures.push(`snapshot.roadmap.phases.${expectedId}`);
    }
  });
  return failures;
}

function phaseEvidenceFailures(snapshot, expectedCommit) {
  const failures = [];
  const audit = snapshot?.phase_evidence_audit;
  const binding = snapshot?.phase_evidence_binding;
  if (snapshot?.schema_version !== "1.3") {
    failures.push("snapshot.schema_version");
  }
  if (
    !hasExactKeys(audit, [
      "schema",
      "coverage_status",
      "source_commit",
      "total_phases",
      "validated_phases",
      "progress_percent",
      "phases",
      "release_authority",
      "auditor_policy",
    ]) ||
    audit.schema !== "cogni.phase-evidence-audit.v2" ||
    audit.coverage_status !== "SEMANTIC_COVERAGE_PASS" ||
    audit.source_commit !== expectedCommit ||
    audit.total_phases !== PHASE_IDS.length ||
    audit.validated_phases !== PHASE_IDS.length ||
    audit.progress_percent !== 100 ||
    audit.release_authority !== false ||
    !Array.isArray(audit.phases) ||
    audit.phases.length !== PHASE_IDS.length
  ) {
    failures.push("snapshot.phase_evidence_audit");
  }

  const evidenceDigests = new Set();
  if (Array.isArray(audit?.phases) && audit.phases.length === PHASE_IDS.length) {
    audit.phases.forEach((phase, index) => {
      const expectedId = PHASE_IDS[index];
      const expectedCount = PHASE_REQUIREMENT_COUNTS.get(expectedId);
      const artifacts = phase?.artifact_sha256;
      const outputs = phase?.trusted_output_sha256;
      if (
        !hasExactKeys(phase, [
          "phase_id",
          "coverage_status",
          "reasons",
          "source_commit",
          "artifact_sha256",
          "trusted_output_sha256",
          "release_authority",
        ]) ||
        phase.phase_id !== expectedId ||
        phase.coverage_status !== "SEMANTIC_COVERAGE_PASS" ||
        !Array.isArray(phase.reasons) ||
        phase.reasons.length !== 0 ||
        phase.source_commit !== expectedCommit ||
        phase.release_authority !== false ||
        !Array.isArray(artifacts) ||
        artifacts.length !== expectedCount ||
        !Array.isArray(outputs) ||
        outputs.length !== expectedCount
      ) {
        failures.push(`snapshot.phase_evidence_audit.phases.${expectedId}`);
        return;
      }
      for (const digest of [...artifacts, ...outputs]) {
        if (!SHA256_PATTERN.test(String(digest || "")) || evidenceDigests.has(digest)) {
          failures.push(`snapshot.phase_evidence_audit.digest_reuse_or_invalid.${expectedId}`);
        } else {
          evidenceDigests.add(digest);
        }
      }
    });
  }

  const policy = audit?.auditor_policy;
  if (
    !hasExactKeys(policy, [
      "source_commit",
      "source_tree",
      "current_source_commit_bound",
      "policy_sha256",
      "files",
    ]) ||
    policy.source_commit !== expectedCommit ||
    !COMMIT_PATTERN.test(String(policy.source_tree || "")) ||
    policy.current_source_commit_bound !== true ||
    !SHA256_PATTERN.test(String(policy.policy_sha256 || "")) ||
    !Array.isArray(policy.files) ||
    policy.files.length !== AUDITOR_POLICY_PATHS.length ||
    policy.files.some(
      (file, index) =>
        !hasExactKeys(file, ["path", "sha256"]) ||
        file.path !== AUDITOR_POLICY_PATHS[index] ||
        !SHA256_PATTERN.test(String(file.sha256 || "")),
    )
  ) {
    failures.push("snapshot.phase_evidence_audit.auditor_policy");
  }

  let auditSha256 = null;
  if (isObject(audit)) {
    try {
      auditSha256 = phaseAuditSha256(audit);
    } catch {
      failures.push("snapshot.phase_evidence_audit.canonicalization");
    }
  }
  const monitoring = snapshot?.monitoring;
  const releaseDeployment = snapshot?.release_deployment;
  const releaseEvidence = snapshot?.release_gate?.evidence_sha256;
  if (
    !hasExactKeys(binding, [
      "schema",
      "audit_sha256",
      "source_commit",
      "sequence",
      "body_sha256",
      "deployment_id",
      "deployment_url",
      "release_gate_evidence_sha256",
      "signature_verified",
    ]) ||
    binding.schema !== "cogni.phase-evidence-monitor-binding.v1" ||
    binding.audit_sha256 !== auditSha256 ||
    binding.source_commit !== expectedCommit ||
    !Number.isSafeInteger(binding.sequence) ||
    binding.sequence < 1 ||
    binding.sequence !== monitoring?.sequence ||
    !SHA256_PATTERN.test(String(binding.body_sha256 || "")) ||
    binding.body_sha256 !== monitoring?.body_sha256 ||
    binding.deployment_id !== releaseDeployment?.deployment_id ||
    binding.deployment_url !== releaseDeployment?.deployment_url ||
    binding.release_gate_evidence_sha256 !== releaseEvidence ||
    binding.signature_verified !== true ||
    monitoring?.signature_verified !== true ||
    monitoring?.payload_signature_verified !== true
  ) {
    failures.push("snapshot.phase_evidence_binding");
  }
  return { failures, auditSha256 };
}

function latestHistoryFailures(history, snapshot, expectedCommit, auditSha256) {
  const failures = [];
  const rows = history?.body?.history;
  if (!Array.isArray(rows) || rows.length < 1) return ["history.no_trusted_live_rows"];
  let previousSequence = 0;
  for (const row of rows) {
    if (
      !isObject(row) ||
      !Number.isSafeInteger(row.sequence) ||
      row.sequence <= previousSequence ||
      !SHA256_PATTERN.test(String(row.body_sha256 || ""))
    ) {
      failures.push("history.sequence_or_digest_order");
      break;
    }
    previousSequence = row.sequence;
  }
  const latest = rows.at(-1);
  const monitoring = snapshot?.monitoring;
  const releaseDeployment = snapshot?.release_deployment;
  const releaseEvidence = snapshot?.release_gate?.evidence_sha256;
  if (
    latest?.sequence !== monitoring?.sequence ||
    latest?.body_sha256 !== monitoring?.body_sha256 ||
    latest?.observed_at !== monitoring?.observed_at ||
    latest?.received_at !== monitoring?.received_at ||
    latest?.source_commit !== expectedCommit ||
    latest?.deployment_id !== releaseDeployment?.deployment_id ||
    latest?.deployment_url !== releaseDeployment?.deployment_url ||
    latest?.signature_verified !== true ||
    latest?.phase_evidence_audit_sha256 !== auditSha256 ||
    latest?.release_gate_evidence_sha256 !== releaseEvidence ||
    latest?.release_gate?.status !== "PASS" ||
    latest?.release_gate?.evidence_sha256 !== releaseEvidence ||
    latest?.roadmap?.trusted_complete !== PHASE_IDS.length ||
    latest?.roadmap?.current_release_validated !== PHASE_IDS.length
  ) {
    failures.push("history.latest_not_snapshot_bound");
  }
  return failures;
}

function deploymentFailures(deployment, expectedCommit, label) {
  const failures = [];
  let parsed;
  try {
    parsed = new URL(String(deployment?.deployment_url || ""));
  } catch {
    parsed = null;
  }
  const uniqueDeployment =
    parsed !== null &&
    parsed.protocol === "https:" &&
    !parsed.username &&
    !parsed.password &&
    !parsed.port &&
    !parsed.search &&
    !parsed.hash &&
    ["", "/"].includes(parsed.pathname) &&
    parsed.hostname !== `${PRODUCTION_PROJECT}.pages.dev` &&
    parsed.hostname.endsWith(`.${PRODUCTION_PROJECT}.pages.dev`);
  const expected = {
    attribution: "BUILD_BOUND",
    branch: "main",
    environment: "production",
    project: PRODUCTION_PROJECT,
    provider: "cloudflare-pages",
    source_commit: expectedCommit,
    url: PRODUCTION_ORIGIN,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (deployment?.[key] !== value) {
      failures.push(`${label}.${key}`);
    }
  }
  if (!uniqueDeployment) failures.push(`${label}.deployment_url`);
  return failures;
}

function responseState(record) {
  return isObject(record?.body)
    ? String(record.body.state || record.body.monitoring?.state || "UNKNOWN")
    : "INVALID";
}

export function evaluateProductionProbe({
  expectedCommit,
  mode,
  health,
  snapshot,
  history,
  observedAt = new Date().toISOString(),
}) {
  if (!/^[0-9a-f]{40}$/.test(String(expectedCommit || ""))) {
    throw new Error("expectedCommit must be one lowercase 40-character Git SHA");
  }
  if (!MODES.has(mode)) throw new Error("mode must be configured or live");
  const failures = [];
  const warnings = [];
  if (health?.status !== 200 || !isObject(health?.body)) {
    failures.push("health.http_or_json");
  } else {
    const checks = health.body.checks;
    const expectedChecks = {
      build_attribution_ready: true,
      d1_binding: true,
      deployment_attribution: "BUILD_BOUND",
      operational_ingest_ready: true,
      publisher_keyring: true,
      release_attribution_ready: false,
      release_evidence_state: "API_EVIDENCE_REQUIRED",
      runtime_configuration_ready: true,
      storage_schema_verified: true,
      storage_state: "READY",
      workspace_id: true,
    };
    if (health.body.ok !== true || health.body.state !== "CONFIGURED") {
      failures.push("health.not_configured");
    }
    if (!isObject(checks)) {
      failures.push("health.checks");
    } else {
      for (const [key, value] of Object.entries(expectedChecks)) {
        if (checks[key] !== value) failures.push(`health.checks.${key}`);
      }
      if (!Number.isInteger(checks.publisher_keys) || checks.publisher_keys < 1) {
        failures.push("health.checks.publisher_keys");
      }
    }
    failures.push(
      ...deploymentFailures(health.body.deployment, expectedCommit, "health.deployment"),
    );
  }

  const snapshotState = responseState(snapshot);
  const historyState = responseState(history);
  if (snapshot?.status !== 200 || !isObject(snapshot?.body)) {
    failures.push("snapshot.http_or_json");
  } else {
    failures.push(
      ...deploymentFailures(
        snapshot.body.deployment,
        expectedCommit,
        "snapshot.deployment",
      ),
    );
    if (!CONFIGURED_SNAPSHOT_STATES.has(snapshotState)) {
      failures.push("snapshot.platform_unavailable");
    } else if (snapshotState !== "LIVE") {
      warnings.push(`snapshot.${snapshotState}`);
    }
  }
  if (history?.status !== 200 || !isObject(history?.body)) {
    failures.push("history.http_or_json");
  } else if (!CONFIGURED_HISTORY_STATES.has(historyState)) {
    failures.push("history.platform_unavailable");
  } else if (historyState !== "AVAILABLE") {
    warnings.push(`history.${historyState}`);
  }

  const healthDeploymentUrl = health?.body?.deployment?.deployment_url;
  const snapshotDeploymentUrl = snapshot?.body?.deployment?.deployment_url;
  if (
    typeof healthDeploymentUrl !== "string" ||
    typeof snapshotDeploymentUrl !== "string" ||
    healthDeploymentUrl !== snapshotDeploymentUrl
  ) {
    failures.push("deployment.cross_endpoint_url");
  }

  if (mode === "live") {
    const monitoring = snapshot?.body?.monitoring;
    const sourceCommit = String(snapshot?.body?.source?.git_commit || "").toLowerCase();
    const releaseDeployment = snapshot?.body?.release_deployment;
    if (
      snapshotState !== "LIVE" ||
      monitoring?.state !== "LIVE" ||
      monitoring?.signature_verified !== true ||
      monitoring?.payload_signature_verified !== true ||
      monitoring?.fresh !== true ||
      monitoring?.current_source_commit_bound !== true ||
      monitoring?.deployment_verified !== true ||
      sourceCommit !== expectedCommit
    ) {
      failures.push("snapshot.not_live_and_trusted");
    }
    if (
      releaseDeployment?.api_verified !== true ||
      releaseDeployment?.provider !== "cloudflare-pages" ||
      !/^[A-Za-z0-9._:-]{1,128}$/.test(
        String(releaseDeployment?.deployment_id || ""),
      ) ||
      releaseDeployment?.canonical_url !== PRODUCTION_ORIGIN ||
      releaseDeployment?.source_commit !== expectedCommit ||
      releaseDeployment?.deployment_url !== snapshot?.body?.deployment?.deployment_url
    ) {
      failures.push("snapshot.release_deployment");
    }
    failures.push(...releaseAndRoadmapFailures(snapshot?.body, expectedCommit));
    const phaseEvidence = phaseEvidenceFailures(snapshot?.body, expectedCommit);
    failures.push(...phaseEvidence.failures);
    if (history?.body?.ok !== true || historyState !== "AVAILABLE") {
      failures.push("history.no_trusted_live_rows");
    } else {
      failures.push(
        ...latestHistoryFailures(
          history,
          snapshot?.body,
          expectedCommit,
          phaseEvidence.auditSha256,
        ),
      );
    }
  }

  const uniqueFailures = [...new Set(failures)].sort();
  const uniqueWarnings = [...new Set(warnings)].sort();
  return {
    schema: "cogni.monitoring-production-probe.v1",
    status: uniqueFailures.length === 0 ? "PASS" : "FAIL",
    mode,
    expected_commit: expectedCommit,
    observed_at: observedAt,
    production_origin: PRODUCTION_ORIGIN,
    failures: uniqueFailures,
    warnings: uniqueWarnings,
    observations: {
      health_http_status: health?.status ?? null,
      health_state: responseState(health),
      history_http_status: history?.status ?? null,
      history_state: historyState,
      snapshot_http_status: snapshot?.status ?? null,
      snapshot_state: snapshotState,
      deployment_url: health?.body?.deployment?.deployment_url ?? null,
    },
  };
}

export function productionProbeExecutionFailure({
  expectedCommit,
  mode,
  observedAt = new Date().toISOString(),
}) {
  if (!COMMIT_PATTERN.test(String(expectedCommit || ""))) {
    throw new Error("expectedCommit must be one lowercase 40-character Git SHA");
  }
  if (!MODES.has(mode)) throw new Error("mode must be configured or live");
  return {
    schema: "cogni.monitoring-production-probe.v1",
    status: "FAIL",
    mode,
    expected_commit: expectedCommit,
    observed_at: observedAt,
    production_origin: PRODUCTION_ORIGIN,
    failures: ["probe.execution_error"],
    warnings: [],
    observations: {
      health_http_status: null,
      health_state: "UNKNOWN",
      history_http_status: null,
      history_state: "UNKNOWN",
      snapshot_http_status: null,
      snapshot_state: "UNKNOWN",
      deployment_url: null,
    },
  };
}

async function readBoundedJson(response) {
  const mediaType = String(response.headers.get("content-type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (mediaType !== "application/json") {
    throw new Error("production endpoint did not return JSON");
  }
  const announced = Number(response.headers.get("content-length"));
  if (Number.isFinite(announced) && announced > MAX_RESPONSE_BYTES) {
    throw new Error("production endpoint response exceeds the byte bound");
  }
  if (!response.body) throw new Error("production endpoint response has no body");
  const chunks = [];
  let size = 0;
  const reader = response.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("production endpoint response exceeds the byte bound");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

async function fetchEndpoint(pathname) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${PRODUCTION_ORIGIN}${pathname}`, {
      method: "GET",
      headers: { Accept: "application/json", "Cache-Control": "no-store" },
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    return { status: response.status, body: await readBoundedJson(response) };
  } finally {
    clearTimeout(timeout);
  }
}

function parseArguments(argv) {
  const options = { expectedCommit: null, mode: null, output: null };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (value === undefined) throw new Error(`missing value for ${flag}`);
    if (flag === "--expected-commit") options.expectedCommit = value.toLowerCase();
    else if (flag === "--mode") options.mode = value;
    else if (flag === "--output") options.output = value;
    else throw new Error(`unsupported argument: ${flag}`);
  }
  if (!/^[0-9a-f]{40}$/.test(String(options.expectedCommit || ""))) {
    throw new Error("--expected-commit must be a 40-character Git SHA");
  }
  if (!MODES.has(options.mode)) throw new Error("--mode must be configured or live");
  return options;
}

function writeNoReplace(path, content) {
  const handle = openSync(resolve(path), "wx", 0o600);
  try {
    writeFileSync(handle, content, "utf8");
  } finally {
    closeSync(handle);
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  let report;
  let executionError = null;
  try {
    const [health, snapshot, history] = await Promise.all([
      fetchEndpoint("/api/health"),
      fetchEndpoint("/api/snapshot"),
      fetchEndpoint("/api/history?limit=60"),
    ]);
    report = evaluateProductionProbe({
      expectedCommit: options.expectedCommit,
      mode: options.mode,
      health,
      snapshot,
      history,
    });
  } catch (error) {
    executionError = error;
    report = productionProbeExecutionFailure({
      expectedCommit: options.expectedCommit,
      mode: options.mode,
    });
  }
  const encoded = `${JSON.stringify(report, null, 2)}\n`;
  process.stdout.write(encoded);
  if (options.output) writeNoReplace(options.output, encoded);
  if (executionError) {
    process.stderr.write("production probe execution failed; see JSON receipt\n");
    process.exitCode = 2;
  } else {
    process.exitCode = report.status === "PASS" ? 0 : 1;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (invokedPath === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`production probe error: ${error.name}: ${error.message}\n`);
    process.exitCode = 2;
  });
}
