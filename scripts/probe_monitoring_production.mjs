#!/usr/bin/env node

import { closeSync, openSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const PRODUCTION_ORIGIN = "https://cogni-os-orchestrator.pages.dev";
const PRODUCTION_PROJECT = "cogni-os-orchestrator";
const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;
const MODES = new Set(["configured", "live"]);

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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
    if (["UNCONFIGURED", "STORAGE_ERROR", "INVALID", "UNKNOWN"].includes(snapshotState)) {
      failures.push("snapshot.platform_unavailable");
    } else if (snapshotState !== "LIVE") {
      warnings.push(`snapshot.${snapshotState}`);
    }
  }
  if (history?.status !== 200 || !isObject(history?.body)) {
    failures.push("history.http_or_json");
  } else if (
    ["UNCONFIGURED", "STORAGE_ERROR", "INVALID", "UNKNOWN"].includes(historyState)
  ) {
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
    if (
      history?.body?.ok !== true ||
      historyState !== "AVAILABLE" ||
      !Array.isArray(history.body.history) ||
      history.body.history.length < 1
    ) {
      failures.push("history.no_trusted_live_rows");
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
  const [health, snapshot, history] = await Promise.all([
    fetchEndpoint("/api/health"),
    fetchEndpoint("/api/snapshot"),
    fetchEndpoint("/api/history?limit=60"),
  ]);
  const report = evaluateProductionProbe({
    expectedCommit: options.expectedCommit,
    mode: options.mode,
    health,
    snapshot,
    history,
  });
  const encoded = `${JSON.stringify(report, null, 2)}\n`;
  if (options.output) writeNoReplace(options.output, encoded);
  process.stdout.write(encoded);
  process.exitCode = report.status === "PASS" ? 0 : 1;
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (invokedPath === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`production probe error: ${error.name}: ${error.message}\n`);
    process.exitCode = 2;
  });
}
