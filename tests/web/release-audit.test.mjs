import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { MAX_BODY_BYTES } from "../../functions/_lib/monitoring.js";
import { onRequest as health } from "../../functions/api/health.js";
import { evaluateProductionProbe } from "../../scripts/probe_monitoring_production.mjs";
import { onRequest as ingest } from "../../functions/api/ingest.js";

const KEY_ID = "publisher-2026-07";
const SECRET = "release-audit-secret-longer-than-thirty-two-characters";
const WORKSPACE = "release-audit-workspace";
const EXPECTED_COMMIT = "a".repeat(40);

function boundDeployment() {
  return {
    attribution: "BUILD_BOUND",
    branch: "main",
    deployment_url:
      "https://a1b2c3d4.cogni-os-orchestrator.pages.dev",
    environment: "production",
    project: "cogni-os-orchestrator",
    provider: "cloudflare-pages",
    source_commit: EXPECTED_COMMIT,
    url: "https://cogni-os-orchestrator.pages.dev",
  };
}

function configuredProductionResponses() {
  const deployment = boundDeployment();
  return {
    health: {
      status: 200,
      body: {
        ok: true,
        state: "CONFIGURED",
        checks: {
          build_attribution_ready: true,
          d1_binding: true,
          deployment_attribution: "BUILD_BOUND",
          operational_ingest_ready: true,
          publisher_keyring: true,
          publisher_keys: 1,
          release_attribution_ready: false,
          release_evidence_state: "API_EVIDENCE_REQUIRED",
          runtime_configuration_ready: true,
          storage_schema_verified: true,
          storage_state: "READY",
          workspace_id: true,
        },
        deployment,
      },
    },
    snapshot: {
      status: 200,
      body: {
        state: "NO_DATA",
        monitoring: { state: "NO_DATA" },
        deployment,
      },
    },
    history: {
      status: 200,
      body: { ok: true, state: "NO_TRUSTED_DATA", history: [] },
    },
  };
}

class SnapshotOnlyD1 {
  prepare(sql) {
    return {
      async first() {
        if (/monitor_(history|nonces)/i.test(sql)) {
          throw new Error("no such table");
        }
        if (/sqlite_master/i.test(sql)) {
          return { name: "monitor_snapshots" };
        }
        return null;
      },
      async all() {
        if (/sqlite_master/i.test(sql)) {
          return { results: [{ name: "monitor_snapshots" }] };
        }
        if (/monitor_(history|nonces)/i.test(sql)) {
          throw new Error("no such table");
        }
        return { results: [] };
      },
    };
  }
}

function validIngestHeaders() {
  return new Headers({
    "content-type": "application/json",
    "x-cogni-key-id": KEY_ID,
    "x-cogni-workspace": WORKSPACE,
    "x-cogni-sequence": "1",
    "x-cogni-observed-at": new Date().toISOString(),
    "x-cogni-nonce": "release_audit_nonce_1234567890",
    "x-cogni-signature": `sha256=${"0".repeat(64)}`,
  });
}

test("health fails closed when history and nonce tables are missing", async () => {
  const response = await health({
    env: {
      MONITOR_DB: new SnapshotOnlyD1(),
      COGNI_WORKSPACE_ID: WORKSPACE,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
    },
  });
  const body = await response.json();
  assert.equal(response.status, 503);
  assert.equal(body.state, "UNCONFIGURED");
  assert.equal(body.checks.storage_state, "NOT_MIGRATED");
});

test("chunked oversized ingest is bounded without request.text allocation", async () => {
  const oversizedChunk = new Uint8Array(MAX_BODY_BYTES + 1);
  const request = {
    method: "POST",
    headers: validIngestHeaders(),
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(oversizedChunk);
        controller.close();
      },
    }),
    async text() {
      throw new Error("request.text performs an unbounded allocation");
    },
  };
  const response = await ingest({
    request,
    env: {
      MONITOR_DB: {},
      COGNI_WORKSPACE_ID: WORKSPACE,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
    },
  });
  const body = await response.json();
  assert.equal(response.status, 413);
  assert.equal(body.error.code, "BODY_TOO_LARGE");
});

test("ingest requires an exact JSON media type", async () => {
  const headers = validIngestHeaders();
  headers.set("content-type", "application/json-evil");
  const response = await ingest({
    request: new Request("https://example.test/api/ingest", {
      method: "POST",
      headers,
      body: "{}",
    }),
    env: {
      MONITOR_DB: {},
      COGNI_WORKSPACE_ID: WORKSPACE,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
    },
  });
  assert.equal(response.status, 415);
  assert.equal((await response.json()).error.code, "UNSUPPORTED_MEDIA_TYPE");
});

test("invalid HMAC is rejected before untrusted JSON schema processing", async () => {
  const response = await ingest({
    request: new Request("https://example.test/api/ingest", {
      method: "POST",
      headers: validIngestHeaders(),
      body: "{}",
    }),
    env: {
      MONITOR_DB: {},
      COGNI_WORKSPACE_ID: WORKSPACE,
      INGEST_HMAC_KEYS: JSON.stringify({ [KEY_ID]: SECRET }),
    },
  });
  const body = await response.json();
  assert.equal(response.status, 401);
  assert.equal(body.error.code, "SIGNATURE_REJECTED");
});

test("production probe accepts an exact configured platform without claiming live data", () => {
  const responses = configuredProductionResponses();
  const result = evaluateProductionProbe({
    expectedCommit: EXPECTED_COMMIT,
    mode: "configured",
    ...responses,
  });
  assert.equal(result.status, "PASS");
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.warnings, [
    "history.NO_TRUSTED_DATA",
    "snapshot.NO_DATA",
  ]);
});

test("production probe rejects an unbound deployment and missing storage migration", () => {
  const result = evaluateProductionProbe({
    expectedCommit: EXPECTED_COMMIT,
    mode: "configured",
    health: {
      status: 503,
      body: {
        ok: false,
        state: "UNCONFIGURED",
        checks: {
          build_attribution_ready: false,
          d1_binding: true,
          deployment_attribution: "UNAVAILABLE",
          operational_ingest_ready: false,
          publisher_keyring: true,
          publisher_keys: 1,
          release_attribution_ready: false,
          release_evidence_state: "UNAVAILABLE",
          runtime_configuration_ready: false,
          storage_schema_verified: false,
          storage_state: "NOT_MIGRATED",
          workspace_id: true,
        },
        deployment: null,
      },
    },
    snapshot: {
      status: 200,
      body: { state: "UNCONFIGURED", monitoring: { state: "UNCONFIGURED" } },
    },
    history: {
      status: 503,
      body: { ok: false, state: "STORAGE_ERROR", history: [] },
    },
  });
  assert.equal(result.status, "FAIL");
  assert.ok(result.failures.includes("health.http_or_json"));
  assert.ok(result.failures.includes("snapshot.deployment.source_commit"));
  assert.ok(result.failures.includes("snapshot.platform_unavailable"));
  assert.ok(result.failures.includes("history.http_or_json"));
});

test("production probe accepts only signed live data bound to API deployment evidence", () => {
  const responses = configuredProductionResponses();
  responses.snapshot.body = {
    state: "LIVE",
    monitoring: {
      state: "LIVE",
      signature_verified: true,
      payload_signature_verified: true,
      fresh: true,
      current_source_commit_bound: true,
      deployment_verified: true,
    },
    source: { git_commit: EXPECTED_COMMIT },
    deployment: boundDeployment(),
    release_deployment: {
      provider: "cloudflare-pages",
      api_verified: true,
      deployment_id: "deployment-123",
      deployment_url:
        "https://a1b2c3d4.cogni-os-orchestrator.pages.dev",
      canonical_url: "https://cogni-os-orchestrator.pages.dev",
      source_commit: EXPECTED_COMMIT,
    },
  };
  responses.history.body = {
    ok: true,
    state: "AVAILABLE",
    history: [{ sequence: 1, state: "LIVE" }],
  };
  const result = evaluateProductionProbe({
    expectedCommit: EXPECTED_COMMIT,
    mode: "live",
    ...responses,
  });
  assert.equal(result.status, "PASS");
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.warnings, []);
});

test("production probe live mode rejects corrupt or unsigned operational data", () => {
  const responses = configuredProductionResponses();
  responses.snapshot.body = {
    state: "CORRUPT",
    monitoring: {
      state: "CORRUPT",
      signature_verified: false,
      payload_signature_verified: false,
      fresh: false,
      current_source_commit_bound: false,
      deployment_verified: false,
    },
    source: { git_commit: EXPECTED_COMMIT },
    deployment: boundDeployment(),
    release_deployment: null,
  };
  responses.history.body = { ok: true, state: "CORRUPT", history: [] };
  const result = evaluateProductionProbe({
    expectedCommit: EXPECTED_COMMIT,
    mode: "live",
    ...responses,
  });
  assert.equal(result.status, "FAIL");
  assert.ok(result.failures.includes("snapshot.not_live_and_trusted"));
  assert.ok(result.failures.includes("snapshot.release_deployment"));
  assert.ok(result.failures.includes("history.no_trusted_live_rows"));
});

test("production probe rejects different deployment URLs for the same commit", () => {
  const responses = configuredProductionResponses();
  responses.snapshot.body.deployment = {
    ...boundDeployment(),
    deployment_url:
      "https://different.cogni-os-orchestrator.pages.dev",
  };
  const result = evaluateProductionProbe({
    expectedCommit: EXPECTED_COMMIT,
    mode: "configured",
    ...responses,
  });
  assert.equal(result.status, "FAIL");
  assert.ok(result.failures.includes("deployment.cross_endpoint_url"));
});

test("production recovery workflow is manual, ordered, and secret-bound", () => {
  const workflow = readFileSync(
    new URL("../../.github/workflows/monitoring-production-recovery.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /^on:\n  workflow_dispatch:/m);
  assert.doesNotMatch(workflow, /^\s{2}(push|pull_request):/m);
  for (const secret of [
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_PAGES_DEPLOY_HOOK",
  ]) {
    assert.equal(
      [...workflow.matchAll(new RegExp(`secrets\\.${secret}`, "g"))].length,
      1,
    );
  }
  assert.doesNotMatch(workflow, /^    env:/m);
  assert.doesNotMatch(workflow, /npx\s+--yes|wrangler@/);
  assert.match(workflow, /npm ci --ignore-scripts/);
  assert.match(workflow, /\.\/node_modules\/\.bin\/wrangler/);
  assert.equal(
    [...workflow.matchAll(/persist-credentials: false/g)].length,
    3,
  );
  const migration = workflow.indexOf("d1 migrations apply");
  const deployHook = workflow.indexOf(
    "- name: Trigger the protected main-branch Pages build",
  );
  const configuredProbe = workflow.indexOf("--mode configured");
  assert.ok(migration >= 0 && migration < deployHook);
  assert.ok(deployHook < configuredProbe);

  const packageLock = JSON.parse(
    readFileSync(new URL("../../package-lock.json", import.meta.url), "utf8"),
  );
  assert.equal(packageLock.packages[""].devDependencies.wrangler, "4.33.1");
  assert.equal(packageLock.packages["node_modules/wrangler"].version, "4.33.1");
  assert.match(
    packageLock.packages["node_modules/wrangler"].integrity,
    /^sha512-[A-Za-z0-9+/]+={0,2}$/,
  );
});
