import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { MAX_BODY_BYTES } from "../../functions/_lib/monitoring.js";
import { onRequest as health } from "../../functions/api/health.js";
import {
  evaluateProductionProbe,
  phaseAuditSha256,
  productionProbeExecutionFailure,
} from "../../scripts/probe_monitoring_production.mjs";
import { onRequest as ingest } from "../../functions/api/ingest.js";

const KEY_ID = "publisher-2026-07";
const SECRET = "release-audit-secret-longer-than-thirty-two-characters";
const WORKSPACE = "release-audit-workspace";
const EXPECTED_COMMIT = "a".repeat(40);
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

function digest(label) {
  return createHash("sha256").update(label, "utf8").digest("hex");
}

function trustedRoadmap() {
  return {
    schema_version: 1,
    total: PHASE_IDS.length,
    trusted_complete: PHASE_IDS.length,
    current_release_validated: PHASE_IDS.length,
    progress_percent: 100,
    progress_basis: "historically-trusted-roadmap-task-states",
    phases: PHASE_IDS.map((id, index) => ({
      id,
      title: `Phase ${index + 1}`,
      state: "verified",
      trusted_complete: true,
      verified_source_commit: EXPECTED_COMMIT,
      current_release_state: "verified",
      current_release_validated: true,
      prerequisites: index === 0 ? [] : [PHASE_IDS[index - 1]],
    })),
  };
}

function trustedPhaseAudit() {
  return {
    schema: "cogni.phase-evidence-audit.v2",
    coverage_status: "SEMANTIC_COVERAGE_PASS",
    source_commit: EXPECTED_COMMIT,
    total_phases: PHASE_IDS.length,
    validated_phases: PHASE_IDS.length,
    progress_percent: 100,
    phases: PHASE_IDS.map((phaseId) => {
      const count = PHASE_REQUIREMENT_COUNTS.get(phaseId);
      return {
        phase_id: phaseId,
        coverage_status: "SEMANTIC_COVERAGE_PASS",
        reasons: [],
        source_commit: EXPECTED_COMMIT,
        artifact_sha256: Array.from({ length: count }, (_, index) =>
          digest(`${phaseId}:artifact:${index}`),
        ),
        trusted_output_sha256: Array.from({ length: count }, (_, index) =>
          digest(`${phaseId}:trusted-output:${index}`),
        ),
        release_authority: false,
      };
    }),
    release_authority: false,
    auditor_policy: {
      source_commit: EXPECTED_COMMIT,
      source_tree: "b".repeat(40),
      current_source_commit_bound: true,
      policy_sha256: digest("auditor-policy"),
      files: [
        {
          path: "scripts/audit_phase_evidence.py",
          sha256: digest("audit-phase-evidence-source"),
        },
        {
          path: "src/cogni_os/phase_evidence.py",
          sha256: digest("phase-evidence-source"),
        },
      ],
    },
  };
}

// This fixture represents the API response after the HMAC-verified D1 row has
// been enveloped. Publishers are forbidden from sending this binding.
function attachResponseDerivedPhaseBinding(snapshot) {
  snapshot.phase_evidence_binding = {
    schema: "cogni.phase-evidence-monitor-binding.v1",
    audit_sha256: phaseAuditSha256(snapshot.phase_evidence_audit),
    source_commit: EXPECTED_COMMIT,
    sequence: snapshot.monitoring.sequence,
    body_sha256: snapshot.monitoring.body_sha256,
    deployment_id: snapshot.release_deployment.deployment_id,
    deployment_url: snapshot.release_deployment.deployment_url,
    release_gate_evidence_sha256: snapshot.release_gate.evidence_sha256,
    signature_verified: true,
  };
}

function trustedLiveResponses() {
  const responses = configuredProductionResponses();
  const observedAt = "2026-08-09T20:00:00.000Z";
  const receivedAt = "2026-08-09T20:00:01.000Z";
  const bodySha256 = digest("trusted-live-snapshot-body");
  const deployment = boundDeployment();
  const roadmap = trustedRoadmap();
  const releaseGate = {
    status: "PASS",
    reasons: [],
    evidence_sha256: digest("independent-release-gate"),
  };
  const releaseDeployment = {
    provider: "cloudflare-pages",
    api_verified: true,
    deployment_id: "deployment-123",
    deployment_url: deployment.deployment_url,
    canonical_url: "https://cogni-os-orchestrator.pages.dev",
    source_commit: EXPECTED_COMMIT,
  };
  responses.snapshot.body = {
    schema_version: "1.3",
    state: "LIVE",
    monitoring: {
      state: "LIVE",
      signature_verified: true,
      payload_signature_verified: true,
      fresh: true,
      current_source_commit_bound: true,
      deployment_verified: true,
      sequence: 7,
      observed_at: observedAt,
      received_at: receivedAt,
      body_sha256: bodySha256,
    },
    source: { git_commit: EXPECTED_COMMIT },
    deployment,
    release_deployment: releaseDeployment,
    release_gate: releaseGate,
    roadmap,
    phase_evidence_audit: trustedPhaseAudit(),
  };
  attachResponseDerivedPhaseBinding(responses.snapshot.body);
  responses.history.body = {
    ok: true,
    state: "AVAILABLE",
    history: [
      {
        sequence: 7,
        observed_at: observedAt,
        received_at: receivedAt,
        body_sha256: bodySha256,
        source_commit: EXPECTED_COMMIT,
        deployment_id: releaseDeployment.deployment_id,
        deployment_url: releaseDeployment.deployment_url,
        signature_verified: true,
        phase_evidence_audit_sha256:
          responses.snapshot.body.phase_evidence_binding.audit_sha256,
        release_gate_evidence_sha256: releaseGate.evidence_sha256,
        release_gate: releaseGate,
        roadmap,
      },
    ],
  };
  return responses;
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

test("production probe preserves a bounded JSON receipt for transport failures", () => {
  const result = productionProbeExecutionFailure({
    expectedCommit: EXPECTED_COMMIT,
    mode: "live",
    observedAt: "2026-08-10T00:00:00.000Z",
  });
  assert.deepEqual(result, {
    schema: "cogni.monitoring-production-probe.v1",
    status: "FAIL",
    mode: "live",
    expected_commit: EXPECTED_COMMIT,
    observed_at: "2026-08-10T00:00:00.000Z",
    production_origin: "https://cogni-os-orchestrator.pages.dev",
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
  });
});

test("production probe CLI seals transport failure to stdout and output before exit 2", () => {
  const output = join(tmpdir(), `cogni-probe-${randomUUID()}.json`);
  const secretCanary = "TRANSPORT-SECRET-CANARY-DO-NOT-LEAK";
  const fetchOverride = `data:text/javascript,${encodeURIComponent(
    `globalThis.fetch=async()=>{throw new Error(${JSON.stringify(secretCanary)})}`,
  )}`;
  try {
    const result = spawnSync(
      process.execPath,
      [
        `--import=${fetchOverride}`,
        "scripts/probe_monitoring_production.mjs",
        "--expected-commit",
        EXPECTED_COMMIT,
        "--mode",
        "live",
        "--output",
        output,
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        windowsHide: true,
      },
    );
    assert.equal(result.status, 2);
    assert.equal(
      result.stderr,
      "production probe execution failed; see JSON receipt\n",
    );
    assert.equal(result.stderr.includes(secretCanary), false);
    assert.equal(result.stdout.includes(secretCanary), false);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "FAIL");
    assert.deepEqual(report.failures, ["probe.execution_error"]);
    assert.equal(readFileSync(output, "utf8"), result.stdout);
  } finally {
    if (existsSync(output)) unlinkSync(output);
  }
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
  const responses = trustedLiveResponses();
  const result = evaluateProductionProbe({
    expectedCommit: EXPECTED_COMMIT,
    mode: "live",
    ...responses,
  });
  assert.equal(result.status, "PASS");
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.warnings, []);
});

test("configured production rejects every corrupt or unknown snapshot and history state", () => {
  for (const state of ["CORRUPT", "TAMPERED", "STORAGE_ERROR", "UNRECOGNIZED"]) {
    const responses = configuredProductionResponses();
    responses.snapshot.body.state = state;
    responses.snapshot.body.monitoring.state = state;
    responses.history.body.state = state;
    const result = evaluateProductionProbe({
      expectedCommit: EXPECTED_COMMIT,
      mode: "configured",
      ...responses,
    });
    assert.equal(result.status, "FAIL", state);
    assert.ok(result.failures.includes("snapshot.platform_unavailable"), state);
    assert.ok(result.failures.includes("history.platform_unavailable"), state);
  }
});

test("live production rejects incomplete, duplicated, or authority-claiming phase evidence", () => {
  const cases = [
    {
      name: "missing audit",
      mutate(snapshot) {
        delete snapshot.phase_evidence_audit;
      },
      expected: "snapshot.phase_evidence_audit",
    },
    {
      name: "cross-domain digest reuse",
      mutate(snapshot) {
        snapshot.phase_evidence_audit.phases[1].artifact_sha256[0] =
          snapshot.phase_evidence_audit.phases[0].trusted_output_sha256[0];
        attachResponseDerivedPhaseBinding(snapshot);
      },
      expected: "snapshot.phase_evidence_audit.digest_reuse_or_invalid.P02-ORCHESTRATION",
    },
    {
      name: "semantic audit claims release authority",
      mutate(snapshot) {
        snapshot.phase_evidence_audit.release_authority = true;
        attachResponseDerivedPhaseBinding(snapshot);
      },
      expected: "snapshot.phase_evidence_audit",
    },
    {
      name: "unknown audit field",
      mutate(snapshot) {
        snapshot.phase_evidence_audit.untrusted_extension = true;
        attachResponseDerivedPhaseBinding(snapshot);
      },
      expected: "snapshot.phase_evidence_audit",
    },
    {
      name: "unknown binding field",
      mutate(snapshot) {
        snapshot.phase_evidence_binding.untrusted_extension = true;
      },
      expected: "snapshot.phase_evidence_binding",
    },
  ];
  for (const scenario of cases) {
    const responses = trustedLiveResponses();
    scenario.mutate(responses.snapshot.body);
    const result = evaluateProductionProbe({
      expectedCommit: EXPECTED_COMMIT,
      mode: "live",
      ...responses,
    });
    assert.equal(result.status, "FAIL", scenario.name);
    assert.ok(result.failures.includes(scenario.expected), scenario.name);
  }
});

test("live production keeps semantic coverage separate from release authority", () => {
  const responses = trustedLiveResponses();
  responses.snapshot.body.release_gate = {
    status: "NO_GO",
    reasons: ["independent release evidence is incomplete"],
    evidence_sha256: null,
  };
  responses.snapshot.body.roadmap.trusted_complete = 10;
  responses.snapshot.body.roadmap.current_release_validated = 10;
  const result = evaluateProductionProbe({
    expectedCommit: EXPECTED_COMMIT,
    mode: "live",
    ...responses,
  });
  assert.equal(result.status, "FAIL");
  assert.ok(result.failures.includes("snapshot.release_gate"));
  assert.ok(result.failures.includes("snapshot.roadmap"));
  assert.ok(result.failures.includes("snapshot.phase_evidence_binding"));
});

test("live production rejects a latest history row not bound to the current signed snapshot", () => {
  const responses = trustedLiveResponses();
  const latest = responses.history.body.history.at(-1);
  latest.source_commit = "b".repeat(40);
  latest.signature_verified = false;
  latest.body_sha256 = digest("different-snapshot-body");
  latest.deployment_id = "different-deployment";
  const result = evaluateProductionProbe({
    expectedCommit: EXPECTED_COMMIT,
    mode: "live",
    ...responses,
  });
  assert.equal(result.status, "FAIL");
  assert.ok(result.failures.includes("history.latest_not_snapshot_bound"));
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
