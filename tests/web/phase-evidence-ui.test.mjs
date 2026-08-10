import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const COMMIT = "a".repeat(40);
const BODY_SHA256 = "b".repeat(64);
const AUDIT_SHA256 = "c".repeat(64);
const RELEASE_SHA256 = "d".repeat(64);
const DEPLOYMENT_URL =
  "https://deployment-current.cogni-os-orchestrator.pages.dev";
const PHASE_IDS = [
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

const nodes = new Map();
globalThis.document = {
  addEventListener() {},
  getElementById(id) {
    return nodes.get(id) || null;
  },
};
globalThis.__COGNI_EVIDENCE_UI_TEST__ = true;
await import("../../public/assets/app.js");
const {
  isLiveVerified,
  releasePassVerified,
  renderMission,
  signedPhaseAudit,
} = globalThis.__COGNI_EVIDENCE_UI_TEST_API__;

function auditPhase(index, coverageStatus = "SEMANTIC_COVERAGE_PASS") {
  return {
    phase_id: PHASE_IDS[index],
    coverage_status: coverageStatus,
    source_commit: COMMIT,
    release_authority: false,
  };
}

function liveFixture() {
  const phases = Array.from({ length: 11 }, (_, index) => auditPhase(index));
  return {
    monitoring: {
      state: "LIVE",
      signature_verified: true,
      payload_signature_verified: true,
      fresh: true,
      current_source_commit_bound: true,
      deployment_verified: true,
      age_seconds: 2,
      max_age_seconds: 180,
      sequence: 17,
      body_sha256: BODY_SHA256,
    },
    source: { git_commit: COMMIT },
    deployment: {
      attribution: "BUILD_BOUND",
      source_commit: COMMIT,
      project: "cogni-os-orchestrator",
      environment: "production",
      branch: "main",
      url: "https://cogni-os-orchestrator.pages.dev",
      deployment_url: DEPLOYMENT_URL,
    },
    release_deployment: {
      api_verified: true,
      provider: "cloudflare-pages",
      deployment_id: "deployment-current",
      canonical_url: "https://cogni-os-orchestrator.pages.dev",
      source_commit: COMMIT,
      deployment_url: DEPLOYMENT_URL,
    },
    release_gate: {
      status: "PASS",
      reasons: [],
      evidence_sha256: RELEASE_SHA256,
    },
    phase_evidence_audit: {
      schema: "cogni.phase-evidence-audit.v2",
      coverage_status: "SEMANTIC_COVERAGE_PASS",
      source_commit: COMMIT,
      total_phases: 11,
      validated_phases: 11,
      progress_percent: 100,
      phases,
      release_authority: false,
    },
    phase_evidence_binding: {
      schema: "cogni.phase-evidence-monitor-binding.v1",
      audit_sha256: AUDIT_SHA256,
      source_commit: COMMIT,
      sequence: 17,
      body_sha256: BODY_SHA256,
      deployment_id: "deployment-current",
      deployment_url: DEPLOYMENT_URL,
      release_gate_evidence_sha256: RELEASE_SHA256,
      signature_verified: true,
    },
    roadmap: {
      total: 11,
      trusted_complete: 11,
      current_release_validated: 11,
      phases: Array.from({ length: 11 }, () => ({
        current_release_validated: true,
        trusted_complete: true,
      })),
    },
  };
}

function uiNode() {
  const attributes = new Map();
  return {
    textContent: "",
    className: "",
    style: {},
    setAttribute(name, value) {
      attributes.set(name, String(value));
    },
    removeAttribute(name) {
      attributes.delete(name);
    },
    getAttribute(name) {
      return attributes.get(name) ?? null;
    },
  };
}

function installMissionNodes() {
  nodes.clear();
  for (const id of [
    "overall-progress-label",
    "phase-audit-count",
    "phase-audit-sha",
    "phase-release-authority",
    "overall-progress",
    "overall-progress-track",
    "release-gate-status",
    "release-gate",
    "next-milestone",
  ]) {
    nodes.set(id, uiNode());
  }
}

test("transport LIVE requires the response-side phase binding cross-bindings", () => {
  const value = liveFixture();
  assert.equal(isLiveVerified(value), true);

  for (const mutate of [
    (candidate) => delete candidate.phase_evidence_binding,
    (candidate) => (candidate.phase_evidence_binding.sequence += 1),
    (candidate) => (candidate.phase_evidence_binding.body_sha256 = "e".repeat(64)),
    (candidate) => (candidate.phase_evidence_binding.source_commit = "f".repeat(40)),
    (candidate) => (candidate.phase_evidence_binding.deployment_id = "other"),
    (candidate) =>
      (candidate.phase_evidence_binding.release_gate_evidence_sha256 = null),
    (candidate) => (candidate.phase_evidence_binding.signature_verified = false),
  ]) {
    const candidate = structuredClone(value);
    mutate(candidate);
    assert.equal(isLiveVerified(candidate), false);
  }
});

test("valid semantic coverage NO_GO remains transport LIVE", () => {
  const value = liveFixture();
  value.phase_evidence_audit.coverage_status = "NO_GO";
  value.phase_evidence_audit.validated_phases = 10;
  value.phase_evidence_audit.progress_percent = 90.9;
  value.phase_evidence_audit.phases[10].coverage_status = "NO_GO";
  value.phase_evidence_audit.phases[10].source_commit = null;
  value.release_gate = {
    status: "NO_GO",
    reasons: ["independent release evidence is incomplete"],
    evidence_sha256: null,
  };
  value.phase_evidence_binding.release_gate_evidence_sha256 = null;
  assert.equal(isLiveVerified(value), true);
  assert.equal(signedPhaseAudit(value)?.validated_phases, 10);
  assert.equal(signedPhaseAudit(value)?.progress_percent, 90.9);
  assert.equal(releasePassVerified(value), false);
  installMissionNodes();
  renderMission(value);
  assert.equal(nodes.get("overall-progress-label").textContent, "90.9%");
  assert.equal(nodes.get("phase-audit-count").textContent, "10 / 11");
  assert.equal(nodes.get("phase-audit-sha").textContent, AUDIT_SHA256);
  assert.equal(nodes.get("release-gate-status").textContent, "NO_GO");
});

test("release PASS requires audit, release gate, and current roadmap 11/11", () => {
  const value = liveFixture();
  assert.equal(releasePassVerified(value), true);

  for (const mutate of [
    (candidate) => (candidate.phase_evidence_audit.validated_phases = 10),
    (candidate) => (candidate.phase_evidence_audit.coverage_status = "SEMANTIC_COVERAGE_FAIL"),
    (candidate) => (candidate.release_gate.status = "NO_GO"),
    (candidate) => (candidate.roadmap.current_release_validated = 10),
    (candidate) => (candidate.roadmap.phases[0].current_release_validated = false),
  ]) {
    const candidate = structuredClone(value);
    mutate(candidate);
    assert.equal(releasePassVerified(candidate), false);
  }
});

test("mission hides audit progress and digest when LIVE binding is unavailable", () => {
  installMissionNodes();
  const stale = liveFixture();
  stale.monitoring.state = "STALE";
  stale.monitoring.fresh = false;
  stale.phase_evidence_binding = null;
  renderMission(stale);

  assert.equal(nodes.get("overall-progress-label").textContent, "—");
  assert.equal(nodes.get("phase-audit-count").textContent, "—");
  assert.equal(nodes.get("phase-audit-sha").textContent, "—");
  assert.equal(nodes.get("phase-release-authority").textContent, "—");
  assert.equal(nodes.get("overall-progress").style.width, "0%");
  assert.equal(nodes.get("release-gate-status").textContent, "NO_GO");
  assert.equal(
    nodes.get("overall-progress-track").getAttribute("aria-valuetext"),
    "검증된 Phase 의미 증거 없음",
  );
});

test("contradictory signed audit aggregate is rejected and hidden", () => {
  const contradictions = [
    (candidate) => (candidate.phase_evidence_audit.validated_phases = 10),
    (candidate) => (candidate.phase_evidence_audit.progress_percent = 90.9),
    (candidate) => (candidate.phase_evidence_audit.coverage_status = "NO_GO"),
    (candidate) => (candidate.phase_evidence_audit.phases[0].phase_id = "P02-ORCHESTRATION"),
    (candidate) => (candidate.phase_evidence_audit.phases[0].release_authority = true),
    (candidate) =>
      (candidate.phase_evidence_audit.phases[0].coverage_status = "INVALID"),
  ];
  for (const mutate of contradictions) {
    installMissionNodes();
    const candidate = liveFixture();
    mutate(candidate);
    assert.equal(isLiveVerified(candidate), true);
    assert.equal(signedPhaseAudit(candidate), null);
    assert.equal(releasePassVerified(candidate), false);
    renderMission(candidate);
    assert.equal(nodes.get("overall-progress-label").textContent, "—");
    assert.equal(nodes.get("phase-audit-count").textContent, "—");
    assert.equal(nodes.get("phase-audit-sha").textContent, "—");
    assert.equal(nodes.get("phase-release-authority").textContent, "—");
    assert.equal(nodes.get("release-gate-status").textContent, "NO_GO");
  }
});

test("mission renders only transport-bound audit values and guarded PASS", () => {
  installMissionNodes();
  renderMission(liveFixture());
  assert.equal(nodes.get("overall-progress-label").textContent, "100%");
  assert.equal(nodes.get("phase-audit-count").textContent, "11 / 11");
  assert.equal(nodes.get("phase-audit-sha").textContent, "c".repeat(64));
  assert.equal(nodes.get("phase-release-authority").textContent, "false");
  assert.equal(nodes.get("release-gate-status").textContent, "PASS");
});

test("mission explains that semantic coverage does not grant release authority", async () => {
  const html = await readFile(
    new URL("../../public/index.html", import.meta.url),
    "utf8",
  );
  assert.match(html, /Semantic coverage is not release authority/);
  assert.match(
    html,
    /의미론적 범위 검증 통과만으로 릴리스 권한이 생기지 않습니다/,
  );
});
