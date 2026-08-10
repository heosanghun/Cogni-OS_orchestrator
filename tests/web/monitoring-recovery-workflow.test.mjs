import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowUrl = new URL(
  "../../.github/workflows/monitoring-production-recovery.yml",
  import.meta.url,
);
const documentationUrl = new URL(
  "../../docs/MONITORING_PRODUCTION_RECOVERY_SECURITY_KO.md",
  import.meta.url,
);

async function workflow() {
  return readFile(workflowUrl, "utf8");
}

test("production recovery is manual, protected-main-only, and environment gated", async () => {
  const source = await workflow();
  assert.match(source, /^on:\n  workflow_dispatch:/m);
  assert.match(source, /default: verify-live/);
  assert.doesNotMatch(source, /^\s{2}(push|pull_request|schedule):/m);
  assert.match(source, /test "\$GITHUB_REF" = "refs\/heads\/main"/);
  assert.match(source, /test "\$GITHUB_REF_PROTECTED" = "true"/);
  assert.match(source, /environment:\n\s+name: monitoring-production/);
  assert.match(
    source,
    /required-reviewer\+prevent-self-review\+main-only\+no-admin-bypass-v1/,
  );
});

test("every referenced action is pinned to one full commit SHA", async () => {
  const source = await workflow();
  const references = [...source.matchAll(/^\s+(?:- )?uses:\s*([^\s#]+)/gm)].map(
    (match) => match[1],
  );
  assert.ok(references.length >= 8);
  for (const reference of references) {
    assert.match(reference, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/);
  }
  assert.match(
    source,
    /actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/,
  );
});

test("pre and post D1 receipts are sanitized, sealed separately, and retained", async () => {
  const source = await workflow();
  assert.match(source, /d1-pre-migration\.json/);
  assert.match(source, /d1-post-migration\.json/);
  assert.match(source, /time_travel_bookmark_sha256/);
  assert.match(source, /database_rows_captured: false/);
  assert.match(source, /raw_bookmark_retained: false/);
  assert.match(source, /secret_material_retained: false/);
  assert.match(source, /PRE_ARTIFACT_SHA256/);
  assert.match(source, /test "\$actual_pre_sha256" = "\$EXPECTED_PRE_FILE_SHA256"/);
  assert.match(source, /chmod 0400 -- "\$EVIDENCE_DIR\/d1-pre-migration\.json"/);
  const preUpload = source.indexOf("Seal immutable pre-migration receipt before mutation");
  const migrationApply = source.indexOf("d1 migrations apply");
  assert.ok(preUpload >= 0 && preUpload < migrationApply);
  assert.match(source, /pre_artifact_sha256: process\.env\.PRE_ARTIFACT_SHA256/);
  assert.match(source, /secrets\.CLOUDFLARE_D1_READ_TOKEN/);
  assert.match(source, /actual_account_sha256/);
  assert.match(source, /test "\$actual_account_sha256" = "\$expected_account_sha256"/);
  assert.doesNotMatch(source, /d1-post-migration\.unbound\.json/);
  assert.match(source, /unapplied remote D1 migrations remain after apply/);
  assert.equal((source.match(/retention-days: 90/g) || []).length, 5);
  assert.equal((source.match(/overwrite: false/g) || []).length, 5);
  assert.match(source, /trap 'rm -rf -- "\$raw_dir"' EXIT/);
});

test("source validation executes and seals the non-release Phase evidence audit", async () => {
  const source = await workflow();
  const audit = source.indexOf("python -I scripts/audit_phase_evidence.py --workspace .");
  const dependencyInstall = source.indexOf("npm ci --ignore-scripts");
  assert.ok(audit >= 0 && audit < dependencyInstall);
  assert.match(source, /cogni\.phase-evidence-audit\.v2/);
  assert.match(source, /release_authority.*is not False/);
  assert.match(source, /SEMANTIC_COVERAGE_PASS/);
  assert.match(source, /name: phase-evidence-audit-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/);
  assert.match(source, /Non-release Phase evidence audit/);
});

test("recovery rehearses policy but never performs D1 or Pages rollback", async () => {
  const source = await workflow();
  assert.match(source, /recovery-rehearsal-receipt\.json/);
  assert.match(source, /PROCEDURE_ONLY_NO_MUTATION/);
  assert.match(source, /restore_command_executed: false/);
  assert.match(source, /rollback_command_executed: false/);
  assert.doesNotMatch(source, /d1\s+time-travel\s+restore/);
  assert.doesNotMatch(source, /deployments\/[^\s]+\/rollback/);
});

test("CONFIGURED recovery cannot publish or claim signed LIVE", async () => {
  const source = await workflow();
  assert.match(source, /Recover platform to CONFIGURED only \(never publish signed LIVE\)/);
  assert.match(source, /--mode configured/);
  assert.match(source, /External trusted publisher and a separate verify-live run required: true/);
  assert.match(source, /Verify externally published signed LIVE data \(read-only\)/);
  assert.match(source, /--mode live/);
  assert.doesNotMatch(source, /INGEST_HMAC_KEYS/);
  assert.doesNotMatch(source, /publish_monitor_snapshot/);
  assert.doesNotMatch(source, /\/api\/ingest/);
});

test("security runbook documents external protection and evidence limits", async () => {
  const documentation = await readFile(documentationUrl, "utf8");
  for (const required of [
    "required reviewer",
    "prevent self-review",
    "administrator bypass",
    "PROCEDURE_ONLY_NO_MUTATION",
    "WORM",
    "외부 신뢰 publisher",
    "https://developers.cloudflare.com/d1/reference/time-travel/",
    "https://developers.cloudflare.com/pages/configuration/rollbacks/",
  ]) {
    assert.ok(documentation.includes(required), `missing runbook contract: ${required}`);
  }
});
