#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";

const EXPECTED_WEB_TESTS = 68;
const EXPECTED_WEB_TEST_INVENTORY_SHA256 =
  "494cb1507fe4e87b532a766fde8b4a08224dae0cd837eb2f547f6610a6d8c8d9";

function run(args) {
  return spawnSync(process.execPath, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    env: process.env,
    windowsHide: true,
  });
}

if (process.argv.length !== 2) {
  throw new Error("Phase 1 Node validation accepts no actor-controlled policy arguments");
}
const webTestFiles = readdirSync("tests/web", { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(".test.mjs"))
  .map((entry) => `tests/web/${entry.name}`)
  .sort();
const web = run(["--test", "--test-reporter=tap", ...webTestFiles]);
const summary = Object.fromEntries(
  ["tests", "pass", "fail", "skipped"].map((key) => {
    const match = web.stdout.match(new RegExp(`^# ${key} (\\d+)$`, "m"));
    return [key, match ? Number(match[1]) : null];
  }),
);
const inventoryNames = [...web.stdout.matchAll(/^# Subtest: (.+)$/gm)]
  .map((match) => match[1].trim())
  .sort();
const uniqueInventoryNames = new Set(inventoryNames);
const inventorySha256 = createHash("sha256")
  .update(`${inventoryNames.join("\n")}\n`, "utf8")
  .digest("hex");
const syntaxTargets = [
  "public/assets/app.js",
  "functions/_lib/deployment.generated.js",
  "functions/_lib/monitoring.js",
  "functions/api/health.js",
  "functions/api/ingest.js",
  "functions/api/snapshot.js",
  "functions/api/history.js",
  "scripts/generate_deployment_attribution.mjs",
  "scripts/probe_monitoring_production.mjs",
  "scripts/validate_p01_node.mjs",
];
const syntaxPassed = syntaxTargets.filter(
  (target) => run(["--check", target]).status === 0,
).length;
const passed =
  web.status === 0 &&
  summary.tests === EXPECTED_WEB_TESTS &&
  summary.pass === EXPECTED_WEB_TESTS &&
  summary.fail === 0 &&
  summary.skipped === 0 &&
  inventoryNames.length === EXPECTED_WEB_TESTS &&
  uniqueInventoryNames.size === EXPECTED_WEB_TESTS &&
  inventorySha256 === EXPECTED_WEB_TEST_INVENTORY_SHA256 &&
  syntaxPassed === syntaxTargets.length;
const record = {
  passed,
  expected_web_tests: EXPECTED_WEB_TESTS,
  expected_inventory_sha256: EXPECTED_WEB_TEST_INVENTORY_SHA256,
  syntax: { passed: syntaxPassed, total: syntaxTargets.length },
  web: {
    ...summary,
    exit_code: web.status,
    files: webTestFiles,
    inventory_names: inventoryNames.length,
    inventory_sha256: inventorySha256,
  },
};
process.stdout.write(`${JSON.stringify(record)}\n`);
process.exitCode = passed ? 0 : 1;
