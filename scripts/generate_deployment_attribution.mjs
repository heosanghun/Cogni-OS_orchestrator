#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

const EXPECTED_PROJECT = "cogni-os-orchestrator";
const EXPECTED_BRANCH = "main";
const CANONICAL_PRODUCTION_URL =
  "https://cogni-os-orchestrator.pages.dev";

const commit = String(process.env.CF_PAGES_COMMIT_SHA || "").toLowerCase();
const isPagesBuild = process.env.CF_PAGES === "1";
const branch = String(process.env.CF_PAGES_BRANCH || "");
const rawDeploymentUrl = String(process.env.CF_PAGES_URL || "");

function normalizedDeploymentUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  const hostname = parsed.hostname.toLowerCase();
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    parsed.search ||
    parsed.hash ||
    !["", "/"].includes(parsed.pathname) ||
    hostname === `${EXPECTED_PROJECT}.pages.dev` ||
    !hostname.endsWith(`.${EXPECTED_PROJECT}.pages.dev`)
  ) {
    return null;
  }
  return `https://${hostname}`;
}

const deploymentUrl = normalizedDeploymentUrl(rawDeploymentUrl);
const buildBound =
  isPagesBuild &&
  /^[0-9a-f]{40}$/.test(commit) &&
  branch === EXPECTED_BRANCH &&
  deploymentUrl !== null;
if (isPagesBuild && !buildBound) {
  throw new Error(
    "Cloudflare Pages production build metadata is missing or invalid; refusing an unbound or preview artifact.",
  );
}
const record = {
  build_bound: buildBound,
  source_commit: buildBound ? commit : null,
  branch: buildBound ? EXPECTED_BRANCH : null,
  url: buildBound ? CANONICAL_PRODUCTION_URL : null,
  deployment_url: buildBound ? deploymentUrl : null,
  project: buildBound ? EXPECTED_PROJECT : null,
  environment: buildBound ? "production" : null,
};
const content = [
  "// Generated during the Cloudflare Pages build; do not edit in the artifact.",
  `export const BUILD_DEPLOYMENT = Object.freeze(${JSON.stringify(record, null, 2)});`,
  "",
].join("\n");
writeFileSync(resolve("functions/_lib/deployment.generated.js"), content, "utf8");
process.stdout.write(
  `${JSON.stringify({ build_bound: record.build_bound, source_commit: record.source_commit })}\n`,
);
