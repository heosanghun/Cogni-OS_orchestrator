import assert from "node:assert/strict";
import test from "node:test";

import { MAX_BODY_BYTES } from "../../functions/_lib/monitoring.js";
import { onRequest as health } from "../../functions/api/health.js";
import { onRequest as ingest } from "../../functions/api/ingest.js";

const KEY_ID = "publisher-2026-07";
const SECRET = "release-audit-secret-longer-than-thirty-two-characters";
const WORKSPACE = "release-audit-workspace";

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
