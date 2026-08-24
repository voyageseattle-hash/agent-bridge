#!/usr/bin/env node

import assert from "node:assert/strict";
import { isAbsolute, resolve } from "node:path";
import { verifyReleaseEvidence } from "./export-release-evidence.mjs";

try {
  assert.equal(process.argv.length, 4, "usage: node scripts/verify-release-evidence.mjs --packet-dir <absolute-packet-directory>");
  assert.equal(process.argv[2], "--packet-dir", "only --packet-dir is supported");
  assert.ok(isAbsolute(process.argv[3]), "--packet-dir must be an absolute path");
  const result = await verifyReleaseEvidence({ packetDir: resolve(process.argv[3]) });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`evidence verification failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
