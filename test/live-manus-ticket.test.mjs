import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import {
  confirmationDigestForBinding,
  consumePendingTicket,
  createPendingTicket,
  scrubManusEnvironment,
} from "./live-manus.mjs";

test("Manus live preview creates a cryptographic pending ticket without contacting a provider", async () => {
  const parent = await mkdtemp(join(tmpdir(), "agent-bridge-live-manus-preview-"));
  const installRoot = join(parent, "install");
  const runtime = join(installRoot, "releases", "preview+abcdef0", "server", "agent-bridge.mjs");
  const credential = join(parent, "credential");
  const evidence = join(parent, "evidence");
  try {
    await mkdir(dirname(runtime), { recursive: true });
    const runtimeBytes = "export const previewOnly = true;\n";
    await writeFile(runtime, runtimeBytes);
    await writeFile(credential, "not-a-real-provider-key\n");
    const result = spawnSync(process.execPath, ["test/live-manus.mjs", "--evidence-dir", evidence], {
      cwd: process.cwd(),
      encoding: "utf8",
      windowsHide: true,
      env: {
        ...process.env,
        AGENT_BRIDGE_SERVER_PATH: runtime,
        AGENT_BRIDGE_INSTALL_ROOT: installRoot,
        AGENT_BRIDGE_EXPECTED_VERSION: "0.3.0-preview",
        AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256: sha256(runtimeBytes),
        AGENT_BRIDGE_MANUS_CREDENTIAL_FILE: credential,
    MANUS_API_KEY: "test-fixture-must-not-be-used",
        MANUS_API_BASE_URL: "http://127.0.0.1:9",
      },
    });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout.trim());
    const ticket = JSON.parse(await readFile(join(evidence, "pending-ticket.json"), "utf8"));
    assert.equal(output.status, "preview");
    assert.equal(output.providerContacted, false);
    assert.match(ticket.binding.nonce, /^[a-f0-9]{64}$/);
    assert.equal(ticket.binding.expectedReply, `LIVE_MANUS_FRESH_OK_${ticket.binding.nonce}`);
    assert.equal(ticket.binding.runtime.sha256, sha256(runtimeBytes));
    assert.equal(ticket.confirmationSha256, output.confirmationSha256);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

function binding(root) {
  const nonce = "a".repeat(64);
  const expectedReply = `LIVE_MANUS_FRESH_OK_${nonce}`;
  const prompt = `Public connection canary only. Do not use browsers, connectors, files, credentials, purchases, messages, or external actions. Reply with exactly this text and nothing else: ${expectedReply}`;
  return {
    schemaVersion: 1,
    promptTemplateVersion: 1,
    nonce,
    expectedReply,
    promptSha256: sha256(prompt),
    model: "manus-1.6-lite",
    timeoutSec: 180,
    dataClassification: "public",
    providerEndpoint: "https://api.manus.ai",
    providerCapabilityPolicy: "manus-v2-empty-connectors-default-skills-v1",
    providerAccountProfile: "live-canary-account-defaults-acknowledged-v1",
    maximumApprovedCostUsd: 0.5,
    maximumReservedCents: 50,
    credentialFile: join(root, "credential"),
    runtime: { path: join(root, "runtime.mjs"), version: "0.3.0-test", sha256: "b".repeat(64), releaseId: "test+abcdef0", releaseMode: true },
    evidence: null,
    createdAt: "2030-01-01T00:00:00.000Z",
    expiresAt: "2030-01-01T00:15:00.000Z",
  };
}

test("Manus live ticket is nonce-bound, atomically one-use, and replay-safe", async () => {
  const parent = await mkdtemp(join(tmpdir(), "agent-bridge-live-manus-ticket-"));
  const evidence = join(parent, "evidence");
  try {
    const ticket = await createPendingTicket(evidence, { binding: binding(parent) });
    assert.match(ticket.binding.nonce, /^[a-f0-9]{64}$/);
    assert.equal(ticket.confirmationSha256, confirmationDigestForBinding(ticket.binding));
    assert.equal(JSON.parse(await readFile(join(evidence, "pending-ticket.json"), "utf8")).state, "pending");

    await assert.rejects(consumePendingTicket(evidence, "f".repeat(64)), /confirmation digest mismatch/i);
    assert.equal(JSON.parse(await readFile(join(evidence, "pending-ticket.json"), "utf8")).state, "pending", "wrong confirmation consumed the ticket");

    await consumePendingTicket(evidence, ticket.confirmationSha256);
    assert.equal(JSON.parse(await readFile(join(evidence, "consumed-ticket.json"), "utf8")).confirmationSha256, ticket.confirmationSha256);
    await assert.rejects(consumePendingTicket(evidence, ticket.confirmationSha256), /already consumed/i);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("confirmation digest binds every execution-critical field and evidence path", async () => {
  const parent = await mkdtemp(join(tmpdir(), "agent-bridge-live-manus-binding-"));
  const evidence = join(parent, "evidence");
  try {
    const ticket = await createPendingTicket(evidence, { binding: binding(parent) });
    const original = ticket.confirmationSha256;
    const mutations = [
      ["nonce", "c".repeat(64)], ["expectedReply", "changed"], ["promptSha256", "d".repeat(64)], ["model", "manus-other"],
      ["timeoutSec", 181], ["dataClassification", "internal"], ["providerEndpoint", "https://example.invalid"],
      ["providerCapabilityPolicy", "changed"], ["providerAccountProfile", "changed"], ["maximumApprovedCostUsd", 0.6], ["maximumReservedCents", 60],
      ["credentialFile", join(parent, "other-credential")], ["createdAt", "2030-01-01T00:00:01.000Z"], ["expiresAt", "2030-01-01T00:16:00.000Z"],
    ];
    for (const [key, value] of mutations) {
      const changed = structuredClone(ticket.binding); changed[key] = value;
      assert.notEqual(confirmationDigestForBinding(changed), original, key);
    }
    for (const key of Object.keys(ticket.binding.runtime)) {
      const changed = structuredClone(ticket.binding); changed.runtime[key] = `${String(changed.runtime[key])}-changed`;
      assert.notEqual(confirmationDigestForBinding(changed), original, `runtime.${key}`);
    }
    for (const key of Object.keys(ticket.binding.evidence)) {
      const changed = structuredClone(ticket.binding); changed.evidence[key] = `${changed.evidence[key]}-changed`;
      assert.notEqual(confirmationDigestForBinding(changed), original, `evidence.${key}`);
    }
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("Manus live child environment strips ambient raw API authority", () => {
  assert.deepEqual(scrubManusEnvironment({
    PATH: "safe",
    MANUS_API_KEY: "test-fixture-must-not-pass",
    MANUS_API_BASE_URL: "https://unexpected.invalid",
    AGENT_BRIDGE_CONFIG: "wrong-config",
  }), { PATH: "safe" });
});

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
