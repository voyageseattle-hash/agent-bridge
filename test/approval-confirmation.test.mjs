import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const out = await mkdtemp(join(tmpdir(), "agent-bridge-approval-confirmation-build-"));
const outfile = join(out, "approval-confirmation.mjs");
await build({ entryPoints: ["src/approval-confirmation.ts"], outfile, bundle: true, platform: "node", format: "esm", target: "node20" });
const {
  buildApprovalElicitationRequest,
  verifyApprovalElicitationResult,
  buildCliApprovalChallenge,
  verifyCliApprovalResult,
} = await import(`${pathToFileURL(outfile).href}?${Date.now()}`);
test.after(async () => rm(out, { recursive: true, force: true }));

const approval = (extra = {}) => ({
  schemaVersion: 1,
  id: "approval_01HX7",
  category: "remote_egress",
  state: "pending",
  scope: {
    subject: "creator-project",
    action: "send selected brief",
    dataClass: "internal",
    root: "C:\\workspace\\creator-project",
    agent: "manus",
    payloadSha256: "a".repeat(64),
  },
  requestedBy: "creator",
  reason: "Bounded independent review",
  requestedAt: "2030-01-01T00:00:00.000Z",
  updatedAt: "2030-01-01T00:00:00.000Z",
  expiresAt: "2030-01-01T01:00:00.000Z",
  estimatedCost: 2.5,
  currency: "USD",
  consumeOnce: true,
  maxUses: 1,
  useCount: 0,
  revision: 0,
  events: [],
  ...extra,
});

test("MCP elicitation displays exact allowlisted authority and accepts only explicit exact confirmation", () => {
  const record = approval();
  const request = buildApprovalElicitationRequest(record);
  assert.equal(request.mode, "form");
  assert.match(request.message, /Category: "remote_egress"/);
  assert.match(request.message, /subject: "creator-project"/);
  assert.match(request.message, /action: "send selected brief"/);
  assert.match(request.message, /dataClass: "internal"/);
  assert.match(request.message, /root: "C:\\\\workspace\\\\creator-project"/);
  assert.match(request.message, /agent: "manus"/);
  assert.match(request.message, /payloadSha256: "a{64}"/);
  assert.match(request.message, /Expires: "2030-01-01T01:00:00.000Z"/);
  assert.match(request.message, /Cost: 2.5 USD/);
  assert.match(request.message, /Use count: 0\/1 \(one-time\)/);
  assert.deepEqual(request.requestedSchema.required, ["approvalId", "approve"]);
  assert.deepEqual(
    verifyApprovalElicitationResult(record, { action: "accept", content: { approvalId: record.id, approve: true } }),
    { accepted: true },
  );
});

test("MCP elicitation treats decline, cancel, missing consent, ID mismatch, and extra fields as non-approval", () => {
  const record = approval();
  assert.deepEqual(verifyApprovalElicitationResult(record, { action: "decline" }), { accepted: false, reason: "declined" });
  assert.deepEqual(verifyApprovalElicitationResult(record, { action: "cancel" }), { accepted: false, reason: "canceled" });
  assert.deepEqual(verifyApprovalElicitationResult(record, { action: "accept", content: { approvalId: record.id, approve: false } }), { accepted: false, reason: "mismatch" });
  assert.deepEqual(verifyApprovalElicitationResult(record, { action: "accept", content: { approvalId: "approval_other", approve: true } }), { accepted: false, reason: "mismatch" });
  assert.deepEqual(verifyApprovalElicitationResult(record, { action: "accept", content: { approvalId: record.id, approve: true, hidden: true } }), { accepted: false, reason: "mismatch" });
  assert.deepEqual(verifyApprovalElicitationResult(record, { action: "accept" }), { accepted: false, reason: "mismatch" });
});

test("CLI challenge requires the exact response and distinguishes decline, cancel, and mismatch", () => {
  const record = approval({ estimatedCost: null, currency: "USD", consumeOnce: false, maxUses: 3, useCount: 1 });
  const prompt = buildCliApprovalChallenge(record);
  assert.match(prompt, /Cost: unknown USD/);
  assert.match(prompt, /Use count: 1\/3 \(reusable\)/);
  assert.match(prompt, /Type exactly: APPROVE approval_01HX7/);
  assert.deepEqual(verifyCliApprovalResult(record, "APPROVE approval_01HX7"), { accepted: true });
  assert.deepEqual(verifyCliApprovalResult(record, "DECLINE approval_01HX7"), { accepted: false, reason: "declined" });
  assert.deepEqual(verifyCliApprovalResult(record, undefined), { accepted: false, reason: "canceled" });
  assert.deepEqual(verifyCliApprovalResult(record, "approve approval_01HX7"), { accepted: false, reason: "mismatch" });
  assert.deepEqual(verifyCliApprovalResult(record, "APPROVE approval_01HX7 "), { accepted: false, reason: "mismatch" });
});

test("confirmation prompts omit request narratives and reject secret-like or spoofing scope text", () => {
  const record = approval({
    requestedBy: "private transcript author",
    reason: "TRANSCRIPT CONTENT MUST NEVER APPEAR",
    events: [{ reason: "MORE TRANSCRIPT CONTENT" }],
  });
  const host = buildApprovalElicitationRequest(record).message;
  const cli = buildCliApprovalChallenge(record);
  for (const prompt of [host, cli]) {
    assert.doesNotMatch(prompt, /TRANSCRIPT CONTENT|private transcript author|MORE TRANSCRIPT/);
    assert.ok(prompt.length <= 8_192);
  }
  assert.throws(
    () => buildApprovalElicitationRequest(approval({ scope: { ...record.scope, action: "send sk-test-fixture-abcdefghijklmnopqrstuvwxyz123456" } })),
    /SECRET_REJECTED/,
  );
  assert.throws(
    () => buildCliApprovalChallenge(approval({ scope: { ...record.scope, subject: "safe\u202Etxt" } })),
    /UNSAFE_DISPLAY/,
  );
});
