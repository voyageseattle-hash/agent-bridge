import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const out = await mkdtemp(join(tmpdir(), "agent-bridge-approvals-build-"));
const outfile = join(out, "approvals.mjs");
await build({ entryPoints: ["src/approvals.ts"], outfile, bundle: true, platform: "node", format: "esm", target: "node20" });
const { ApprovalStore, projectApproval, APPROVAL_CATEGORIES } = await import(`${pathToFileURL(outfile).href}?${Date.now()}`);
test.after(async () => rm(out, { recursive: true, force: true }));

const baseTime = Date.parse("2030-01-01T00:00:00.000Z");
const scope = (extra = {}) => ({ subject: "creator-project", action: "send selected brief", dataClass: "internal", root: "C:\\workspace", agent: "manus", payloadSha256: "a".repeat(64), ...extra });
const request = (extra = {}) => ({ category: "remote_egress", scope: scope(), requestedBy: "creator", reason: "Get a bounded independent research review", expiresAt: "2030-01-01T01:00:00.000Z", ...extra });

async function fixture(start = baseTime) {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-approvals-"));
  let time = start;
  const store = new ApprovalStore(state, 500, 50, () => new Date(time));
  return { state, store, tick(ms = 1_000) { time += ms; } };
}

test("all required approval categories create versioned, scoped, durable records", async () => {
  const f = await fixture();
  try {
    for (const category of APPROVAL_CATEGORIES) {
      const record = f.store.create(request({ category, ...(category === "paid_or_unknown_cost" ? { currency: "usd" } : {}) }));
      assert.equal(record.schemaVersion, 2);
      assert.equal(record.state, "pending");
      assert.equal(record.events[0].type, "requested");
      assert.equal(record.events[0].reason, record.reason);
      assert.deepEqual(f.store.get(record.id), record);
    }
    assert.equal(f.store.list().length, APPROVAL_CATEGORIES.length);
  } finally { await rm(f.state, { recursive: true, force: true }); }
});

test("one-time approval binds exact scope and cannot be reused", async () => {
  const f = await fixture();
  try {
    const pending = f.store.create(request());
    f.tick();
    const approved = await f.store.approve(pending.id, { approvedBy: "human-owner", reason: "Reviewed the outbound brief" });
    assert.equal(approved.state, "approved");
    assert.equal(approved.revision, 1);
    await assert.rejects(f.store.consume(pending.id, { consumedBy: "bridge", scope: scope({ action: "send whole repository" }), reason: "wrong scope" }), /SCOPE_MISMATCH/);
    f.tick();
    const consumed = await f.store.consume(pending.id, { consumedBy: "bridge", scope: scope(), reason: "Submitted approved brief" });
    assert.equal(consumed.state, "consumed");
    assert.equal(consumed.useCount, 1);
    assert.deepEqual(consumed.events.map((event) => event.type), ["requested", "approved", "consumed"]);
    await assert.rejects(f.store.consume(pending.id, { consumedBy: "bridge", scope: scope(), reason: "try twice" }), /INVALID_TRANSITION/);
  } finally { await rm(f.state, { recursive: true, force: true }); }
});

test("bounded reusable approvals remain approved until their configured use limit", async () => {
  const f = await fixture();
  try {
    const pending = f.store.create(request({ category: "secrets", consumeOnce: false, maxUses: 3 }));
    f.tick(); await f.store.approve(pending.id, { approvedBy: "owner", reason: "Three matching calls allowed" });
    for (let index = 1; index <= 3; index++) {
      f.tick();
      const current = await f.store.consume(pending.id, { consumedBy: "bridge", scope: scope(), reason: `approved call ${index}` });
      assert.equal(current.useCount, index);
      assert.equal(current.state, index === 3 ? "consumed" : "approved");
    }
    const stored = f.store.get(pending.id);
    assert.deepEqual(stored.events.map((event) => event.type), ["requested", "approved", "used", "used", "consumed"]);
  } finally { await rm(f.state, { recursive: true, force: true }); }
});

test("denial, cancellation, and expiry enforce exact terminal transitions", async (t) => {
  await t.test("denied pending request is terminal", async () => {
    const f = await fixture(); try {
      const pending = f.store.create(request()); f.tick();
      const denied = await f.store.deny(pending.id, { deniedBy: "owner", reason: "Too much project context" });
      assert.equal(denied.state, "denied");
      await assert.rejects(f.store.approve(pending.id, { approvedBy: "owner", reason: "changed mind" }), /INVALID_TRANSITION/);
    } finally { await rm(f.state, { recursive: true, force: true }); }
  });
  await t.test("pending and approved requests can be canceled", async () => {
    const f = await fixture(); try {
      const pending = f.store.create(request()); f.tick();
      assert.equal((await f.store.cancel(pending.id, { canceledBy: "creator", reason: "No longer needed" })).state, "canceled");
      const second = f.store.create(request({ scope: scope({ subject: "second" }) })); f.tick();
      await f.store.approve(second.id, { approvedBy: "owner", reason: "Initially safe" }); f.tick();
      assert.equal((await f.store.cancel(second.id, { canceledBy: "owner", reason: "Plan changed" })).state, "canceled");
    } finally { await rm(f.state, { recursive: true, force: true }); }
  });
  await t.test("due requests expire and cannot be approved", async () => {
    const f = await fixture(); try {
      const pending = f.store.create(request({ expiresAt: "2030-01-01T00:00:01.000Z" })); f.tick(1_000);
      await assert.rejects(f.store.approve(pending.id, { approvedBy: "owner", reason: "too late" }), /APPROVAL_EXPIRED/);
      const expired = f.store.get(pending.id);
      assert.equal(expired.state, "expired");
      assert.equal(expired.events.at(-1).type, "expired");
    } finally { await rm(f.state, { recursive: true, force: true }); }
  });
});

test("cost metadata is normalized and paid or unknown cost requests retain currency", async () => {
  const f = await fixture();
  try {
    const paid = f.store.create(request({ category: "paid_or_unknown_cost", estimatedCost: 2.5, currency: "usd" }));
    assert.equal(paid.estimatedCost, 2.5);
    assert.equal(paid.currency, "USD");
    const unknown = f.store.create(request({ category: "paid_or_unknown_cost", currency: "USD", scope: scope({ subject: "unknown-cost-job" }) }));
    assert.equal(unknown.estimatedCost, null);
    assert.throws(() => f.store.create(request({ category: "paid_or_unknown_cost" })), /require(?:s)? currency/);
    assert.throws(() => f.store.create(request({ estimatedCost: 1 })), /requires currency/);
    assert.throws(() => f.store.create(request({ consumeOnce: false, maxUses: 1 })), /reusable approvals/);
    assert.throws(() => f.store.create(request({ consumeOnce: false, maxUses: 2 })), /APPROVAL_REUSABLE_FORBIDDEN.*remote_egress/);
    assert.throws(() => f.store.create(request({ category: "paid_or_unknown_cost", currency: "USD", consumeOnce: false, maxUses: 2 })), /APPROVAL_REUSABLE_FORBIDDEN.*paid_or_unknown_cost/);
  } finally { await rm(f.state, { recursive: true, force: true }); }
});

test("secret values and unknown input scope fields are rejected before persistence", async () => {
  const f = await fixture();
  try {
  assert.throws(() => f.store.create(request({ reason: "use sk-test-fixture-abcdefghijklmnopqrstuvwxyz123456" })), /SECRET_MATERIAL_REJECTED/);
    assert.throws(() => f.store.create(request({ scope: scope({ surprise: true }) })), /unknown field/);
    assert.throws(() => f.store.create(request({ scope: scope({ payloadSha256: "A".repeat(64) }) })), /lowercase SHA-256/);
    assert.throws(() => f.store.create(request({ scope: scope({ payloadSha256: "a".repeat(63) }) })), /lowercase SHA-256/);
    assert.throws(() => f.store.create(request({ hidden: true })), /INVALID_REQUEST.*unknown field/);
    assert.equal(f.store.list().length, 0);
  } finally { await rm(f.state, { recursive: true, force: true }); }
});

test("strict loading fails closed for traversal, corruption, future schema, and inconsistent history", async (t) => {
  await t.test("unsafe id and invalid JSON", async () => {
    const f = await fixture(); try {
      assert.throws(() => f.store.get("../escape"), /INVALID_ID/);
      const record = f.store.create(request()); await writeFile(f.store.path(record.id), "{bad", "utf8");
      assert.throws(() => f.store.get(record.id), /APPROVAL_CORRUPT.*invalid JSON/);
    } finally { await rm(f.state, { recursive: true, force: true }); }
  });
  await t.test("future schema and unknown fields", async () => {
    const f = await fixture(); try {
      const record = f.store.create(request()); const path = f.store.path(record.id);
      const raw = JSON.parse(await readFile(path, "utf8")); raw.schemaVersion = 3; await writeFile(path, JSON.stringify(raw), "utf8");
      assert.throws(() => f.store.get(record.id), /UNSUPPORTED_VERSION.*3/);
      raw.schemaVersion = 2; raw.hidden = "no"; await writeFile(path, JSON.stringify(raw), "utf8");
      assert.throws(() => f.store.get(record.id), /APPROVAL_CORRUPT.*unknown field/);
    } finally { await rm(f.state, { recursive: true, force: true }); }
  });
  await t.test("state and event history cannot disagree", async () => {
    const f = await fixture(); try {
      const record = f.store.create(request()); const path = f.store.path(record.id);
      const raw = JSON.parse(await readFile(path, "utf8")); raw.state = "approved"; await writeFile(path, JSON.stringify(raw), "utf8");
      assert.throws(() => f.store.get(record.id), /state approved does not match event history/);
    } finally { await rm(f.state, { recursive: true, force: true }); }
  });
});

test("legacy v1 approvals migrate for audit but live authority is canceled", async () => {
  const f = await fixture();
  try {
    const record = f.store.create(request());
    const path = f.store.path(record.id);
    const raw = JSON.parse(await readFile(path, "utf8"));
    raw.schemaVersion = 1;
    delete raw.scope.payloadSha256;
    await writeFile(path, JSON.stringify(raw), "utf8");
    const migrated = f.store.get(record.id);
    assert.equal(migrated.schemaVersion, 2);
    assert.equal(migrated.state, "canceled");
    assert.match(migrated.scope.payloadSha256, /^[a-f0-9]{64}$/);
    assert.equal(migrated.events.at(-1).type, "canceled");
    assert.match(migrated.events.at(-1).reason, /legacy unbound approval invalidated/);
    assert.equal(JSON.parse(await readFile(path, "utf8")).schemaVersion, 2);
  } finally { await rm(f.state, { recursive: true, force: true }); }
});

test("listing filters exact scope metadata and projection bounds every free-text field", async () => {
  const f = await fixture();
  try {
    const long = "x".repeat(100);
    const first = f.store.create(request({ scope: scope({ subject: "first", action: long, root: long, agent: long }), requestedBy: long, reason: long }));
    f.tick();
    f.store.create(request({ category: "deploy_or_publish", scope: scope({ subject: "second", agent: "codex" }) }));
    assert.deepEqual(f.store.list({ category: "remote_egress", subject: "first" }).map((value) => value.id), [first.id]);
    assert.throws(() => f.store.list({ hidden: true }), /INVALID_LIST_FILTER.*unknown field/);
    const projected = projectApproval(first, 10);
    assert.ok(projected.scope.action.length < 40);
    assert.ok(projected.scope.root.length < 40);
    assert.ok(projected.scope.agent.length < 40);
    assert.ok(projected.requestedBy.length < 40);
    assert.ok(projected.reason.length < 40);
    assert.ok(projected.events[0].actor.length < 40);
    assert.ok(projected.events[0].reason.length < 40);
    assert.equal("secret" in projected, false);
  } finally { await rm(f.state, { recursive: true, force: true }); }
});

test("per-record locking serializes competing decisions", async () => {
  const f = await fixture();
  try {
    const pending = f.store.create(request());
    const results = await Promise.allSettled([
      f.store.approve(pending.id, { approvedBy: "owner-a", reason: "approve" }),
      f.store.deny(pending.id, { deniedBy: "owner-b", reason: "deny" }),
    ]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(results.filter((result) => result.status === "rejected").length, 1);
    assert.ok(["approved", "denied"].includes(f.store.get(pending.id).state));
  } finally { await rm(f.state, { recursive: true, force: true }); }
});
