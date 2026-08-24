import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const out = await mkdtemp(join(tmpdir(), "agent-bridge-workboards-build-"));
const outfile = join(out, "workboards.mjs");
await build({ entryPoints: ["src/workboards.ts"], outfile, bundle: true, platform: "node", format: "esm", target: "node20" });
const { WorkboardStore, projectWorkboard, integratorBrief } = await import(`${pathToFileURL(outfile).href}?${Date.now()}`);
test.after(async () => rm(out, { recursive: true, force: true }));

async function fixture() { const state = await mkdtemp(join(tmpdir(), "agent-bridge-workboards-")); return { state, store: new WorkboardStore(state, 500, 50) }; }
async function cleanup(value) { await rm(value.state, { recursive: true, force: true }); }
const item = (key, extra = {}) => ({ key, title: key, instructions: `Investigate ${key}`, ...extra });

test("creation rejects duplicate keys, unknown dependencies, and cycles", async () => {
  const f = await fixture(); try {
    assert.throws(() => f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a"), item("a")] }), /duplicate/i);
    assert.throws(() => f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a", { dependsOn: ["missing"] })] }), /unknown dependency/i);
    assert.throws(() => f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a", { dependsOn: ["b"] }), item("b", { dependsOn: ["a"] })] }), /cycle/i);
  } finally { await cleanup(f); }
});

test("new cooperative work items default to provider-restricted network egress", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a")] });
    assert.deepEqual(board.items[0].requirements, {
      dataClass: "internal", filesystem: "read-only", network: "restricted", capabilities: [],
    });
  } finally { await cleanup(f); }
});

test("dependency acceptance gates work and independent review is enforced", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "objective", cwd: process.cwd(), items: [item("research"), item("implement", { dependsOn: ["research"] })] });
    await assert.rejects(f.store.run(board.id, "implement", "claude", async () => ({ summary: "no" })), /BLOCKED/);
    await f.store.run(board.id, "research", "codex", async ({ sandbox }) => { assert.equal(sandbox, "read-only"); return { sessionId: "native", summary: "finding", evidence: "proof", risks: "none" }; });
    await assert.rejects(f.store.review(board.id, "research", "codex", "accepted", "self"), /SUBMITTER/);
    await f.store.review(board.id, "research", "claude", "accepted", "independent");
    const ran = await f.store.run(board.id, "implement", "claude", async () => ({ summary: "done" }));
    assert.equal(ran.items.find((x) => x.key === "implement").status, "submitted");
  } finally { await cleanup(f); }
});

test("separate ready items run in parallel while same item has one lease and cap is enforced", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), maxParallel: 2, items: [item("a"), item("b"), item("c")] });
    let release; const gate = new Promise((resolve) => { release = resolve; });
    const runA = f.store.run(board.id, "a", "codex", async () => { await gate; return { summary: "a" }; });
    await new Promise((resolve) => setTimeout(resolve, 10));
    await assert.rejects(f.store.run(board.id, "a", "claude", async () => ({ summary: "stolen" })), /BUSY/);
    const runB = f.store.run(board.id, "b", "claude", async () => { await gate; return { summary: "b" }; });
    await new Promise((resolve) => setTimeout(resolve, 10));
    await assert.rejects(f.store.run(board.id, "c", "codex", async () => ({ summary: "c" })), /CAPACITY/);
    release(); await Promise.all([runA, runB]);
  } finally { await cleanup(f); }
});

test("failure retry clears stale failure state and still obeys attempt budgets", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a", { budget: { maxAttempts: 2, maxWallSec: 3, tokenBudgetHint: 99 } })] });
    const failed = await f.store.run(board.id, "a", "codex", async () => { throw new Error("boom"); });
    assert.equal(failed.items[0].status, "failed"); assert.equal(failed.items[0].attempts, 1);
    const retried = await f.store.run(board.id, "a", "codex", async ({ item: claimed, timeoutSec }) => { assert.equal(claimed.failure, undefined); assert.equal(timeoutSec, 3); return { summary: "retry" }; }, { retryFailed: true });
    assert.equal(retried.items[0].failure, undefined);
    await assert.rejects(f.store.run(board.id, "a", "codex", async () => ({ summary: "third" })), /NOT_READY/);
  } finally { await cleanup(f); }
});

test("rejection preserves review rationale and returns the item to ready", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a")] });
    await f.store.run(board.id, "a", "codex", async () => ({ summary: "weak" }));
    const rejected = await f.store.review(board.id, "a", "claude", "rejected", "missing evidence");
    assert.equal(rejected.items[0].status, "ready");
    assert.equal(rejected.items[0].review.rationale, "missing evidence");
    const rerun = await f.store.run(board.id, "a", "codex", async ({ item: claimed }) => { assert.equal(claimed.review, undefined); assert.equal(claimed.submission, undefined); return { summary: "replacement" }; });
    assert.equal(rerun.items[0].review, undefined);
  } finally { await cleanup(f); }
});

test("reviewer lease blocks duplicate reviewers and capacity blocks both directions", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), maxParallel: 1, items: [item("a"), item("b"), item("c")] });
    await f.store.run(board.id, "a", "codex", async () => ({ summary: "a" }));
    await f.store.run(board.id, "b", "codex", async () => ({ summary: "b" }));
    let release; const gate = new Promise((resolve) => { release = resolve; });
    const reviewing = f.store.runReview(board.id, "a", "claude", async ({ sandbox }) => { assert.equal(sandbox, "read-only"); await gate; return { verdict: "accepted", rationale: "good" }; });
    await new Promise((resolve) => setTimeout(resolve, 10));
    await assert.rejects(f.store.runReview(board.id, "a", "gemini", async () => ({ verdict: "accepted", rationale: "duplicate" })), /REVIEW_BUSY/);
    await assert.rejects(f.store.runReview(board.id, "b", "claude", async () => ({ verdict: "accepted", rationale: "over capacity" })), /CAPACITY/);
    await assert.rejects(f.store.run(board.id, "c", "codex", async () => ({ summary: "must wait for reviewer" })), /CAPACITY/);
    release(); const complete = await reviewing; assert.equal(complete.items.find((candidate) => candidate.key === "a").status, "accepted");
  } finally { await cleanup(f); }
});

test("review failures retain a submitted item for bounded retry, then block it", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a", { budget: { maxAttempts: 2 } })] });
    await f.store.run(board.id, "a", "codex", async () => ({ summary: "candidate" }));
    const first = await f.store.runReview(board.id, "a", "claude", async () => { throw new Error("review transport failed"); });
    assert.equal(first.items[0].status, "submitted"); assert.equal(first.items[0].reviewAttempts, 1); assert.equal(first.items[0].failure.code, "REVIEW_FAILED");
    const second = await f.store.runReview(board.id, "a", "claude", async () => { throw new Error("review transport failed again"); });
    assert.equal(second.items[0].status, "blocked"); assert.equal(second.items[0].reviewAttempts, 2);
    const forced = f.store.get(board.id); forced.items[0].status = "submitted"; f.store.save(forced, forced.revision);
    await assert.rejects(f.store.runReview(board.id, "a", "claude", async () => ({ verdict: "accepted", rationale: "too late" })), /REVIEW_BUDGET_EXHAUSTED/);
  } finally { await cleanup(f); }
});

test("a successful review retry clears the previous review failure", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a", { budget: { maxAttempts: 2 } })] });
    await f.store.run(board.id, "a", "codex", async () => ({ summary: "submitted" }));
    const first = await f.store.runReview(board.id, "a", "claude", async () => { throw new Error("temporary review outage"); });
    assert.equal(first.items[0].failure.code, "REVIEW_FAILED");
    const second = await f.store.runReview(board.id, "a", "claude", async ({ item: claimed }) => {
      assert.equal(claimed.failure, undefined);
      return { verdict: "accepted", rationale: "Independent evidence was checked successfully." };
    });
    assert.equal(second.items[0].status, "accepted");
    assert.equal(second.items[0].failure, undefined);
  } finally { await cleanup(f); }
});

test("expired lease is reclaimable and projection/briefing bound all owned text", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x".repeat(100), objective: "objective".repeat(100), cwd: "c".repeat(100), items: [item("a", { title: "t".repeat(100), instructions: "i".repeat(100) })] });
    const stored = f.store.get(board.id); stored.items[0].status = "running"; stored.items[0].owner = { agentId: "gone", leaseId: "secret-lease", claimedAt: new Date(0).toISOString(), expiresAt: new Date(0).toISOString() }; f.store.save(stored, stored.revision);
    const ran = await f.store.run(board.id, "a", "claude", async () => ({ summary: "s".repeat(100), evidence: "e".repeat(100), risks: "r".repeat(100) }));
    await f.store.review(board.id, "a", "codex", "accepted", "okay".repeat(100), "native-review-secret");
    const mutated = f.store.get(board.id); mutated.items[0].failure = { code: "X".repeat(100), message: "failure".repeat(100), at: new Date().toISOString() }; f.store.save(mutated, mutated.revision);
    const projected = projectWorkboard(f.store.get(board.id), 10); assert.ok(projected.items[0].submission.summary.length < 40); assert.ok(projected.objective.length < 40); assert.ok(projected.items[0].instructions.length < 40); assert.ok(projected.items[0].review.rationale.length < 40); assert.equal(projected.items[0].review.sessionId, undefined); assert.ok(projected.items[0].failure.message.length < 40);
    const brief = integratorBrief(f.store.get(board.id), 100); assert.ok(brief.length <= 115); assert.match(brief, /objective/);
  } finally { await cleanup(f); }
});

test("expired leases do not consume parallel capacity", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), maxParallel: 1, items: [item("expired"), item("ready")] });
    const stored = f.store.get(board.id);
    stored.items[0].status = "running";
    stored.items[0].owner = { agentId: "gone", leaseId: "expired-lease", claimedAt: new Date(0).toISOString(), expiresAt: new Date(0).toISOString() };
    f.store.save(stored, stored.revision);
    const ran = await f.store.run(board.id, "ready", "codex", async () => ({ summary: "ran" }));
    assert.equal(ran.items.find((candidate) => candidate.key === "expired").status, "ready");
    assert.equal(ran.items.find((candidate) => candidate.key === "ready").status, "submitted");
  } finally { await cleanup(f); }
});

test("a rejected item cannot bypass its attempt budget", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a", { budget: { maxAttempts: 1 } })] });
    await f.store.run(board.id, "a", "codex", async () => ({ summary: "weak" }));
    const rejected = await f.store.review(board.id, "a", "claude", "rejected", "redo it");
    assert.equal(rejected.items[0].status, "blocked");
    await assert.rejects(f.store.run(board.id, "a", "codex", async () => ({ summary: "retry" })), /NOT_READY.*blocked/);
  } finally { await cleanup(f); }
});

test("mixed execution and review sequences end blocked when either retry budget is exhausted", async (t) => {
  await t.test("execution budget exhausted after an earlier rejection", async () => {
    const f = await fixture(); try {
      const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a", { budget: { maxAttempts: 2 } })] });
      await f.store.run(board.id, "a", "codex", async () => ({ summary: "first" }));
      const first = await f.store.review(board.id, "a", "claude", "rejected", "revise");
      assert.equal(first.items[0].status, "ready");
      await f.store.run(board.id, "a", "codex", async () => ({ summary: "second" }));
      const terminal = await f.store.runReview(board.id, "a", "claude", async () => ({ verdict: "rejected", rationale: "still incomplete" }));
      assert.equal(terminal.items[0].attempts, 2);
      assert.equal(terminal.items[0].reviewAttempts, 1);
      assert.equal(terminal.items[0].status, "blocked");
    } finally { await cleanup(f); }
  });

  await t.test("review budget exhausted after a failed review", async () => {
    const f = await fixture(); try {
      const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a", { budget: { maxAttempts: 2 } })] });
      await f.store.run(board.id, "a", "codex", async () => ({ summary: "candidate" }));
      const failed = await f.store.runReview(board.id, "a", "claude", async () => { throw new Error("temporary reviewer outage"); });
      assert.equal(failed.items[0].status, "submitted");
      const terminal = await f.store.runReview(board.id, "a", "claude", async () => ({ verdict: "rejected", rationale: "missing evidence" }));
      assert.equal(terminal.items[0].attempts, 1);
      assert.equal(terminal.items[0].reviewAttempts, 2);
      assert.equal(terminal.items[0].status, "blocked");
    } finally { await cleanup(f); }
  });
});

test("unversioned v0.3-dev boards migrate in memory and persist on the next locked save", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "legacy", objective: "preserve me", cwd: process.cwd(), items: [item("a", { budget: { maxAttempts: 3, maxWallSec: 9, tokenBudgetHint: 77 } })] });
    await f.store.run(board.id, "a", "codex", async () => ({ sessionId: "native-session", summary: "legacy result", evidence: "proof", risks: "none" }));
    const path = f.store.path(board.id); const legacy = JSON.parse(await readFile(path, "utf8"));
    delete legacy.schemaVersion; delete legacy.status; delete legacy.lifecycle; delete legacy.items[0].reviewSpent;
    for (const field of ["kind", "acceptanceCriteria", "requirements", "artifacts", "evidence", "approval", "cancellation"]) delete legacy.items[0][field];
    await writeFile(path, JSON.stringify(legacy, null, 2), "utf8");

    const migrated = f.store.get(board.id);
    assert.equal(migrated.schemaVersion, 2);
    assert.deepEqual(migrated.items[0].reviewSpent, { wallMs: 0, turns: 0 });
    assert.equal(migrated.items[0].submission.summary, "legacy result");
    assert.equal(migrated.items[0].spent.turns, 1);
    assert.equal(migrated.items[0].requirements.network, "restricted");
    assert.equal(migrated.revision, legacy.revision);
    assert.equal(migrated.updatedAt, legacy.updatedAt);
    const unchanged = JSON.parse(await readFile(path, "utf8"));
    assert.equal(unchanged.schemaVersion, undefined, "unlocked reads must not rewrite persisted state");
    f.store.save(migrated, migrated.revision);
    const persisted = JSON.parse(await readFile(path, "utf8"));
    assert.equal(persisted.schemaVersion, 2);
    assert.deepEqual(persisted.items[0].reviewSpent, { wallMs: 0, turns: 0 });
  } finally { await cleanup(f); }
});

test("load fails closed for invalid JSON, corrupt records, and unknown future schemas", async (t) => {
  await t.test("invalid JSON", async () => {
    const f = await fixture(); try { const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a")] }); await writeFile(f.store.path(board.id), "{broken", "utf8"); assert.throws(() => f.store.get(board.id), /WORKBOARD_CORRUPT.*invalid JSON/); } finally { await cleanup(f); }
  });
  await t.test("unknown and malformed fields", async () => {
    const f = await fixture(); try {
      const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a")] }); const path = f.store.path(board.id);
      const unknown = JSON.parse(await readFile(path, "utf8")); unknown.surprise = true; await writeFile(path, JSON.stringify(unknown), "utf8"); assert.throws(() => f.store.get(board.id), /WORKBOARD_CORRUPT.*unknown field/);
      delete unknown.surprise; unknown.items[0].spent.turns = "one"; await writeFile(path, JSON.stringify(unknown), "utf8"); assert.throws(() => f.store.get(board.id), /WORKBOARD_CORRUPT.*spent\.turns/);
      unknown.items[0].spent.turns = 0; delete unknown.items[0].reviewSpent; await writeFile(path, JSON.stringify(unknown), "utf8"); assert.throws(() => f.store.get(board.id), /WORKBOARD_CORRUPT.*reviewSpent/);
    } finally { await cleanup(f); }
  });
  await t.test("inconsistent accepted state", async () => {
    const f = await fixture(); try {
      const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a")] }); const path = f.store.path(board.id);
      const invalid = JSON.parse(await readFile(path, "utf8")); invalid.items[0].status = "accepted";
      await writeFile(path, JSON.stringify(invalid), "utf8");
      assert.throws(() => f.store.get(board.id), /WORKBOARD_CORRUPT.*accepted.*submission/);
    } finally { await cleanup(f); }
  });
  await t.test("future schema", async () => {
    const f = await fixture(); try { const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a")] }); const path = f.store.path(board.id); const future = JSON.parse(await readFile(path, "utf8")); future.schemaVersion = 3; await writeFile(path, JSON.stringify(future), "utf8"); assert.throws(() => f.store.get(board.id), /WORKBOARD_UNSUPPORTED_VERSION.*3/); } finally { await cleanup(f); }
  });
});

test("review usage is separate, cumulative, and updated on failure and success", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a", { budget: { maxAttempts: 2 } })] });
    const submitted = await f.store.run(board.id, "a", "codex", async () => ({ summary: "candidate" }));
    const executionSpent = structuredClone(submitted.items[0].spent);
    const failed = await f.store.runReview(board.id, "a", "claude", async () => { await new Promise((resolve) => setTimeout(resolve, 5)); throw new Error("temporary review failure"); });
    assert.deepEqual(failed.items[0].spent, executionSpent);
    assert.equal(failed.items[0].reviewSpent.turns, 1);
    assert.ok(failed.items[0].reviewSpent.wallMs >= 1);
    const failedWallMs = failed.items[0].reviewSpent.wallMs;
    const accepted = await f.store.runReview(board.id, "a", "claude", async () => { await new Promise((resolve) => setTimeout(resolve, 5)); return { verdict: "accepted", rationale: "verified" }; });
    assert.deepEqual(accepted.items[0].spent, executionSpent);
    assert.equal(accepted.items[0].reviewSpent.turns, 2);
    assert.ok(accepted.items[0].reviewSpent.wallMs > failedWallMs);
    const projected = projectWorkboard(accepted, 10);
    assert.deepEqual(projected.items[0].reviewSpent, accepted.items[0].reviewSpent);
  } finally { await cleanup(f); }
});

test("creator metadata, inert references, and approval gates persist and project safely", async () => {
  const f = await fixture(); try {
    const source = { id: "source-1", kind: "source", path: "C:\\creator\\draft.psd", hash: "sha256:abc", mediaType: "image/vnd.adobe.photoshop", dataClass: "confidential", accessibility: "local" };
    const board = f.store.create({
      title: "Creator packet", objective: "Prepare a reviewed asset", cwd: process.cwd(),
      items: [item("design", {
        kind: "design",
        acceptanceCriteria: ["Matches the approved composition", "Includes provenance evidence"],
        requirements: { dataClass: "confidential", filesystem: "metadata-only", network: "restricted", capabilities: ["image-review"] },
        artifacts: [source],
        evidence: [{ id: "brief-1", kind: "document", uri: "artifact://brief/1", mediaType: "text/markdown", dataClass: "internal", accessibility: "inline" }],
        approval: { required: true, reason: "Paid remote review" },
      })],
    });
    assert.equal(board.schemaVersion, 2); assert.equal(board.items[0].kind, "design"); assert.equal(board.items[0].approval.state, "pending");
    await assert.rejects(f.store.run(board.id, "design", "claude", async () => ({ summary: "must not run" })), /APPROVAL_REQUIRED/);
    const approved = await f.store.decideApproval(board.id, "design", "creator", "approved", "Approved for this item only");
    assert.equal(approved.items[0].approval.state, "approved");
    await assert.rejects(f.store.decideApproval(board.id, "design", "creator", "approved", "again"), /NOT_PENDING/);
    const submitted = await f.store.run(board.id, "design", "claude", async () => ({
      summary: "Prepared candidate",
      artifacts: [{ id: "render-1", kind: "image", uri: "artifact://render/1", hash: "sha256:def", mediaType: "image/png", dataClass: "internal", accessibility: "inline" }],
      evidenceRefs: [{ id: "check-1", kind: "report", accessibility: "unavailable", dataClass: "internal" }],
    }));
    assert.deepEqual(submitted.items[0].artifacts.map((reference) => reference.id), ["source-1", "render-1"]);
    assert.deepEqual(submitted.items[0].evidence.map((reference) => reference.id), ["brief-1", "check-1"]);
    const projected = projectWorkboard(submitted, 12);
    assert.ok(projected.items[0].acceptanceCriteria.every((criterion) => criterion.length < 40));
    assert.ok(projected.items[0].artifacts[0].path.length < 40);
  } finally { await cleanup(f); }
});

test("board lifecycle transitions are explicit, lease-safe, listed, and terminal", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "Lifecycle", objective: "Finish", cwd: process.cwd(), items: [item("a")] });
    const paused = await f.store.pause(board.id, "Creator paused the packet"); assert.equal(paused.status, "paused"); assert.ok(paused.lifecycle.pausedAt);
    await assert.rejects(f.store.run(board.id, "a", "codex", async () => ({ summary: "no" })), /INVALID_TRANSITION.*paused/);
    await assert.rejects(f.store.pause(board.id, "again"), /INVALID_TRANSITION/);
    const resumed = await f.store.resume(board.id, "Creator resumed"); assert.equal(resumed.status, "active"); assert.ok(resumed.lifecycle.resumedAt);
    let release; const gate = new Promise((resolve) => { release = resolve; });
    const running = f.store.run(board.id, "a", "codex", async () => { await gate; return { summary: "done" }; });
    await new Promise((resolve) => setTimeout(resolve, 10));
    await assert.rejects(f.store.pause(board.id, "unsafe"), /WORKBOARD_BUSY.*a/);
    await assert.rejects(f.store.cancel(board.id, "unsafe"), /WORKBOARD_BUSY.*a/);
    release(); await running;
    await f.store.review(board.id, "a", "claude", "accepted", "independently checked");
    const completed = await f.store.complete(board.id, "All acceptance criteria met"); assert.equal(completed.status, "completed"); assert.ok(completed.lifecycle.completedAt);
    await assert.rejects(f.store.resume(board.id), /INVALID_TRANSITION/);
    const archived = await f.store.archive(board.id, "Retained for history"); assert.equal(archived.status, "archived"); assert.ok(archived.lifecycle.archivedAt);
    assert.equal(f.store.list().some((candidate) => candidate.id === board.id && candidate.status === "archived"), true);
  } finally { await cleanup(f); }
});

test("item and board cancellation preserve history and enforce completion rules", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "Cancel", objective: "Bounded stop", cwd: process.cwd(), items: [item("keep"), item("drop")] });
    await f.store.run(board.id, "keep", "codex", async () => ({ summary: "kept" }));
    await f.store.review(board.id, "keep", "claude", "accepted", "verified");
    const itemCanceled = await f.store.cancelItem(board.id, "drop", "No longer in creator scope");
    assert.equal(itemCanceled.items.find((candidate) => candidate.key === "drop").status, "canceled");
    assert.match(itemCanceled.items.find((candidate) => candidate.key === "drop").cancellation.reason, /creator scope/);
    await assert.rejects(f.store.cancelItem(board.id, "drop", "again"), /INVALID_TRANSITION/);
    const completed = await f.store.complete(board.id); assert.equal(completed.status, "completed");

    const second = f.store.create({ title: "Cancel board", objective: "Stop", cwd: process.cwd(), items: [item("a"), item("b")] });
    const canceled = await f.store.cancel(second.id, "Creator canceled the board");
    assert.equal(canceled.status, "canceled"); assert.ok(canceled.items.every((candidate) => candidate.status === "canceled"));
    await assert.rejects(f.store.complete(second.id), /INVALID_TRANSITION/);
    assert.equal((await f.store.archive(second.id)).status, "archived");
  } finally { await cleanup(f); }
});

test("explicit retry resets outcomes but never attempts, usage, or review budgets", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "Retry", objective: "Bounded", cwd: process.cwd(), items: [item("a", { budget: { maxAttempts: 2 } })] });
    const first = await f.store.run(board.id, "a", "codex", async () => { throw new Error("first failure"); });
    const firstSpent = structuredClone(first.items[0].spent);
    const reset = await f.store.retry(board.id, "a");
    assert.equal(reset.items[0].status, "ready"); assert.equal(reset.items[0].attempts, 1); assert.deepEqual(reset.items[0].spent, firstSpent); assert.equal(reset.items[0].failure, undefined);
    const second = await f.store.run(board.id, "a", "codex", async () => { throw new Error("second failure"); });
    assert.equal(second.items[0].attempts, 2);
    await assert.rejects(f.store.retry(board.id, "a"), /BUDGET_EXHAUSTED/);

    const rejectedBoard = f.store.create({ title: "Review budget", objective: "Bounded", cwd: process.cwd(), items: [item("b", { budget: { maxAttempts: 1 } })] });
    await f.store.run(rejectedBoard.id, "b", "codex", async () => ({ summary: "candidate" }));
    await f.store.review(rejectedBoard.id, "b", "claude", "rejected", "not acceptable");
    await assert.rejects(f.store.retry(rejectedBoard.id, "b"), /BUDGET_EXHAUSTED/);
  } finally { await cleanup(f); }
});

test("schema v1 boards migrate to lifecycle schema v2 without rewriting an unlocked read", async () => {
  const f = await fixture(); try {
    const board = f.store.create({ title: "v1", objective: "migrate", cwd: process.cwd(), items: [item("a")] }); const path = f.store.path(board.id);
    const legacy = JSON.parse(await readFile(path, "utf8")); legacy.schemaVersion = 1; delete legacy.status; delete legacy.lifecycle;
    for (const candidate of legacy.items) for (const field of ["kind", "acceptanceCriteria", "requirements", "artifacts", "evidence", "approval", "cancellation"]) delete candidate[field];
    await writeFile(path, JSON.stringify(legacy, null, 2), "utf8");
    const migrated = f.store.get(board.id);
    assert.equal(migrated.schemaVersion, 2); assert.equal(migrated.status, "active"); assert.equal(migrated.items[0].kind, "other"); assert.deepEqual(migrated.items[0].artifacts, []);
    assert.equal(migrated.items[0].requirements.network, "restricted");
    assert.equal(JSON.parse(await readFile(path, "utf8")).schemaVersion, 1);
    f.store.save(migrated, migrated.revision); assert.equal(JSON.parse(await readFile(path, "utf8")).schemaVersion, 2);
  } finally { await cleanup(f); }
});

test("new lifecycle and reference fields fail closed when persisted inconsistently", async (t) => {
  await t.test("completed state without completion history", async () => {
    const f = await fixture(); try { const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a")] }); const path = f.store.path(board.id); const invalid = JSON.parse(await readFile(path, "utf8")); invalid.status = "completed"; await writeFile(path, JSON.stringify(invalid), "utf8"); assert.throws(() => f.store.get(board.id), /WORKBOARD_CORRUPT.*completed/); } finally { await cleanup(f); }
  });
  await t.test("reference with executable payload or missing locator", async () => {
    const f = await fixture(); try { const board = f.store.create({ title: "x", objective: "x", cwd: process.cwd(), items: [item("a")] }); const path = f.store.path(board.id); const invalid = JSON.parse(await readFile(path, "utf8")); invalid.items[0].artifacts.push({ id: "bad", kind: "source", dataClass: "internal", accessibility: "local", contents: "secret" }); await writeFile(path, JSON.stringify(invalid), "utf8"); assert.throws(() => f.store.get(board.id), /WORKBOARD_CORRUPT.*unknown field/); } finally { await cleanup(f); }
  });
});
