import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { promisify } from "node:util";
import { build } from "esbuild";

const outputDir = await mkdtemp(join(tmpdir(), "agent-bridge-budget-build-"));
const outfile = join(outputDir, "budgets.mjs");
await build({ entryPoints: ["src/budgets.ts"], outfile, bundle: true, platform: "node", format: "esm", target: "node20" });
const { approvedCostToCents, RemoteCostBudgetStore } = await import(`${pathToFileURL(outfile).href}?${Date.now()}`);
const execFileAsync = promisify(execFile);
test.after(async () => { await rm(outputDir, { recursive: true, force: true }); });

test("approved remote maximum cost normalizes to positive whole USD cents", () => {
  assert.equal(approvedCostToCents(0.29, "USD"), 29);
  assert.equal(approvedCostToCents(1000, "USD"), 100_000);
  assert.equal(approvedCostToCents(282_337_563.72, "USD"), 28_233_756_372);
  assert.throws(() => approvedCostToCents(null, "USD"), /BOUNDED_COST_REQUIRED/);
  assert.throws(() => approvedCostToCents(0, "USD"), /BOUNDED_COST_REQUIRED/);
  assert.throws(() => approvedCostToCents(1, "EUR"), /CURRENCY_REQUIRED/);
  assert.throws(() => approvedCostToCents(0.001, "USD"), /WHOLE_CENTS_REQUIRED/);
});

test("cumulative remote-cost reservations persist and never replenish", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-budget-"));
  try {
    const policy = { currency: "USD", maxReservedCents: 500 };
    const store = new RemoteCostBudgetStore(state, policy, 30_000, 60_000);
    assert.deepEqual(store.status(), { enabled: true, currency: "USD", maxReservedCents: 500, committedCents: 0, remainingCents: 500, reservationCount: 0 });
    await store.reserve({ approvalId: "approval-1", agentId: "manus", sessionId: "session-1", turnIndex: 0, cents: 200 });
    const restarted = new RemoteCostBudgetStore(state, policy, 30_000, 60_000);
    assert.equal(restarted.status().committedCents, 200);
    await restarted.reserve({ approvalId: "approval-2", agentId: "manus", sessionId: "session-2", turnIndex: 0, cents: 300 });
    await assert.rejects(
      restarted.reserve({ approvalId: "approval-3", agentId: "manus", sessionId: "session-3", turnIndex: 0, cents: 1 }),
      /CUMULATIVE_BUDGET_EXHAUSTED/,
    );
    assert.equal(restarted.status().committedCents, 500);
    await assert.rejects(
      restarted.reserve({ approvalId: "approval-2", agentId: "manus", sessionId: "session-2", turnIndex: 1, cents: 1 }),
      /APPROVAL_ALREADY_RESERVED/,
    );
    assert.equal(restarted.status().reservationCount, 2);
    await rm(restarted.path);
    assert.throws(() => restarted.status(), /CUMULATIVE_BUDGET_LEDGER_MISSING/);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("separate processes fail closed behind an abandoned budget lock", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-budget-stale-lock-"));
  try {
    const lock = join(state, "budget-locks", "cumulative-remote-cost.lock");
    await mkdir(lock, { recursive: true });
    await writeFile(join(lock, "owner.json"), JSON.stringify({ token: "stale-owner", pid: 999999, acquiredAt: new Date(0).toISOString() }), "utf8");
    const moduleUrl = pathToFileURL(outfile).href;
    const child = `
      import { RemoteCostBudgetStore } from ${JSON.stringify(moduleUrl)};
      const store = new RemoteCostBudgetStore(${JSON.stringify(state)}, { currency: "USD", maxReservedCents: 100 }, 0, 1_000);
      await store.reserve({ approvalId: "approval-" + process.pid, agentId: "manus", sessionId: "session-" + process.pid, turnIndex: 0, cents: 60 });
    `;
    const results = await Promise.allSettled([
      execFileAsync(process.execPath, ["--input-type=module", "--eval", child]),
      execFileAsync(process.execPath, ["--input-type=module", "--eval", child]),
    ]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 0);
    const failures = results.filter((result) => result.status === "rejected");
    assert.equal(failures.length, 2);
    for (const failure of failures) assert.match(String(failure.reason?.stderr ?? failure.reason), /CUMULATIVE_BUDGET_BUSY/);
    const store = new RemoteCostBudgetStore(state, { currency: "USD", maxReservedCents: 100 });
    assert.equal(store.status().committedCents, 0);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("a dedicated ledger lock prevents concurrent sessions oversubscribing the cap", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-budget-concurrency-"));
  try {
    const policy = { currency: "USD", maxReservedCents: 100 };
    const left = new RemoteCostBudgetStore(state, policy, 30_000, 60_000);
    const right = new RemoteCostBudgetStore(state, policy, 30_000, 60_000);
    const results = await Promise.allSettled([
      left.reserve({ approvalId: "approval-left", agentId: "manus", sessionId: "session-left", turnIndex: 0, cents: 60 }),
      right.reserve({ approvalId: "approval-right", agentId: "manus", sessionId: "session-right", turnIndex: 0, cents: 60 }),
    ]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(results.filter((result) => result.status === "rejected" && /CUMULATIVE_BUDGET_EXHAUSTED/.test(String(result.reason))).length, 1);
    assert.equal(left.status().committedCents, 60);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("malformed and future budget ledgers fail closed", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-budget-corrupt-"));
  try {
    const dir = join(state, "budgets");
    await mkdir(dir, { recursive: true });
    const path = join(dir, "cumulative-remote-cost.json");
    await writeFile(path, "{bad json", "utf8");
    const store = new RemoteCostBudgetStore(state, { currency: "USD", maxReservedCents: 100 });
    assert.throws(() => store.status(), /CUMULATIVE_BUDGET_CORRUPT.*invalid JSON/);
    await writeFile(path, JSON.stringify({ schemaVersion: 2 }), "utf8");
    assert.throws(() => store.status(), /CUMULATIVE_BUDGET_UNSUPPORTED_VERSION/);
    await writeFile(path, JSON.stringify({ schemaVersion: 1, currency: "USD", committedCents: 1, reservationCount: 0, recentReservations: [], extra: true }), "utf8");
    assert.throws(() => store.status(), /CUMULATIVE_BUDGET_CORRUPT.*unknown field/);
  } finally { await rm(state, { recursive: true, force: true }); }
});
