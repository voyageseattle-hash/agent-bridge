import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const outputDir = await mkdtemp(join(tmpdir(), "agent-bridge-manus-confirmation-"));
const outputFile = join(outputDir, "fixture.mjs");
await build({
  stdin: {
    contents: [
      'export { Bridge } from "./src/bridge.ts";',
      'export { ManusAdapter } from "./src/adapters/manus.ts";',
      'export { SessionStore } from "./src/sessions.ts";',
      'export { ApprovalStore } from "./src/approvals.ts";',
      'export { RemoteCostBudgetStore } from "./src/budgets.ts";',
      'export { canonicalDirectory } from "./src/config.ts";',
      'export { renderTurn } from "./src/render.ts";',
    ].join("\n"),
    resolveDir: process.cwd(),
    sourcefile: "manus-confirmation-fixture.ts",
  },
  outfile: outputFile,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
});
const { Bridge, ManusAdapter, SessionStore, ApprovalStore, RemoteCostBudgetStore, canonicalDirectory, renderTurn } = await import(pathToFileURL(outputFile).href);
test.after(async () => { await rm(outputDir, { recursive: true, force: true }); });

function acknowledgedManus(options = {}) {
  return new ManusAdapter({ acknowledgeAccountDefaultCapabilities: true, accountCapabilityProfile: "test-reviewed-profile", ...options });
}

const TASK_EMAIL = "L".repeat(22);
const TASK_AMBIGUOUS = "M".repeat(22);
const TASK_BROWSER = "N".repeat(22);
const TASK_VIDEO = "O".repeat(22);
const TASK_CREDIT = "P".repeat(22);
const TASK_FORGED = "Q".repeat(22);

function config(root, state, budget) {
  return {
    agents: { manus: {} },
    defaults: { cwd: root, sandbox: "read-only", timeoutSec: 2 },
    allowedRoots: [root],
    policy: {
      sandboxCeiling: "workspace-write",
      remoteEgress: { enabled: true, allowedAgents: ["manus"], allowedRoots: [root], allowedDataClasses: ["internal"] },
      ...(budget ? { cumulativeRemoteCost: budget } : {}),
    },
    handoffMaxChars: 10_000,
    stateDir: state,
    sessionLockWaitMs: 0,
    sessionLockStaleMs: 60_000,
  };
}

function seedWaiting(store, root, action) {
  const session = store.create({ title: "waiting Manus task", cwd: root });
  store.record(session, "manus", "initial task", {
    text: "Manus task is waiting for input.",
    nativeSessionId: action.taskId,
    exitCode: null,
    isError: true,
    stderr: "",
    timedOut: false,
    durationMs: 1,
    meta: { taskStatus: "waiting", resumable: true, waitingAction: action },
  }, new Date().toISOString(), session.revision);
  return store.get(session.id);
}

function provider(options = {}) {
  const calls = [];
  const confirmed = new Set();
  const actions = new Map();
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, ...options, fetch: async (url, init) => {
    const target = new URL(String(url));
    calls.push({ url: target.href, init });
    if (target.pathname.endsWith("task.confirmAction")) {
      const body = JSON.parse(init.body);
      confirmed.add(body.task_id);
      return response({ ok: true, task_id: body.task_id, confirmed: true });
    }
    const taskId = target.searchParams.get("task_id");
    const action = actions.get(taskId);
    if (confirmed.has(taskId)) {
      return response({ ok: true, messages: [
        { type: "status_update", status_update: { agent_status: "stopped" } },
        { type: "assistant_message", content: `completed ${action.eventType}` },
      ] });
    }
    return response({ ok: true, messages: [{ type: "status_update", status_update: {
      agent_status: "waiting",
      status_detail: { waiting_for_event_id: action.eventId, waiting_for_event_type: action.eventType },
    } }] });
  } });
  return { adapter, calls, actions };
}

function response(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

async function approve(store, category, scope, cost) {
  const record = store.create({
    category,
    scope,
    requestedBy: "test",
    reason: `authorize ${category}`,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    ...(cost ?? {}),
  });
  await store.approve(record.id, { approvedBy: "test-user", reason: "exact test approval" });
  return store.get(record.id);
}

test("Manus preview is side-effect-free and exact email-draft confirmation is durably recorded", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-manus-email-"));
  try {
    const root = canonicalDirectory(process.cwd());
    const store = new SessionStore(state, 0);
    const approvals = new ApprovalStore(state);
    const remote = provider();
    const action = { taskId: TASK_EMAIL, eventId: "evt_email", eventType: "gmailSendAction" };
    remote.actions.set(action.taskId, action);
    const seeded = seedWaiting(store, root, action);
    const bridge = new Bridge(config(root, state), new Map([["manus", remote.adapter]]), store, approvals);

    const preview = await bridge.previewManusConfirmation({
      sessionId: seeded.id, eventId: action.eventId, input: { accept: true, save_draft: true },
      allowRemoteEgress: true, dataClassification: "internal",
    });
    assert.equal(remote.calls.length, 0);
    assert.equal(store.get(seeded.id).revision, seeded.revision);
    assert.deepEqual(preview.action, { eventId: action.eventId, eventType: action.eventType });
    assert.deepEqual(preview.requiredCategories, ["remote_egress", "browser_or_connectors"]);
    assert.deepEqual(preview.executionEnvelope, {
      schemaVersion: 2,
      eventId: action.eventId,
      eventType: action.eventType,
      input: { accept: true, save_draft: true },
      providerCapabilityPolicy: "manus-v2-empty-connectors-default-skills-v1",
      providerEndpoint: "https://api.manus.ai",
      providerAccountProfile: "test-reviewed-profile",
    });
    assert.doesNotMatch(JSON.stringify(preview), new RegExp(TASK_EMAIL));
    const changedProvider = provider({ accountCapabilityProfile: "changed-reviewed-profile" });
    changedProvider.actions.set(action.taskId, action);
    const changedPreview = await new Bridge(config(root, state), new Map([["manus", changedProvider.adapter]]), store, approvals).previewManusConfirmation({
      sessionId: seeded.id, eventId: action.eventId, input: { accept: true, save_draft: true },
      allowRemoteEgress: true, dataClassification: "internal",
    });
    assert.notEqual(changedPreview.payloadSha256, preview.payloadSha256);

    const egress = await approve(approvals, "remote_egress", preview.scope);
    const browser = await approve(approvals, "browser_or_connectors", preview.scope);
    const outcome = await bridge.confirmManusAction({
      sessionId: seeded.id, eventId: action.eventId, input: { accept: true, save_draft: true },
      allowRemoteEgress: true, dataClassification: "internal", approval_ids: [browser.id, egress.id],
      expectedSessionRevision: preview.sessionRevision,
    });
    assert.equal(outcome.result.text, "completed gmailSendAction");
    assert.equal(remote.calls.filter((call) => call.url.endsWith("task.confirmAction")).length, 1);
    assert.equal(approvals.get(egress.id).state, "consumed");
    assert.equal(approvals.get(browser.id).state, "consumed");
    const persisted = store.get(seeded.id);
    assert.equal(persisted.revision, seeded.revision + 3);
    assert.equal(persisted.turns.at(-3).meta.taskStatus, "confirmation_attempted");
    assert.equal(persisted.turns.at(-2).meta.taskStatus, "confirmation_accepted");
    assert.equal(persisted.turns.at(-1).response, "completed gmailSendAction");
    assert.throws(() => bridge.getManusWaitingAction(seeded.id), /MANUS_WAITING_ACTION_MISSING/);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("lost Manus confirmation response leaves a durable non-replayable attempt", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-manus-lost-response-"));
  try {
    const root = canonicalDirectory(process.cwd());
    const store = new SessionStore(state, 0);
    const approvals = new ApprovalStore(state);
    const action = { taskId: TASK_AMBIGUOUS, eventId: "evt_ambiguous", eventType: "gmailSendAction" };
    let posts = 0;
    const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url) => {
      if (String(url).includes("task.confirmAction")) {
        posts++;
        throw new TypeError("simulated connection reset after provider acceptance");
      }
      return response({ ok: true, messages: [{ type: "status_update", status_update: {
        agent_status: "waiting", status_detail: { waiting_for_event_id: action.eventId, waiting_for_event_type: action.eventType },
      } }] });
    } });
    const seeded = seedWaiting(store, root, action);
    const bridge = new Bridge(config(root, state), new Map([["manus", adapter]]), store, approvals);
    const base = { sessionId: seeded.id, eventId: action.eventId, input: { accept: true, save_draft: true }, allowRemoteEgress: true, dataClassification: "internal" };
    const preview = await bridge.previewManusConfirmation(base);
    const egress = await approve(approvals, "remote_egress", preview.scope);
    const browser = await approve(approvals, "browser_or_connectors", preview.scope);
    const options = { ...base, approval_ids: [egress.id, browser.id], expectedSessionRevision: preview.sessionRevision };
    await assert.rejects(bridge.confirmManusAction(options), /Manus confirmation request failed/);
    assert.equal(posts, 1);
    assert.equal(approvals.get(egress.id).state, "consumed");
    assert.equal(approvals.get(browser.id).state, "consumed");
    const persisted = store.get(seeded.id);
    assert.equal(persisted.turns.at(-1).meta.taskStatus, "confirmation_attempted");
    assert.throws(() => bridge.getManusWaitingAction(seeded.id), /MANUS_WAITING_ACTION_MISSING/);

    const freshEgress = await approve(approvals, "remote_egress", preview.scope);
    const freshBrowser = await approve(approvals, "browser_or_connectors", preview.scope);
    await assert.rejects(bridge.confirmManusAction({
      ...options, approval_ids: [freshEgress.id, freshBrowser.id], expectedSessionRevision: persisted.revision,
    }), /MANUS_WAITING_ACTION_MISSING/);
    assert.equal(posts, 1, "an ambiguous confirmation must never be replayed");
    assert.equal(approvals.get(freshEgress.id).state, "approved");
    assert.equal(approvals.get(freshBrowser.id).state, "approved");
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Manus confirmation preflight failures preserve approvals and avoid provider calls", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-manus-preflight-"));
  try {
    const root = canonicalDirectory(process.cwd());
    const store = new SessionStore(state, 0);
    const approvals = new ApprovalStore(state);
    const remote = provider();
    const action = { taskId: TASK_BROWSER, eventId: "evt_browser", eventType: "needConnectMyBrowser" };
    remote.actions.set(action.taskId, action);
    const seeded = seedWaiting(store, root, action);
    const bridge = new Bridge(config(root, state), new Map([["manus", remote.adapter]]), store, approvals);
    const base = { sessionId: seeded.id, eventId: action.eventId, input: { action: "skip" }, allowRemoteEgress: true, dataClassification: "internal" };
    const preview = await bridge.previewManusConfirmation(base);
    const egress = await approve(approvals, "remote_egress", preview.scope);
    const browser = await approve(approvals, "browser_or_connectors", preview.scope);
    const execute = { ...base, approval_ids: [egress.id, browser.id], expectedSessionRevision: preview.sessionRevision };

    await assert.rejects(bridge.confirmManusAction({ ...execute, expectedSessionRevision: undefined }), /SESSION_REVISION_REQUIRED/);
    await assert.rejects(bridge.confirmManusAction({ ...execute, eventId: "evt_other" }), /MANUS_WAITING_ACTION_STALE/);
    await assert.rejects(bridge.confirmManusAction({ ...execute, estimatedCost: 0, estimatedCurrency: "USD" }), /APPROVAL_COST_NOT_APPLICABLE/);
    await assert.rejects(bridge.confirmManusAction({ ...execute, timeoutSec: 7201 }), /TIMEOUT_INVALID/);
    assert.equal(remote.calls.length, 0);
    assert.equal(approvals.get(egress.id).state, "approved");
    assert.equal(approvals.get(browser.id).state, "approved");

    const wrongBridge = new Bridge(config(root, state), new Map([["manus", { id: "manus", displayName: "wrong", capabilities: {} }]]), store, approvals);
    await assert.rejects(wrongBridge.confirmManusAction(execute), /MANUS_ADAPTER_REQUIRED/);
    assert.equal(approvals.get(egress.id).state, "approved");

    remote.actions.set(action.taskId, { ...action, eventId: "evt_live_changed" });
    await assert.rejects(bridge.confirmManusAction(execute), /waiting action changed/i);
    assert.equal(remote.calls.filter((call) => call.url.includes("task.listMessages")).length, 1);
    assert.equal(remote.calls.some((call) => call.url.endsWith("task.confirmAction")), false);
    assert.equal(approvals.get(egress.id).state, "approved");
    assert.equal(approvals.get(browser.id).state, "approved");
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Manus video confirmation reserves approved maximum and session locking prevents duplicate confirmation", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-manus-video-"));
  try {
    const root = canonicalDirectory(process.cwd());
    const store = new SessionStore(state, 100);
    const approvals = new ApprovalStore(state);
    const budgetPolicy = { currency: "USD", maxReservedCents: 100 };
    const budget = new RemoteCostBudgetStore(state, budgetPolicy);
    const remote = provider();
    const action = { taskId: TASK_VIDEO, eventId: "evt_video", eventType: "videoGenerate" };
    remote.actions.set(action.taskId, action);
    const seeded = seedWaiting(store, root, action);
    const bridge = new Bridge(config(root, state, budgetPolicy), new Map([["manus", remote.adapter]]), store, approvals, budget);
    const base = { sessionId: seeded.id, eventId: action.eventId, input: { choice: "standard" }, allowRemoteEgress: true, dataClassification: "internal" };
    const preview = await bridge.previewManusConfirmation(base);
    const egress = await approve(approvals, "remote_egress", preview.scope);
    const paid = await approve(approvals, "paid_or_unknown_cost", preview.scope, { estimatedCost: 0.60, currency: "USD" });
    const options = { ...base, approval_ids: [egress.id, paid.id], expectedSessionRevision: preview.sessionRevision, estimatedCost: 0.50, estimatedCurrency: "USD" };
    const settled = await Promise.allSettled([bridge.confirmManusAction(options), bridge.confirmManusAction(options)]);
    assert.equal(settled.filter((item) => item.status === "fulfilled").length, 1);
    assert.match(settled.find((item) => item.status === "rejected").reason.message, /SESSION_REVISION_MISMATCH/);
    assert.equal(remote.calls.filter((call) => call.url.endsWith("task.confirmAction")).length, 1);
    assert.equal(budget.status().committedCents, 60);
    assert.equal(budget.status().reservationCount, 1);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Manus high-credit rejection requires exact zero USD approval and does not reserve budget", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-manus-credit-"));
  try {
    const root = canonicalDirectory(process.cwd());
    const store = new SessionStore(state, 0);
    const approvals = new ApprovalStore(state);
    const budgetPolicy = { currency: "USD", maxReservedCents: 100 };
    const budget = new RemoteCostBudgetStore(state, budgetPolicy);
    const remote = provider();
    const action = { taskId: TASK_CREDIT, eventId: "evt_credit", eventType: "apiHighCreditNotice" };
    remote.actions.set(action.taskId, action);
    const seeded = seedWaiting(store, root, action);
    const bridge = new Bridge(config(root, state, budgetPolicy), new Map([["manus", remote.adapter]]), store, approvals, budget);
    const base = { sessionId: seeded.id, eventId: action.eventId, input: { action: "reject" }, allowRemoteEgress: true, dataClassification: "internal" };
    const preview = await bridge.previewManusConfirmation(base);
    const egress = await approve(approvals, "remote_egress", preview.scope);
    const paid = await approve(approvals, "paid_or_unknown_cost", preview.scope, { estimatedCost: 0, currency: "USD" });
    const execute = { ...base, approval_ids: [egress.id, paid.id], expectedSessionRevision: preview.sessionRevision };
    await assert.rejects(bridge.confirmManusAction({ ...execute, estimatedCost: 1, estimatedCurrency: "USD" }), /APPROVAL_COST_MISMATCH/);
    assert.equal(remote.calls.length, 0);
    await bridge.confirmManusAction({ ...execute, estimatedCost: 0, estimatedCurrency: "USD" });
    assert.equal(budget.status().committedCents, 0);
    assert.equal(budget.status().reservationCount, 0);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("forged waiting metadata fails closed and rendered Manus metadata omits native task ids", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-manus-forged-"));
  try {
    const root = canonicalDirectory(process.cwd());
    const store = new SessionStore(state, 0);
    const forged = seedWaiting(store, root, {
      taskId: TASK_FORGED, eventId: "evt_forged", eventType: "gmailSendAction",
      description: "password=hunter2 bearer secret.example/path",
    });
    const bridge = new Bridge(config(root, state), new Map(), store);
    assert.throws(() => bridge.getManusWaitingAction(forged.id), /MANUS_WAITING_ACTION_INVALID/);

    const rendered = renderTurn({
      session: store.get(forged.id),
      result: { text: "waiting", exitCode: null, isError: true, stderr: "", timedOut: false, durationMs: 1, meta: {
        taskStatus: "waiting",
        providerRequestId: "req_private_create",
        providerRequestSha256: "a".repeat(64),
        providerErrorRequestId: "req_private_poll",
        providerErrorRequestSha256: "b".repeat(64),
        waitingAction: { taskId: "native_secret_task", eventId: "evt_safe", eventType: "gmailSendAction" },
      } },
      continuity: "native-resume",
      contextDeltaApplied: false,
      agent: { id: "manus", displayName: "Manus", capabilities: {} },
    });
    assert.doesNotMatch(JSON.stringify(rendered), /native_secret_task|taskId|req_private_create|req_private_poll/);
    assert.deepEqual(rendered.structuredContent.meta.waitingAction, { eventId: "evt_safe", eventType: "gmailSendAction" });
    assert.equal(rendered.structuredContent.meta.providerRequestSha256, "a".repeat(64));
    assert.equal(rendered.structuredContent.meta.providerErrorRequestSha256, "b".repeat(64));
  } finally { await rm(state, { recursive: true, force: true }); }
});
