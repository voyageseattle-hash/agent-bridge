import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const outputDir = await mkdtemp(join(tmpdir(), "agent-bridge-core-"));
async function load(name, entry) {
  const outfile = join(outputDir, `${name}.mjs`);
  await build({ entryPoints: [entry], outfile, bundle: true, platform: "node", format: "esm", target: "node20" });
  return import(`${pathToFileURL(outfile).href}?${Date.now()}`);
}
const [{ CodexAdapter }, { ClaudeAdapter }, config, sessions, { Bridge, deriveRemoteTurnApprovalScope, payloadSha256 }, env, { ManusAdapter }, { buildRegistry }, { ApprovalStore }, { RemoteCostBudgetStore }] = await Promise.all([
  load("codex", "src/adapters/codex.ts"), load("claude", "src/adapters/claude.ts"),
  load("config", "src/config.ts"), load("sessions", "src/sessions.ts"),
  load("bridge", "src/bridge.ts"), load("env", "src/env.ts"), load("manus", "src/adapters/manus.ts"), load("registry", "src/adapters/index.ts"),
  load("approvals", "src/approvals.ts"), load("budgets", "src/budgets.ts"),
]);
test.after(async () => { await rm(outputDir, { recursive: true, force: true }); });

const request = { prompt: "implement it", cwd: process.cwd(), sandbox: "workspace-write", timeoutMs: 1_000 };

test("Codex fresh and resume commands use their distinct exact grammars", () => {
  const adapter = new CodexAdapter("codex-test");
  assert.deepEqual(adapter.buildSpawn({ ...request, model: "gpt-test" }).args, [
    "exec", "--json", "--skip-git-repo-check", "--ignore-user-config", "--cd", request.cwd,
    "--sandbox", "workspace-write", "--model", "gpt-test", "-",
  ]);
  const resume = adapter.buildSpawn({ ...request, resumeSessionId: "thread-42", model: "gpt-test" }).args;
  assert.deepEqual(resume, ["exec", "resume", "thread-42", "--json", "--skip-git-repo-check", "--ignore-user-config", "--model", "gpt-test", "-"]);
  assert.ok(!resume.includes("--cd") && !resume.includes("--sandbox"));
});

test("Claude uses noninteractive strict empty MCP configuration without --bare", () => {
  const args = new ClaudeAdapter("claude-test").buildSpawn({ ...request, model: "opus", resumeSessionId: "native-1" }).args;
  assert.deepEqual(args, [
    "-p", "implement it", "--output-format", "json", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
    "--model", "opus", "--resume", "native-1", "--add-dir", request.cwd, "--permission-mode", "acceptEdits",
  ]);
  assert.ok(!args.includes("--bare"));
});

test("config loading fails closed for absent or malformed configuration", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-config-"));
  try {
    assert.throws(() => config.loadConfig(join(root, "missing.json")), /config not found.*refusing unrestricted fallback/i);
    const malformed = join(root, "malformed.json");
    await writeFile(malformed, "{not json", "utf8");
    assert.throws(() => config.loadConfig(malformed), /invalid agent-bridge config/i);
    const unsafe = join(root, "unsafe.json");
    await writeFile(unsafe, JSON.stringify({ allowedRoots: [] }), "utf8");
    assert.throws(() => config.loadConfig(unsafe), /allowedRoots.*at least 1/i);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("configured Manus acknowledgement requires and propagates a stable account capability profile", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-manus-config-"));
  try {
    const key = join(root, "manus-key");
    await writeFile(key, "test-key\n", "utf8");
    const invalid = join(root, "invalid.json");
    await writeFile(invalid, JSON.stringify({ allowedRoots: [root], agents: { manus: { enabled: true, credentialFile: key, acknowledgeAccountDefaultCapabilities: true } } }), "utf8");
    assert.throws(() => config.loadConfig(invalid), /accountCapabilityProfile is required/);
    const valid = join(root, "valid.json");
    await writeFile(valid, JSON.stringify({ allowedRoots: [root], agents: { manus: { enabled: true, credentialFile: key, acknowledgeAccountDefaultCapabilities: true, accountCapabilityProfile: "reviewed-2026-08-19" } } }), "utf8");
    const loaded = config.loadConfig(valid);
    const adapter = buildRegistry(loaded).get("manus");
    assert.equal(adapter.hasAcknowledgedAccountDefaultCapabilities(), true);
    assert.doesNotThrow(() => adapter.assertRequestSupported({ prompt: "safe", model: "manus-1.6" }));
    assert.equal(adapter.approvalCapabilityIdentity().accountProfile, "reviewed-2026-08-19");
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("allowed roots use canonical paths and reject a junction/symlink escape", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-root-"));
  const outside = await mkdtemp(join(tmpdir(), "agent-bridge-outside-"));
  const escape = join(root, "escape");
  try {
    try { await symlink(outside, escape, process.platform === "win32" ? "junction" : "dir"); }
    catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) return t.skip(`symlink creation unavailable: ${error.code}`);
      throw error;
    }
    const canonicalRoot = config.canonicalDirectory(root, "allowed root");
    assert.throws(() => config.assertAllowedCwd(escape, { allowedRoots: [canonicalRoot] }), /outside the allowed roots/i);
  } finally { await rm(root, { recursive: true, force: true }); await rm(outside, { recursive: true, force: true }); }
});

test("sanitized child environment excludes arbitrary inherited secrets", () => {
  const previous = process.env.BRIDGE_TEST_ARBITRARY_SECRET;
  process.env.BRIDGE_TEST_ARBITRARY_SECRET = "do-not-forward";
  try {
    const actual = env.sanitizedEnvironment("codex", { BRIDGE_EXPLICIT: "ok" });
    assert.equal(actual.BRIDGE_TEST_ARBITRARY_SECRET, undefined);
    assert.equal(actual.BRIDGE_EXPLICIT, "ok");
  } finally {
    if (previous === undefined) delete process.env.BRIDGE_TEST_ARBITRARY_SECRET;
    else process.env.BRIDGE_TEST_ARBITRARY_SECRET = previous;
  }
});

test("SessionStore rejects overlapping work on the same session and detects CAS conflicts", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-state-"));
  try {
    const store = new sessions.SessionStore(state, 0);
    const session = store.create({ title: "lock", cwd: process.cwd() });
    let release;
    const held = store.withLock(session.id, () => new Promise((resolve) => { release = resolve; }));
    await new Promise((resolve) => setTimeout(resolve, 10));
    await assert.rejects(store.withLock(session.id, async () => undefined), /SESSION_BUSY/);
    release(); await held;
    const first = store.get(session.id);
    const stale = store.get(session.id);
    store.save(first, first.revision);
    assert.throws(() => store.save(stale, stale.revision), /SESSION_CONFLICT/);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge sends only unseen cross-agent delta when returning A after B", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-bridge-"));
  try {
    const seen = [];
    function mock(id) {
      return { id, displayName: id, capabilities: { resume: true, model: true, sandbox: true, structuredOutput: true }, execute: async (req) => {
        seen.push({ id, ...req });
        return { text: `${id} result`, nativeSessionId: `${id}-native`, exitCode: 0, isError: false, stderr: "", timedOut: false };
      } };
    }
    const cfg = { agents: { a: {}, b: {} }, defaults: { cwd: process.cwd(), sandbox: "read-only", timeoutSec: 1 }, allowedRoots: [config.canonicalDirectory(process.cwd())], handoffMaxChars: 10_000, stateDir: state, sessionLockWaitMs: 0, sessionLockStaleMs: 60_000 };
    const bridge = new Bridge(cfg, new Map([["a", mock("a")], ["b", mock("b")]]), new sessions.SessionStore(state, 0));
    const one = await bridge.runTurn({ agentId: "a", prompt: "initial task" });
    const two = await bridge.runTurn({ agentId: "b", sessionId: one.session.id, prompt: "b task" });
    const three = await bridge.runTurn({ agentId: "a", sessionId: one.session.id, prompt: "a again" });
    assert.equal(two.continuity, "context-replay");
    assert.equal(three.continuity, "native-resume");
    assert.equal(three.contextDeltaApplied, true);
    assert.equal(seen[2].resumeSessionId, "a-native");
    assert.match(seen[2].prompt, /b result/);
    assert.doesNotMatch(seen[2].prompt, /initial task/);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge suppresses configured args and environment for strict cooperative turns", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-strict-"));
  try {
    let seen;
    const adapter = { id: "a", displayName: "a", capabilities: { resume: false, model: true, sandbox: true, structuredOutput: true }, execute: async (req) => {
      seen = req;
      return { text: "ok", exitCode: 0, isError: false, stderr: "", timedOut: false };
    } };
    const cfg = { agents: { a: { extraArgs: ["--sandbox", "danger-full-access"], extraEnv: { DANGEROUS_OVERRIDE: "yes" } } }, defaults: { cwd: process.cwd(), sandbox: "read-only", timeoutSec: 1 }, allowedRoots: [config.canonicalDirectory(process.cwd())], handoffMaxChars: 10_000, stateDir: state, sessionLockWaitMs: 0, sessionLockStaleMs: 60_000 };
    const bridge = new Bridge(cfg, new Map([["a", adapter]]), new sessions.SessionStore(state, 0));
    await bridge.runTurn({ agentId: "a", prompt: "strict", sandbox: "read-only", allowAgentConfigExtensions: false });
    assert.equal(seen.sandbox, "read-only");
    assert.equal(seen.extraArgs, undefined);
    assert.equal(seen.extraEnv, undefined);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge enforces configured sandbox authority before launching an adapter", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-ceiling-"));
  try {
    let launched = false;
    const adapter = { id: "a", displayName: "a", capabilities: { resume: false, model: true, sandbox: true, structuredOutput: true }, execute: async () => {
      launched = true;
      return { text: "unexpected", exitCode: 0, isError: false, stderr: "", timedOut: false };
    } };
    const root = config.canonicalDirectory(process.cwd());
    const cfg = { agents: { a: {} }, defaults: { cwd: root, sandbox: "read-only", timeoutSec: 1 }, allowedRoots: [root], policy: { sandboxCeiling: "read-only", remoteEgress: { enabled: false, allowedAgents: [], allowedRoots: [], allowedDataClasses: [] } }, handoffMaxChars: 10_000, stateDir: state, sessionLockWaitMs: 0, sessionLockStaleMs: 60_000 };
    const bridge = new Bridge(cfg, new Map([["a", adapter]]), new sessions.SessionStore(state, 0));
    await assert.rejects(bridge.runTurn({ agentId: "a", prompt: "escalate", sandbox: "workspace-write" }), /SANDBOX_AUTHORITY_DENIED/i);
    assert.equal(launched, false);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge reports a throwing health probe without hiding healthy backends", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-health-"));
  try {
    const healthy = { id: "healthy", displayName: "healthy", capabilities: { resume: false, model: false, sandbox: false, structuredOutput: false }, health: async () => ({ binary: { ok: true, version: "1" }, auth: { status: "authenticated" }, usable: true }) };
    const broken = { id: "broken", displayName: "broken", capabilities: { resume: false, model: false, sandbox: false, structuredOutput: false }, health: async () => { throw new Error("secret provider exception"); } };
    const cfg = { agents: { healthy: {}, broken: {} }, defaults: { cwd: process.cwd(), sandbox: "read-only", timeoutSec: 1 }, allowedRoots: [config.canonicalDirectory(process.cwd())], handoffMaxChars: 10_000, stateDir: state, sessionLockWaitMs: 0, sessionLockStaleMs: 60_000 };
    const bridge = new Bridge(cfg, new Map([["healthy", healthy], ["broken", broken]]), new sessions.SessionStore(state, 0));
    const health = await bridge.listAgents();
    assert.equal(health.find((agent) => agent.id === "healthy").health.usable, true);
    const failure = health.find((agent) => agent.id === "broken").health;
    assert.equal(failure.usable, false);
    assert.equal(failure.binary.error, "health probe failed");
    assert.doesNotMatch(JSON.stringify(failure), /secret provider exception/);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge preflights cooperative backend read-only compatibility", () => {
  const registry = new Map([
    ["local-safe", { id: "local-safe", bin: "safe", displayName: "safe", capabilities: { resume: false, model: true, sandbox: true, structuredOutput: false } }],
    ["local-unsafe", { id: "local-unsafe", bin: "unsafe", displayName: "unsafe", capabilities: { resume: false, model: true, sandbox: false, structuredOutput: false } }],
    ["remote", { id: "remote", displayName: "remote", capabilities: { resume: false, model: true, sandbox: false, structuredOutput: false } }],
  ]);
  const bridge = new Bridge({ agents: {}, defaults: { sandbox: "read-only", timeoutSec: 1 }, allowedRoots: [], handoffMaxChars: 1000, stateDir: "unused", sessionLockWaitMs: 0, sessionLockStaleMs: 60000 }, registry, {});
  assert.equal(bridge.cooperativeAdapter("local-safe").id, "local-safe");
  assert.equal(bridge.cooperativeAdapter("remote").id, "remote");
  assert.throws(() => bridge.cooperativeAdapter("local-unsafe"), /INCOMPATIBLE.*read-only/i);
  assert.throws(() => bridge.cooperativeAdapter("missing"), /unknown agent/i);
});

test("Bridge persists a Manus task after a post-create API failure", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-manus-persist-"));
  try {
    const manusTaskId = "R".repeat(22);
    const adapter = new ManusAdapter({ apiKey: "test-key", acknowledgeAccountDefaultCapabilities: true, accountCapabilityProfile: "test-reviewed-profile", pollIntervalMs: 0, fetch: async (url) => {
      if (String(url).endsWith("task.create")) return new Response(JSON.stringify({ code: 0, data: { task_id: manusTaskId } }));
      return new Response(JSON.stringify({ code: 500, message: "untrusted provider detail" }), { status: 500 });
    } });
    const store = new sessions.SessionStore(state, 0);
    const root = config.canonicalDirectory(process.cwd());
    const cfg = { agents: { manus: {} }, defaults: { cwd: root, sandbox: "read-only", timeoutSec: 1 }, allowedRoots: [root], policy: { sandboxCeiling: "workspace-write", remoteEgress: { enabled: true, allowedAgents: ["manus"], allowedRoots: [root], allowedDataClasses: ["internal"] } }, handoffMaxChars: 10_000, stateDir: state, sessionLockWaitMs: 0, sessionLockStaleMs: 60_000 };
    const approvals = new ApprovalStore(state);
    const bridge = new Bridge(cfg, new Map([["manus", adapter]]), store, approvals);
    await assert.rejects(bridge.runTurn({ agentId: "manus", prompt: "must not leave locally" }), /REMOTE_EGRESS_CONSENT_REQUIRED/i);
    const approvalScopeForTurn = (await bridge.previewTurnApproval({
      agentId: "manus", prompt: "run the task", allowRemoteEgress: true, dataClassification: "internal",
    })).scope;
    const egress = await createApproved(approvals, "remote_egress", approvalScopeForTurn);
    const cost = await createApproved(approvals, "paid_or_unknown_cost", approvalScopeForTurn, { estimatedCost: 0, currency: "USD" });
    const outcome = await bridge.runTurn({ agentId: "manus", prompt: "run the task", allowRemoteEgress: true, dataClassification: "internal", estimatedCost: 0, estimatedCurrency: "USD", approval_ids: [egress.id, cost.id] });
    assert.equal(outcome.result.isError, true);
    assert.equal(outcome.result.nativeSessionId, manusTaskId);
    assert.equal(outcome.result.meta.taskStatus, "unknown");
    const persisted = store.get(outcome.session.id);
    assert.equal(persisted.turns.length, 1);
    assert.equal(persisted.nativeSessions.manus, manusTaskId);
    assert.doesNotMatch(persisted.turns[0].response, new RegExp(`${manusTaskId}|untrusted provider detail`));
    const [listing] = await bridge.listAgents();
    assert.equal(listing.cooperativeReady, false);
    assert.match(listing.cooperativeReason, /cannot independently inspect local workspace evidence/i);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge fails closed and consumes exact scoped remote approvals", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-remote-approvals-"));
  try {
    const root = config.canonicalDirectory(process.cwd());
    const cfg = remoteConfig(root, state);
    let launches = 0;
    const adapter = remoteAdapter(async () => {
      launches++;
      return { text: "remote ok", exitCode: 0, isError: false, stderr: "", timedOut: false };
    });
    const sessionStore = new sessions.SessionStore(state, 0);
    const withoutApprovals = new Bridge(cfg, new Map([["manus", adapter]]), sessionStore);
    const turn = { agentId: "manus", prompt: "review", allowRemoteEgress: true, dataClassification: "internal", estimatedCost: 0, estimatedCurrency: "USD" };
    await assert.rejects(withoutApprovals.runTurn(turn), /APPROVAL_STORE_REQUIRED/);

    const approvals = new ApprovalStore(state);
    const bridge = new Bridge(cfg, new Map([["manus", adapter]]), sessionStore, approvals);
    await assert.rejects(bridge.runTurn(turn), /APPROVAL_REQUIRED/);

    const wrong = await createApproved(approvals, "remote_egress", approvalScope(root, "review", { action: "delegate:other" }));
    const matchingCost = await createApproved(approvals, "paid_or_unknown_cost", approvalScope(root, "review"), { estimatedCost: 0, currency: "USD" });
    await assert.rejects(bridge.runTurn({ ...turn, approval_ids: [wrong.id, matchingCost.id] }), /APPROVAL_SCOPE_MISMATCH/);
    assert.equal(approvals.get(wrong.id).state, "approved", "wrong-scope approval must not be consumed");
    assert.equal(approvals.get(matchingCost.id).state, "approved", "another category must not be consumed after preflight failure");

    const differentPayloadEgress = await createApproved(approvals, "remote_egress", approvalScope(root, "review only headings"));
    const differentPayloadCost = await createApproved(approvals, "paid_or_unknown_cost", approvalScope(root, "review only headings"), { estimatedCost: 0, currency: "USD" });
    await assert.rejects(bridge.runTurn({ ...turn, approval_ids: [differentPayloadEgress.id, differentPayloadCost.id] }), /APPROVAL_SCOPE_MISMATCH/);
    assert.equal(approvals.get(differentPayloadEgress.id).state, "approved", "a benign approval cannot authorize different prompt bytes");
    assert.equal(approvals.get(differentPayloadCost.id).state, "approved", "a payload mismatch must not consume the unrelated cost gate");

    const exact = await createApproved(approvals, "remote_egress", approvalScope(root, "review"));
    const exactCost = await createApproved(approvals, "paid_or_unknown_cost", approvalScope(root, "review"), { estimatedCost: 0, currency: "USD" });
    const first = await bridge.runTurn({ ...turn, approval_ids: [exact.id, exactCost.id] });
    assert.equal(first.result.text, "remote ok");
    assert.equal(approvals.get(exact.id).state, "consumed");
    await assert.rejects(bridge.runTurn({ ...turn, approval_ids: [exact.id, exactCost.id] }), /APPROVAL_NOT_APPROVED/);
    assert.equal(launches, 1, "failed authorization must never launch the remote adapter");
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge binds remote approval to the finalized context-replay prompt", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-context-approval-"));
  try {
    const root = config.canonicalDirectory(process.cwd());
    const cfg = remoteConfig(root, state);
    cfg.agents.local = {};
    const sessionStore = new sessions.SessionStore(state, 0);
    const approvals = new ApprovalStore(state);
    let transmittedPrompt;
    const local = {
      id: "local", displayName: "Local", capabilities: { resume: false, model: true, sandbox: true, structuredOutput: false },
      execute: async () => ({ text: "local evidence", exitCode: 0, isError: false, stderr: "", timedOut: false }),
    };
    const remote = remoteAdapter(async (request) => {
      transmittedPrompt = request.prompt;
      return { text: "remote review", exitCode: 0, isError: false, stderr: "", timedOut: false };
    });
    const bridge = new Bridge(cfg, new Map([["local", local], ["manus", remote]]), sessionStore, approvals);
    const first = await bridge.runTurn({ agentId: "local", prompt: "inspect locally" });
    const rawOnlyEgress = await createApproved(approvals, "remote_egress", approvalScope(root, "review the evidence"));
    const rawOnlyCost = await createApproved(approvals, "paid_or_unknown_cost", approvalScope(root, "review the evidence"), { estimatedCost: 0, currency: "USD" });
    const remoteTurn = {
      agentId: "manus", sessionId: first.session.id, prompt: "review the evidence", allowRemoteEgress: true,
      dataClassification: "internal", estimatedCost: 0, estimatedCurrency: "USD",
    };
    await assert.rejects(bridge.runTurn({
      ...remoteTurn, approval_ids: [rawOnlyEgress.id, rawOnlyCost.id], expectedSessionRevision: first.session.revision,
    }), /APPROVAL_SCOPE_MISMATCH/);
    assert.equal(approvals.get(rawOnlyEgress.id).state, "approved");
    assert.equal(approvals.get(rawOnlyCost.id).state, "approved");

    const beforePreview = sessionStore.get(first.session.id);
    const preview = await bridge.previewTurnApproval(remoteTurn);
    assert.equal(preview.continuity, "context-replay");
    assert.equal(preview.contextDeltaApplied, true);
    assert.equal(preview.sessionRevision, beforePreview.revision);
    assert.deepEqual(sessionStore.get(first.session.id), beforePreview, "preview must not persist session state");
    assert.equal(transmittedPrompt, undefined, "preview must not call the provider");

    const exactEgress = await createApproved(approvals, "remote_egress", preview.scope);
    const exactCost = await createApproved(approvals, "paid_or_unknown_cost", preview.scope, { estimatedCost: 0, currency: "USD" });
    const outcome = await bridge.runTurn({
      ...remoteTurn, approval_ids: [exactEgress.id, exactCost.id], expectedSessionRevision: preview.sessionRevision,
    });
    assert.equal(outcome.continuity, "context-replay");
    assert.equal(payloadSha256(transmittedPrompt), preview.promptSha256);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge rejects remote approval replay across models and bridge sessions", async () => {
  const root = config.canonicalDirectory(process.cwd());
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-approval-envelope-"));
  try {
    let launches = 0;
    const cfg = remoteConfig(root, state);
    cfg.agents.local = {};
    const local = {
      id: "local", displayName: "Local", capabilities: { resume: false, model: true, sandbox: true, structuredOutput: false },
      execute: async () => ({ text: "identical local evidence", exitCode: 0, isError: false, stderr: "", timedOut: false }),
    };
    const remote = remoteAdapter(async () => {
      launches++;
      return { text: "remote", exitCode: 0, isError: false, stderr: "", timedOut: false };
    });
    const store = new sessions.SessionStore(state, 0);
    const approvals = new ApprovalStore(state, 0);
    const bridge = new Bridge(cfg, new Map([["local", local], ["manus", remote]]), store, approvals);

    const modelPreview = await bridge.previewTurnApproval({
      agentId: "manus", prompt: "same request", model: "manus-1.6-lite",
      allowRemoteEgress: true, dataClassification: "internal",
    });
    const modelEgress = await createApproved(approvals, "remote_egress", modelPreview.scope);
    const modelCost = await createApproved(approvals, "paid_or_unknown_cost", modelPreview.scope, { estimatedCost: 0, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      agentId: "manus", prompt: "same request", model: "manus-1.6-max",
      allowRemoteEgress: true, dataClassification: "internal", estimatedCost: 0, estimatedCurrency: "USD",
      approval_ids: [modelEgress.id, modelCost.id],
    }), /APPROVAL_SCOPE_MISMATCH/);

    const first = await bridge.runTurn({ agentId: "local", prompt: "seed" });
    const second = await bridge.runTurn({ agentId: "local", prompt: "seed" });
    const sessionPreview = await bridge.previewTurnApproval({
      agentId: "manus", sessionId: first.session.id, prompt: "same request",
      allowRemoteEgress: true, dataClassification: "internal",
    });
    const sessionEgress = await createApproved(approvals, "remote_egress", sessionPreview.scope);
    const sessionCost = await createApproved(approvals, "paid_or_unknown_cost", sessionPreview.scope, { estimatedCost: 0, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      agentId: "manus", sessionId: second.session.id, expectedSessionRevision: second.session.revision,
      prompt: "same request", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 0, estimatedCurrency: "USD", approval_ids: [sessionEgress.id, sessionCost.id],
    }), /APPROVAL_SCOPE_MISMATCH/);
    assert.equal(launches, 0);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge rejects reusable remote authority before every provider launch", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-reusable-remote-"));
  try {
    const root = config.canonicalDirectory(process.cwd());
    const approvals = new ApprovalStore(state);
    let launches = 0;
    const bridge = new Bridge(
      remoteConfig(root, state),
      new Map([["manus", remoteAdapter(async () => {
        launches++;
        return { text: "must not run", exitCode: 0, isError: false, stderr: "", timedOut: false };
      })]]),
      new sessions.SessionStore(state, 0),
      approvals,
    );
    const targetScope = approvalScope(root, "same paid request");
    const reusable = approvals.create({
      category: "secrets", scope: targetScope, requestedBy: "legacy-test", reason: "legacy reusable authority",
      expiresAt: new Date(Date.now() + 60_000).toISOString(), consumeOnce: false, maxUses: 2,
    });
    await approvals.approve(reusable.id, { approvedBy: "legacy-user", reason: "legacy approval" });
    const persisted = approvals.get(reusable.id);
    await writeFile(approvals.path(reusable.id), JSON.stringify({ ...persisted, category: "remote_egress" }), "utf8");
    const cost = await createApproved(approvals, "paid_or_unknown_cost", targetScope, { estimatedCost: 1, currency: "USD" });
    const turn = {
      agentId: "manus", prompt: "same paid request", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 1, estimatedCurrency: "USD", approval_ids: [reusable.id, cost.id],
    };
    await assert.rejects(bridge.runTurn(turn), /APPROVAL_REUSABLE_FORBIDDEN/);
    await assert.rejects(bridge.runTurn(turn), /APPROVAL_REUSABLE_FORBIDDEN/);
    assert.equal(launches, 0);
    assert.equal(approvals.get(cost.id).state, "approved", "preflight must not consume the one-time cost record");
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge requires a new preview when a remote handoff session revision changes", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-stale-preview-"));
  try {
    const root = config.canonicalDirectory(process.cwd());
    const cfg = remoteConfig(root, state);
    cfg.agents.local = {};
    const approvals = new ApprovalStore(state);
    const store = new sessions.SessionStore(state, 0);
    let remoteLaunches = 0;
    const local = {
      id: "local", displayName: "Local", capabilities: { resume: false, model: true, sandbox: true, structuredOutput: false },
      execute: async () => ({ text: "local update", exitCode: 0, isError: false, stderr: "", timedOut: false }),
    };
    const bridge = new Bridge(cfg, new Map([
      ["local", local],
      ["manus", remoteAdapter(async () => {
        remoteLaunches++;
        return { text: "unexpected", exitCode: 0, isError: false, stderr: "", timedOut: false };
      })],
    ]), store, approvals);
    const first = await bridge.runTurn({ agentId: "local", prompt: "initial evidence" });
    const remote = {
      agentId: "manus", sessionId: first.session.id, prompt: "review it", allowRemoteEgress: true,
      dataClassification: "internal", estimatedCost: 0, estimatedCurrency: "USD",
    };
    const preview = await bridge.previewTurnApproval(remote);
    const egress = await createApproved(approvals, "remote_egress", preview.scope);
    const cost = await createApproved(approvals, "paid_or_unknown_cost", preview.scope, { estimatedCost: 0, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      ...remote, approval_ids: [egress.id, cost.id],
    }), /SESSION_REVISION_REQUIRED/);
    assert.equal(remoteLaunches, 0);
    assert.equal(approvals.get(egress.id).state, "approved");
    assert.equal(approvals.get(cost.id).state, "approved");
    await bridge.runTurn({ agentId: "local", sessionId: first.session.id, prompt: "new evidence" });
    await assert.rejects(bridge.runTurn({
      ...remote, approval_ids: [egress.id, cost.id], expectedSessionRevision: preview.sessionRevision,
    }), /SESSION_REVISION_MISMATCH.*preview again/);
    assert.equal(remoteLaunches, 0);
    assert.equal(approvals.get(egress.id).state, "approved");
    assert.equal(approvals.get(cost.id).state, "approved");
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge rejects expired approvals before consuming another category", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-expired-approvals-"));
  try {
    const root = config.canonicalDirectory(process.cwd());
    let approvalNow = new Date();
    const approvals = new ApprovalStore(state, 30_000, 7_500_000, () => approvalNow);
    const egress = await createApproved(approvals, "remote_egress", approvalScope(root, "unknown cost"));
    const paid = await createApproved(approvals, "paid_or_unknown_cost", approvalScope(root, "unknown cost"), { currency: "USD" });
    approvalNow = new Date(Date.now() + 120_000);
    await approvals.expireDue(paid.id, "test-clock");
    const bridge = new Bridge(remoteConfig(root, state), new Map([["manus", remoteAdapter()]]), new sessions.SessionStore(state, 0), approvals);
    await assert.rejects(bridge.runTurn({
      agentId: "manus", prompt: "unknown cost", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCurrency: "USD", approval_ids: [egress.id, paid.id],
    }), /APPROVAL_NOT_APPROVED.*expired/);
    assert.equal(approvals.get(egress.id).state, "approved", "preflight failure must not consume another category");
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge always requires a distinct currency-bound cost approval for remote API turns", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-paid-approvals-"));
  try {
    const root = config.canonicalDirectory(process.cwd());
    const approvals = new ApprovalStore(state);
    const bridge = new Bridge(remoteConfig(root, state), new Map([["manus", remoteAdapter()]]), new sessions.SessionStore(state, 0), approvals);
    const egress = await createApproved(approvals, "remote_egress", approvalScope(root, "paid review"));
    const base = { agentId: "manus", prompt: "paid review", allowRemoteEgress: true, dataClassification: "internal", estimatedCurrency: "USD" };
    await assert.rejects(bridge.runTurn({ ...base, estimatedCost: 0, approval_ids: [egress.id] }), /paid_or_unknown_cost/);
    await assert.rejects(bridge.runTurn({ ...base, estimatedCost: 0, estimatedCurrency: undefined, approval_ids: [egress.id] }), /APPROVAL_INVALID_CURRENCY/);
    assert.equal(approvals.get(egress.id).useCount, 0, "zero-cost claims must not bypass or consume the paid gate");
    await assert.rejects(bridge.runTurn({ ...base, estimatedCost: 1, approval_ids: [egress.id] }), /paid_or_unknown_cost/);
    assert.equal(approvals.get(egress.id).useCount, 0);

    const underfunded = await createApproved(approvals, "paid_or_unknown_cost", approvalScope(root, "paid review"), { estimatedCost: 0.5, currency: "USD" });
    await assert.rejects(bridge.runTurn({ ...base, estimatedCost: 1, approval_ids: [egress.id, underfunded.id] }), /APPROVAL_COST_MISMATCH/);
    assert.equal(approvals.get(egress.id).useCount, 0);
    assert.equal(approvals.get(underfunded.id).state, "approved");

    const wrongCurrency = await createApproved(approvals, "paid_or_unknown_cost", approvalScope(root, "paid review"), { estimatedCost: 2, currency: "EUR" });
    await assert.rejects(bridge.runTurn({ ...base, estimatedCost: 1, approval_ids: [egress.id, wrongCurrency.id] }), /APPROVAL_CURRENCY_MISMATCH/);
    assert.equal(approvals.get(egress.id).useCount, 0);
    assert.equal(approvals.get(wrongCurrency.id).state, "approved");

    const paid = await createApproved(approvals, "paid_or_unknown_cost", approvalScope(root, "paid review"), { estimatedCost: 2, currency: "USD" });
    await bridge.runTurn({ ...base, estimatedCost: 1, approval_ids: [paid.id, egress.id] });
    assert.equal(approvals.get(paid.id).state, "consumed");
    assert.equal(approvals.get(egress.id).state, "consumed");

    const unknownEgress = await createApproved(approvals, "remote_egress", approvalScope(root, "paid review"));
    const unknownCost = await createApproved(approvals, "paid_or_unknown_cost", approvalScope(root, "paid review"), { currency: "USD" });
    await bridge.runTurn({ ...base, approval_ids: [unknownCost.id, unknownEgress.id] });
    assert.equal(approvals.get(unknownCost.id).state, "consumed");
    assert.equal(approvals.get(unknownEgress.id).state, "consumed");
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge reserves configured cumulative direct-remote budget before every provider launch", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-cumulative-budget-"));
  try {
    const root = config.canonicalDirectory(process.cwd());
    const cfg = remoteConfig(root, state);
    cfg.policy.cumulativeRemoteCost = { currency: "USD", maxReservedCents: 100 };
    const approvals = new ApprovalStore(state);
    const budget = new RemoteCostBudgetStore(state, cfg.policy.cumulativeRemoteCost, 30_000, 60_000);
    let launches = 0;
    const adapter = remoteAdapter(async () => { launches++; throw new Error("provider accepted then transport failed"); });
    const store = new sessions.SessionStore(state, 0);

    const missingStoreScope = approvalScope(root, "missing store");
    const missingStoreEgress = await createApproved(approvals, "remote_egress", missingStoreScope);
    const missingStoreCost = await createApproved(approvals, "paid_or_unknown_cost", missingStoreScope, { estimatedCost: 0.25, currency: "USD" });
    const missingStore = new Bridge(cfg, new Map([["manus", adapter]]), store, approvals);
    await assert.rejects(missingStore.runTurn({
      agentId: "manus", prompt: "missing store", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 0.25, estimatedCurrency: "USD", approval_ids: [missingStoreEgress.id, missingStoreCost.id],
    }), /CUMULATIVE_BUDGET_STORE_REQUIRED/);
    assert.equal(approvals.get(missingStoreEgress.id).state, "approved");
    assert.equal(launches, 0);

    const bridge = new Bridge(cfg, new Map([["manus", adapter]]), store, approvals, budget);
    const preview = await bridge.previewTurnApproval({
      agentId: "manus", prompt: "preview only", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 0.25, estimatedCurrency: "USD",
    });
    assert.equal(preview.sessionRevision, null);
    assert.equal(budget.status().committedCents, 0, "preview must not reserve budget");
    assert.equal(store.list(10).length, 0, "preview must not persist a session");
    assert.equal(launches, 0, "preview must not launch a provider");

    const zeroScope = approvalScope(root, "zero claim");
    const zeroEgress = await createApproved(approvals, "remote_egress", zeroScope);
    const zeroCost = await createApproved(approvals, "paid_or_unknown_cost", zeroScope, { estimatedCost: 0, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      agentId: "manus", prompt: "zero claim", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 0, estimatedCurrency: "USD", approval_ids: [zeroEgress.id, zeroCost.id],
    }), /CUMULATIVE_BUDGET_BOUNDED_COST_REQUIRED/);
    assert.equal(budget.status().committedCents, 0);
    assert.equal(approvals.get(zeroCost.id).state, "approved");

    const firstScope = approvalScope(root, "first bounded call");
    const firstEgress = await createApproved(approvals, "remote_egress", firstScope);
    const firstCost = await createApproved(approvals, "paid_or_unknown_cost", firstScope, { estimatedCost: 0.60, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      agentId: "manus", prompt: "first bounded call", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 0.50, estimatedCurrency: "USD", approval_ids: [firstEgress.id, firstCost.id],
    }), /provider accepted then transport failed/);
    assert.equal(budget.status().committedCents, 60, "provider failure must never release a reservation");
    assert.equal(approvals.get(firstCost.id).state, "consumed");
    assert.equal(launches, 1);

    const overScope = approvalScope(root, "over cap");
    const overEgress = await createApproved(approvals, "remote_egress", overScope);
    const overCost = await createApproved(approvals, "paid_or_unknown_cost", overScope, { estimatedCost: 0.50, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      agentId: "manus", prompt: "over cap", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 0.50, estimatedCurrency: "USD", approval_ids: [overEgress.id, overCost.id],
    }), /CUMULATIVE_BUDGET_EXHAUSTED/);
    assert.equal(approvals.get(overEgress.id).state, "approved", "budget rejection must occur before approval consumption");
    assert.equal(budget.status().committedCents, 60);
    assert.equal(launches, 1);

    const exactScope = approvalScope(root, "exact remainder");
    const exactEgress = await createApproved(approvals, "remote_egress", exactScope);
    const exactCost = await createApproved(approvals, "paid_or_unknown_cost", exactScope, { estimatedCost: 0.40, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      agentId: "manus", prompt: "exact remainder", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 0.40, estimatedCurrency: "USD", approval_ids: [exactEgress.id, exactCost.id],
    }), /provider accepted then transport failed/);
    assert.equal(budget.status().committedCents, 100);
    assert.equal(launches, 2);

    await writeFile(budget.path, "{corrupt ledger", "utf8");
    const corruptScope = approvalScope(root, "corrupt ledger");
    const corruptEgress = await createApproved(approvals, "remote_egress", corruptScope);
    const corruptCost = await createApproved(approvals, "paid_or_unknown_cost", corruptScope, { estimatedCost: 0.01, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      agentId: "manus", prompt: "corrupt ledger", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 0.01, estimatedCurrency: "USD", approval_ids: [corruptEgress.id, corruptCost.id],
    }), /CUMULATIVE_BUDGET_CORRUPT/);
    assert.equal(approvals.get(corruptEgress.id).state, "approved", "corruption must fail before approval consumption");
    assert.equal(approvals.get(corruptCost.id).state, "approved");
    assert.equal(launches, 2, "corruption must fail before provider launch");
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge rejects a pre-reserved approval after a crash window without consuming or launching", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-cumulative-budget-retry-"));
  try {
    const root = config.canonicalDirectory(process.cwd());
    const cfg = remoteConfig(root, state);
    cfg.policy.cumulativeRemoteCost = { currency: "USD", maxReservedCents: 100 };
    const approvals = new ApprovalStore(state);
    const budget = new RemoteCostBudgetStore(state, cfg.policy.cumulativeRemoteCost, 30_000, 60_000);
    let launches = 0;
    const bridge = new Bridge(cfg, new Map([["manus", remoteAdapter(async () => { launches++; return { text: "unexpected", exitCode: 0, isError: false, stderr: "", timedOut: false }; })]]), new sessions.SessionStore(state, 0), approvals, budget);
    const scope = approvalScope(root, "retry after reservation");
    const egress = await createApproved(approvals, "remote_egress", scope);
    const paid = await createApproved(approvals, "paid_or_unknown_cost", scope, { estimatedCost: 0.25, currency: "USD" });
    await budget.reserve({ approvalId: paid.id, agentId: "manus", sessionId: "prior-crash", turnIndex: 0, cents: 25 });

    await assert.rejects(bridge.runTurn({
      agentId: "manus", prompt: "retry after reservation", allowRemoteEgress: true, dataClassification: "internal",
      estimatedCost: 0.25, estimatedCurrency: "USD", approval_ids: [egress.id, paid.id],
    }), /CUMULATIVE_BUDGET_APPROVAL_ALREADY_RESERVED/);
    assert.equal(approvals.get(egress.id).state, "approved");
    assert.equal(approvals.get(paid.id).state, "approved");
    assert.equal(budget.status().committedCents, 25);
    assert.equal(budget.status().reservationCount, 1);
    assert.equal(launches, 0);
    assert.equal(bridge.listSessions(10).length, 0, "failed fresh turn must clean up its ephemeral bridge session");
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge Manus preflight and lifecycle gates run before approval consumption or provider POST", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-manus-preflight-"));
  try {
    let calls = 0;
    const adapter = new ManusAdapter({
      apiKey: "test-key", acknowledgeAccountDefaultCapabilities: true, accountCapabilityProfile: "test-reviewed-profile",
      fetch: async () => { calls++; return new Response(JSON.stringify({ ok: true, task_id: "U".repeat(22), messages: [
        { id: "provider-waiting", type: "status_update", timestamp: 20, status_update: { agent_status: "waiting" } },
      ] })); },
    });
    const root = config.canonicalDirectory(process.cwd());
    const cfg = remoteConfig(root, state);
    const store = new sessions.SessionStore(state, 0);
    const approvals = new ApprovalStore(state);
    const bridge = new Bridge(cfg, new Map([["manus", adapter]]), store, approvals);
    await assert.rejects(bridge.previewTurnApproval({ agentId: "manus", prompt: "hello", model: "manus-invalid", allowRemoteEgress: true, dataClassification: "internal" }), /Unsupported Manus model/);
    await assert.rejects(bridge.previewTurnApproval({ agentId: "manus", prompt: "x".repeat(4_501), allowRemoteEgress: true, dataClassification: "internal" }), /prompt is too large/i);

    const session = store.create({ title: "unknown Manus", cwd: root });
    session.nativeSessionPolicies.manus = { cwd: root, sandbox: "read-only", model: "manus-1.6" };
    store.record(session, "manus", "initial", { text: "unknown", nativeSessionId: "S".repeat(22), exitCode: null, isError: true, stderr: "", timedOut: false, durationMs: 1, meta: { taskStatus: "unknown" } }, new Date().toISOString(), session.revision);
    const dummy = approvalScope(root, "must not send");
    const egress = await createApproved(approvals, "remote_egress", dummy);
    const cost = await createApproved(approvals, "paid_or_unknown_cost", dummy, { estimatedCost: 0, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      agentId: "manus", sessionId: session.id, expectedSessionRevision: 1, prompt: "must not send", model: "manus-1.6-max",
      allowRemoteEgress: true, dataClassification: "internal", estimatedCost: 0, estimatedCurrency: "USD", approval_ids: [egress.id, cost.id],
    }), /MANUS_RECONCILIATION_REQUIRED/);
    assert.equal(approvals.get(egress.id).state, "approved");
    assert.equal(approvals.get(cost.id).state, "approved");
    assert.equal(calls, 0);

    const stopped = store.create({ title: "stale stopped Manus", cwd: root });
    store.record(stopped, "manus", "initial", { text: "done", nativeSessionId: "U".repeat(22), exitCode: 0, isError: false, stderr: "", timedOut: false, durationMs: 1, meta: { taskStatus: "stopped" } }, new Date().toISOString(), stopped.revision);
    const preview = await bridge.previewTurnApproval({ agentId: "manus", sessionId: stopped.id, prompt: "must not send", allowRemoteEgress: true, dataClassification: "internal" });
    const stoppedEgress = await createApproved(approvals, "remote_egress", preview.scope);
    const stoppedCost = await createApproved(approvals, "paid_or_unknown_cost", preview.scope, { estimatedCost: 0, currency: "USD" });
    await assert.rejects(bridge.runTurn({
      agentId: "manus", sessionId: stopped.id, expectedSessionRevision: preview.sessionRevision, prompt: "must not send",
      allowRemoteEgress: true, dataClassification: "internal", estimatedCost: 0, estimatedCurrency: "USD", approval_ids: [stoppedEgress.id, stoppedCost.id],
    }), /ordinary continuation is denied/i);
    assert.equal(approvals.get(stoppedEgress.id).state, "approved");
    assert.equal(approvals.get(stoppedCost.id).state, "approved");
    assert.equal(calls, 1);
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("Bridge reconciles an unknown Manus task without sending a new message", async () => {
  const state = await mkdtemp(join(tmpdir(), "agent-bridge-manus-reconcile-"));
  try {
    const taskId = "T".repeat(22);
    const calls = [];
    const adapter = new ManusAdapter({
      apiKey: "test-key", acknowledgeAccountDefaultCapabilities: true, accountCapabilityProfile: "test-reviewed-profile", pollIntervalMs: 0,
      fetch: async (url, init) => {
        calls.push({ url: String(url), method: init.method });
        return new Response(JSON.stringify({ ok: true, task_id: taskId, messages: [
          { id: "done", type: "status_update", timestamp: 20, status_update: { agent_status: "stopped" } },
          { id: "answer", type: "assistant_message", timestamp: 10, assistant_message: { content: "recovered result" } },
        ] }));
      },
    });
    const root = config.canonicalDirectory(process.cwd());
    const store = new sessions.SessionStore(state, 0);
    const bridge = new Bridge(remoteConfig(root, state), new Map([["manus", adapter]]), store);
    const session = store.create({ title: "unknown Manus", cwd: root });
    store.record(session, "manus", "initial", { text: "unknown", nativeSessionId: taskId, exitCode: null, isError: true, stderr: "", timedOut: false, durationMs: 1, meta: { taskStatus: "unknown" } }, new Date().toISOString(), session.revision);
    const outcome = await bridge.reconcileManusTask({ sessionId: session.id, expectedSessionRevision: 1, allowRemoteEgress: true, dataClassification: "internal", timeoutSec: 1 });
    assert.equal(outcome.result.text, "recovered result");
    assert.equal(outcome.result.meta.taskStatus, "stopped");
    assert.ok(calls.every((call) => call.method === "GET"));
    assert.ok(calls.every((call) => call.url.includes("task.listMessages")));
  } finally { await rm(state, { recursive: true, force: true }); }
});

test("projectSession clips text and removes native IDs plus structured metadata", () => {
  const projected = sessions.projectSession({ id: "safe-id", title: "t", cwd: "c", createdAt: "x", updatedAt: "x", revision: 2, nativeSessions: { a: "secret-native" }, nativeSessionPolicies: { a: { cwd: "c", sandbox: "read-only" } }, lastSeenTurnByAgent: { a: 0 }, turns: [{ index: 0, agentId: "a", prompt: "abcdefgh", response: "12345678", isError: false, nativeSessionId: "secret-native", startedAt: "x", durationMs: 1, exitCode: 0, stderr: "zzzzzzzz", timedOut: false, meta: { token: "structured" } }] }, 4);
  assert.equal(projected.nativeSessions.a, undefined);
  assert.equal(projected.turns[0].nativeSessionId, undefined);
  assert.equal(projected.turns[0].meta, undefined);
  assert.match(projected.turns[0].prompt, /^abcd/);
  assert.match(projected.turns[0].response, /^1234/);
  assert.match(projected.turns[0].stderr, /^zzzz/);
});

function remoteConfig(root, state) {
  return { agents: { manus: {} }, defaults: { cwd: root, sandbox: "read-only", timeoutSec: 1 }, allowedRoots: [root], policy: { sandboxCeiling: "workspace-write", remoteEgress: { enabled: true, allowedAgents: ["manus"], allowedRoots: [root], allowedDataClasses: ["internal"] } }, handoffMaxChars: 10_000, stateDir: state, sessionLockWaitMs: 0, sessionLockStaleMs: 60_000 };
}

function remoteAdapter(execute = async () => ({ text: "ok", exitCode: 0, isError: false, stderr: "", timedOut: false })) {
  return { id: "manus", displayName: "Manus", capabilities: { resume: false, model: true, sandbox: false, structuredOutput: false, remote: true, localFilesystem: false, independentReview: false }, execute };
}

function approvalScope(root, prompt, overrides = {}, envelopeOverrides = {}) {
  const envelope = {
    schemaVersion: 2,
    prompt,
    model: null,
    sandbox: "read-only",
    timeoutMs: 1_000,
    continuity: "new",
    contextDeltaApplied: false,
    forceFresh: false,
    nativeResume: false,
    bridgeSessionId: null,
    sessionRevision: null,
    allowAgentConfigExtensions: true,
    providerCapabilityPolicy: "provider-default",
    providerEndpoint: null,
    providerAccountProfile: null,
    ...envelopeOverrides,
  };
  return { ...deriveRemoteTurnApprovalScope({ agentId: "manus", cwd: root, dataClassification: "internal", envelope }), ...overrides };
}

async function createApproved(store, category, scope, overrides = {}) {
  const record = store.create({
    category, scope, requestedBy: "test", reason: `authorize ${category}`,
    expiresAt: new Date(Date.now() + 60_000).toISOString(), ...overrides,
  });
  await store.approve(record.id, { approvedBy: "test-user", reason: "approved for test" });
  return store.get(record.id);
}
