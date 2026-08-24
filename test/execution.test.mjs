import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const outputDir = await mkdtemp(join(tmpdir(), "agent-bridge-execution-"));
await build({
  entryPoints: {
    runner: "src/runner.ts",
    codex: "src/adapters/codex.ts",
    claude: "src/adapters/claude.ts",
    gemini: "src/adapters/gemini.ts",
    render: "src/render.ts",
    bridge: "src/bridge.ts",
  },
  outdir: outputDir,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
});
const runner = await import(`${pathToFileURL(join(outputDir, "runner.js")).href}?${Date.now()}`);
const { CodexAdapter } = await import(`${pathToFileURL(join(outputDir, "codex.js")).href}?${Date.now()}`);
const { ClaudeAdapter } = await import(`${pathToFileURL(join(outputDir, "claude.js")).href}?${Date.now()}`);
const { GeminiAdapter } = await import(`${pathToFileURL(join(outputDir, "gemini.js")).href}?${Date.now()}`);
const render = await import(`${pathToFileURL(join(outputDir, "render.js")).href}?${Date.now()}`);
const { Bridge } = await import(`${pathToFileURL(join(outputDir, "bridge.js")).href}?${Date.now()}`);
test.after(async () => { await rm(outputDir, { recursive: true, force: true }); });

test("spawn failures are represented as errors by every local adapter", async () => {
  const raw = await runner.runProcess(
    { command: `agent-bridge-missing-binary-${process.pid}`, args: [] },
    { cwd: process.cwd(), timeoutMs: 1_000, agentId: "codex" },
  );
  assert.equal(raw.exitCode, null);
  assert.equal(raw.timedOut, false);
  assert.equal(raw.aborted, false);
  assert.match(raw.stderr, /failed to spawn/i);
  assert.equal(new CodexAdapter().parse(raw).isError, true);
  assert.equal(new ClaudeAdapter().parse({ ...raw, stdout: '{"result":"unexpected success"}' }).isError, true);
  assert.equal(new GeminiAdapter().parse({ ...raw, stdout: '{"response":"unexpected success"}' }).isError, true);
});

test("an AbortSignal terminates a local child and is distinct from timeout", { timeout: 10_000 }, async () => {
  const controller = new AbortController();
  const resultPromise = runner.runProcess(
    { command: process.execPath, args: ["-e", "setInterval(() => {}, 1000)"] },
    { cwd: process.cwd(), timeoutMs: 8_000, agentId: "codex", signal: controller.signal },
  );
  setTimeout(() => controller.abort(), 50).unref();
  const raw = await resultPromise;
  assert.equal(raw.aborted, true);
  assert.equal(raw.timedOut, false);
  assert.notEqual(raw.exitCode, 0);
  assert.match(raw.stderr, /canceled.*terminating/i);
});

test("a pre-aborted signal prevents process launch", async () => {
  const controller = new AbortController();
  controller.abort();
  const raw = await runner.runProcess(
    { command: process.execPath, args: ["-e", "process.exit(0)"] },
    { cwd: process.cwd(), timeoutMs: 1_000, agentId: "codex", signal: controller.signal },
  );
  assert.equal(raw.aborted, true);
  assert.equal(raw.exitCode, null);
  assert.match(raw.stderr, /before spawn/i);
});

test("turn rendering is bounded and retains a pageable full-output reference", () => {
  const full = `${"head".repeat(10_000)}FINAL-TAIL`;
  const turn = {
    index: 0, agentId: "codex", prompt: "p", response: full, isError: false,
    startedAt: new Date().toISOString(), durationMs: 5, exitCode: 0, stderr: "", timedOut: false,
  };
  const session = {
    schemaVersion: 1, id: "session-output", title: "output", cwd: process.cwd(),
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), revision: 1,
    nativeSessions: {}, nativeSessionPolicies: {}, lastSeenTurnByAgent: {}, turns: [turn],
  };
  const rendered = render.renderTurn({
    session,
    result: { text: full, exitCode: 0, isError: false, stderr: "", timedOut: false, durationMs: 5 },
    continuity: "new", contextDeltaApplied: false,
    agent: { id: "codex", displayName: "Codex", capabilities: {} },
  });
  assert.equal(rendered.structuredContent.output_truncated, true);
  assert.ok(rendered.structuredContent.output.length <= render.TURN_OUTPUT_PREVIEW_CHARS);
  assert.match(rendered.structuredContent.output, /FINAL-TAIL$/);
  assert.deepEqual(rendered.structuredContent.output_ref, {
    bridge_session_id: "session-output", turn: 0, tool: "get_turn_output",
  });
  assert.ok(rendered.content[0].text.length < 25_000);

  const first = render.pageTurnText(session, 0, "output", 0, 10_000);
  const second = render.pageTurnText(session, 0, "output", first.nextOffset, 100_000);
  assert.equal(first.text + second.text, full);
  assert.equal(second.complete, true);
  assert.equal(second.nextOffset, null);
});

test("Bridge forwards the caller AbortSignal to direct adapters", async () => {
  let session;
  let receivedSignal;
  let startedResolve;
  const started = new Promise((resolve) => { startedResolve = resolve; });
  const store = {
    create({ title, cwd }) {
      session = {
        schemaVersion: 1, id: "signal-session", title, cwd,
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), revision: 0,
        nativeSessions: {}, nativeSessionPolicies: {}, lastSeenTurnByAgent: {}, turns: [],
      };
      return session;
    },
    get() { return session; },
    async withLock(_id, fn) { return fn(); },
    delete() {},
    record(value, agentId, prompt, result, startedAt) {
      value.turns.push({ index: 0, agentId, prompt, response: result.text, isError: result.isError, startedAt, ...result });
      value.revision++;
    },
  };
  const adapter = {
    id: "remote", displayName: "Remote", capabilities: { resume: false, model: true, sandbox: false, structuredOutput: true },
    async execute(_request, options) {
      receivedSignal = options.signal;
      startedResolve();
      await new Promise((resolve) => options.signal.addEventListener("abort", resolve, { once: true }));
      return { text: "canceled", exitCode: null, isError: true, stderr: "", timedOut: false, meta: { aborted: true } };
    },
  };
  const config = {
    agents: { remote: {} }, defaults: { cwd: process.cwd(), sandbox: "read-only", timeoutSec: 10 },
    allowedRoots: [process.cwd()], handoffMaxChars: 10_000, stateDir: "unused", sessionLockWaitMs: 0, sessionLockStaleMs: 60_000,
  };
  const bridge = new Bridge(config, new Map([["remote", adapter]]), store);
  const controller = new AbortController();
  const outcomePromise = bridge.runTurn({ agentId: "remote", prompt: "wait", signal: controller.signal });
  await started;
  controller.abort();
  const outcome = await outcomePromise;
  assert.equal(receivedSignal, controller.signal);
  assert.equal(outcome.result.isError, true);
  assert.equal(outcome.session.turns.length, 1);
});
