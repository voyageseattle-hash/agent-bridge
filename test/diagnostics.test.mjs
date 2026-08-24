import assert from "node:assert/strict";
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const outputDir = await mkdtemp(join(tmpdir(), "agent-bridge-diagnostics-build-"));
async function load(name, entry) {
  const outfile = join(outputDir, `${name}.mjs`);
  await build({ entryPoints: [entry], outfile, bundle: true, platform: "node", format: "esm", target: "node20" });
  return import(`${pathToFileURL(outfile).href}?${Date.now()}`);
}
const [{ buildDiagnostics, sanitizeDiagnosticDetail }, { Bridge }] = await Promise.all([load("diagnostics", "src/diagnostics.ts"), load("bridge", "src/bridge.ts")]);
test.after(async () => { await rm(outputDir, { recursive: true, force: true }); });

test("unknown local auth is not usable", async () => {
  const adapter = {
    id: "local", displayName: "Local", bin: process.execPath, versionArgs: ["--version"],
    capabilities: { resume: false, model: false, sandbox: false, structuredOutput: false },
    authSpec: () => ({ command: process.execPath, args: ["--version"] }),
    parseAuth: () => ({ status: "unknown", detail: "probe format changed" }),
  };
  const config = { agents: { local: {} }, defaults: { timeoutSec: 1, sandbox: "read-only" }, allowedRoots: [process.cwd()], handoffMaxChars: 1000, stateDir: join(tmpdir(), "diagnostics-unused"), sessionLockWaitMs: 0, sessionLockStaleMs: 60000, configPath: "C:\\safe\\config.json", configSource: "test" };
  const bridge = new Bridge(config, new Map([["local", adapter]]), {});
  const [agent] = await bridge.listAgents();
  assert.equal(agent.health.auth.status, "unknown");
  assert.equal(agent.health.usable, false);
});

test("diagnostics omit config contents and secrets while reporting safe operational evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-diagnostics-"));
  try {
    await mkdir(join(root, "sessions"));
    await writeFile(join(root, "sessions", "one.json"), "secret-config-value");
    const secret = "super-secret-not-to-leak";
    const configPath = join(root, `config-${secret}.json`);
    await writeFile(configPath, JSON.stringify({ marker: secret }));
    const config = { agents: { codex: { extraEnv: { SECRET: secret } } }, defaults: { timeoutSec: 1, sandbox: "read-only" }, allowedRoots: [join("C:\\Users\\test", "Documents")], handoffMaxChars: 1000, stateDir: root, sessionLockWaitMs: 0, sessionLockStaleMs: 60000, configPath, configSource: "test" };
    const report = buildDiagnostics(config, new Map([["codex", { id: "codex", displayName: "Codex", bin: "C:\\Apps\\bin\\abcdef123456\\codex.exe", capabilities: {} }]]), { runtime: { version: "test" }, platform: "win32", userProfile: "C:\\Users\\test" });
    const text = JSON.stringify(report);
    assert.equal(report.config.allowedRootCount, 1);
    assert.equal(report.state.sessionFiles, 1);
    assert.match(report.config.broadRootWarnings[0], /user content library/i);
    assert.match(report.binaries[0].driftHints[0], /versioned/i);
    assert.doesNotMatch(text, new RegExp(secret));
    assert.doesNotMatch(text, /secret-config-value/);
    assert.ok(report.config.pathSha256.length === 64);
    assert.equal(report.config.contentHashStatus, "verified");
    assert.ok(report.config.contentSha256.length === 64);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("diagnostics resolve bare command names through PATH", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-diagnostics-path-"));
  try {
    const executable = process.platform === "win32" ? join(root, "bridge-probe.CMD") : join(root, "bridge-probe");
    await writeFile(executable, process.platform === "win32" ? "@exit /b 0\r\n" : "#!/bin/sh\nexit 0\n");
    if (process.platform !== "win32") await chmod(executable, 0o700);
    const config = { agents: {}, defaults: { timeoutSec: 1, sandbox: "read-only" }, allowedRoots: [process.cwd()], handoffMaxChars: 1000, stateDir: join(root, "state"), sessionLockWaitMs: 0, sessionLockStaleMs: 60000, configPath: join(root, "config.json"), configSource: "test" };
    const report = buildDiagnostics(config, new Map([["probe", { id: "probe", displayName: "Probe", bin: "bridge-probe", capabilities: {} }]]), {
      platform: process.platform,
      pathEnv: root,
      pathExt: process.platform === "win32" ? ".CMD" : undefined,
    });
    assert.equal(report.binaries[0].exists, true);
    assert.equal(report.binaries[0].resolvedPath, executable);
    assert.deepEqual(report.binaries[0].driftHints, []);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("diagnostics preserve explicit executable identity and do not fall back to PATH", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-diagnostics-explicit-"));
  try {
    const executable = process.execPath;
    const missing = join(root, "missing", process.platform === "win32" ? "node.exe" : "node");
    const config = { agents: {}, defaults: { timeoutSec: 1, sandbox: "read-only" }, allowedRoots: [process.cwd()], handoffMaxChars: 1000, stateDir: join(root, "state"), sessionLockWaitMs: 0, sessionLockStaleMs: 60000, configPath: join(root, "config.json"), configSource: "test" };
    const report = buildDiagnostics(config, new Map([
      ["present", { id: "present", displayName: "Present", bin: executable, capabilities: {} }],
      ["missing", { id: "missing", displayName: "Missing", bin: missing, capabilities: {} }],
    ]), { platform: process.platform, pathEnv: join(executable, "not-used") });
    assert.equal(report.binaries[0].configuredPath, executable);
    assert.equal(report.binaries[0].exists, true);
    assert.equal(report.binaries[0].resolvedPath, executable);
    assert.equal(report.binaries[1].exists, false);
    assert.match(report.binaries[1].driftHints[0], /path does not exist/i);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("diagnostics warn for Windows and POSIX filesystem roots", () => {
  const root = join(tmpdir(), "agent-bridge-diagnostics-root-state");
  const config = { agents: {}, defaults: { timeoutSec: 1, sandbox: "read-only" }, allowedRoots: ["C:\\", "/"], handoffMaxChars: 1000, stateDir: root, sessionLockWaitMs: 0, sessionLockStaleMs: 60000, configPath: "C:\\safe\\config.json", configSource: "test" };
  const report = buildDiagnostics(config, new Map(), { platform: "win32", userProfile: "C:\\Users\\test", pathEnv: "" });
  assert.equal(report.config.broadRootWarnings.length, 2);
  assert.match(report.config.broadRootWarnings[0], /filesystem root/i);
  assert.match(report.config.broadRootWarnings[1], /filesystem root/i);
});

test("diagnostic detail sanitizer redacts common provider credential shapes and bounds output", () => {
  const raw = "\u001b[31mBearer abc123\nforged: usable api_key=sk-test-fixture-abcdefghijklmnop https://user:pass@example.invalid/?token=topsecret " + "x".repeat(200);
  const sanitized = sanitizeDiagnosticDetail(raw, 80);
  assert.ok(sanitized.length <= 80);
  assert.doesNotMatch(sanitized, /abc123|abcdefghijklmnop|user:pass|topsecret/);
  assert.doesNotMatch(sanitized, /[\r\n\u001b]/);
  assert.match(sanitized, /REDACTED/);
});

test("diagnostics compare a versioned runtime against the promoted release marker", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-promotion-"));
  try {
    const releaseId = "0.3.0-rc.1+abcdef1";
    const runtimePath = join(root, "releases", releaseId, "server", "agent-bridge.mjs");
    const runtimeHash = "a".repeat(64);
    await mkdir(join(root, "releases", releaseId, "server"), { recursive: true });
    await writeFile(runtimePath, "runtime");
    await writeFile(join(root, "current-release.json"), JSON.stringify({ schemaVersion: 1, releaseId, releasePath: join(root, "releases", releaseId), runtimeSha256: runtimeHash }));
    const config = { agents: {}, defaults: { timeoutSec: 1, sandbox: "read-only" }, allowedRoots: [process.cwd()], handoffMaxChars: 1000, stateDir: join(root, "state"), sessionLockWaitMs: 0, sessionLockStaleMs: 60000, configPath: join(root, "config.json"), configSource: "test" };
    const current = buildDiagnostics(config, new Map(), { runtime: { path: runtimePath, sha256: runtimeHash } });
    assert.equal(current.promotion.status, "current");
    const drift = buildDiagnostics(config, new Map(), { runtime: { path: runtimePath, sha256: "b".repeat(64) } });
    assert.equal(drift.promotion.status, "drift");
    assert.match(drift.promotion.detail, /SHA-256 differs/i);
  } finally { await rm(root, { recursive: true, force: true }); }
});
