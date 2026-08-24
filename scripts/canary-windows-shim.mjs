import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

if (process.platform !== "win32") throw new Error("canary-windows-shim.mjs requires Windows");

const args = parseArgs(process.argv.slice(2));
const releasePath = await realpath(requiredAbsoluteDirectory(args, "release-path"));
const installRoot = await realpath(requiredAbsoluteDirectory(args, "install-root"));
const releasesRoot = await realpath(join(installRoot, "releases"));
if (!samePath(dirname(releasePath), releasesRoot)) {
  throw new Error(`--release-path must be one immutable release directly below ${releasesRoot}`);
}
const expectedVersion = required(args, "expected-version");
const expectedRuntimeSha256 = required(args, "expected-runtime-sha256").toLowerCase();
if (!/^[a-f0-9]{64}$/.test(expectedRuntimeSha256)) throw new Error("--expected-runtime-sha256 must be a lowercase SHA-256 digest");

const runtime = resolve(releasePath, "server", "agent-bridge.mjs");
if (!existsSync(runtime)) throw new Error(`installed runtime not found: ${runtime}`);
const canonicalRuntime = await realpath(runtime);
const runtimeRelative = relative(releasePath, canonicalRuntime).replaceAll("\\", "/");
if (runtimeRelative !== "server/agent-bridge.mjs") throw new Error("installed runtime escaped or did not match the selected immutable release path");
assert.equal(sha256(await readFile(canonicalRuntime)), expectedRuntimeSha256, "installed runtime hash differs from release evidence");

const evidenceRoot = requiredAbsolutePath(required(args, "evidence-dir"), "evidence-dir");
if (existsSync(evidenceRoot)) throw new Error(`refusing to overwrite existing evidence directory: ${evidenceRoot}`);
const canonicalEvidenceTarget = await canonicalizeProspectivePath(evidenceRoot);
if (isInsideOrEqual(installRoot, canonicalEvidenceTarget)) throw new Error("--evidence-dir resolves inside the Agent Bridge install root");
await mkdir(evidenceRoot, { recursive: true });
const canonicalEvidenceRoot = await realpath(evidenceRoot);
if (isInsideOrEqual(installRoot, canonicalEvidenceRoot)) throw new Error("created evidence directory unexpectedly resolved inside the Agent Bridge install root");

const stablePaths = {
  shim: join(installRoot, "agent-bridge.mjs"),
  config: join(installRoot, "config.json"),
  marker: join(installRoot, "current-release.json"),
};
const stableFilesBefore = await hashOptionalFiles(stablePaths);
const canonicalTemporaryRoot = await realpath(tmpdir());
if (isInsideOrEqual(installRoot, canonicalTemporaryRoot)) {
  throw new Error("the system temporary directory resolves inside the Agent Bridge install root");
}
const fixtureRoot = await mkdtemp(join(tmpdir(), "agent bridge installed shim canary "));
const work = join(fixtureRoot, "work");
const state = join(fixtureRoot, "state");
const prefix = join(fixtureRoot, "Creator Tools");
const entry = join(prefix, "node_modules", "canary-codex", "cli.mjs");
const shim = join(prefix, "canary-codex.cmd");
const logPath = join(fixtureRoot, "argv-log.jsonl");
// Keep the sentinel target free of spaces. A vulnerable cmd.exe launch can
// split an unquoted redirect target at the first space and otherwise make an
// exact-file assertion look safe even though another command executed.
const sentinel = join(canonicalTemporaryRoot, `agent-bridge-shim-injection-${randomUUID()}.sentinel`);
const configPath = join(fixtureRoot, "config.json");
const model = `canary-model & echo injected > ${sentinel}`;
const extraArg = `--canary-extra=x&echo injected>${sentinel}`;
const prompt = `Return the exact local canary acknowledgement; do not execute: x&echo injected>${sentinel}`;
let health;
let diagnostic;
let turn;
let argvPreserved = false;
let sentinelAbsent = false;
let failure;

try {
  await Promise.all([mkdir(work, { recursive: true }), mkdir(state, { recursive: true }), mkdir(dirname(entry), { recursive: true })]);
  await writeFile(entry, [
    'import { appendFile } from "node:fs/promises";',
    'const args = process.argv.slice(2);',
    'let stdin = ""; process.stdin.setEncoding("utf8"); for await (const chunk of process.stdin) stdin += chunk;',
    `await appendFile(${JSON.stringify(logPath)}, JSON.stringify({ args, stdin }) + "\\n");`,
    'if (args[0] === "--version") { console.log("canary-codex 1.0.0"); process.exit(0); }',
    'if (args[0] === "login" && args[1] === "status") { console.log("Logged in"); process.exit(0); }',
    'console.log(JSON.stringify({ type: "thread.started", thread_id: "canary-native" }));',
    'console.log(JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "CANARY_READ_ONLY_OK" } }));',
    'console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 1 } }));',
  ].join("\n"), "utf8");
  await writeFile(shim, [
    "@ECHO off", "GOTO start", ":find_dp0", "SET dp0=%~dp0", "EXIT /b", ":start", "SETLOCAL", "CALL :find_dp0",
    "IF EXIST \"%dp0%\\node.exe\" ( SET \"_prog=%dp0%\\node.exe\" ) ELSE ( SET \"_prog=node\" )",
    "endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" \"%dp0%\\node_modules\\canary-codex\\cli.mjs\" %*",
  ].join("\r\n"), "utf8");
  await writeFile(configPath, `${JSON.stringify({
    agents: {
      codex: { enabled: true, bin: shim, extraArgs: [extraArg] },
      claude: { enabled: false }, gemini: { enabled: false }, manus: { enabled: false },
    },
    defaults: { cwd: work, sandbox: "read-only", timeoutSec: 30 },
    allowedRoots: [work],
    policy: { sandboxCeiling: "read-only", remoteEgress: { enabled: false, allowedAgents: [], allowedRoots: [], allowedDataClasses: [] } },
    handoffMaxChars: 24_000, stateDir: state, sessionLockWaitMs: 30_000, sessionLockStaleMs: 7_500_000,
  }, null, 2)}\n`, "utf8");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [canonicalRuntime, "--config", configPath],
    env: childEnvironment(), stderr: "pipe",
  });
  const client = new Client({ name: "agent-bridge-installed-windows-shim-canary", version: "1.0.0" });
  try {
    await client.connect(transport);
    health = await client.callTool({ name: "list_agents", arguments: {} });
    assert.notEqual(health.isError, true, JSON.stringify(health));
    const agents = health.structuredContent?.agents;
    assert.equal(Array.isArray(agents), true, "list_agents did not return agents");
    assert.equal(agents.length, 1, "canary unexpectedly enabled another provider");
    assert.equal(agents[0].id, "codex");
    assert.equal(agents[0].health?.usable, true, `mock Codex health was not usable: ${JSON.stringify(agents[0].health)}`);
    diagnostic = await client.callTool({ name: "diagnose_install", arguments: {} });
    assert.notEqual(diagnostic.isError, true, JSON.stringify(diagnostic));
    const runtimeIdentity = diagnostic.structuredContent?.diagnostics?.runtime;
    assert.equal(runtimeIdentity?.version, expectedVersion, "installed runtime reported an unexpected version");
    assert.equal(runtimeIdentity?.sha256, expectedRuntimeSha256, "installed runtime reported an unexpected SHA-256");
    assert.equal(samePath(await realpath(runtimeIdentity?.path), canonicalRuntime), true, "installed runtime reported a different path");
    turn = await client.callTool({ name: "delegate_task", arguments: { agent: "codex", prompt, cwd: work, model } });
    assert.notEqual(turn.isError, true, JSON.stringify(turn));
    assert.equal(turn.structuredContent?.is_error, false, "mock Codex turn failed");
  } finally {
    await client.close().catch(() => {});
  }

  const launches = (await readFile(logPath, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const delegate = launches.find((launch) => launch.args?.[0] === "exec");
  assert.ok(delegate, "mock Codex did not receive a delegated exec argv");
  const expectedDelegateArgs = [
    "exec", "--json", "--skip-git-repo-check", "--ignore-user-config",
    "--cd", work, "--sandbox", "read-only", "--model", model, extraArg, "-",
  ];
  argvPreserved = JSON.stringify(delegate.args) === JSON.stringify(expectedDelegateArgs) && delegate.stdin === prompt;
  assert.equal(argvPreserved, true, "shell-sensitive model, extension argument, cwd, or stdin changed before mock Codex");
} catch (error) {
  failure = safeError(error);
} finally {
  sentinelAbsent = !existsSync(sentinel);
  if (!sentinelAbsent) failure ??= "a shell metacharacter created the injection sentinel";
  const stableFilesAfter = await hashOptionalFiles(stablePaths);
  if (JSON.stringify(stableFilesAfter) !== JSON.stringify(stableFilesBefore)) {
    failure ??= "canary changed the stable shim, shared config, or promotion marker";
  }
  const evidence = {
    schemaVersion: 1,
    status: failure ? "fail" : "pass",
    runId: randomUUID(),
    checkedAt: new Date().toISOString(),
    releasePath,
    runtimePath: canonicalRuntime,
    version: expectedVersion,
    runtimeSha256: expectedRuntimeSha256,
    health: summarizeTool(health),
    diagnostic: summarizeTool(diagnostic),
    turn: summarizeTool(turn),
    argvPreserved,
    sentinelAbsent,
    stableFilesBefore,
    stableFilesAfter,
    ...(failure ? { failure } : {}),
  };
  try { await rm(fixtureRoot, { recursive: true, force: true }); } catch { /* evidence is still written */ }
  try { await rm(sentinel, { force: true }); } catch { /* status still records whether it existed */ }
  const evidencePath = join(canonicalEvidenceRoot, "canary-windows-shim-evidence.json");
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ ...evidence, evidencePath }, null, 2)}\n`);
  if (failure) process.exitCode = 1;
}

function summarizeTool(result) {
  if (!result) return { ran: false };
  return { ran: true, isError: result.isError === true };
}
function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index]; const value = values[index + 1];
    if (!flag?.startsWith("--") || value === undefined || value.startsWith("--")) throw new Error(`invalid argument near ${flag ?? "(end)"}`);
    const key = flag.slice(2); if (Object.hasOwn(parsed, key)) throw new Error(`duplicate argument --${key}`); parsed[key] = value;
  }
  const known = new Set(["release-path", "install-root", "expected-version", "expected-runtime-sha256", "evidence-dir"]);
  for (const key of Object.keys(parsed)) if (!known.has(key)) throw new Error(`unknown argument --${key}`);
  return parsed;
}
function required(values, name) { const value = values[name]; if (typeof value !== "string" || !value) throw new Error(`--${name} is required`); return value; }
function requiredAbsolutePath(value, name) { if (!isAbsolute(value)) throw new Error(`--${name} must be an absolute path`); return resolve(value); }
function requiredAbsoluteDirectory(values, name) { const value = requiredAbsolutePath(required(values, name), name); if (!existsSync(value) || !statSync(value).isDirectory()) throw new Error(`--${name} must be an existing directory: ${value}`); return value; }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
async function hashOptionalFiles(paths) { const result = {}; for (const [name, path] of Object.entries(paths)) result[name] = existsSync(path) ? sha256(await readFile(path)) : null; return result; }
function childEnvironment() { const names = ["PATH", "PATHEXT", "SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA"]; return Object.fromEntries(names.flatMap((name) => process.env[name] === undefined ? [] : [[name, process.env[name]]])); }
function samePath(left, right) { return left.toLowerCase() === right.toLowerCase(); }
function isInsideOrEqual(parent, child) { const value = relative(parent, child); return value === "" || (!value.startsWith("..") && !isAbsolute(value)); }
async function canonicalizeProspectivePath(target) { let existing = target; const missing = []; while (!existsSync(existing)) { const parent = dirname(existing); if (samePath(parent, existing)) throw new Error(`no existing ancestor for evidence path: ${target}`); missing.unshift(existing.slice(parent.length).replace(/^[\\/]+/, "")); existing = parent; } const canonicalExisting = await realpath(existing); if (!statSync(canonicalExisting).isDirectory()) throw new Error(`evidence path ancestor is not a directory: ${existing}`); return resolve(canonicalExisting, ...missing); }
function safeError(error) { return (error instanceof Error ? error.message : String(error)).replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").replace(/[A-Za-z]:\\[^\s,;]+/g, "<path>").slice(0, 500); }
