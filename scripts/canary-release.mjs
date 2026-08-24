import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const REQUIRED_TOOLS = [
  "archive_workboard", "cancel_work_item", "cancel_workboard", "collect_recommendations", "complete_workboard",
  "continue_session", "create_workboard", "decide_approval", "decide_work_item_approval", "delegate_task",
  "diagnose_install", "get_budget_status", "get_creator_status", "get_session", "get_turn_output", "get_workboard", "handoff", "list_agents",
  "get_manus_waiting_action", "list_approvals", "list_sessions", "list_workboards", "pause_workboard",
  "preview_manus_confirmation", "preview_recommendation_approval", "preview_turn_approval", "reconcile_manus_task", "request_approval",
  "resume_workboard", "retry_work_item", "review_work_item", "run_work_item", "confirm_manus_action",
];

const args = parseArgs(process.argv.slice(2));
const profile = args.profile ?? "strict";
if (!["strict", "rollback-minimum"].includes(profile)) throw new Error("--profile must be strict or rollback-minimum");
const promotion = args.promotion ?? "unpromoted";
if (!["current", "unpromoted"].includes(promotion)) throw new Error("--promotion must be current or unpromoted");
const requiredTools = profile === "strict" ? REQUIRED_TOOLS : ["list_agents"];
const entrypoint = args.entrypoint ?? "runtime";
if (!["runtime", "stable-shim"].includes(entrypoint)) throw new Error("--entrypoint must be runtime or stable-shim");
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
const runtimeRelative = relative(releasePath, canonicalRuntime);
if (runtimeRelative.startsWith("..") || isAbsolute(runtimeRelative) || runtimeRelative.replaceAll("\\", "/") !== "server/agent-bridge.mjs") {
  throw new Error("installed runtime escaped or did not match the selected immutable release path");
}
const actualRuntimeSha256 = sha256(await readFile(canonicalRuntime));
assert.equal(actualRuntimeSha256, expectedRuntimeSha256, "installed runtime hash differs from release evidence");
if (profile === "rollback-minimum") {
  const releaseMetadata = JSON.parse(await readFile(join(releasePath, "release-metadata.json"), "utf8"));
  assert.equal(releaseMetadata.version, expectedVersion, "release metadata version differs from expected version");
  assert.equal(releaseMetadata.files?.["server/agent-bridge.mjs"]?.sha256, expectedRuntimeSha256, "release metadata runtime hash differs from expected runtime hash");
}

const stablePaths = {
  shim: join(installRoot, "agent-bridge.mjs"),
  config: join(installRoot, "config.json"),
  marker: join(installRoot, "current-release.json"),
};
const localPromotion = await inspectLocalPromotion({ stablePaths, releasePath, expectedRuntimeSha256 });
let expectedStableConfigSha256 = null;
let expectedStableShimSha256 = null;
if (entrypoint === "stable-shim") {
  assert.equal(promotion, "current", "stable-shim entrypoint requires --promotion current");
  expectedStableShimSha256 = required(args, "expected-stable-shim-sha256").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expectedStableShimSha256)) throw new Error("--expected-stable-shim-sha256 must be a lowercase SHA-256 digest");
  assert.equal(localPromotion.hashes.shim, expectedStableShimSha256, "stable shim hash differs from the reviewed switch result");
  const stableShim = await readFile(stablePaths.shim, "utf8");
  const imports = [...stableShim.matchAll(/^await import\(new URL\("(\.\/releases\/[^"\r\n]+\/server\/agent-bridge\.mjs)", import\.meta\.url\)\.href\);$/gm)];
  assert.equal(imports.length, 1, "stable shim must contain exactly one generated immutable-runtime import");
  assert.equal(imports[0][1], `./releases/${releasePath.split(/[\\/]/).pop()}/server/agent-bridge.mjs`, "stable shim import does not target the selected immutable runtime");
  expectedStableConfigSha256 = required(args, "expected-stable-config-sha256").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expectedStableConfigSha256)) throw new Error("--expected-stable-config-sha256 must be a lowercase SHA-256 digest");
  assert.equal(localPromotion.hashes.config, expectedStableConfigSha256, "stable shared config hash differs from the reviewed fixture config");
  const stableConfig = JSON.parse(await readFile(stablePaths.config, "utf8"));
  assert.ok(stableConfig && typeof stableConfig === "object" && !Array.isArray(stableConfig), "stable shared config must be a JSON object");
  assert.ok(stableConfig.agents && typeof stableConfig.agents === "object" && !Array.isArray(stableConfig.agents), "stable shared config must declare disabled agents");
  for (const [id, agent] of Object.entries(stableConfig.agents)) {
    assert.equal(agent?.enabled, false, `stable-shim canary refuses enabled backend ${id}`);
  }
  assert.notEqual(stableConfig.policy?.remoteEgress?.enabled, true, "stable-shim canary refuses enabled remote egress");
}
const before = await hashOptionalFiles(stablePaths);
let evidenceRoot;
let createdDefaultEvidenceRoot = false;
if (args["evidence-dir"]) {
  evidenceRoot = requiredAbsolutePath(args["evidence-dir"], "evidence-dir");
} else {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  if (isInsideOrEqual(installRoot, canonicalTemporaryRoot)) {
    throw new Error("the system temporary directory resolves inside the Agent Bridge install root");
  }
  evidenceRoot = await mkdtemp(join(canonicalTemporaryRoot, "agent-bridge-release-canary-"));
  createdDefaultEvidenceRoot = true;
}
if (isInsideOrEqual(installRoot, evidenceRoot)) {
  throw new Error("--evidence-dir must be outside the Agent Bridge install root and immutable releases");
}
if (args["evidence-dir"] && existsSync(evidenceRoot)) throw new Error(`refusing to overwrite existing evidence directory: ${evidenceRoot}`);
const canonicalEvidenceTarget = await canonicalizeProspectivePath(evidenceRoot);
if (isInsideOrEqual(installRoot, canonicalEvidenceTarget)) {
  throw new Error("--evidence-dir resolves inside the Agent Bridge install root through an existing link or junction");
}
await mkdir(evidenceRoot, { recursive: true });
const createdEvidenceRoot = await realpath(evidenceRoot);
if (isInsideOrEqual(installRoot, createdEvidenceRoot)) {
  if (createdDefaultEvidenceRoot) await rm(evidenceRoot, { recursive: true, force: true });
  throw new Error("created evidence directory unexpectedly resolved inside the Agent Bridge install root");
}
const work = join(evidenceRoot, "work");
const state = join(evidenceRoot, "state");
await Promise.all([mkdir(work, { recursive: true }), mkdir(state, { recursive: true })]);
const configPath = join(evidenceRoot, "config.json");
const canaryConfig = {
  agents: {
    codex: { enabled: false }, claude: { enabled: false },
    ...(profile === "strict" ? { gemini: { enabled: false }, manus: { enabled: false } } : {}),
  },
  defaults: { cwd: work, sandbox: "read-only", timeoutSec: 30 },
  allowedRoots: [work],
  handoffMaxChars: 24_000,
  stateDir: state,
  sessionLockWaitMs: 30_000,
  sessionLockStaleMs: 7_500_000,
  ...(profile === "strict" ? {
    policy: {
      sandboxCeiling: "read-only",
      remoteEgress: { enabled: false, allowedAgents: [], allowedRoots: [], allowedDataClasses: [] },
    },
  } : {}),
};
await writeFile(configPath, `${JSON.stringify(canaryConfig, null, 2)}\n`, "utf8");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: entrypoint === "stable-shim" ? [join(installRoot, "agent-bridge.mjs")] : [canonicalRuntime, "--config", configPath],
  env: childEnvironment(),
  stderr: "pipe",
});
const client = new Client({ name: "agent-bridge-installed-release-canary", version: "1.0.0" });
let tools;
let diagnostic;
let budgetStatus;
let agents;
let serverVersion;
try {
  await client.connect(transport);
  serverVersion = client.getServerVersion();
  assert.equal(serverVersion?.version, expectedVersion, "MCP initialize server version differs from expected version");
  tools = await client.listTools();
  const names = new Set(tools.tools.map((tool) => tool.name));
  for (const name of requiredTools) assert.ok(names.has(name), `installed runtime is missing required MCP tool ${name}`);
  if (profile === "strict") {
    diagnostic = await client.callTool({ name: "diagnose_install", arguments: {} });
    assert.notEqual(diagnostic.isError, true, JSON.stringify(diagnostic));
  }
  agents = await client.callTool({ name: "list_agents", arguments: {} });
  assert.notEqual(agents.isError, true, JSON.stringify(agents));
  if (profile === "strict") budgetStatus = await client.callTool({ name: "get_budget_status", arguments: {} });
  if (profile === "strict") {
    assert.notEqual(budgetStatus.isError, true, JSON.stringify(budgetStatus));
    assert.deepEqual(budgetStatus.structuredContent.budget, { enabled: false }, "provider-disabled canary unexpectedly enabled a cumulative remote-cost budget");
    assert.deepEqual(diagnostic.structuredContent.budget, { enabled: false }, "diagnostics and the dedicated budget tool disagree");
  }
} finally {
  await client.close().catch(() => {});
}

if (promotion === "current") assert.equal(localPromotion.current, true, "current canary local marker/shim/config state is not current");
else assert.equal(localPromotion.current, false, "unpromoted canary local marker/shim/config state is unexpectedly current");
if (profile === "strict") {
  const report = diagnostic.structuredContent.diagnostics;
  assert.equal(report.runtime.version, expectedVersion, "installed runtime reported an unexpected version");
  assert.equal(report.runtime.sha256, expectedRuntimeSha256, "diagnostics runtime hash differs from release evidence");
  assert.equal(await realpath(report.runtime.path), canonicalRuntime, "diagnostics reported a different runtime path");
  assert.equal(report.promotion.status === "current", localPromotion.current, "diagnostics and local promotion state disagree");
  assert.equal(report.state.sessionFiles, 0, "provider-disabled canary unexpectedly created a bridge session");
  assert.deepEqual(diagnostic.structuredContent.agents, [], "provider-disabled canary unexpectedly enabled a backend");
  assert.deepEqual(agents.structuredContent.agents, [], "provider-disabled canary unexpectedly enabled a backend");
}

const after = await hashOptionalFiles(stablePaths);
assert.deepEqual(after, before, "canary changed the stable shim, shared config, or promotion marker");
const evidence = {
  schemaVersion: 1,
  status: "pass",
  runId: randomUUID(),
  checkedAt: new Date().toISOString(),
  releasePath,
  runtimePath: canonicalRuntime,
  version: expectedVersion,
  runtimeSha256: expectedRuntimeSha256,
  serverVersion,
  entrypoint,
  profile,
  expectedPromotion: promotion,
  expectedStableShimSha256,
  expectedStableConfigSha256,
  promotionStatus: localPromotion.status,
  localPromotion,
  toolCount: tools.tools.length,
  requiredToolCount: requiredTools.length,
  providerCount: Array.isArray(agents.structuredContent?.agents) ? agents.structuredContent.agents.length : null,
  budget: budgetStatus?.structuredContent?.budget ?? null,
  stableFilesBefore: before,
  stableFilesAfter: after,
  configPath,
  stateDir: state,
};
const evidencePath = join(evidenceRoot, "canary-evidence.json");
await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify({ ...evidence, evidencePath }, null, 2)}\n`);

function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!flag?.startsWith("--") || value === undefined || value.startsWith("--")) throw new Error(`invalid argument near ${flag ?? "(end)"}`);
    const key = flag.slice(2);
    if (Object.hasOwn(parsed, key)) throw new Error(`duplicate argument --${key}`);
    parsed[key] = value;
  }
  const known = new Set(["release-path", "install-root", "expected-version", "expected-runtime-sha256", "expected-stable-shim-sha256", "expected-stable-config-sha256", "evidence-dir", "profile", "promotion", "entrypoint"]);
  for (const key of Object.keys(parsed)) if (!known.has(key)) throw new Error(`unknown argument --${key}`);
  return parsed;
}
function required(values, name) {
  const value = values[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`--${name} is required`);
  return value;
}
function requiredAbsolutePath(value, name) {
  if (!isAbsolute(value)) throw new Error(`--${name} must be an absolute path`);
  return resolve(value);
}
function requiredAbsoluteDirectory(values, name) {
  const value = requiredAbsolutePath(required(values, name), name);
  if (!existsSync(value)) throw new Error(`--${name} does not exist: ${value}`);
  return value;
}
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
async function hashOptionalFiles(paths) {
  const result = {};
  for (const [name, path] of Object.entries(paths)) result[name] = existsSync(path) ? sha256(await readFile(path)) : null;
  return result;
}
async function inspectLocalPromotion({ stablePaths, releasePath, expectedRuntimeSha256 }) {
  const hashes = await hashOptionalFiles(stablePaths);
  let marker = null;
  try { marker = hashes.marker ? JSON.parse(await readFile(stablePaths.marker, "utf8")) : null; } catch { /* not current */ }
  const current = marker?.schemaVersion === 1
    && marker.releaseId === releasePath.split(/[\\/]/).pop()
    && typeof marker.releasePath === "string" && samePath(marker.releasePath, releasePath)
    && marker.runtimeSha256 === expectedRuntimeSha256
    && marker.shimSha256 === hashes.shim
    && marker.configSha256 === hashes.config;
  return { status: current ? "current" : (marker ? "drift" : "marker-missing"), current, hashes };
}
function childEnvironment() {
  const names = ["PATH", "PATHEXT", "SystemRoot", "ComSpec", "TEMP", "TMP", "USERPROFILE", "HOME"];
  return Object.fromEntries(names.flatMap((name) => process.env[name] === undefined ? [] : [[name, process.env[name]]]));
}
function samePath(left, right) { return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right; }
function isInsideOrEqual(parent, child) {
  const value = relative(parent, child);
  return value === "" || (!value.startsWith("..") && !isAbsolute(value));
}
async function canonicalizeProspectivePath(target) {
  let existing = target;
  const missing = [];
  while (!existsSync(existing)) {
    const parent = dirname(existing);
    if (samePath(parent, existing)) throw new Error(`no existing ancestor for evidence path: ${target}`);
    missing.unshift(existing.slice(parent.length).replace(/^[\\/]+/, ""));
    existing = parent;
  }
  const canonicalExisting = await realpath(existing);
  if (!statSync(canonicalExisting).isDirectory()) throw new Error(`evidence path ancestor is not a directory: ${existing}`);
  return resolve(canonicalExisting, ...missing);
}
