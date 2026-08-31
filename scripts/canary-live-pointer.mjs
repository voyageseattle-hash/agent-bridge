#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { lstat, mkdir, readFile, readdir, realpath, rename, unlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";
import { RELEASE_OPERATION_CONTRACT } from "./release-operations.mjs";

const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^[a-f0-9]{40}$/;
const STRICT_VERSION = "0.3.0-rc.9";
const ROLLBACK_VERSION = "0.2.1";
const ROLLBACK_SOURCE_GIT_SHA = "4785d630c416df692869540a52466c9895cfa6d6";
const SANDBOX_MODES = ["read-only", "workspace-write", "full-access"];
const DATA_CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"];
const STRICT_TOOLS = [
  "archive_workboard", "cancel_work_item", "cancel_workboard", "collect_recommendations", "complete_workboard",
  "continue_session", "create_workboard", "decide_approval", "decide_work_item_approval", "delegate_task",
  "diagnose_install", "get_budget_status", "get_creator_status", "get_session", "get_turn_output", "get_workboard", "handoff", "list_agents",
  "get_manus_waiting_action", "list_approvals", "list_sessions", "list_workboards", "pause_workboard",
  "preview_manus_confirmation", "preview_recommendation_approval", "preview_turn_approval", "reconcile_manus_task", "request_approval",
  "resume_workboard", "retry_work_item", "review_work_item", "run_work_item", "confirm_manus_action",
];
const CONFIG_SCHEMA = z.object({
  agents: z.record(z.object({
    enabled: z.boolean().optional(),
    bin: z.string().min(1).optional(),
    defaultModel: z.string().min(1).optional(),
    extraArgs: z.array(z.string()).optional(),
    extraEnv: z.record(z.string()).optional(),
    credentialFile: z.string().min(1).optional(),
    baseUrl: z.string().url().optional(),
    allowDevelopmentBaseUrl: z.boolean().optional(),
    acknowledgeAccountDefaultCapabilities: z.boolean().optional(),
    accountCapabilityProfile: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/).optional(),
    sandboxCeiling: z.enum(SANDBOX_MODES).optional(),
  }).strict()).optional(),
  defaults: z.object({
    timeoutSec: z.number().int().positive().max(7200).optional(),
    sandbox: z.enum(SANDBOX_MODES).optional(),
    cwd: z.string().min(1).optional(),
  }).strict().optional(),
  allowedRoots: z.array(z.string().min(1)).min(1),
  policy: z.object({
    sandboxCeiling: z.enum(SANDBOX_MODES).optional(),
    remoteEgress: z.object({
      enabled: z.boolean().optional(),
      allowedAgents: z.array(z.string().min(1)).max(32).optional(),
      allowedRoots: z.array(z.string().min(1)).max(64).optional(),
      allowedDataClasses: z.array(z.enum(DATA_CLASSIFICATIONS)).max(DATA_CLASSIFICATIONS.length).optional(),
    }).strict().optional(),
    cumulativeRemoteCost: z.object({
      currency: z.literal("USD"),
      maxReservedCents: z.number().int().min(1).max(100_000_000_000),
    }).strict().optional(),
  }).strict().optional(),
  handoffMaxChars: z.number().int().min(1000).max(1_000_000).optional(),
  stateDir: z.string().min(1).optional(),
  sessionLockWaitMs: z.number().int().min(0).max(300_000).optional(),
  sessionLockStaleMs: z.number().int().min(60_000).max(86_400_000).optional(),
  _notes: z.unknown().optional(),
}).strict();

const args = parseArgs(process.argv.slice(2));
const profile = args.profile ?? "strict";
if (!['strict', 'rollback-minimum'].includes(profile)) throw new Error("--profile must be strict or rollback-minimum");
const requiredTools = profile === "strict" ? STRICT_TOOLS : ["list_agents"];
const expectedVersion = required(args, "expected-version");
const expectedSourceGitSha = requiredGitSha(args, "expected-source-git-sha");
const expectedRuntimeSha256 = requiredHash(args, "expected-runtime-sha256");
const expectedMetadataSha256 = requiredHash(args, "expected-metadata-sha256");
const expectedManifestSha256 = requiredHash(args, "expected-manifest-sha256");
const expectedStableShimSha256 = requiredHash(args, "expected-stable-shim-sha256");
const expectedSharedConfigSha256 = requiredHash(args, "expected-shared-config-sha256");

const installRoot = await canonicalDirectory(required(args, "install-root"), "--install-root");
const releasesRoot = await canonicalDirectory(join(installRoot, "releases"), "installed releases directory");
const releasePath = await canonicalDirectory(required(args, "release-path"), "--release-path");
assert.ok(samePath(dirname(releasePath), releasesRoot), "--release-path must be one immutable release directly below installRoot\\releases");

const evidenceRoot = requiredAbsolute(args, "evidence-dir");
if (existsSync(evidenceRoot)) throw new Error(`refusing to overwrite existing evidence directory: ${evidenceRoot}`);
const canonicalEvidenceTarget = await canonicalizeProspectivePath(evidenceRoot);
assert.ok(!isInsideOrEqual(installRoot, canonicalEvidenceTarget), "--evidence-dir must resolve outside the Agent Bridge install root");
assert.ok(samePath(evidenceRoot, canonicalEvidenceTarget), "--evidence-dir must not traverse a symlink or junction");

const stablePaths = {
  shim: join(installRoot, "agent-bridge.mjs"),
  config: join(installRoot, "config.json"),
  marker: join(installRoot, "current-release.json"),
};
const initialPointers = await readPointerSnapshot(stablePaths);
assert.equal(initialPointers.shim.sha256, expectedStableShimSha256, "stable shim hash differs from the expected switch result");
assert.equal(initialPointers.config.sha256, expectedSharedConfigSha256, "shared config hash differs from the expected core config");

const immutable = await inspectImmutableRelease(releasePath, {
  version: expectedVersion,
  sourceGitSha: expectedSourceGitSha,
  runtimeSha256: expectedRuntimeSha256,
  metadataSha256: expectedMetadataSha256,
  manifestSha256: expectedManifestSha256,
  profile,
});
const releaseId = basename(releasePath);
const expectedImport = `./releases/${releaseId}/server/agent-bridge.mjs`;
const shimText = initialPointers.shim.bytes.toString("utf8");
const imports = [...shimText.matchAll(/^await import\(new URL\("(\.\/releases\/[^"\r\n]+\/server\/agent-bridge\.mjs)", import\.meta\.url\)\.href\);$/gm)];
assert.equal(imports.length, 1, "stable shim must contain exactly one generated immutable-runtime import");
assert.equal(imports[0][1], expectedImport, "stable shim does not target the selected immutable release");

const marker = parseJson(initialPointers.marker.bytes, "promotion marker");
assert.equal(marker.schemaVersion, 1, "promotion marker schema is unsupported");
assert.equal(marker.releaseId, releaseId, "promotion marker release ID differs from the selected release");
assert.equal(typeof marker.releasePath, "string");
assert.ok(isAbsolute(marker.releasePath), "promotion marker release path must be absolute");
assert.ok(samePath(marker.releasePath, releasePath), "promotion marker release path differs from the selected release");
assert.equal(marker.runtimeSha256, expectedRuntimeSha256, "promotion marker runtime hash differs from the selected release");
assert.equal(marker.shimSha256, expectedStableShimSha256, "promotion marker shim hash differs from the expected switch result");
assert.equal(marker.configSha256, expectedSharedConfigSha256, "promotion marker config hash differs from the expected shared config");

const config = parseConfig(initialPointers.config.bytes);
const capabilityProjection = deriveCoreProjection(config);
const capabilityProjectionSha256 = sha256(Buffer.from(JSON.stringify({
  schemaVersion: 1,
  releaseId,
  runtimeSha256: expectedRuntimeSha256,
  configSha256: expectedSharedConfigSha256,
  profile: "windows-local-core",
  capabilities: capabilityProjection,
}), "utf8"));
const sessionStateBefore = await snapshotSessionRecords(resolveStateDir(config.stateDir));

await mkdir(evidenceRoot, { recursive: false });
const createdEvidenceRoot = await realpath(evidenceRoot);
assert.ok(samePath(createdEvidenceRoot, evidenceRoot), "created evidence directory resolved through a link or junction");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [stablePaths.shim],
  env: minimalChildEnvironment(),
  stderr: "pipe",
});
const client = new Client({ name: "agent-bridge-live-pointer-canary", version: "1.0.0" });
let serverVersion;
let toolCount = 0;
try {
  await client.connect(transport);
  serverVersion = client.getServerVersion();
  assert.equal(serverVersion?.version, expectedVersion, "MCP initialize server version differs from the selected release");
  const listed = await client.listTools();
  toolCount = listed.tools.length;
  const names = new Set(listed.tools.map((tool) => tool.name));
  for (const name of requiredTools) assert.ok(names.has(name), `stable shim runtime is missing required MCP tool ${name}`);
} finally {
  await client.close().catch(() => {});
}

const sessionStateAfter = await snapshotSessionRecords(resolveStateDir(config.stateDir));
assert.deepEqual(sessionStateAfter, sessionStateBefore, "pointer-only canary observed a created or changed session record");
const afterPointers = await readPointerSnapshot(stablePaths);
assertPointerSnapshotsEqual(afterPointers, initialPointers);
const afterImmutable = await inspectImmutableRelease(releasePath, {
  version: expectedVersion, sourceGitSha: expectedSourceGitSha, runtimeSha256: expectedRuntimeSha256,
  metadataSha256: expectedMetadataSha256, manifestSha256: expectedManifestSha256, profile,
});
assert.deepEqual(afterImmutable, immutable, "pointer-only canary observed immutable release drift");

const evidence = {
  schemaVersion: 1,
  status: "pass",
  runId: randomUUID(),
  checkedAt: new Date().toISOString(),
  releaseId,
  version: expectedVersion,
  runtimeSha256: expectedRuntimeSha256,
  metadataSha256: immutable.metadataSha256,
  manifestSha256: immutable.manifestSha256,
  immutableFileCount: immutable.fileCount,
  immutablePayloadDigest: immutable.payloadDigest,
  profile,
  acceptanceProfile: "windows-local-core",
  capabilityProjection,
  capabilityProjectionSha256,
  serverVersion,
  mcpInitializePassed: true,
  listToolsPassed: true,
  toolCount,
  requiredToolCount: requiredTools.length,
  providerDelegationsAttempted: 0,
  sessionRecordsBefore: sessionStateBefore.count,
  sessionRecordsAfter: sessionStateAfter.count,
  sessionRecordDigestBefore: sessionStateBefore.digest,
  sessionRecordDigestAfter: sessionStateAfter.digest,
  stableFilesBefore: publicPointerHashes(initialPointers),
  stableFilesAfter: publicPointerHashes(afterPointers),
  environmentContract: "minimal-system-no-agent-bridge-config-credential-or-provider-overrides",
};
const temporaryEvidencePath = join(evidenceRoot, ".canary-live-pointer-evidence.json.tmp");
const evidencePath = join(evidenceRoot, "canary-live-pointer-evidence.json");
await writeFile(temporaryEvidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
try {
  const finalPointers = await readPointerSnapshot(stablePaths);
  assertPointerSnapshotsEqual(finalPointers, initialPointers);
  const finalImmutable = await inspectImmutableRelease(releasePath, {
    version: expectedVersion, sourceGitSha: expectedSourceGitSha, runtimeSha256: expectedRuntimeSha256,
    metadataSha256: expectedMetadataSha256, manifestSha256: expectedManifestSha256, profile,
  });
  assert.deepEqual(finalImmutable, immutable, "pointer-only canary observed immutable release drift before evidence publication");
  const finalSessions = await snapshotSessionRecords(resolveStateDir(config.stateDir));
  assert.deepEqual(finalSessions, sessionStateBefore, "pointer-only canary observed session drift before evidence publication");
  await rename(temporaryEvidencePath, evidencePath);
} catch (error) {
  await unlink(temporaryEvidencePath).catch(() => {});
  throw error;
}
process.stdout.write(`${JSON.stringify({ ...evidence, evidencePath }, null, 2)}\n`);

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!flag?.startsWith("--") || value === undefined || value.startsWith("--")) throw new Error(`invalid argument near ${flag ?? "(end)"}`);
    const key = flag.slice(2);
    if (Object.hasOwn(result, key)) throw new Error(`duplicate argument --${key}`);
    result[key] = value;
  }
  const known = new Set(["release-path", "install-root", "expected-version", "expected-source-git-sha", "expected-runtime-sha256", "expected-metadata-sha256", "expected-manifest-sha256", "expected-stable-shim-sha256", "expected-shared-config-sha256", "evidence-dir", "profile"]);
  for (const key of Object.keys(result)) if (!known.has(key)) throw new Error(`unknown argument --${key}`);
  return result;
}
function required(values, name) {
  const value = values[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`--${name} is required`);
  return value;
}
function requiredAbsolute(values, name) {
  const value = required(values, name);
  if (!isAbsolute(value)) throw new Error(`--${name} must be an absolute path`);
  return resolve(value);
}
function requiredHash(values, name) {
  const value = required(values, name);
  if (!SHA256.test(value)) throw new Error(`--${name} must be a lowercase SHA-256 digest`);
  return value;
}
function requiredGitSha(values, name) {
  const value = required(values, name);
  if (!GIT_SHA.test(value)) throw new Error(`--${name} must be a lowercase 40-character Git SHA`);
  return value;
}
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function parseJson(bytes, label) {
  try { return JSON.parse(bytes.toString("utf8")); }
  catch { throw new Error(`${label} is not valid JSON`); }
}
async function canonicalDirectory(value, label) {
  if (!isAbsolute(value)) throw new Error(`${label} must be an absolute path`);
  const requested = resolve(value);
  const info = await lstat(requested);
  assert.ok(info.isDirectory() && !info.isSymbolicLink(), `${label} must be a real directory, not a symlink or junction`);
  const canonical = await realpath(requested);
  assert.ok(samePath(canonical, requested), `${label} must not traverse a symlink or junction`);
  return canonical;
}
async function readRegularPinnedFile(path, label) {
  const info = await lstat(path);
  assert.ok(info.isFile() && !info.isSymbolicLink(), `${label} must be a regular file, not a symlink`);
  const canonical = await realpath(path);
  assert.ok(samePath(canonical, resolve(path)), `${label} must not traverse a symlink or junction`);
  const bytes = await readFile(path);
  return { bytes, sha256: sha256(bytes), size: bytes.byteLength };
}
async function readPointerSnapshot(paths) {
  return {
    shim: await readRegularPinnedFile(paths.shim, "stable shim"),
    config: await readRegularPinnedFile(paths.config, "shared config"),
    marker: await readRegularPinnedFile(paths.marker, "promotion marker"),
  };
}
function publicPointerHashes(snapshot) {
  return { shim: snapshot.shim.sha256, config: snapshot.config.sha256, marker: snapshot.marker.sha256 };
}
function assertPointerSnapshotsEqual(actual, expected) {
  assert.deepEqual(publicPointerHashes(actual), publicPointerHashes(expected), "pointer-only canary changed or observed drift in the stable shim, shared config, or promotion marker");
}
async function inspectImmutableRelease(root, expected) {
  const { version, sourceGitSha, runtimeSha256, metadataSha256, manifestSha256, profile: toolProfile } = expected;
  const metadataRecord = await readRegularPinnedFile(join(root, "release-metadata.json"), "release metadata");
  const manifestRecord = await readRegularPinnedFile(join(root, "manifest.json"), "installed manifest");
  assert.equal(metadataRecord.sha256, metadataSha256, "release metadata hash differs from the reviewed package record");
  assert.equal(manifestRecord.sha256, manifestSha256, "installed manifest hash differs from the reviewed package record");
  const metadata = parseJson(metadataRecord.bytes, "release metadata");
  const manifest = parseJson(manifestRecord.bytes, "installed manifest");
  assert.equal(metadata.version, version, "release metadata version differs from the expected version");
  assert.match(metadata.gitSha, GIT_SHA, "release metadata Git SHA is invalid");
  assert.equal(metadata.gitSha, sourceGitSha, "release metadata Git SHA differs from the reviewed package record");
  assert.equal(basename(root), `${version}+${metadata.gitSha.slice(0, 7)}`, "immutable release directory identity differs from release metadata");
  assert.ok(metadata.files && typeof metadata.files === "object" && !Array.isArray(metadata.files), "release metadata files map is missing");
  assert.equal(metadata.files["server/agent-bridge.mjs"]?.sha256, runtimeSha256, "release metadata runtime hash differs from the expected runtime");
  if (toolProfile === "strict") {
    assert.equal(version, STRICT_VERSION, "strict pointer canary is limited to RC9");
    assert.equal(manifest.manifest_version, "0.3", "strict pointer canary requires the RC9 manifest schema");
    assert.deepEqual(metadata.operations, RELEASE_OPERATION_CONTRACT, "strict pointer canary requires the RC9 immutable operation contract");
    assert.deepEqual(Object.keys(metadata.files).sort(), [...RELEASE_OPERATION_CONTRACT.payloads].sort(), "strict pointer canary requires the complete RC9 immutable payload set");
  } else {
    assert.equal(version, ROLLBACK_VERSION, "rollback-minimum is limited to the historical v0.2.1 runtime");
    assert.equal(sourceGitSha, ROLLBACK_SOURCE_GIT_SHA, "rollback-minimum requires the exact historical v0.2.1 source Git SHA");
  }
  assert.equal(manifest.version, version, "installed manifest version differs from the expected version");
  let releaseIdentity = manifest._meta?.["com.agentbridge.release"];
  let legacyManifestIdentity = false;
  if (toolProfile === "rollback-minimum") {
    assert.equal(manifest.manifest_version, "0.1", "rollback-minimum requires the historical v0.2.1 manifest schema");
    assert.equal(releaseIdentity, undefined, "rollback-minimum requires the historical manifest metadata identity");
  }
  if (releaseIdentity === undefined) {
    assert.equal(toolProfile, "rollback-minimum", "strict pointer canary requires the namespaced manifest release identity");
    assert.equal(version, ROLLBACK_VERSION, "legacy manifest identity is accepted only for the exact v0.2.1 rollback runtime");
    assert.equal(manifest.manifest_version, "0.1", "legacy v0.2.1 manifest version must be 0.1");
    assert.equal(Object.hasOwn(metadata, "operations"), false, "legacy v0.2.1 release metadata must be operation-free");
    releaseIdentity = manifest.metadata;
    assert.ok(releaseIdentity && typeof releaseIdentity === "object" && !Array.isArray(releaseIdentity), "legacy v0.2.1 manifest metadata identity is missing or invalid");
    assert.deepEqual(Object.keys(releaseIdentity).sort(), ["runtime_sha256", "source_git_sha"], "legacy v0.2.1 manifest metadata identity has unexpected fields");
    legacyManifestIdentity = true;
  }
  assert.ok(releaseIdentity && typeof releaseIdentity === "object" && !Array.isArray(releaseIdentity), "installed manifest release identity is missing or invalid");
  assert.equal(releaseIdentity.source_git_sha, metadata.gitSha, "installed manifest Git identity differs from release metadata");
  assert.equal(releaseIdentity.runtime_sha256, runtimeSha256, "installed manifest runtime hash differs from the expected runtime");
  const payload = [];
  for (const relativePath of Object.keys(metadata.files).sort()) {
    assert.ok(isSafeMetadataPath(relativePath), `release metadata contains an unsafe payload path: ${relativePath}`);
    const expected = metadata.files[relativePath];
    assert.match(expected?.sha256, SHA256, `release metadata SHA-256 is invalid for ${relativePath}`);
    if (expected?.bytes === undefined) {
      assert.equal(legacyManifestIdentity, true, `release metadata byte count is missing for ${relativePath}`);
    } else {
      assert.ok(Number.isSafeInteger(expected.bytes) && expected.bytes >= 0, `release metadata byte count is invalid for ${relativePath}`);
    }
    const path = resolve(root, ...relativePath.split("/"));
    assert.ok(isInsideOrEqual(root, path), `release metadata payload escapes the immutable release: ${relativePath}`);
    const actual = await readRegularPinnedFile(path, `immutable payload ${relativePath}`);
    assert.equal(actual.sha256, expected.sha256, `immutable payload hash differs for ${relativePath}`);
    if (expected.bytes !== undefined) assert.equal(actual.size, expected.bytes, `immutable payload byte count differs for ${relativePath}`);
    payload.push([relativePath, actual.sha256, actual.size]);
  }
  const runtime = payload.find(([name]) => name === "server/agent-bridge.mjs");
  assert.ok(runtime, "release metadata omits server/agent-bridge.mjs");
  return {
    metadataSha256: metadataRecord.sha256,
    manifestSha256: manifestRecord.sha256,
    fileCount: payload.length,
    payloadDigest: sha256(Buffer.from(JSON.stringify(payload), "utf8")),
  };
}
function isSafeMetadataPath(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\\") || value.startsWith("/") || value.includes(":")) return false;
  const parts = value.split("/");
  return parts.every((part) => part.length > 0 && part !== "." && part !== "..");
}
function parseConfig(bytes) {
  const raw = parseJson(bytes, "shared config");
  const parsed = CONFIG_SCHEMA.safeParse(raw);
  if (!parsed.success) throw new Error(`shared config fails the RC9 runtime schema: ${parsed.error.issues.map((issue) => issue.path.join(".") || "root").join(", ")}`);
  return parsed.data;
}
function deriveCoreProjection(config) {
  const agents = config.agents ?? {};
  const enabled = (id, fallback) => agents[id]?.enabled ?? fallback;
  const unknownEnabledAgents = Object.entries(agents).filter(([id, value]) => !["codex", "claude", "gemini", "manus"].includes(id) && value.enabled !== false).map(([id]) => id);
  assert.deepEqual(unknownEnabledAgents, [], "windows-local-core does not allow enabled unknown agents");
  const projection = {
    codexEnabled: enabled("codex", true),
    claudeEnabled: enabled("claude", true),
    geminiEnabled: enabled("gemini", false),
    manusEnabled: enabled("manus", false),
    directRemoteEgressEnabled: config.policy?.remoteEgress?.enabled ?? false,
    directRemoteAllowedAgentCount: new Set(config.policy?.remoteEgress?.allowedAgents ?? []).size,
  };
  assert.equal(projection.codexEnabled, true, "windows-local-core requires Codex enabled");
  assert.equal(projection.claudeEnabled, true, "windows-local-core requires Claude enabled");
  assert.equal(projection.geminiEnabled, false, "windows-local-core requires Gemini disabled");
  assert.equal(projection.manusEnabled, false, "windows-local-core requires Manus disabled");
  assert.equal(projection.directRemoteEgressEnabled, false, "windows-local-core requires direct remote egress disabled");
  assert.equal(projection.directRemoteAllowedAgentCount, 0, "windows-local-core requires an empty direct-remote allowlist");
  return projection;
}
function resolveStateDir(value) {
  if (!value) return join(homedir(), ".agent-bridge");
  if (value === "~") return homedir();
  if (value.startsWith("~/") || value.startsWith("~\\")) return resolve(homedir(), value.slice(2));
  return resolve(value);
}
async function snapshotSessionRecords(stateDir) {
  const sessionDir = join(stateDir, "sessions");
  if (!existsSync(sessionDir)) return { count: 0, digest: sha256(Buffer.from("[]", "utf8")) };
  const info = await lstat(sessionDir);
  assert.ok(info.isDirectory() && !info.isSymbolicLink(), "session record directory must not be a symlink or junction");
  const canonicalSessionDir = await realpath(sessionDir);
  assert.ok(samePath(canonicalSessionDir, sessionDir), "session record directory must not traverse a symlink or junction");
  const records = [];
  for (const entry of (await readdir(canonicalSessionDir, { withFileTypes: true })).sort((left, right) => left.name.localeCompare(right.name))) {
    const path = join(canonicalSessionDir, entry.name);
    const item = await lstat(path);
    assert.ok(!item.isSymbolicLink(), "session record snapshot refuses symlink entries");
    if (item.isFile()) {
      const bytes = await readFile(path);
      records.push([entry.name, "file", bytes.byteLength, sha256(bytes)]);
    } else {
      records.push([entry.name, item.isDirectory() ? "directory" : "other", item.size, null]);
    }
  }
  return { count: records.filter(([name, type]) => type === "file" && name.endsWith(".json")).length, digest: sha256(Buffer.from(JSON.stringify(records), "utf8")) };
}
function minimalChildEnvironment() {
  const allowed = ["SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"];
  return Object.fromEntries(allowed.flatMap((name) => process.env[name] === undefined ? [] : [[name, process.env[name]]]));
}
function samePath(left, right) {
  const normalize = (value) => resolve(value).replace(/^\\\\\?\\/, "");
  return process.platform === "win32" ? normalize(left).toLowerCase() === normalize(right).toLowerCase() : normalize(left) === normalize(right);
}
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
    missing.unshift(basename(existing));
    existing = parent;
  }
  const canonicalExisting = await realpath(existing);
  const info = await lstat(existing);
  assert.ok(info.isDirectory(), "evidence path ancestor must be a directory");
  return resolve(canonicalExisting, ...missing);
}
