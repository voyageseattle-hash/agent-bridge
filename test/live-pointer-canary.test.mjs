import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { RELEASE_OPERATION_CONTRACT, RELEASE_OPERATION_FILES } from "../scripts/release-operations.mjs";

test("live pointer canary proves the core stable shim without forwarding ambient provider overrides", async () => {
  const fixture = await createFixture("strict");
  const ambientConfig = join(fixture.root, "ambient-do-not-use.json");
  const secret = "private-canary-secret-must-not-appear";
  try {
    await writeFile(ambientConfig, JSON.stringify({ invalid: secret }));
    const result = runCanary(fixture, {
      AGENT_BRIDGE_CONFIG: ambientConfig,
      AGENT_BRIDGE_BUNDLE_MODE: "1",
      AGENT_BRIDGE_ENABLE_MANUS: "true",
      MANUS_API_KEY: secret,
      MANUS_API_BASE_URL: `https://${secret}.invalid`,
      OPENAI_API_KEY: secret,
      ANTHROPIC_API_KEY: secret,
      GEMINI_API_KEY: secret,
      NODE_OPTIONS: "--no-warnings",
    });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "pass");
    assert.equal(report.profile, "strict");
    assert.equal(report.acceptanceProfile, "windows-local-core");
    assert.deepEqual(report.capabilityProjection, {
      codexEnabled: true,
      claudeEnabled: true,
      geminiEnabled: false,
      manusEnabled: false,
      directRemoteEgressEnabled: false,
      directRemoteAllowedAgentCount: 0,
    });
    assert.equal(report.mcpInitializePassed, true);
    assert.equal(report.listToolsPassed, true);
    assert.equal(report.requiredToolCount, 33);
    assert.ok(report.toolCount >= report.requiredToolCount);
    assert.equal(report.providerDelegationsAttempted, 0);
    assert.equal(report.sessionRecordsBefore, 0);
    assert.equal(report.sessionRecordsAfter, 0);
    assert.equal(report.sessionRecordDigestAfter, report.sessionRecordDigestBefore);
    assert.deepEqual(report.stableFilesAfter, report.stableFilesBefore);
    const retained = await readFile(report.evidencePath, "utf8");
    assert.equal(JSON.parse(retained).status, "pass");
    assert.ok(!`${result.stdout}\n${retained}`.includes(secret), "sanitized evidence exposed an ambient credential or config value");
    assert.ok(!retained.includes(fixture.releasePath), "retained evidence exposed an install path");
    await assertStableBytes(fixture);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("live pointer canary supports the rollback-minimum tool profile", async () => {
  const fixture = await createFixture("rollback", { legacyV021: true });
  try {
    const result = runCanary(fixture, {}, "rollback-minimum");
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.profile, "rollback-minimum");
    assert.equal(report.version, "0.2.1");
    assert.equal(report.immutableFileCount, 3);
    assert.equal(report.requiredToolCount, 1);
    assert.equal(report.providerDelegationsAttempted, 0);
    assert.deepEqual(report.stableFilesAfter, report.stableFilesBefore);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("rollback-minimum rejects a synthetic legacy v0.2.1 release with another source Git SHA", async () => {
  const fixture = await createFixture("rollback-wrong-source", { legacyV021: true, gitSha: "b".repeat(40) });
  try {
    const result = runCanary(fixture, {}, "rollback-minimum");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /requires the exact historical v0.2.1 source Git SHA/i);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("live pointer canary binds reviewed source and package identities", async (t) => {
  await t.test("wrong source Git SHA", async () => {
    const fixture = await createFixture("wrong-source");
    try {
      const result = runCanary(fixture, {}, "strict", { sourceGitSha: "c".repeat(40) });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /Git SHA differs from the reviewed package record/i);
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  });
  await t.test("wrong metadata hash", async () => {
    const fixture = await createFixture("wrong-metadata");
    try {
      const result = runCanary(fixture, {}, "strict", { metadataSha256: "d".repeat(64) });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /metadata hash differs from the reviewed package record/i);
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  });
  await t.test("wrong manifest hash", async () => {
    const fixture = await createFixture("wrong-manifest");
    try {
      const result = runCanary(fixture, {}, "strict", { manifestSha256: "e".repeat(64) });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /manifest hash differs from the reviewed package record/i);
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  });
  await t.test("strict rejects a non-RC9 version", async () => {
    const fixture = await createFixture("strict-version", { version: "0.3.0-rc.8" });
    try {
      const result = runCanary(fixture);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /strict pointer canary is limited to RC9/i);
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  });
  await t.test("strict rejects a non-0.3 manifest schema", async () => {
    const fixture = await createFixture("strict-schema", { manifestVersion: "0.1" });
    try {
      const result = runCanary(fixture);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /requires the RC9 manifest schema/i);
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  });
});

test("live pointer canary fails closed on non-core capability state, pointer drift, and evidence overwrite", async (t) => {
  await t.test("non-empty remote allowlist", async () => {
    const fixture = await createFixture("allowlist", { remoteAllowedAgents: ["manus"] });
    try {
      const result = runCanary(fixture);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /empty direct-remote allowlist/i);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  await t.test("marker points to another release", async () => {
    const fixture = await createFixture("marker-drift");
    try {
      const marker = JSON.parse(fixture.stable.marker.toString("utf8"));
      marker.releaseId = "another-release";
      fixture.stable.marker = Buffer.from(`${JSON.stringify(marker)}\n`);
      await writeFile(join(fixture.installRoot, "current-release.json"), fixture.stable.marker);
      const result = runCanary(fixture);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /promotion marker release ID differs/i);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  await t.test("evidence directory already exists", async () => {
    const fixture = await createFixture("overwrite");
    try {
      await mkdir(fixture.evidenceDir);
      const result = runCanary(fixture);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /refusing to overwrite existing evidence directory/i);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
});

test("live pointer canary rejects a junction-selected immutable release", async (t) => {
  const fixture = await createFixture("junction");
  const alias = join(fixture.installRoot, "releases", "alias");
  try {
    try { await symlink(fixture.releasePath, alias, process.platform === "win32" ? "junction" : "dir"); }
    catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) return t.skip(`junction or symlink unavailable: ${error.code}`);
      throw error;
    }
    const result = runCanary({ ...fixture, releasePath: alias });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /real directory, not a symlink or junction|must not traverse a symlink or junction/i);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("live pointer canary rejects a session directory reached through a parent junction", async (t) => {
  const fixture = await createFixture("session-parent-junction");
  const externalState = join(fixture.root, "external-state");
  try {
    await mkdir(join(externalState, "sessions"), { recursive: true });
    await writeFile(join(externalState, "sessions", "existing.json"), "{}\n");
    try { await symlink(externalState, fixture.stateDir, process.platform === "win32" ? "junction" : "dir"); }
    catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) return t.skip(`junction or symlink unavailable: ${error.code}`);
      throw error;
    }
    const result = runCanary(fixture);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /session record directory must not traverse a symlink or junction/i);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

async function createFixture(label, options = {}) {
  const root = await mkdtemp(join(tmpdir(), `agent-bridge-live-pointer-${label}-`));
  const installRoot = join(root, "install");
  const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
  const version = options.version ?? (options.legacyV021 ? "0.2.1" : pkg.version);
  const gitSha = options.gitSha ?? (options.legacyV021 ? "4785d630c416df692869540a52466c9895cfa6d6" : "a".repeat(40));
  const releaseId = `${version}+${gitSha.slice(0, 7)}`;
  const releasePath = join(installRoot, "releases", releaseId);
  const runtimePath = join(releasePath, "server", "agent-bridge.mjs");
  const allowedRoot = join(root, "allowed");
  const stateDir = join(root, "state");
  const evidenceDir = join(root, "evidence");
  await mkdir(join(releasePath, "server"), { recursive: true });
  await mkdir(join(releasePath, "operations"), { recursive: true });
  await mkdir(allowedRoot, { recursive: true });
  if (options.legacyV021) await writeFile(runtimePath, legacyRuntime());
  else await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtimePath);
  const runtime = await readFile(runtimePath);
  const runtimeSha256 = sha256(runtime);
  const sourceMapPath = join(releasePath, "server", "agent-bridge.mjs.map");
  if (options.legacyV021) await writeFile(sourceMapPath, "{}\n");
  else await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs.map"), sourceMapPath);
  const sourceMap = await readFile(sourceMapPath);
  const files = {
    "server/agent-bridge.mjs": { sha256: runtimeSha256, bytes: runtime.byteLength },
    "server/agent-bridge.mjs.map": { sha256: sha256(sourceMap), bytes: sourceMap.byteLength },
  };
  if (options.legacyV021) {
    const legacyConfig = Buffer.from('{"agents":{}}\n');
    await writeFile(join(releasePath, "server", "config.json"), legacyConfig);
    files["server/config.json"] = { sha256: sha256(legacyConfig) };
  } else {
    for (const operation of RELEASE_OPERATION_FILES) {
      const target = join(releasePath, ...operation.target.split("/"));
      await copyFile(join(process.cwd(), operation.source), target);
      const bytes = await readFile(target);
      files[operation.target] = { sha256: sha256(bytes), bytes: bytes.byteLength };
    }
  }
  const metadata = Buffer.from(`${JSON.stringify({
    package: pkg.name,
    version,
    builtAt: "2026-08-30T00:00:00.000Z",
    gitSha,
    ...(!options.legacyV021 ? { operations: RELEASE_OPERATION_CONTRACT } : {}),
    files,
  }, null, 2)}\n`);
  const manifest = Buffer.from(`${JSON.stringify({
    manifest_version: options.manifestVersion ?? (options.legacyV021 ? "0.1" : "0.3"),
    name: "agent-bridge",
    version,
    ...(options.legacyV021
      ? { metadata: { source_git_sha: gitSha, runtime_sha256: runtimeSha256 } }
      : { _meta: { "com.agentbridge.release": { source_git_sha: gitSha, runtime_sha256: runtimeSha256 } } }),
  }, null, 2)}\n`);
  await writeFile(join(releasePath, "release-metadata.json"), metadata);
  await writeFile(join(releasePath, "manifest.json"), manifest);

  const secret = "embedded-disabled-extra-env-must-not-appear";
  const config = Buffer.from(`${JSON.stringify({
    agents: {
      codex: { enabled: true, extraEnv: { PRIVATE_CANARY_SENTINEL: secret } },
      claude: { enabled: true },
      gemini: { enabled: false },
      manus: { enabled: false },
    },
    defaults: { cwd: allowedRoot, sandbox: "read-only", timeoutSec: 30 },
    allowedRoots: [allowedRoot],
    stateDir,
    policy: {
      sandboxCeiling: "read-only",
      remoteEgress: { enabled: false, allowedAgents: options.remoteAllowedAgents ?? [], allowedRoots: [], allowedDataClasses: [] },
    },
  }, null, 2)}\n`);
  const shim = Buffer.from([
    "#!/usr/bin/env node",
    'import { existsSync } from "node:fs";',
    'import { fileURLToPath } from "node:url";',
    "",
    'const sharedConfig = fileURLToPath(new URL("./config.json", import.meta.url));',
    "if (!process.env.AGENT_BRIDGE_CONFIG && existsSync(sharedConfig)) {",
    "  process.env.AGENT_BRIDGE_CONFIG = sharedConfig;",
    "}",
    `await import(new URL("./releases/${releaseId}/server/agent-bridge.mjs", import.meta.url).href);`,
  ].join("\n"));
  const marker = Buffer.from(`${JSON.stringify({
    schemaVersion: 1,
    releaseId,
    releasePath,
    runtimeSha256,
    shimSha256: sha256(shim),
    configSha256: sha256(config),
    promotedAt: "2026-08-30T00:00:00.000Z",
    backupPath: null,
  })}\n`);
  await writeFile(join(installRoot, "agent-bridge.mjs"), shim);
  await writeFile(join(installRoot, "config.json"), config);
  await writeFile(join(installRoot, "current-release.json"), marker);
  return {
    root, installRoot, releasePath, evidenceDir, stateDir, version, runtimeSha256,
    stable: { shim, config, marker },
    hashes: { shim: sha256(shim), config: sha256(config), metadata: sha256(metadata), manifest: sha256(manifest) }, gitSha,
  };
}

function runCanary(fixture, ambient = {}, profile = "strict", expected = {}) {
  return spawnSync(process.execPath, [
    "scripts/canary-live-pointer.mjs",
    "--release-path", fixture.releasePath,
    "--install-root", fixture.installRoot,
    "--expected-version", fixture.version,
    "--expected-source-git-sha", expected.sourceGitSha ?? fixture.gitSha,
    "--expected-runtime-sha256", fixture.runtimeSha256,
    "--expected-metadata-sha256", expected.metadataSha256 ?? fixture.hashes.metadata,
    "--expected-manifest-sha256", expected.manifestSha256 ?? fixture.hashes.manifest,
    "--expected-stable-shim-sha256", fixture.hashes.shim,
    "--expected-shared-config-sha256", fixture.hashes.config,
    "--evidence-dir", fixture.evidenceDir,
    "--profile", profile,
  ], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000,
    env: { ...process.env, ...ambient },
  });
}

async function assertStableBytes(fixture) {
  assert.deepEqual(await readFile(join(fixture.installRoot, "agent-bridge.mjs")), fixture.stable.shim);
  assert.deepEqual(await readFile(join(fixture.installRoot, "config.json")), fixture.stable.config);
  assert.deepEqual(await readFile(join(fixture.installRoot, "current-release.json")), fixture.stable.marker);
}
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }

function legacyRuntime() {
  return Buffer.from([
    'import { createInterface } from "node:readline";',
    'const lines = createInterface({ input: process.stdin });',
    'function send(id, result) { process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\\n"); }',
    'lines.on("line", (line) => {',
    '  const message = JSON.parse(line);',
    '  if (message.id === undefined) return;',
    '  if (message.method === "initialize") return send(message.id, { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "synthetic-prior", version: "0.2.1" } });',
    '  if (message.method === "tools/list") return send(message.id, { tools: [{ name: "list_agents", description: "Synthetic rollback probe", inputSchema: { type: "object", properties: {}, additionalProperties: false } }] });',
    '  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } }) + "\\n");',
    '});',
    '',
  ].join("\n"));
}
