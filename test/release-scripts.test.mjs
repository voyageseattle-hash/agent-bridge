import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { copyFile, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

const onWindows = process.platform === "win32";
const powershell = "powershell.exe";

test("Windows release scripts install immutably, switch atomically, block live processes, and protect state", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-release-scripts-"));
  const installRoot = join(root, "install");
  const stateDir = join(root, "state");
  const bundle = join(root, "agent-bridge.mcpb");
  const version = "0.3.0-rc.1";
  const gitSha = "1234567890abcdef1234567890abcdef12345678";
  const releaseId = `${version}+${gitSha.slice(0, 7)}`;
  const runtime = Buffer.from("export const release = 'test';\n");
  const sourceMap = Buffer.from("{}\n");
  try {
    const scripts = await createQuiescenceHarness(root, ["configure-clients.ps1", "cutover-lock.psm1", "cutover-release.ps1", "switch-release.ps1", "inspect-install.ps1", "protect-state.ps1"]);
    await mkdir(stateDir);
    await writeFile(join(installRoot, "config.json"), "{}\n", { recursive: true }).catch(async () => {
      await mkdir(installRoot, { recursive: true });
      await writeFile(join(installRoot, "config.json"), "{}\n");
    });
    await writeFile(bundle, releaseBundle({ version, gitSha, runtime, sourceMap }));
    const bundleHash = sha256(await readFile(bundle));

    const installed = runScript("scripts/install-release.ps1", ["-BundlePath", bundle, "-InstallRoot", installRoot, "-ExpectedBundleSha256", bundleHash]);
    assert.equal(installed.status, 0, installed.stderr);
    const installResult = JSON.parse(installed.stdout);
    assert.equal(installResult.releaseId, releaseId);
    assert.equal(installResult.bundleSha256, bundleHash);
    assert.deepEqual(await readFile(join(installRoot, "releases", releaseId, "server", "agent-bridge.mjs")), runtime);

    const duplicate = runScript("scripts/install-release.ps1", ["-BundlePath", bundle, "-InstallRoot", installRoot]);
    assert.notEqual(duplicate.status, 0);
    assert.match(duplicate.stderr, /immutable release already exists/i);

    const switched = runScript(scripts.switch, ["-ReleaseId", releaseId, "-InstallRoot", installRoot]);
    assert.equal(switched.status, 0, switched.stderr);
    const shim = await readFile(join(installRoot, "agent-bridge.mjs"), "utf8");
    assert.ok(shim.includes(releaseId));
    assert.equal(JSON.parse(await readFile(join(installRoot, "current-release.json"), "utf8")).releaseId, releaseId);
    const firstBackup = JSON.parse(switched.stdout).backupPath;
    const firstBackupState = JSON.parse(await readFile(join(firstBackup, "rollback-state.json"), "utf8"));
    assert.equal(firstBackupState.files.find((entry) => entry.path === "agent-bridge.mjs").existed, false);
    assert.equal(firstBackupState.files.find((entry) => entry.path === "current-release.json").existed, false);

    await writeFile(join(installRoot, "agent-bridge.mjs"), "// prior shim\n");
    await writeFile(join(installRoot, "current-release.json"), "{\"releaseId\":\"prior\"}\n");
    const failedMarker = runScript(scripts.switch, ["-ReleaseId", releaseId, "-InstallRoot", installRoot], { AGENT_BRIDGE_TEST_FAIL_MARKER_WRITE: "1" });
    assert.notEqual(failedMarker.status, 0);
    assert.match(failedMarker.stderr, /prior shim\/config\/marker state was restored/i);
    assert.equal(await readFile(join(installRoot, "agent-bridge.mjs"), "utf8"), "// prior shim\n");
    assert.equal(await readFile(join(installRoot, "current-release.json"), "utf8"), "{\"releaseId\":\"prior\"}\n");

    const postMarkerReady = join(root, "post-marker-ready");
    const stagedConfig = join(root, "staged-config.json");
    const stagedConfigBytes = Buffer.from("{\"staged\":true}\n");
    await writeFile(stagedConfig, stagedConfigBytes);
    const failedLiveShim = spawn(powershell, ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scripts.switch, "-ReleaseId", releaseId, "-InstallRoot", installRoot, "-StagedConfigPath", stagedConfig, "-ExpectedConfigSha256", sha256(stagedConfigBytes)], {
      cwd: process.cwd(), env: { ...process.env, AGENT_BRIDGE_TEST_FAIL_LIVE_SHIM_WRITE: "1", AGENT_BRIDGE_TEST_POST_MARKER_DELAY_MS: "1200", AGENT_BRIDGE_TEST_POST_MARKER_READY_PATH: postMarkerReady }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
    });
    await waitForPath(postMarkerReady);
    assert.equal(existsSync(postMarkerReady), true, "switch never reached the deterministic post-marker hook");
    assert.match(await readFile(join(installRoot, "agent-bridge.mjs"), "utf8"), /cutover is in progress/);
    assert.deepEqual(await readFile(join(installRoot, "config.json")), stagedConfigBytes, "staged config was not activated behind the maintenance barrier");
    assert.equal(JSON.parse(await readFile(join(installRoot, "current-release.json"), "utf8")).releaseId, releaseId);
    const failedLiveShimResult = await collect(failedLiveShim);
    assert.notEqual(failedLiveShimResult.code, 0);
    assert.match(failedLiveShimResult.stderr, /prior shim\/config\/marker state was restored/i);
    assert.equal(await readFile(join(installRoot, "agent-bridge.mjs"), "utf8"), "// prior shim\n");
    assert.equal(await readFile(join(installRoot, "config.json"), "utf8"), "{}\n");
    assert.equal(await readFile(join(installRoot, "current-release.json"), "utf8"), "{\"releaseId\":\"prior\"}\n");

    await writeFile(join(installRoot, ".agent-bridge-cutover.lock"), "held\n");
    const locked = runScript(scripts.switch, ["-ReleaseId", releaseId, "-InstallRoot", installRoot]);
    assert.notEqual(locked.status, 0);
    assert.match(locked.stderr, /cutover mutation owns the install lock/i);
    await rm(join(installRoot, ".agent-bridge-cutover.lock"));

    const bypass = runScript(scripts.switch, ["-ReleaseId", releaseId, "-InstallRoot", installRoot, "-MutationContextToken", "a".repeat(32), "-MutationOwnerPid", String(process.pid)]);
    assert.notEqual(bypass.status, 0);
    assert.match(bypass.stderr, /requires an in-process mutation invocation/i);

    const modulePath = join(process.cwd(), "scripts", "cutover-lock.psm1").replaceAll("'", "''");
    const quotedInstall = installRoot.replaceAll("'", "''");
    const lockLifecycle = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", `Import-Module '${modulePath}' -Force; $one = Enter-AgentBridgeMutationLock -InstallRoot '${quotedInstall}'; Exit-AgentBridgeMutationLock $one; if (Test-Path -LiteralPath '${quotedInstall}\\.agent-bridge-cutover.lock') { throw 'diagnostic lock survived owner release' }; $two = Enter-AgentBridgeMutationLock -InstallRoot '${quotedInstall}'; Exit-AgentBridgeMutationLock $two; 'reacquired'`], { encoding: "utf8", windowsHide: true });
    assert.equal(lockLifecycle.status, 0, lockLifecycle.stderr);
    assert.match(lockLifecycle.stdout, /reacquired/);

    const abandonedReady = join(root, "abandoned-owner-ready");
    const abandonedOwner = spawn(powershell, ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", `Import-Module '${modulePath}' -Force; $lock = Enter-AgentBridgeMutationLock -InstallRoot '${quotedInstall}'; [IO.File]::WriteAllText('${abandonedReady.replaceAll("'", "''")}', 'ready'); Start-Sleep -Milliseconds 200; [Environment]::FailFast('abandon mutex test')`], { stdio: "ignore", windowsHide: true });
    await waitForPath(abandonedReady);
    assert.equal(existsSync(abandonedReady), true, "abandoned mutex owner did not acquire the test lock");
    if (abandonedOwner.exitCode === null) await new Promise((resolve) => abandonedOwner.once("exit", resolve));
    assert.equal(existsSync(join(installRoot, ".agent-bridge-cutover.lock")), true, "crashed owner did not leave its durable diagnostic lock");
    const abandoned = runScript(scripts.switch, ["-ReleaseId", releaseId, "-InstallRoot", installRoot]);
    assert.notEqual(abandoned.status, 0);
    assert.match(abandoned.stderr, /cutover mutation owns the install lock/i);
    assert.equal(JSON.parse(await readFile(join(installRoot, ".agent-bridge-cutover.lock"), "utf8")).status, "active");
    await rm(join(installRoot, ".agent-bridge-cutover.lock"));

    await writeFile(join(installRoot, "agent-bridge.mjs"), "setInterval(() => {}, 1000);\n");
    const raced = spawn(powershell, ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scripts.switch, "-ReleaseId", releaseId, "-InstallRoot", installRoot], {
      cwd: process.cwd(), env: { ...process.env, AGENT_BRIDGE_TEST_PRE_BARRIER_DELAY_MS: "1200", AGENT_BRIDGE_TEST_PRE_BARRIER_READY_PATH: join(root, "pre-barrier-ready") }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
    });
    await waitForPath(join(root, "pre-barrier-ready"));
    assert.equal(existsSync(join(root, "pre-barrier-ready")), true, "switch never reached the deterministic pre-barrier hook");
    const oldRuntimeRace = spawn(process.execPath, [join(installRoot, "agent-bridge.mjs")], { stdio: "ignore", windowsHide: true });
    try {
      const raceResult = await collect(raced);
      assert.notEqual(raceResult.code, 0, raceResult.stderr);
      assert.match(raceResult.stderr, /prior shim\/config\/marker state was restored/i);
      assert.equal(await readFile(join(installRoot, "agent-bridge.mjs"), "utf8"), "setInterval(() => {}, 1000);\n");
      assert.equal(await readFile(join(installRoot, "current-release.json"), "utf8"), "{\"releaseId\":\"prior\"}\n");
    } finally {
      oldRuntimeRace.kill();
      await new Promise((resolve) => oldRuntimeRace.once("exit", resolve));
    }

    const switchedAfterRace = runScript(scripts.switch, ["-ReleaseId", releaseId, "-InstallRoot", installRoot]);
    assert.equal(switchedAfterRace.status, 0, switchedAfterRace.stderr);

    const stagedSwitch = runScript(scripts.switch, ["-ReleaseId", releaseId, "-InstallRoot", installRoot, "-StagedConfigPath", stagedConfig, "-ExpectedConfigSha256", sha256(stagedConfigBytes)]);
    assert.equal(stagedSwitch.status, 0, stagedSwitch.stderr);
    assert.deepEqual(await readFile(join(installRoot, "config.json")), stagedConfigBytes);
    const stagedMarker = JSON.parse(await readFile(join(installRoot, "current-release.json"), "utf8"));
    assert.equal(stagedMarker.configSha256, sha256(stagedConfigBytes));
    assert.equal(JSON.parse(stagedSwitch.stdout).verification.current, true);

    const live = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", join(installRoot, "agent-bridge.mjs")], { stdio: "ignore" });
    try {
      await new Promise((resolve) => setTimeout(resolve, 500));
      const blocked = runScript(scripts.switch, ["-ReleaseId", releaseId, "-InstallRoot", installRoot]);
      assert.notEqual(blocked.status, 0);
      assert.match(blocked.stderr, /refusing cutover mutation while 1 Agent Bridge process/i);
    } finally {
      live.kill();
      await new Promise((resolve) => live.once("exit", resolve));
    }

    const stateBefore = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-AuditOnly"]);
    assert.equal(stateBefore.status, 0, stateBefore.stderr);
    assert.equal(JSON.parse(stateBefore.stdout).compliant, false);
    const protectedState = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-BackupPath", join(root, "state-acl-backup.json"), "-Force"]);
    assert.equal(protectedState.status, 0, protectedState.stderr);
    assert.equal(JSON.parse(protectedState.stdout).compliant, true);
    await writeFile(join(stateDir, "created-after-protection.json"), "{}\n");
    const stateAfter = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-AuditOnly"]);
    assert.equal(stateAfter.status, 0, stateAfter.stderr);
    assert.equal(JSON.parse(stateAfter.stdout).compliant, true, "new state children must inherit only approved grants");
    const inspectScript = await createInspectionHarness(root);
    const inspected = runScript(inspectScript, ["-InstallRoot", installRoot, "-StateDir", stateDir]);
    assert.equal(inspected.status, 0, inspected.stderr);
    const report = JSON.parse(inspected.stdout);
    assert.equal(report.stateAcl.protected, true);
    assert.deepEqual(report.stateAcl.unexpectedAllowIdentities, []);
    assert.equal(report.currentRelease.releaseId, releaseId);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Windows installer rejects an unexpected external bundle hash before extraction", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-release-external-hash-"));
  try {
    const bundle = join(root, "agent-bridge.mcpb");
    await writeFile(bundle, releaseBundle({ version: "0.3.0-rc.1", gitSha: "abcdef1234567890abcdef1234567890abcdef12", runtime: Buffer.from("runtime\n"), sourceMap: Buffer.from("{}\n") }));
    const result = runScript("scripts/install-release.ps1", ["-BundlePath", bundle, "-InstallRoot", join(root, "install"), "-ExpectedBundleSha256", "f".repeat(64)]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /bundle SHA-256 mismatch/i);
    await assert.rejects(readFile(join(root, "install", "releases", "0.3.0-rc.1+abcdef1", "server", "agent-bridge.mjs")));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Windows installer accepts only the exact operation-free v0.2.1 legacy manifest identity", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-release-legacy-identity-"));
  const runtime = Buffer.from("export const legacy = true;\n");
  const sourceMap = Buffer.from("{}\n");
  const config = Buffer.from("{\"agents\":{}}\n");
  const gitSha = "4785d630c416df692869540a52466c9895cfa6d6";
  try {
    const legacyBundle = join(root, "legacy-v0.2.1.mcpb");
    await writeFile(legacyBundle, releaseBundle({
      version: "0.2.1", gitSha, runtime, sourceMap, legacyManifestIdentity: true,
      additionalEntries: [{ relative: "server/config.json", bytes: config }],
      omitByteCountsFor: ["server/config.json"],
    }));
    const installed = runScript("scripts/install-release.ps1", ["-BundlePath", legacyBundle, "-InstallRoot", join(root, "legacy-install"), "-ExpectedBundleSha256", sha256(await readFile(legacyBundle))]);
    assert.equal(installed.status, 0, installed.stderr);
    const result = JSON.parse(installed.stdout);
    assert.equal(result.releaseId, `0.2.1+${gitSha.slice(0, 7)}`);
    assert.equal(result.runtimeSha256, sha256(runtime));
    assert.equal(result.operationsPath, null);
    assert.deepEqual(await readFile(join(result.releasePath, "server", "config.json")), config);

    const wrongSchemaBundle = join(root, "legacy-v0.2.1-wrong-schema.mcpb");
    await writeFile(wrongSchemaBundle, releaseBundle({
      version: "0.2.1", gitSha, runtime, sourceMap, legacyManifestIdentity: true, manifestVersion: "0.3",
    }));
    const wrongSchema = runScript("scripts/install-release.ps1", ["-BundlePath", wrongSchemaBundle, "-InstallRoot", join(root, "wrong-schema-install")]);
    assert.notEqual(wrongSchema.status, 0);
    assert.match(wrongSchema.stderr, /manifest release identity is missing or invalid/i);

    const modernBundle = join(root, "modern-with-legacy-identity.mcpb");
    await writeFile(modernBundle, releaseBundle({ version: "0.2.2", gitSha, runtime, sourceMap, legacyManifestIdentity: true }));
    const rejected = runScript("scripts/install-release.ps1", ["-BundlePath", modernBundle, "-InstallRoot", join(root, "modern-install")]);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /manifest release identity is missing or invalid/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rollback rehearsal initializes a fresh shared config and completes candidate to prior to candidate", { skip: !onWindows, timeout: 120_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-rollback-success-"));
  const candidateBundle = join(root, "candidate.mcpb");
  const priorBundle = join(root, "prior.mcpb");
  const evidenceDir = join(root, "evidence");
  const operationNames = [
    "check-cutover-readiness.ps1", "cutover-release.ps1", "switch-release.ps1", "inspect-install.ps1",
    "protect-state.ps1", "configure-clients.ps1", "cutover-lock.psm1", "cutover-quiescence.psm1",
  ];
  try {
    const version = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8")).version;
    const runtime = await readFile(join(process.cwd(), "dist", "agent-bridge.mjs"));
    const sourceMap = await readFile(join(process.cwd(), "dist", "agent-bridge.mjs.map"));
    const priorRuntime = Buffer.from([
      'import { createInterface } from "node:readline";',
      'const lines = createInterface({ input: process.stdin });',
      'function send(id, result) { process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\\n"); }',
      'lines.on("line", (line) => {',
      '  const message = JSON.parse(line);',
      '  if (message.id === undefined) return;',
      '  if (message.method === "initialize") return send(message.id, { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "synthetic-prior", version: "0.2.1" } });',
      '  if (message.method === "tools/list") return send(message.id, { tools: [{ name: "list_agents", description: "Synthetic rollback probe", inputSchema: { type: "object", properties: {}, additionalProperties: false } }] });',
      '  if (message.method === "tools/call") return send(message.id, { content: [{ type: "text", text: "No enabled agents" }], structuredContent: { agents: [] }, isError: false });',
      '  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } }) + "\\n");',
      '});',
      '',
    ].join("\n"));
    const scripts = await createQuiescenceHarness(root, operationNames);
    const harnessRoot = dirname(scripts.switch);
    const operations = await Promise.all(operationNames.map(async (name) => ({
      relative: `operations/${name}`,
      bytes: await readFile(join(harnessRoot, name)),
    })));
    await writeFile(candidateBundle, releaseBundle({ version, gitSha: "a".repeat(40), runtime, sourceMap, operations }));
    await writeFile(priorBundle, releaseBundle({
      version: "0.2.1", gitSha: "b".repeat(40), runtime: priorRuntime, sourceMap: Buffer.from("{}\n"), legacyManifestIdentity: true,
      additionalEntries: [{ relative: "server/config.json", bytes: Buffer.from("{\"agents\":{}}\n") }],
      omitByteCountsFor: ["server/config.json"],
    }));
    const candidateHash = sha256(await readFile(candidateBundle));
    const priorHash = sha256(await readFile(priorBundle));

    const rehearsed = runScript("scripts/rehearse-rollback.ps1", [
      "-CandidateBundlePath", candidateBundle, "-ExpectedCandidateBundleSha256", candidateHash,
      "-PriorBundlePath", priorBundle, "-ExpectedPriorBundleSha256", priorHash,
      "-EvidenceDir", evidenceDir,
      "-NodePath", process.execPath,
    ], {}, 90_000);
    assert.equal(rehearsed.status, 0, rehearsed.stderr);
    const report = JSON.parse(rehearsed.stdout);
    assert.equal(report.status, "pass");
    assert.deepEqual(report.steps.map((step) => step.name), ["candidate-first", "prior", "candidate-restored"]);
    assert.deepEqual(report.steps.map((step) => step.releaseId), [`${version}+aaaaaaa`, "0.2.1+bbbbbbb", `${version}+aaaaaaa`]);
    assert.equal(report.initialSharedConfig.sha256, report.stagedConfig.sha256);
    assert.deepEqual(
      await readFile(join(report.fixtureInstall, "config.json")),
      await readFile(report.stagedConfig.path),
      "fresh rehearsal fixture did not retain the verified provider-disabled shared config",
    );
    const expectedCanaries = [
      { profile: "strict", version, releaseId: `${version}+aaaaaaa` },
      { profile: "rollback-minimum", version: "0.2.1", releaseId: "0.2.1+bbbbbbb" },
      { profile: "strict", version, releaseId: `${version}+aaaaaaa` },
    ];
    for (const [index, step] of report.steps.entries()) {
      const canary = JSON.parse(await readFile(step.canaryEvidencePath, "utf8"));
      assert.equal(canary.status, "pass");
      assert.equal(canary.promotionStatus, "current");
      assert.equal(canary.entrypoint, "stable-shim");
      assert.equal(canary.profile, expectedCanaries[index].profile);
      assert.equal(canary.version, expectedCanaries[index].version);
      assert.equal(step.releaseId, expectedCanaries[index].releaseId);
    }
    assert.equal(JSON.parse(await readFile(join(report.fixtureInstall, "current-release.json"), "utf8")).releaseId, `${version}+aaaaaaa`);
    assert.equal(sha256(await readFile(join(evidenceDir, "artifact-manifest.json"))), report.artifactManifestSha256);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("cutover transaction restores every registration and install pointer after promotion failure", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-cutover-transaction-"));
  const profile = join(root, "profile"); const appData = join(root, "roaming"); const localAppData = join(root, "local");
  const installRoot = join(profile, ".codex", "agent-bridge");
  const stateDir = join(root, "state");
  const version = "0.3.0-rc.1"; const gitSha = "abcdef1234567890abcdef1234567890abcdef12"; const releaseId = `${version}+${gitSha.slice(0, 7)}`;
  const bundle = join(root, "candidate.mcpb"); const runtime = Buffer.from("export const candidate = true;\n");
  const shim = join(installRoot, "agent-bridge.mjs"); const config = join(installRoot, "config.json"); const marker = join(installRoot, "current-release.json");
  const codex = join(profile, ".codex", "config.toml"); const claude = join(profile, ".claude.json"); const legacy = join(appData, "Claude", "claude_desktop_config.json");
  const packaged = join(localAppData, "Packages", "Claude_test", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json");
  try {
    const scripts = await createQuiescenceHarness(root, ["configure-clients.ps1", "cutover-lock.psm1", "cutover-release.ps1", "switch-release.ps1", "inspect-install.ps1", "protect-state.ps1"]);
    await mkdir(stateDir);
    for (const path of [shim, config, marker, codex, claude, legacy, packaged]) await mkdir(dirname(path), { recursive: true });
    await writeFile(config, "{\"shared\":true}\n"); await writeFile(shim, "// old shim\n"); await writeFile(marker, "{\"releaseId\":\"old\"}\n");
    await writeFile(codex, "keep = \"codex\"\n");
    await writeFile(claude, "{\"unrelated\":true}\n");
    await writeFile(legacy, "{\"legacy\":true}\n");
    await writeFile(packaged, "{\"packaged\":true}\n");
    const originals = new Map(await Promise.all([shim, config, marker, codex, claude, legacy, packaged].map(async (path) => [path, await readFile(path)])));
    await writeFile(bundle, releaseBundle({ version, gitSha, runtime, sourceMap: Buffer.from("{}\n"), operations: releaseOperationFixtures() }));
    const installed = runScript("scripts/install-release.ps1", ["-BundlePath", bundle, "-InstallRoot", installRoot]);
    assert.equal(installed.status, 0, installed.stderr);
    const mutationPidLog = join(root, "mutation-pids.txt");
    const stateAclBackup = join(root, "state-acl-backup.json");
    const result = runScript(scripts.cutover, ["-ReleaseId", releaseId, "-InstallRoot", installRoot, "-StateDir", stateDir, "-UserProfile", profile, "-AppData", appData, "-LocalAppData", localAppData, "-NodePath", process.execPath, "-ApplyStateAcl", "-StateAclBackupPath", stateAclBackup], { AGENT_BRIDGE_TEST_FAIL_MARKER_WRITE: "1", AGENT_BRIDGE_TEST_MUTATION_PID_LOG: mutationPidLog });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /client registrations were restored/i);
    const hardenedState = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-AuditOnly"]);
    assert.equal(hardenedState.status, 0, hardenedState.stderr);
    assert.equal(JSON.parse(hardenedState.stdout).compliant, true, "promotion rollback must not undo forward-only ACL hardening");
    assert.match(sha256(await readFile(stateAclBackup)), /^[0-9a-f]{64}$/, "retained ACL backup must remain readable");
    assert.match(result.stderr, /hardening remains committed by policy[\s\S]*retained backup/i);
    for (const [path, expected] of originals) assert.deepEqual(await readFile(path), expected, path);
    await assert.rejects(readFile(join(installRoot, ".agent-bridge-cutover.lock")));
    const temporary = (await readdir(installRoot)).filter((name) => name.startsWith(".agent-bridge-"));
    assert.deepEqual(temporary, []);
    assert.equal(JSON.parse(await readFile(marker, "utf8")).releaseId, "old");
    const mutationPids = Object.fromEntries((await readFile(mutationPidLog, "utf8")).trim().split("\n").map((line) => line.split(":")));
    assert.equal(mutationPids.configure, mutationPids.cutover, "configure mutation did not run in the lock-owning PowerShell process");
    assert.equal(mutationPids.switch, mutationPids.cutover, "switch mutation did not run in the lock-owning PowerShell process");
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("cutover validates its target before registrations and reports target plus executing-operation provenance", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-cutover-provenance-"));
  const profile = join(root, "profile"); const appData = join(root, "roaming"); const localAppData = join(root, "local");
  const installRoot = join(profile, ".codex", "agent-bridge");
  const stateDir = join(root, "state");
  const version = "0.3.0-rc.1"; const gitSha = "1234567890abcdef1234567890abcdef12345678"; const releaseId = `${version}+${gitSha.slice(0, 7)}`;
  const runtime = Buffer.from("export const cutoverProvenance = true;\n"); const operations = releaseOperationFixtures();
  const bundle = join(root, "candidate.mcpb");
  const shim = join(installRoot, "agent-bridge.mjs"); const config = join(installRoot, "config.json"); const marker = join(installRoot, "current-release.json");
  const codex = join(profile, ".codex", "config.toml"); const claude = join(profile, ".claude.json"); const legacy = join(appData, "Claude", "claude_desktop_config.json"); const packaged = join(localAppData, "Packages", "Claude_test", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json");
  try {
    const scripts = await createQuiescenceHarness(root, ["configure-clients.ps1", "cutover-lock.psm1", "cutover-release.ps1", "switch-release.ps1", "inspect-install.ps1", "protect-state.ps1"]);
    await mkdir(stateDir);
    for (const path of [shim, config, marker, codex, claude, legacy, packaged]) await mkdir(dirname(path), { recursive: true });
    await writeFile(shim, "// prior shim\n"); await writeFile(config, "{\"shared\":true}\n"); await writeFile(marker, "{\"releaseId\":\"prior\"}\n");
    await writeFile(codex, "keep = \"codex\"\n"); await writeFile(claude, "{\"keep\":true}\n"); await writeFile(legacy, "{\"legacy\":true}\n"); await writeFile(packaged, "{\"packaged\":true}\n");
    const originals = new Map(await Promise.all([shim, config, marker, codex, claude, legacy, packaged].map(async (path) => [path, await readFile(path)])));
    await writeFile(bundle, releaseBundle({ version, gitSha, runtime, sourceMap: Buffer.from("{}\n"), operations }));
    const installed = runScript("scripts/install-release.ps1", ["-BundlePath", bundle, "-InstallRoot", installRoot]);
    assert.equal(installed.status, 0, installed.stderr);
    const releasePath = JSON.parse(installed.stdout).releasePath;

    const cutoverArgs = ["-InstallRoot", installRoot, "-StateDir", stateDir, "-UserProfile", profile, "-AppData", appData, "-LocalAppData", localAppData, "-NodePath", process.execPath];
    const malformed = runScript(scripts.cutover, ["-ReleaseId", "not-a-release", ...cutoverArgs]);
    assert.notEqual(malformed.status, 0);
    assert.match(malformed.stderr, /validation/i);
    for (const [path, bytes] of originals) assert.deepEqual(await readFile(path), bytes, `malformed ID mutated ${path}`);

    const operation = operations.find((entry) => entry.relative === "operations/cutover-release.ps1");
    const operationPath = join(releasePath, ...operation.relative.split("/"));
    await writeFile(operationPath, Buffer.concat([operation.bytes, Buffer.from("# tampered\n")]));
    const tampered = runScript(scripts.cutover, ["-ReleaseId", releaseId, ...cutoverArgs]);
    assert.notEqual(tampered.status, 0);
    assert.match(tampered.stderr, /immutable release operation SHA-256 mismatch: operations\/cutover-release\.ps1/i);
    for (const [path, bytes] of originals) assert.deepEqual(await readFile(path), bytes, `untrusted target mutated ${path}`);

    await writeFile(operationPath, operation.bytes);
    const unexpectedOperation = join(releasePath, "operations", "unexpected.ps1");
    await writeFile(unexpectedOperation, "throw 'unexpected'\n");
    const expanded = runScript(scripts.cutover, ["-ReleaseId", releaseId, ...cutoverArgs]);
    assert.notEqual(expanded.status, 0);
    assert.match(expanded.stderr, /immutable release installed payload inventory mismatch/i);
    for (const [path, bytes] of originals) assert.deepEqual(await readFile(path), bytes, `expanded target mutated ${path}`);
    await rm(unexpectedOperation);

    const completed = runScript(scripts.cutover, ["-ReleaseId", releaseId, ...cutoverArgs, "-ApplyStateAcl", "-StateAclBackupPath", join(root, "state-acl-backup.json")]);
    assert.equal(completed.status, 0, completed.stderr);
    const report = JSON.parse(completed.stdout);
    assert.equal(report.status, "cutover-complete");
    assert.deepEqual(report.stateAcl.authorization, { applyStateAcl: true, protectionInvoked: true, rollbackPolicy: "forward-only-security-hardening" });
    assert.equal(report.target.releaseId, releaseId);
    assert.equal(report.target.releasePath, releasePath);
    assert.equal(report.target.runtime.sha256, sha256(runtime));
    assert.equal(report.target.runtime.bytes, runtime.length);
    assert.equal(report.target.operations.directory, join(releasePath, "operations"));
    assert.equal(report.target.operations.files.length, operations.length);
    assert.equal(report.execution.operationDirectory, dirname(scripts.cutover));
    assert.deepEqual(report.execution.files.map((file) => file.name), ["cutover-release.ps1", "configure-clients.ps1", "switch-release.ps1", "inspect-install.ps1", "protect-state.ps1", "cutover-lock.psm1", "cutover-quiescence.psm1"]);
    for (const file of report.execution.files) {
      assert.equal(file.sha256, sha256(await readFile(file.path)));
      assert.equal(file.bytes, (await readFile(file.path)).length);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("Windows installer rejects a bundle whose runtime hash does not match metadata", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-release-tamper-"));
  try {
    const bundle = join(root, "tampered.mcpb");
    const runtime = Buffer.from("tampered runtime\n");
    const sourceMap = Buffer.from("{}\n");
    const bytes = releaseBundle({
      version: "0.3.0-rc.1",
      gitSha: "abcdef1234567890abcdef1234567890abcdef12",
      runtime,
      sourceMap,
      claimedRuntimeHash: "0".repeat(64),
    });
    await writeFile(bundle, bytes);
    const result = runScript("scripts/install-release.ps1", ["-BundlePath", bundle, "-InstallRoot", join(root, "install")]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SHA-256 mismatch for server\/agent-bridge\.mjs/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("ACL inspection and protection work under PowerShell 7", { skip: !onWindows }, async (t) => {
  const probe = spawnSync("pwsh.exe", ["-NoLogo", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"], { encoding: "utf8", windowsHide: true });
  if (probe.error?.code === "ENOENT") return t.skip("pwsh.exe is not installed");
  assert.equal(probe.status, 0, probe.stderr);
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-pwsh-acl-"));
  const stateDir = join(root, "state");
  const installRoot = join(root, "install");
  try {
    await mkdir(stateDir);
    await mkdir(installRoot);
    const protectedState = runScriptWith("pwsh.exe", "scripts/protect-state.ps1", ["-StateDir", stateDir, "-BackupPath", join(root, "state-acl-backup.json"), "-Force"]);
    assert.equal(protectedState.status, 0, protectedState.stderr);
    assert.equal(JSON.parse(protectedState.stdout).status, "protected");
    const inspectScript = await createInspectionHarness(root);
    const inspected = runScriptWith("pwsh.exe", inspectScript, ["-InstallRoot", installRoot, "-StateDir", stateDir]);
    assert.equal(inspected.status, 0, inspected.stderr);
    const report = JSON.parse(inspected.stdout);
    assert.equal(report.stateAcl.protected, true);
    assert.deepEqual(report.stateAcl.unexpectedAllowIdentities, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("state ACL backup supports exact manual restore and automatic partial-apply recovery", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-acl-roundtrip-"));
  const stateDir = join(root, "state");
  const backup = join(root, "state-acl-backup.json");
  const refusedBackup = join(root, "state-acl-refused-backup.json");
  const injectedBackup = join(root, "state-acl-injected-backup.json");
  try {
    await mkdir(join(stateDir, "child"), { recursive: true });
    await writeFile(join(stateDir, "child", "record.json"), "{}\n");
    const before = aclProjection(stateDir);
    const applied = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-BackupPath", backup, "-Force"]);
    assert.equal(applied.status, 0, applied.stderr);
    const receipt = JSON.parse(applied.stdout);
    assert.equal(receipt.backupPath, backup);
    assert.match(receipt.backupSha256, /^[0-9a-f]{64}$/);
    const restored = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-RestoreFrom", backup, "-ExpectedBackupSha256", receipt.backupSha256, "-Force"]);
    assert.equal(restored.status, 0, restored.stderr);
    assert.deepEqual(aclProjection(stateDir), before, "manual restore did not return every item to its original owner/DACL projection");

    const refused = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-BackupPath", refusedBackup, "-Force"], { AGENT_BRIDGE_TEST_FAIL_STATE_ACL_BEFORE_APPLY: "1" });
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /refused before ACL mutation/i);
    assert.ok(existsSync(refusedBackup), "pre-mutation refusal must retain the external backup");
    assert.deepEqual(aclProjection(stateDir), before, "pre-mutation refusal changed the state ACL");

    const injected = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-BackupPath", injectedBackup, "-Force"], { AGENT_BRIDGE_TEST_FAIL_STATE_ACL_AFTER: "2" });
    assert.notEqual(injected.status, 0);
    assert.match(injected.stderr, /automatic ACL recovery restored the pre-image/i);
    assert.ok(existsSync(injectedBackup), "automatic recovery must retain the external backup");
    assert.deepEqual(aclProjection(stateDir), before, "injected partial apply did not automatically restore the pre-image");

    const tampered = await readFile(backup);
    await writeFile(backup, Buffer.concat([tampered, Buffer.from("\n", "utf8")]));
    const denied = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-RestoreFrom", backup, "-ExpectedBackupSha256", receipt.backupSha256, "-Force"]);
    assert.notEqual(denied.status, 0);
    assert.match(denied.stderr, /SHA-256 mismatch.*before mutation/i);
    assert.deepEqual(aclProjection(stateDir), before, "tampered backup changed state before refusal");
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("state ACL protection refuses reparse points before mutation", { skip: !onWindows }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-acl-reparse-"));
  const stateDir = join(root, "state");
  const outside = join(root, "outside");
  try {
    await mkdir(stateDir);
    await mkdir(outside);
    const junction = join(stateDir, "linked");
    const created = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", `New-Item -ItemType Junction -Path '${junction.replaceAll("'", "''")}' -Target '${outside.replaceAll("'", "''")}' | Out-Null`], { encoding: "utf8", windowsHide: true });
    if (created.status !== 0) return t.skip(`junction creation unavailable: ${created.stderr}`);
    const audited = runScript("scripts/protect-state.ps1", ["-StateDir", stateDir, "-AuditOnly"]);
    assert.notEqual(audited.status, 0);
    assert.match(audited.stderr, /reparse point/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function runScript(script, args, env = {}, timeout) {
  return runScriptWith(powershell, script, args, env, timeout);
}

function runScriptWith(shell, script, args, env = {}, timeout) {
  return spawnSync(shell, ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, ...args], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, ...env },
    ...(timeout === undefined ? {} : { timeout }),
  });
}

function aclProjection(stateDir) {
  const quoted = stateDir.replaceAll("'", "''");
  const command = `$sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access; $items = @(Get-Item -LiteralPath '${quoted}' -Force); $items += @(Get-ChildItem -LiteralPath '${quoted}' -Force -Recurse); @($items | Sort-Object FullName | ForEach-Object { $acl = if ($_.PSIsContainer) { [IO.DirectoryInfo]::new($_.FullName).GetAccessControl() } else { [IO.FileInfo]::new($_.FullName).GetAccessControl() }; [pscustomobject]@{ path=$_.FullName; owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value; protected=[bool]$acl.AreAccessRulesProtected; sddl=$acl.GetSecurityDescriptorSddlForm($sections) } }) | ConvertTo-Json -Depth 4`;
  const result = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-Command", command], { cwd: process.cwd(), encoding: "utf8", windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.trim(), `ACL projection produced no output: ${result.stderr}`);
  const parsed = JSON.parse(result.stdout);
  return Array.isArray(parsed) ? parsed : [parsed];
}

async function waitForPath(path, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(path) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

async function createQuiescenceHarness(root, scriptNames) {
  const harnessRoot = join(root, "quiescence-harness");
  await mkdir(harnessRoot);
  for (const name of scriptNames) {
    await copyFile(join(process.cwd(), "scripts", name), join(harnessRoot, name));
  }
  const source = await readFile(join(process.cwd(), "scripts", "cutover-quiescence.psm1"), "utf8");
  const needle = "CimCmdlets\\Get-CimInstance Win32_Process -ErrorAction Stop";
  assert.equal(source.split(needle).length - 1, 1, "production quiescence CIM call shape changed");
  const testDouble = "function Get-AgentBridgeTestCimInstance { [CmdletBinding()] param([Parameter(Position = 0)][string]$ClassName, [string]$Filter) return @() }";
  await writeFile(join(harnessRoot, "cutover-quiescence.psm1"), source
    .replace(/Set-StrictMode -Version Latest\r?\n/, (line) => `${line}\r\n${testDouble}\r\n`)
    .replace(needle, "Get-AgentBridgeTestCimInstance Win32_Process -ErrorAction Stop"));
  return { switch: join(harnessRoot, "switch-release.ps1"), cutover: join(harnessRoot, "cutover-release.ps1") };
}

async function createInspectionHarness(root) {
  const harnessRoot = join(root, "inspection-harness");
  await mkdir(harnessRoot);
  const source = await readFile(join(process.cwd(), "scripts", "inspect-install.ps1"), "utf8");
  const needle = 'CimCmdlets\\Get-CimInstance Win32_Process -Filter "Name = \'node.exe\'" -ErrorAction Stop';
  assert.equal(source.split(needle).length - 1, 1, "production inspection CIM call shape changed");
  const testDouble = "function Get-AgentBridgeTestCimInstance { [CmdletBinding()] param([Parameter(Position = 0)][string]$ClassName, [string]$Filter) return @() }";
  const harnessScript = join(harnessRoot, "inspect-install.ps1");
  await writeFile(harnessScript, source
    .replace(/Set-StrictMode -Version Latest\r?\n/, (line) => `${line}\r\n${testDouble}\r\n`)
    .replace(needle, 'Get-AgentBridgeTestCimInstance Win32_Process -Filter "Name = \'node.exe\'" -ErrorAction Stop'));
  return harnessScript;
}

async function collect(child) {
  let stdout = ""; let stderr = "";
  child.stdout.on("data", (data) => { stdout += data; });
  child.stderr.on("data", (data) => { stderr += data; });
  const code = await new Promise((resolve) => child.once("exit", resolve));
  return { code, stdout, stderr };
}

function releaseBundle({
  version, gitSha, runtime, sourceMap, claimedRuntimeHash = sha256(runtime), operations = null,
  legacyManifestIdentity = false, manifestVersion = legacyManifestIdentity ? "0.1" : "0.3",
  additionalEntries = [], omitByteCountsFor = [],
}) {
  const operationEntries = operations ?? [];
  const manifest = Buffer.from(`${JSON.stringify({
    manifest_version: manifestVersion, name: "agent-bridge", version,
    description: "test", author: { name: "test" },
    server: { type: "node", entry_point: "server/agent-bridge.mjs" },
    ...(legacyManifestIdentity
      ? { metadata: { source_git_sha: gitSha, runtime_sha256: claimedRuntimeHash } }
      : { _meta: { "com.agentbridge.release": { source_git_sha: gitSha, runtime_sha256: claimedRuntimeHash } } }),
  })}\n`);
  const metadata = Buffer.from(`${JSON.stringify({
    package: "agent-bridge-mcp", version, gitSha,
    operations: operationEntries.length ? releaseOperationContract() : undefined,
    files: {
      "server/agent-bridge.mjs": { sha256: claimedRuntimeHash, bytes: runtime.length },
      "server/agent-bridge.mjs.map": { sha256: sha256(sourceMap), bytes: sourceMap.length },
      ...Object.fromEntries(operationEntries.map((entry) => [entry.relative, { sha256: sha256(entry.bytes), bytes: entry.bytes.length }])),
      ...Object.fromEntries(additionalEntries.map((entry) => [entry.relative, {
        sha256: sha256(entry.bytes),
        ...(!omitByteCountsFor.includes(entry.relative) ? { bytes: entry.bytes.length } : {}),
      }])),
    },
  })}\n`);
  return zipStore([
    { relative: "manifest.json", bytes: manifest },
    { relative: "release-metadata.json", bytes: metadata },
    { relative: "server/agent-bridge.mjs", bytes: runtime },
    { relative: "server/agent-bridge.mjs.map", bytes: sourceMap },
    ...operationEntries,
    ...additionalEntries,
  ]);
}

function releaseOperationContract() {
  return {
    capability: "immutable-release-operations-v2",
    schemaVersion: 2,
    platform: "windows",
    payloads: [
      "server/agent-bridge.mjs",
      "server/agent-bridge.mjs.map",
      ...releaseOperationFixtures().map((entry) => entry.relative),
    ],
    entryPoints: {
      readiness: "operations/check-cutover-readiness.ps1",
      cutover: "operations/cutover-release.ps1",
      rollback: "operations/switch-release.ps1",
      inspection: "operations/inspect-install.ps1",
      stateProtection: "operations/protect-state.ps1",
    },
  };
}

function releaseOperationFixtures() {
  return [
    "operations/check-cutover-readiness.ps1",
    "operations/cutover-release.ps1",
    "operations/switch-release.ps1",
    "operations/inspect-install.ps1",
    "operations/protect-state.ps1",
    "operations/configure-clients.ps1",
    "operations/cutover-lock.psm1",
    "operations/cutover-quiescence.psm1",
  ].map((relative) => ({ relative, bytes: Buffer.from(`# fixture ${relative}\n`) }));
}

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function crc32(bytes) { let crc = 0xffffffff; for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1)); } return (crc ^ 0xffffffff) >>> 0; }
function u16(value) { const bytes = Buffer.alloc(2); bytes.writeUInt16LE(value); return bytes; }
function u32(value) { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value >>> 0); return bytes; }
function zipStore(entries) {
  const local = []; const central = []; let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.relative); const crc = crc32(entry.bytes);
    const header = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(entry.bytes.length), u32(entry.bytes.length), u16(name.length), u16(0), name, entry.bytes]);
    local.push(header);
    central.push(Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(entry.bytes.length), u32(entry.bytes.length), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), name]));
    offset += header.length;
  }
  const localBytes = Buffer.concat(local); const centralBytes = Buffer.concat(central);
  return Buffer.concat([localBytes, centralBytes, u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(centralBytes.length), u32(localBytes.length), u16(0)]);
}
