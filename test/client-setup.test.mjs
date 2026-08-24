import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

const onWindows = process.platform === "win32";
const powershell = "powershell.exe";

test("client configuration dry-run classifies registrations without touching them", { skip: !onWindows }, async () => {
  const fixture = await makeFixture();
  try {
    const beforeCodex = await readFile(fixture.codex, "utf8");
    const result = runConfigure(fixture);
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "dry-run");
    assert.equal(report.backupPath, null);
    assert.equal(client(report, "codex").state, "direct-release");
    assert.equal(client(report, "claude-code").state, "correct");
    assert.equal(client(report, "claude-desktop-legacy").state, "stale");
    assert.equal(client(report, "claude-desktop-packaged").state, "absent");
    assert.equal(await readFile(fixture.codex, "utf8"), beforeCodex);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("client configuration classifies and rewrites CRLF TOML without duplicating its registration", { skip: !onWindows }, async () => {
  const fixture = await makeFixture("agent-bridge#client-setup-crlf-");
  try {
    const crlf = (await readFile(fixture.codex, "utf8")).replaceAll("\n", "\r\n");
    await writeFile(fixture.codex, crlf);
    const beforeResult = runConfigure(fixture);
    assert.equal(beforeResult.status, 0, beforeResult.stderr);
    const before = JSON.parse(beforeResult.stdout);
    assert.equal(client(before, "codex").state, "direct-release");

    const scripts = await createQuiescenceHarness(fixture.root, ["configure-clients.ps1", "cutover-lock.psm1"]);
    const applied = runConfigure(fixture, ["-Apply"], scripts.configure);
    assert.equal(applied.status, 0, applied.stderr);
    const afterResult = runConfigure(fixture);
    assert.equal(afterResult.status, 0, afterResult.stderr);
    const after = JSON.parse(afterResult.stdout);
    assert.equal(client(after, "codex").state, "correct");
    assert.equal((await readFile(fixture.codex, "utf8")).match(/\[mcp_servers\.agent_bridge\]/g)?.length, 1);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("client configuration applies with backups, preserves unrelated content, and restores exact originals", { skip: !onWindows }, async () => {
  const fixture = await makeFixture();
  try {
    const scripts = await createQuiescenceHarness(fixture.root, ["configure-clients.ps1", "cutover-lock.psm1"]);
    const original = new Map();
    for (const path of [fixture.codex, fixture.claudeCode, fixture.legacy]) original.set(path, await readFile(path));

    const applied = runConfigure(fixture, ["-Apply"], scripts.configure);
    assert.equal(applied.status, 0, applied.stderr);
    const report = JSON.parse(applied.stdout);
    assert.equal(report.status, "applied");
    assert.ok(report.backupPath);

    const codex = await readFile(fixture.codex, "utf8");
    assert.match(codex, /keep_me = "yes"/);
    assert.match(codex, new RegExp(escapeRegex(tomlString(fixture.shim))));
    assert.doesNotMatch(codex, /releases\\old/);
    const claudeCode = JSON.parse(await readFile(fixture.claudeCode, "utf8"));
    assert.deepEqual(claudeCode.unrelated, { keep: true });
    assert.equal(claudeCode.mcpServers["agent-bridge"].customField, "preserved");
    assert.equal(claudeCode.mcpServers["agent-bridge"].args[0], fixture.shim);
    assert.equal(claudeCode.mcpServers["agent-bridge"].env.EXTRA, "keep");
    assert.equal(claudeCode.mcpServers["agent-bridge"].env.AGENT_BRIDGE_CONFIG, fixture.config);
    const packaged = JSON.parse(await readFile(fixture.packaged, "utf8"));
    assert.equal(packaged.mcpServers["agent-bridge"].args[0], fixture.shim);

    const manifest = JSON.parse(await readFile(join(report.backupPath, "restore-manifest.json"), "utf8"));
    assert.equal(manifest.files.length, 3);
    assert.equal(manifest.files.filter((entry) => entry.existed).length, 2);
    for (const entry of manifest.files.filter((item) => item.existed)) {
      assert.deepEqual(await readFile(join(report.backupPath, entry.backupFile)), original.get(entry.originalPath));
    }

    const restored = runConfigure(fixture, ["-RestoreFrom", report.backupPath, "-Apply"], scripts.configure);
    assert.equal(restored.status, 0, restored.stderr);
    for (const [path, bytes] of original) assert.deepEqual(await readFile(path), bytes);
    await assert.rejects(readFile(fixture.packaged));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("client configuration refuses ambiguous TOML before writing anything", { skip: !onWindows }, async () => {
  const fixture = await makeFixture();
  try {
    const duplicate = `${await readFile(fixture.codex, "utf8")}\n[mcp_servers.agent-bridge]\ncommand = "node"\n`;
    await writeFile(fixture.codex, duplicate);
    const result = runConfigure(fixture, ["-Apply"]);
    assert.equal(result.status, 2, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "refused");
    assert.equal(client(report, "codex").state, "ambiguous");
    assert.equal(await readFile(fixture.codex, "utf8"), duplicate);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("commented desired TOML values cannot mask stale live assignments", { skip: !onWindows }, async () => {
  const fixture = await makeFixture();
  try {
    await writeFile(fixture.codex, `[mcp_servers.agent_bridge]\ncommand = "C:\\\\wrong\\\\node.exe"\nargs = ["C:\\\\wrong\\\\agent-bridge.mjs"]\n# command = ${tomlString(fixture.node)}\n# args = [${tomlString(fixture.shim)}]\n\n[mcp_servers.agent_bridge.env]\nAGENT_BRIDGE_CONFIG = "C:\\\\wrong\\\\config.json"\n# AGENT_BRIDGE_CONFIG = ${tomlString(fixture.config)}\n`);
    const result = runConfigure(fixture);
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(client(report, "codex").state, "stale");
    assert.equal(client(report, "codex").changeRequired, true);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("client configuration refuses multiple packaged Claude Desktop targets", { skip: !onWindows }, async () => {
  const fixture = await makeFixture();
  try {
    await mkdir(join(fixture.localAppData, "Packages", "Claude_second"), { recursive: true });
    const result = runConfigure(fixture, ["-Apply"]);
    assert.equal(result.status, 2, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "refused");
    assert.equal(report.desktopPackageCandidates.length, 2);
    assert.match(report.errors.join("\n"), /target is ambiguous/i);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("client configuration refuses Apply while its target install is active", { skip: !onWindows }, async () => {
  const fixture = await makeFixture();
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", fixture.shim], { stdio: "ignore", windowsHide: true });
  try {
    await new Promise((resolve) => setTimeout(resolve, 600));
    const result = runConfigure(fixture, ["-Apply"]);
    assert.equal(result.status, 2, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "refused");
    assert.equal(report.activeProcesses.length, 1);
    assert.equal(report.backupPath, null);
  } finally {
    child.kill();
    await new Promise((resolve) => child.once("exit", resolve));
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("client configuration Apply fails closed when a cutover diagnostic lock is present", { skip: !onWindows }, async () => {
  const fixture = await makeFixture();
  try {
    await writeFile(join(fixture.installRoot, ".agent-bridge-cutover.lock"), "held\n");
    const result = runConfigure(fixture, ["-Apply"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /cutover mutation owns the install lock/i);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

async function makeFixture(prefix = "agent-bridge-client-setup-") {
  const root = await mkdtemp(join(tmpdir(), prefix));
  const userProfile = join(root, "profile");
  const appData = join(root, "roaming");
  const localAppData = join(root, "local");
  const installRoot = join(userProfile, ".codex", "agent-bridge");
  const shim = join(installRoot, "agent-bridge.mjs");
  const config = join(installRoot, "config.json");
  const node = process.execPath;
  const codex = join(userProfile, ".codex", "config.toml");
  const claudeCode = join(userProfile, ".claude.json");
  const legacy = join(appData, "Claude", "claude_desktop_config.json");
  const packageRoot = join(localAppData, "Packages", "Claude_test");
  const packaged = join(packageRoot, "LocalCache", "Roaming", "Claude", "claude_desktop_config.json");
  for (const path of [shim, config, codex, claudeCode, legacy]) await mkdir(dirname(path), { recursive: true });
  await mkdir(packageRoot, { recursive: true });
  await writeFile(shim, "// fixture shim\n");
  await writeFile(config, "{}\n");
  await writeFile(codex, `keep_me = "yes"\n\n[mcp_servers.agent_bridge]\ncommand = ${tomlString(node)}\nargs = [${tomlString(join(installRoot, "releases", "old", "server", "agent-bridge.mjs"))}]\n\n[mcp_servers.agent_bridge.env]\nAGENT_BRIDGE_CONFIG = ${tomlString(config)}\n\n[unrelated]\nvalue = 7\n`);
  await writeFile(claudeCode, `${JSON.stringify({
    unrelated: { keep: true },
    mcpServers: { "agent-bridge": { command: node, args: [shim], customField: "preserved", env: { AGENT_BRIDGE_CONFIG: config, EXTRA: "keep" } } },
  }, null, 2)}\n`);
  await writeFile(legacy, `${JSON.stringify({ mcpServers: { "agent-bridge": { command: node, args: ["C:\\stale\\agent-bridge.mjs"] } }, keep: 9 }, null, 2)}\n`);
  return { root, userProfile, appData, localAppData, installRoot, shim, config, node, codex, claudeCode, legacy, packaged };
}

function runConfigure(fixture, extra = [], script = "scripts/configure-clients.ps1") {
  return spawnSync(powershell, ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
    "-UserProfile", fixture.userProfile, "-AppData", fixture.appData, "-LocalAppData", fixture.localAppData,
    "-InstallRoot", fixture.installRoot, "-NodePath", fixture.node, ...extra], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true, maxBuffer: 4 * 1024 * 1024,
  });
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
  return { configure: join(harnessRoot, "configure-clients.ps1") };
}

function client(report, name) { return report.clients.find((entry) => entry.client === name); }
function tomlString(value) { return JSON.stringify(value); }
function escapeRegex(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
