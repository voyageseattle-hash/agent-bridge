import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

const onWindows = process.platform === "win32";

test("install inspection counts bridge processes without disclosing their arguments", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-inspection-redaction-test-"));
  const profile = join(root, "profile");
  const appData = join(root, "roaming");
  const localAppData = join(root, "local");
  const installRoot = join(profile, ".codex", "agent-bridge");
  const secret = "sk-inspection-must-never-be-returned-1234567890";
  let child;
  try {
    await mkdir(installRoot, { recursive: true });
    child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", join(installRoot, "agent-bridge.mjs"), secret], {
      windowsHide: true,
      stdio: "ignore",
    });
    await new Promise((resolve) => setTimeout(resolve, 250));
    const report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.ok(report.activeProcessCount >= 1);
    assert.ok(report.activeProcesses.every((process) => process.commandLine === null));
    assert.ok(report.globalActiveProcessCount >= report.activeProcessCount);
    assert.doesNotMatch(JSON.stringify(report), new RegExp(secret));
  } finally {
    if (child && child.exitCode === null) child.kill();
    await rm(root, { recursive: true, force: true });
  }
});

test("install inspection parses active MCP registrations instead of matching comments or unrelated strings", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge#inspection-test-"));
  const profile = join(root, "profile");
  const appData = join(root, "roaming");
  const localAppData = join(root, "local");
  const installRoot = join(profile, ".codex", "agent-bridge");
  const shim = join(installRoot, "agent-bridge.mjs");
  const stale = join(root, "stale", "agent-bridge.mjs");
  const direct = join(installRoot, "releases", "old", "server", "agent-bridge.mjs");
  const sharedConfig = join(installRoot, "config.json");
  const codex = join(profile, ".codex", "config.toml");
  const claude = join(profile, ".claude.json");
  const desktop = join(localAppData, "Packages", "Claude_test", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json");
  try {
    for (const path of [shim, codex, claude, desktop]) await mkdir(dirname(path), { recursive: true });
    await mkdir(appData, { recursive: true });
    await writeFile(shim, "// stable shim\n");
    await writeFile(sharedConfig, "{}\n");
    await writeFile(codex, `[mcp_servers.agent_bridge]\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(stale)}]\n# args = [${JSON.stringify(shim)}]\n\n[unrelated]\nnote = ${JSON.stringify(shim)}\n`);
    await writeFile(claude, `${JSON.stringify({
      mcpServers: { "agent-bridge": { command: process.execPath, args: [stale] } },
      unrelated: { desiredPathOnly: shim },
    })}\n`);
    await writeFile(desktop, `${JSON.stringify({ mcpServers: { "agent-bridge": { command: process.execPath, args: [shim], env: { AGENT_BRIDGE_CONFIG: sharedConfig } } } })}\n`);

    let report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.codex.parseStatus, "parsed");
    assert.equal(report.registrations.codex.usesStableShim, false);
    assert.equal(report.registrations.codex.pinsReleaseDirectly, false);
    assert.equal(report.registrations.claudeCode.usesStableShim, false);
    assert.equal(report.registrations.claudeCode.usesSharedConfig, false);
    assert.equal(report.registrations.claudeCode.registrationReady, false);
    assert.equal(report.registrations.claudeCode.pinsReleaseDirectly, false);
    assert.equal(report.registrations.claudeDesktopPackages[0].usesStableShim, true);
    assert.equal(report.registrations.claudeDesktopPackages[0].usesExpectedNode, true);
    assert.equal(report.registrations.claudeDesktopPackages[0].usesSharedConfig, true);
    assert.equal(report.registrations.claudeDesktopPackages[0].registrationReady, true);

    await writeFile(claude, `${JSON.stringify({ mcpServers: { "agent-bridge": { command: process.execPath, args: [direct], env: { AGENT_BRIDGE_CONFIG: sharedConfig } } }, unrelated: shim })}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.claudeCode.usesStableShim, false);
    assert.equal(report.registrations.claudeCode.pinsReleaseDirectly, true);

    await writeFile(codex, `[mcp_servers.agent_bridge]\nargs = [${JSON.stringify(shim)}]\n\n[mcp_servers.agent_bridge.env]\nAGENT_BRIDGE_CONFIG = ${JSON.stringify(sharedConfig)}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.codex.parseStatus, "ambiguous");
    assert.equal(report.registrations.codex.registrationReady, false);

    await writeFile(codex, `[mcp_servers.agent_bridge]\ncommand = ${JSON.stringify(process.execPath)}\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(shim)}]\n\n[mcp_servers.agent_bridge.env]\nAGENT_BRIDGE_CONFIG = ${JSON.stringify(sharedConfig)}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.codex.parseStatus, "ambiguous");
    assert.equal(report.registrations.codex.registrationReady, false);

    await writeFile(codex, `[mcp_servers.agent_bridge]\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(shim)}]\n\n[mcp_servers.agent_bridge.env]\nAGENT_BRIDGE_CONFIG = ${JSON.stringify(sharedConfig)}\n`.replaceAll("\n", "\r\n"));
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.codex.parseStatus, "parsed", "Windows PowerShell must parse CRLF TOML and preserve a one-element args array");
    assert.equal(report.registrations.codex.usesStableShim, true);
    assert.equal(report.registrations.codex.usesExpectedNode, true);
    assert.equal(report.registrations.codex.registrationReady, true);

    await writeFile(codex, `[mcp_servers.agent_bridge]\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(shim)}]\n\n[mcp_servers.agent_bridge.env]\nAGENT_BRIDGE_CONFIG = '${sharedConfig}'\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.codex.usesSharedConfig, true, "valid TOML literal strings must preserve Windows backslashes");
    assert.equal(report.registrations.codex.registrationReady, true);

    await writeFile(codex, `[mcp_servers.agent_bridge]\ncommand = ${JSON.stringify(process.execPath)}\nargs = ${JSON.stringify(shim)}\n\n[mcp_servers.agent_bridge.env]\nAGENT_BRIDGE_CONFIG = ${JSON.stringify(sharedConfig)}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.codex.parseStatus, "unsupported-command-or-args");
    assert.equal(report.registrations.codex.registrationReady, false, "TOML scalar args must not be accepted as an argument array");

    await writeFile(desktop, `${JSON.stringify({ mcpServers: { "agent-bridge": { command: "C:\\wrong\\cmd.exe", args: [shim], env: { AGENT_BRIDGE_CONFIG: sharedConfig } } } })}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.claudeDesktopPackages[0].usesExpectedNode, false);
    assert.equal(report.registrations.claudeDesktopPackages[0].registrationReady, false);

    await writeFile(desktop, `${JSON.stringify({ mcpServers: { "agent-bridge": { args: [shim], env: { AGENT_BRIDGE_CONFIG: sharedConfig } } } })}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.claudeDesktopPackages[0].parseStatus, "ambiguous");
    assert.equal(report.registrations.claudeDesktopPackages[0].registrationReady, false);

    await writeFile(desktop, `{"mcpServers":{"agent-bridge":{"command":${JSON.stringify(process.execPath)},"args":[${JSON.stringify(stale)}],"args":[${JSON.stringify(shim)}],"env":{"AGENT_BRIDGE_CONFIG":${JSON.stringify(sharedConfig)}}}}}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.claudeDesktopPackages[0].parseStatus, "ambiguous");
    assert.equal(report.registrations.claudeDesktopPackages[0].registrationReady, false, "duplicate JSON args must fail closed");

    await writeFile(desktop, `{"mcpServers":{"agent-bridge":{"command":${JSON.stringify(process.execPath)},"args":[${JSON.stringify(shim)}],"env":{"AGENT_BRIDGE_CONFIG":${JSON.stringify(stale)},"AGENT_BRIDGE_CONFIG":${JSON.stringify(sharedConfig)}}}}}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.claudeDesktopPackages[0].parseStatus, "ambiguous");
    assert.equal(report.registrations.claudeDesktopPackages[0].registrationReady, false, "duplicate shared-config keys must fail closed");

    await writeFile(desktop, `{"mcpServers":{"agent-bridge":{"command":${JSON.stringify(process.execPath)},"command":${JSON.stringify(process.execPath)},"args":[${JSON.stringify(shim)}],"env":{"AGENT_BRIDGE_CONFIG":${JSON.stringify(sharedConfig)}}}}}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.claudeDesktopPackages[0].parseStatus, "ambiguous");
    assert.equal(report.registrations.claudeDesktopPackages[0].registrationReady, false);

    await writeFile(desktop, `${JSON.stringify({ mcpServers: { "agent-bridge": { command: process.execPath, args: shim, env: { AGENT_BRIDGE_CONFIG: sharedConfig } } } })}\n`);
    report = inspect({ profile, appData, localAppData, installRoot, stateDir: join(root, "missing-state") });
    assert.equal(report.registrations.claudeDesktopPackages[0].registrationReady, false, "scalar args must not be accepted as an argument array");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("install inspection warns about a divergent fallback beside an unshared registration", { skip: !onWindows }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-fallback-inspection-test-"));
  const profile = join(root, "profile");
  const appData = join(root, "roaming");
  const localAppData = join(root, "local");
  const installRoot = join(profile, ".codex", "agent-bridge");
  const stateDir = join(root, "state");
  const shim = join(installRoot, "agent-bridge.mjs");
  const sharedConfig = join(installRoot, "config.json");
  const claude = join(profile, ".claude.json");
  try {
    for (const path of [shim, sharedConfig, claude, join(stateDir, "config.json")]) await mkdir(dirname(path), { recursive: true });
    await mkdir(appData, { recursive: true });
    await mkdir(localAppData, { recursive: true });
    await writeFile(shim, "// stable shim\n");
    await writeFile(sharedConfig, "{}\n");
    await writeFile(join(stateDir, "config.json"), '{"agents":{"manus":{"enabled":true}}}\n');
    await writeFile(claude, `${JSON.stringify({ mcpServers: { "agent-bridge": { command: process.execPath, args: [shim] } } })}\n`);

    let report = inspect({ profile, appData, localAppData, installRoot, stateDir });
    assert.equal(report.fallbackConfig.differsFromSharedConfig, true);
    assert.equal(report.fallbackConfig.divergentRegistrationRisk, true);
    assert.deepEqual(report.fallbackConfig.affectedRegistrationPaths, [claude]);

    await writeFile(join(stateDir, "config.json"), "{}\n");
    report = inspect({ profile, appData, localAppData, installRoot, stateDir });
    assert.equal(report.fallbackConfig.differsFromSharedConfig, false);
    assert.equal(report.fallbackConfig.divergentRegistrationRisk, false);
    assert.deepEqual(report.fallbackConfig.affectedRegistrationPaths, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function inspect({ profile, appData, localAppData, installRoot, stateDir }) {
  const result = spawnSync("powershell.exe", [
    "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/inspect-install.ps1",
    "-UserProfile", profile, "-AppData", appData, "-LocalAppData", localAppData,
    "-InstallRoot", installRoot, "-StateDir", stateDir, "-NodePath", process.execPath,
  ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
