import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const onWindows = process.platform === "win32";
const scriptsRoot = resolve("scripts");

test("exact cutover scripts complete under an empty PowerShell-scoped CIM inventory", { skip: !onWindows }, async () => {
  const fixture = await createFixture("empty");
  try {
    const result = await runCutover(fixture, emptyCalls(20));
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).status, "cutover-complete");
    assert.match(await readFile(fixture.paths.shim, "utf8"), new RegExp(escapeRegex(fixture.releaseId)));
    assert.equal(JSON.parse(await readFile(fixture.paths.marker, "utf8")).releaseId, fixture.releaseId);
    for (const path of fixture.registrationPaths) {
      assert.match(await readFile(path, "utf8"), new RegExp(escapeRegex(fixture.paths.shim.replaceAll("\\", "\\\\"))));
    }
    assert.ok(result.calls >= 12, `expected the complete quiescence sequence, saw ${result.calls} CIM calls`);
    const repeated = await runCutover(fixture, emptyCalls(20));
    assert.equal(repeated.status, 0, repeated.stderr);
    const repeatedReport = JSON.parse(repeated.stdout);
    assert.equal(repeatedReport.status, "already-current");
    assert.equal(repeatedReport.stateAcl.after.compliant, true);
    assert.deepEqual(repeatedReport.stateAcl.authorization, { applyStateAcl: true, protectionInvoked: false, rollbackPolicy: "forward-only-security-hardening" });
    assert.equal(repeatedReport.registrationBackupPath, null);
    assert.equal(repeatedReport.promotion.backupPath, null);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("cutover refuses a noncompliant state ACL without explicit repair authorization", { skip: !onWindows }, async () => {
  const fixture = await createFixture("acl-authorization");
  try {
    const result = await runCutover(fixture, emptyCalls(20), { applyStateAcl: false });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /explicit -ApplyStateAcl authorization is required/i);
    await assertExactState(fixture, fixture.originals);
    const audit = runPowerShell("scripts/protect-state.ps1", ["-StateDir", fixture.paths.state, "-AuditOnly"]);
    assert.equal(audit.status, 0, audit.stderr);
    assert.equal(JSON.parse(audit.stdout).compliant, false, "an unauthorized cutover must not repair the ACL");
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

for (const scenario of [
  { label: "different-hash", bytes: Buffer.from('{"fallback":true}\r\n', "utf8") },
  { label: "different-path", bytes: null },
]) {
  test(`cutover rejects a fallback config with a ${scenario.label.replace("-", " ")}`, { skip: !onWindows }, async () => {
    const fixture = await createFixture(`fallback-${scenario.label}`);
    try {
      const fallback = join(fixture.paths.state, "config.json");
      const bytes = scenario.bytes ?? await readFile(fixture.paths.config);
      await writeFile(fallback, bytes);
      const result = await runCutover(fixture, emptyCalls(20));
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /fallback config whose path or SHA-256 differs/i);
      assert.doesNotMatch(result.stderr, /client registrations were restored/i);
      await assertExactState(fixture, fixture.originals);
      assert.deepEqual(await readFile(fallback), bytes, "fallback config bytes changed");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
}

for (const initialSampleIndex of [1, 2]) {
  test(`a host in initial quiescence sample ${initialSampleIndex} leaves registrations and install pointers byte-identical`, { skip: !onWindows }, async () => {
    const fixture = await createFixture(`initial-${initialSampleIndex}`);
    const secret = `initial-host-secret-${initialSampleIndex}`;
    try {
      const calls = emptyCalls(20);
      // Call zero is the bridge-only precheck; calls one and two are the two
      // operational-quiescence samples before any registration mutation.
      calls[initialSampleIndex] = { processes: [proc(100 + initialSampleIndex, 1, "codex.exe", "C:\\Codex.exe", secret)] };
      const result = await runCutover(fixture, calls);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /operational quiescence failed/i);
      await assertExactState(fixture, fixture.originals);
      assertSecretRedacted(result, secret);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
}

for (const preSwitchSampleIndex of [7, 8]) {
  test(`a host in pre-switch quiescence call ${preSwitchSampleIndex + 1} restores registrations and every install pointer`, { skip: !onWindows }, async () => {
    const fixture = await createFixture(`pre-switch-${preSwitchSampleIndex}`);
    const secret = `pre-switch-host-secret-${preSwitchSampleIndex}`;
    try {
      const calls = emptyCalls(24);
      // After registration Apply, cutover-release takes two more operational
      // samples. A host in either sample must trigger the registration restore.
      calls[preSwitchSampleIndex] = { processes: [proc(200 + preSwitchSampleIndex, 1, "claude.exe", "C:\\Claude.exe", secret)] };
      const result = await runCutover(fixture, calls);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /client registrations were restored/i);
      await assertExactState(fixture, fixture.originals);
      assertSecretRedacted(result, secret);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
}

test("a host descendant observed after the maintenance barrier restores registrations and install state", { skip: !onWindows }, async () => {
  const fixture = await createFixture("post-barrier-descendant");
  const secretRoot = "post-barrier-codex-root-secret";
  const secretChild = "post-barrier-descendant-secret";
  try {
    const calls = emptyCalls(28);
    // The twelfth CIM call is the operational sample immediately after the
    // bridge-only barrier precheck. The wrapper records the real shim bytes at
    // that exact call, then returns a host tree whose child is not a bridge.
    calls[13] = {
      observePath: fixture.paths.shim,
      processes: [
        proc(310, 1, "codex.exe", "C:\\Codex.exe", secretRoot),
        proc(311, 310, "helper.exe", "C:\\helper.exe", secretChild),
      ],
    };
    const result = await runCutover(fixture, calls);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /client registrations were restored/i);
    assert.match(result.observedText, /cutover is in progress/i, "CIM double did not observe the refusing maintenance shim");
    await assertExactState(fixture, fixture.originals);
    assertSecretRedacted(result, secretRoot);
    assertSecretRedacted(result, secretChild);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("a CIM capture failure fails closed before mutation and does not expose its raw message", { skip: !onWindows }, async () => {
  const fixture = await createFixture("capture-error");
  const secret = "CIM failed while reading private-user-command-line";
  try {
    const calls = emptyCalls(20);
    calls[1] = { error: secret };
    const result = await runCutover(fixture, calls);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /capture failed; no mutation was authorized/i);
    await assertExactState(fixture, fixture.originals);
    assertSecretRedacted(result, secret);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

async function createFixture(label) {
  const root = await mkdtemp(join(tmpdir(), `agent-bridge-quiescence-${label}-`));
  const profile = join(root, "profile");
  const appData = join(root, "roaming");
  const localAppData = join(root, "local");
  const installRoot = join(profile, ".codex", "agent-bridge");
  const version = "0.3.0-rc.5";
  const gitSha = "abcdef1234567890abcdef1234567890abcdef12";
  const releaseId = `${version}+${gitSha.slice(0, 7)}`;
  const releaseRoot = join(installRoot, "releases", releaseId);
  const runtime = join(releaseRoot, "server", "agent-bridge.mjs");
  const paths = {
    shim: join(installRoot, "agent-bridge.mjs"),
    config: join(installRoot, "config.json"),
    marker: join(installRoot, "current-release.json"),
    codex: join(profile, ".codex", "config.toml"),
    claude: join(profile, ".claude.json"),
    legacy: join(appData, "Claude", "claude_desktop_config.json"),
    packaged: join(localAppData, "Packages", "Claude_test", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"),
    state: join(root, "state"),
  };
  const initial = new Map([
    [paths.shim, Buffer.from("// exact prior shim\r\n", "utf8")],
    [paths.config, Buffer.from("{\"shared\":true}\r\n", "utf8")],
    [paths.marker, Buffer.from("{\"releaseId\":\"old\",\"sentinel\":\"marker\"}\r\n", "utf8")],
    [paths.codex, Buffer.from("keep = \"codex\"\r\n", "utf8")],
    [paths.claude, Buffer.from("{\"unrelated\":\"claude\"}\r\n", "utf8")],
    [paths.legacy, Buffer.from("{\"legacy\":true}\r\n", "utf8")],
    [paths.packaged, Buffer.from("{\"packaged\":true}\r\n", "utf8")],
  ]);
  for (const [path, bytes] of initial) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes);
  }
  await mkdir(paths.state);
  const runtimeBytes = Buffer.from("export const candidate = true;\n", "utf8");
  const sourceMapBytes = Buffer.from("{}\n", "utf8");
  await mkdir(dirname(runtime), { recursive: true });
  await writeFile(runtime, runtimeBytes);
  await writeFile(`${runtime}.map`, sourceMapBytes);
  const operationNames = [
    "check-cutover-readiness.ps1", "cutover-release.ps1", "switch-release.ps1", "inspect-install.ps1",
    "protect-state.ps1", "configure-clients.ps1", "cutover-lock.psm1", "cutover-quiescence.psm1",
  ];
  const operationFiles = {};
  for (const name of operationNames) {
    const bytes = await readFile(join(scriptsRoot, name));
    const target = join(releaseRoot, "operations", name);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes);
    operationFiles[`operations/${name}`] = { sha256: sha256(bytes), bytes: bytes.length };
  }
  await writeFile(join(releaseRoot, "release-metadata.json"), `${JSON.stringify({
    version, gitSha,
    operations: operationContract(),
    files: {
      "server/agent-bridge.mjs": { sha256: sha256(runtimeBytes), bytes: runtimeBytes.length },
      "server/agent-bridge.mjs.map": { sha256: sha256(sourceMapBytes), bytes: sourceMapBytes.length },
      ...operationFiles,
    },
  })}\n`);
  return {
    root, profile, appData, localAppData, installRoot, releaseId, paths,
    registrationPaths: [paths.codex, paths.claude, paths.legacy, paths.packaged],
    originals: new Map([...initial].map(([path, bytes]) => [path, Buffer.from(bytes)])),
  };
}

async function runCutover(fixture, calls, { applyStateAcl = true } = {}) {
  const scenarioPath = join(fixture.root, "cim-calls.json");
  const callLogPath = join(fixture.root, "cim-call-count.txt");
  const observationPath = join(fixture.root, "cim-observation.txt");
  const wrapperPath = join(fixture.root, "invoke-cutover-with-cim-double.ps1");
  const harnessRoot = join(fixture.root, "script-harness");
  await mkdir(harnessRoot, { recursive: true });
  await writeFile(callLogPath, "0\n");
  for (const name of ["cutover-release.ps1", "configure-clients.ps1", "switch-release.ps1", "inspect-install.ps1", "protect-state.ps1", "cutover-lock.psm1"]) {
    await copyFile(join(scriptsRoot, name), join(harnessRoot, name));
  }
  for (const name of ["configure-clients.ps1", "inspect-install.ps1", "cutover-lock.psm1"]) {
    const productionScript = await readFile(join(harnessRoot, name), "utf8");
    await writeFile(join(harnessRoot, name), replaceExactProductionCimCall(productionScript));
  }
  const productionModule = await readFile(join(scriptsRoot, "cutover-quiescence.psm1"), "utf8");
  await writeFile(join(harnessRoot, "cutover-quiescence.psm1"), replaceExactProductionCimCall(productionModule));
  const cutoverScript = join(harnessRoot, "cutover-release.ps1");
  await writeFile(scenarioPath, `${JSON.stringify({ calls })}\n`);
  await writeFile(wrapperPath, cutoverWrapper());
  const child = spawnSync("powershell.exe", [
    "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", wrapperPath,
    "-ScenarioPath", scenarioPath, "-CallLogPath", callLogPath, "-ObservationPath", observationPath,
    "-TargetScript", cutoverScript, "-ReleaseId", fixture.releaseId, "-InstallRoot", fixture.installRoot,
    "-StateDir", fixture.paths.state,
    "-UserProfile", fixture.profile, "-AppData", fixture.appData, "-LocalAppData", fixture.localAppData,
    "-NodePath", process.execPath,
    ...(applyStateAcl ? ["-ApplyStateAcl", "-StateAclBackupPath", join(fixture.root, "state-acl-backup.json")] : []),
  ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
  const callsMade = Number((await readFile(callLogPath, "utf8")).trim());
  let observedText = null;
  try { observedText = Buffer.from(await readFile(observationPath, "utf8"), "base64").toString("utf8"); } catch {}
  return { status: child.status, stdout: child.stdout, stderr: child.stderr, calls: callsMade, observedText };
}

function cutoverWrapper() {
  return String.raw`[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ScenarioPath,
    [Parameter(Mandatory=$true)][string]$CallLogPath,
    [Parameter(Mandatory=$true)][string]$ObservationPath,
    [Parameter(Mandatory=$true)][string]$TargetScript,
    [Parameter(Mandatory=$true)][string]$ReleaseId,
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$StateDir,
    [Parameter(Mandatory=$true)][string]$UserProfile,
    [Parameter(Mandatory=$true)][string]$AppData,
    [Parameter(Mandatory=$true)][string]$LocalAppData,
    [Parameter(Mandatory=$true)][string]$NodePath,
    [switch]$ApplyStateAcl,
    [string]$StateAclBackupPath
)
$ErrorActionPreference = 'Stop'
$global:AgentBridgeCimScenario = Get-Content -Raw -LiteralPath $ScenarioPath | ConvertFrom-Json
$global:AgentBridgeCimIndex = 0
$global:AgentBridgeCimCallLog = $CallLogPath
$global:AgentBridgeCimObservation = $ObservationPath
function global:Invoke-AgentBridgeCimTestDouble {
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$ClassName, [string]$Filter)
    $index = $global:AgentBridgeCimIndex
    $global:AgentBridgeCimIndex++
    [IO.File]::WriteAllText($global:AgentBridgeCimCallLog, [string]$global:AgentBridgeCimIndex)
    $calls = @($global:AgentBridgeCimScenario.calls)
    if ($index -ge $calls.Count) { throw 'CIM test sequence exhausted' }
    $call = $calls[$index]
    if ($call.PSObject.Properties.Name -contains 'observePath' -and $call.observePath) {
        $bytes = [IO.File]::ReadAllBytes([string]$call.observePath)
        [IO.File]::WriteAllText($global:AgentBridgeCimObservation, [Convert]::ToBase64String($bytes))
    }
    if ($call.PSObject.Properties.Name -contains 'error' -and $call.error) { throw [string]$call.error }
    return @($call.processes)
}
function global:Get-CimInstance {
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$ClassName, [string]$Filter)
    Invoke-AgentBridgeCimTestDouble @PSBoundParameters
}
try {
    $targetArgs = @{ ReleaseId = $ReleaseId; InstallRoot = $InstallRoot; StateDir = $StateDir; UserProfile = $UserProfile; AppData = $AppData; LocalAppData = $LocalAppData; NodePath = $NodePath; QuiescenceSamples = 2; QuiescenceIntervalMilliseconds = 250 }
    if ($ApplyStateAcl) { $targetArgs.ApplyStateAcl = $true; $targetArgs.StateAclBackupPath = $StateAclBackupPath }
    & $TargetScript @targetArgs
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
`;
}

async function assertExactState(fixture, expected) {
  for (const [path, bytes] of expected) {
    assert.deepEqual(await readFile(path), bytes, `${path} was not restored byte-for-byte`);
  }
}

function emptyCalls(count) { return Array.from({ length: count }, () => ({ processes: [] })); }
function proc(ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine) { return { ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine }; }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function escapeRegex(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function assertSecretRedacted(result, secret) { assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, new RegExp(escapeRegex(secret), "i")); }

function runPowerShell(script, args) {
  return spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, ...args], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true, maxBuffer: 4 * 1024 * 1024,
  });
}

function operationContract() {
  const operations = [
    "operations/check-cutover-readiness.ps1", "operations/cutover-release.ps1", "operations/switch-release.ps1", "operations/inspect-install.ps1",
    "operations/protect-state.ps1", "operations/configure-clients.ps1", "operations/cutover-lock.psm1", "operations/cutover-quiescence.psm1",
  ];
  return {
    capability: "immutable-release-operations-v2",
    schemaVersion: 2,
    platform: "windows",
    payloads: ["server/agent-bridge.mjs", "server/agent-bridge.mjs.map", ...operations],
    entryPoints: {
      readiness: operations[0], cutover: operations[1], rollback: operations[2], inspection: operations[3], stateProtection: operations[4],
    },
  };
}

function replaceExactProductionCimCall(text) {
  const needles = [
    "CimCmdlets\\Get-CimInstance Win32_Process -ErrorAction Stop",
    "CimCmdlets\\Get-CimInstance Win32_Process -Filter \"Name = 'node.exe'\" -ErrorAction Stop",
  ];
  const needle = needles.find((candidate) => text.includes(candidate));
  assert.ok(needle, "production CIM call shape changed");
  assert.equal(text.split(needle).length - 1, 1, "production CIM call must be unambiguous");
  const privateDouble = String.raw`function Get-AgentBridgeTestCimInstance {
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$ClassName, [string]$Filter)
    $index = $global:AgentBridgeCimIndex
    $global:AgentBridgeCimIndex++
    [IO.File]::WriteAllText($global:AgentBridgeCimCallLog, [string]$global:AgentBridgeCimIndex)
    $calls = @($global:AgentBridgeCimScenario.calls)
    if ($index -ge $calls.Count) { throw 'CIM test sequence exhausted' }
    $call = $calls[$index]
    if ($call.PSObject.Properties.Name -contains 'observePath' -and $call.observePath) {
        $bytes = [IO.File]::ReadAllBytes([string]$call.observePath)
        [IO.File]::WriteAllText($global:AgentBridgeCimObservation, [Convert]::ToBase64String($bytes))
    }
    if ($call.PSObject.Properties.Name -contains 'error' -and $call.error) { throw [string]$call.error }
    return @($call.processes)
}

`;
  return text.replace(/Set-StrictMode -Version Latest\r?\n/, (line) => `${line}\r\n${privateDouble}`)
    .replace(needle, needle.replace("CimCmdlets\\Get-CimInstance", "Get-AgentBridgeTestCimInstance"));
}
