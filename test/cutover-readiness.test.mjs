import assert from "node:assert/strict";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const skip = process.platform !== "win32";
const productionReadinessScript = resolve("scripts/check-cutover-readiness.ps1");
const productionQuiescenceModule = resolve("scripts/cutover-quiescence.psm1");

test("readiness reports ready only after every PowerShell-scoped CIM sample is empty", { skip }, async () => {
  const result = await run({ samples: [[], []] });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.status, "ready");
  assert.equal(result.report.ready, true);
  assert.equal(result.report.samples.length, 2);
  assert.equal(result.calls, 2);
});

test("readiness blocks a bridge process without exposing its secret-shaped argv", { skip }, async () => {
  const secret = "--api-key sk-test-private-bridge-argument";
  const result = await run({ samples: [[proc(10, 1, "node.exe", "C:\\node.exe", `node C:\\bridge\\agent-bridge.mjs ${secret}`)], []] });
  assert.equal(result.status, 2);
  assert.equal(result.report.status, "not-ready");
  const bridge = result.report.samples[0].bridgeProcesses[0];
  assert.equal(bridge.commandLine, null);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, new RegExp(escapeRegex(secret), "i"));
});

test("readiness blocks Codex and Claude roots plus descendants without host command lines", { skip }, async () => {
  const secrets = ["secret codex command", "secret child", "secret claude command", "secret helper"];
  const result = await run({ samples: [[
    proc(20, 1, "codex.exe", "C:\\Codex.exe", secrets[0]), proc(21, 20, "node.exe", "C:\\node.exe", secrets[1]),
    proc(30, 1, "claude.exe", "C:\\Claude.exe", secrets[2]), proc(31, 30, "helper.exe", "C:\\helper.exe", secrets[3]),
  ], []] });
  assert.equal(result.status, 2);
  assert.equal(result.report.samples[0].hostProcesses.length, 4);
  for (const host of result.report.samples[0].hostProcesses) assert.equal(host.commandLine, null);
  for (const secret of secrets) assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, new RegExp(escapeRegex(secret), "i"));
});

test("readiness fails closed and redacts a CIM capture error", { skip }, async () => {
  const secret = "synthetic CIM unavailable: user-secret-command-line";
  const result = await run({ samples: [{ error: secret }] });
  assert.equal(result.status, 2);
  assert.equal(result.report.status, "error");
  assert.equal(result.report.error, "process inventory failed closed");
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, new RegExp(escapeRegex(secret), "i"));
});

test("readiness rejects invalid bounds", { skip }, () => {
  const result = spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", productionReadinessScript, "-Samples", "1"], { cwd: process.cwd(), encoding: "utf8", windowsHide: true });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /validation/i);
});

test("the production module ignores a caller-scoped Get-CimInstance spoof", { skip }, () => {
  const modulePath = productionQuiescenceModule.replaceAll("'", "''");
  const command = `$global:AgentBridgeSpoofCalls = 0; function global:Get-CimInstance { $global:AgentBridgeSpoofCalls++; @() }; Import-Module '${modulePath}' -Force; Get-AgentBridgeCutoverProcessSample -InstallRoot 'C:\\definitely-not-agent-bridge' | Out-Null; "spoof-calls=$global:AgentBridgeSpoofCalls"`;
  const result = spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], { cwd: process.cwd(), encoding: "utf8", windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /spoof-calls=0/);
});

async function run(scenario) {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-readiness-"));
  const fixture = join(root, "snapshots.json");
  const calls = join(root, "calls.txt");
  const wrapper = join(root, "invoke-with-cim-double.ps1");
  const readinessScript = join(root, "check-cutover-readiness.ps1");
  const quiescenceModule = join(root, "cutover-quiescence.psm1");
  try {
    await writeFile(fixture, `${JSON.stringify(scenario)}\n`);
    await copyFile(productionReadinessScript, readinessScript);
    const productionModuleText = await readFile(productionQuiescenceModule, "utf8");
    const patchedModuleText = replaceExactProductionCimCall(productionModuleText);
    await writeFile(quiescenceModule, patchedModuleText);
    await writeFile(wrapper, cimWrapper());
    const child = spawnSync("powershell.exe", [
      "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", wrapper,
      "-ScenarioPath", fixture, "-CallLogPath", calls, "-TargetScript", readinessScript,
      "-InstallRoot", "C:\\bridge", "-Samples", "2", "-IntervalMilliseconds", "250",
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true });
    const callText = await import("node:fs/promises").then(({ readFile }) => readFile(calls, "utf8"));
    return { status: child.status, stderr: child.stderr, stdout: child.stdout, report: JSON.parse(child.stdout), calls: Number(callText.trim()) };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function cimWrapper() {
  return String.raw`[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ScenarioPath,
    [Parameter(Mandatory=$true)][string]$CallLogPath,
    [Parameter(Mandatory=$true)][string]$TargetScript,
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [int]$Samples,
    [int]$IntervalMilliseconds
)
$ErrorActionPreference = 'Stop'
$global:AgentBridgeCimScenario = Get-Content -Raw -LiteralPath $ScenarioPath | ConvertFrom-Json
$global:AgentBridgeCimIndex = 0
$global:AgentBridgeCimCallLog = $CallLogPath
function global:Get-AgentBridgeTestCimInstance {
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$ClassName, [string]$Filter)
    $index = $global:AgentBridgeCimIndex
    $global:AgentBridgeCimIndex++
    [IO.File]::WriteAllText($global:AgentBridgeCimCallLog, [string]$global:AgentBridgeCimIndex)
    $samples = @($global:AgentBridgeCimScenario.samples)
    if ($index -ge $samples.Count) { throw 'CIM test sequence exhausted' }
    $sample = $samples[$index]
    if ($sample -and $sample.PSObject.Properties.Name -contains 'error') { throw [string]$sample.error }
    return @($sample)
}
& $TargetScript -InstallRoot $InstallRoot -Samples $Samples -IntervalMilliseconds $IntervalMilliseconds
exit $LASTEXITCODE
`;
}

function proc(ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine) {
  return { ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine };
}

function replaceExactProductionCimCall(text) {
  const needle = "CimCmdlets\\Get-CimInstance Win32_Process -ErrorAction Stop";
  assert.equal(text.split(needle).length - 1, 1, "production module CIM call shape changed");
  return text.replace(needle, "Get-AgentBridgeTestCimInstance Win32_Process -ErrorAction Stop");
}

function escapeRegex(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
