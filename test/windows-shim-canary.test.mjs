import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("installed Windows shim canary preserves hostile argv without changing stable files", { skip: process.platform !== "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-windows-shim-canary-test-"));
  const installRoot = join(root, "install");
  const releasePath = join(installRoot, "releases", "candidate");
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  const evidenceDir = join(root, "evidence");
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    const stable = { shim: "// stable shim\n", config: "{\"shared\":true}\n", marker: "{\"releaseId\":\"old\"}\n" };
    await writeFile(join(installRoot, "agent-bridge.mjs"), stable.shim);
    await writeFile(join(installRoot, "config.json"), stable.config);
    await writeFile(join(installRoot, "current-release.json"), stable.marker);
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const result = spawnSync(process.execPath, [
      "scripts/canary-windows-shim.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", createHash("sha256").update(await readFile(runtime)).digest("hex"),
      "--evidence-dir", evidenceDir,
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "pass");
    assert.equal(report.argvPreserved, true);
    assert.equal(report.sentinelAbsent, true);
    assert.deepEqual(report.health, { ran: true, isError: false });
    assert.deepEqual(report.diagnostic, { ran: true, isError: false });
    assert.deepEqual(report.turn, { ran: true, isError: false });
    assert.equal(JSON.parse(await readFile(report.evidencePath, "utf8")).status, "pass");
    assert.equal(await readFile(join(installRoot, "agent-bridge.mjs"), "utf8"), stable.shim);
    assert.equal(await readFile(join(installRoot, "config.json"), "utf8"), stable.config);
    assert.equal(await readFile(join(installRoot, "current-release.json"), "utf8"), stable.marker);

    const wrongVersionEvidence = join(root, "wrong-version-evidence");
    const wrongVersion = spawnSync(process.execPath, [
      "scripts/canary-windows-shim.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", "9.9.9-invalid",
      "--expected-runtime-sha256", createHash("sha256").update(await readFile(runtime)).digest("hex"),
      "--evidence-dir", wrongVersionEvidence,
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.notEqual(wrongVersion.status, 0, "canary accepted a caller-supplied version that the installed runtime did not report");
    const wrongVersionReport = JSON.parse(wrongVersion.stdout);
    assert.equal(wrongVersionReport.status, "fail");
    assert.deepEqual(wrongVersionReport.diagnostic, { ran: true, isError: false });
    assert.match(wrongVersionReport.failure, /unexpected version/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
