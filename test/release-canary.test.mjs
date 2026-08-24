import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("installed release canary exercises MCP without changing live pointers", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-installed-canary-test-"));
  const installRoot = join(root, "install");
  const releasePath = join(installRoot, "releases", "candidate");
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  const evidenceDir = join(root, "evidence");
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const runtimeHash = sha256(await readFile(runtime));
    const stable = {
      shim: "// existing stable shim\n",
      config: "{\"shared\":true}\n",
      marker: `${JSON.stringify({
        schemaVersion: 1,
        releaseId: "older+0000000",
        releasePath: join(installRoot, "releases", "older+0000000"),
        runtimeSha256: "0".repeat(64),
      })}\n`,
    };
    await writeFile(join(installRoot, "agent-bridge.mjs"), stable.shim);
    await writeFile(join(installRoot, "config.json"), stable.config);
    await writeFile(join(installRoot, "current-release.json"), stable.marker);

    const result = spawnSync(process.execPath, [
      "scripts/canary-release.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", runtimeHash,
      "--evidence-dir", evidenceDir,
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "pass");
    assert.equal(report.version, pkg.version);
    assert.equal(report.runtimeSha256, runtimeHash);
    assert.equal(report.promotionStatus, "drift");
    assert.equal(report.requiredToolCount, 33);
    assert.ok(report.toolCount >= report.requiredToolCount);
    assert.equal(report.providerCount, 0);
    assert.equal(JSON.parse(await readFile(report.evidencePath, "utf8")).status, "pass");
    assert.equal(await readFile(join(installRoot, "agent-bridge.mjs"), "utf8"), stable.shim);
    assert.equal(await readFile(join(installRoot, "config.json"), "utf8"), stable.config);
    assert.equal(await readFile(join(installRoot, "current-release.json"), "utf8"), stable.marker);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("installed release canary refuses matching runtime bytes outside the selected install", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-external-canary-test-"));
  const installRoot = join(root, "install");
  const externalRelease = join(root, "external", "releases", "candidate");
  const runtime = join(externalRelease, "server", "agent-bridge.mjs");
  try {
    await mkdir(join(installRoot, "releases"), { recursive: true });
    await mkdir(join(externalRelease, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const result = spawnSync(process.execPath, [
      "scripts/canary-release.mjs",
      "--release-path", externalRelease,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", sha256(await readFile(runtime)),
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /one immutable release directly below/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("installed release canary refuses evidence storage inside the immutable install", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-contained-evidence-test-"));
  const installRoot = join(root, "install");
  const releasePath = join(installRoot, "releases", "candidate");
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  const forbiddenEvidence = join(releasePath, "canary-evidence");
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const result = spawnSync(process.execPath, [
      "scripts/canary-release.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", sha256(await readFile(runtime)),
      "--evidence-dir", forbiddenEvidence,
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /evidence-dir must be outside/i);
    await assert.rejects(readFile(join(forbiddenEvidence, "canary-evidence.json")));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("installed release canary rejects an external junction that resolves evidence inside the install", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-linked-evidence-test-"));
  const installRoot = join(root, "install");
  const releasePath = join(installRoot, "releases", "candidate");
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  const alias = join(root, "external-alias");
  const forbiddenEvidence = join(alias, "canary-evidence");
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    try { await symlink(installRoot, alias, process.platform === "win32" ? "junction" : "dir"); }
    catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) return t.skip(`junction/symlink unavailable: ${error.code}`);
      throw error;
    }
    const beforeRuntime = await readFile(runtime);
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const result = spawnSync(process.execPath, [
      "scripts/canary-release.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", sha256(beforeRuntime),
      "--evidence-dir", forbiddenEvidence,
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /resolves inside.*link or junction/i);
    await assert.rejects(readFile(join(forbiddenEvidence, "canary-evidence.json")));
    assert.deepEqual(await readFile(runtime), beforeRuntime);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("installed release canary validates default temporary storage before creating evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-temp-containment-test-"));
  const installRoot = join(root, "install");
  const releasePath = join(installRoot, "releases", "candidate");
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    const before = await readdir(releasePath);
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const result = spawnSync(process.execPath, [
      "scripts/canary-release.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", sha256(await readFile(runtime)),
    ], {
      cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000,
      env: { ...process.env, TEMP: releasePath, TMP: releasePath, TMPDIR: releasePath },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /temporary directory resolves inside/i);
    assert.deepEqual(await readdir(releasePath), before, "failed default-temp validation must not create evidence inside the release");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("installed release canary resolves a temporary-directory junction before creating evidence", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-temp-junction-test-"));
  const installRoot = join(root, "install");
  const releasePath = join(installRoot, "releases", "candidate");
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  const tempAlias = join(root, "temp-alias");
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    try { await symlink(releasePath, tempAlias, process.platform === "win32" ? "junction" : "dir"); }
    catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) return t.skip(`junction/symlink unavailable: ${error.code}`);
      throw error;
    }
    const before = await readdir(releasePath);
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const result = spawnSync(process.execPath, [
      "scripts/canary-release.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", sha256(await readFile(runtime)),
    ], {
      cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000,
      env: { ...process.env, TEMP: tempAlias, TMP: tempAlias, TMPDIR: tempAlias },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /temporary directory resolves inside/i);
    assert.deepEqual(await readdir(releasePath), before);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }

test("rollback-minimum requires immutable release metadata before starting legacy compatibility checks", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-rollback-minimum-metadata-test-"));
  const installRoot = join(root, "install");
  const releasePath = join(installRoot, "releases", "candidate");
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const result = spawnSync(process.execPath, [
      "scripts/canary-release.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", sha256(await readFile(runtime)),
      "--profile", "rollback-minimum",
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /release-metadata\.json/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("stable-shim canary requires an exact reviewed shared-config hash", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-stable-shim-config-test-"));
  const installRoot = join(root, "install");
  const releasePath = join(installRoot, "releases", "candidate");
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    await writeFile(join(installRoot, "agent-bridge.mjs"), "// inert fixture\n");
    await writeFile(join(installRoot, "config.json"), JSON.stringify({ agents: { codex: { enabled: false }, claude: { enabled: false } } }));
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const result = spawnSync(process.execPath, [
      "scripts/canary-release.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", sha256(await readFile(runtime)),
      "--entrypoint", "stable-shim",
      "--promotion", "current",
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /expected-stable-shim-sha256.*required/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("stable-shim canary rejects a self-consistent marker whose shim targets another release", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-stable-shim-target-test-"));
  const installRoot = join(root, "install");
  const releasePath = join(installRoot, "releases", "candidate");
  const otherRelease = join(installRoot, "releases", "other");
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await mkdir(join(otherRelease, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), join(otherRelease, "server", "agent-bridge.mjs"));
    const shim = 'await import(new URL("./releases/other/server/agent-bridge.mjs", import.meta.url).href);\n';
    const config = JSON.stringify({ agents: { codex: { enabled: false }, claude: { enabled: false } } }) + "\n";
    await writeFile(join(installRoot, "agent-bridge.mjs"), shim);
    await writeFile(join(installRoot, "config.json"), config);
    const runtimeHash = sha256(await readFile(runtime));
    await writeFile(join(installRoot, "current-release.json"), JSON.stringify({
      schemaVersion: 1, releaseId: "candidate", releasePath, runtimeSha256: runtimeHash,
      shimSha256: sha256(Buffer.from(shim)), configSha256: sha256(Buffer.from(config)),
    }));
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8"));
    const result = spawnSync(process.execPath, [
      "scripts/canary-release.mjs",
      "--release-path", releasePath,
      "--install-root", installRoot,
      "--expected-version", pkg.version,
      "--expected-runtime-sha256", runtimeHash,
      "--entrypoint", "stable-shim",
      "--promotion", "current",
      "--expected-stable-shim-sha256", sha256(Buffer.from(shim)),
      "--expected-stable-config-sha256", sha256(Buffer.from(config)),
    ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /stable shim import does not target the selected immutable runtime/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
