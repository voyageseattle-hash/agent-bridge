import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("release live-test support requires absolute runtime identity evidence", async () => {
  const module = await import(`./live-support.mjs?${Date.now()}`);
  const fixture = await mkdtemp(join(tmpdir(), "agent-bridge-live-support-"));
  const installRoot = join(fixture, "install");
  const releaseId = "0.3.0-rc.1+test";
  const releasePath = join(installRoot, "releases", releaseId);
  const runtime = join(releasePath, "server", "agent-bridge.mjs");
  const prior = {
    path: process.env.AGENT_BRIDGE_SERVER_PATH,
    version: process.env.AGENT_BRIDGE_EXPECTED_VERSION,
    hash: process.env.AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256,
    install: process.env.AGENT_BRIDGE_INSTALL_ROOT,
  };
  try {
    await mkdir(join(releasePath, "server"), { recursive: true });
    await copyFile(join(process.cwd(), "dist", "agent-bridge.mjs"), runtime);
    process.env.AGENT_BRIDGE_SERVER_PATH = "relative/server.mjs";
    await assert.rejects(module.resolveLiveServer(), /must be absolute/);
    process.env.AGENT_BRIDGE_SERVER_PATH = runtime;
    delete process.env.AGENT_BRIDGE_EXPECTED_VERSION;
    delete process.env.AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256;
    await assert.rejects(module.resolveLiveServer(), /EXPECTED_VERSION/);
    process.env.AGENT_BRIDGE_EXPECTED_VERSION = "0.3.0-rc.1";
    process.env.AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256 = createHash("sha256").update(await readFile(runtime)).digest("hex");
    process.env.AGENT_BRIDGE_INSTALL_ROOT = installRoot;
    const identity = await module.resolveLiveServer();
    assert.equal(identity.releaseMode, true);
    assert.equal(identity.expectedVersion, "0.3.0-rc.1");
    assert.equal(identity.releaseId, releaseId);

    const sourceRuntime = join(process.cwd(), "dist", "agent-bridge.mjs");
    process.env.AGENT_BRIDGE_SERVER_PATH = sourceRuntime;
    process.env.AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256 = createHash("sha256").update(await readFile(sourceRuntime)).digest("hex");
    await assert.rejects(module.resolveLiveServer(), /must identify one immutable runtime/);
  } finally {
    restore("AGENT_BRIDGE_SERVER_PATH", prior.path);
    restore("AGENT_BRIDGE_EXPECTED_VERSION", prior.version);
    restore("AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256", prior.hash);
    restore("AGENT_BRIDGE_INSTALL_ROOT", prior.install);
    await rm(fixture, { recursive: true, force: true });
  }
});

test("required live-test skips emit structured evidence and exit nonzero", () => {
  const result = spawnSync(process.execPath, [
    "--input-type=module", "--eval",
    "import { skipLive } from './test/live-support.mjs'; skipLive('claude', 'quota unavailable');",
  ], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true,
    env: { ...process.env, AGENT_BRIDGE_LIVE_REQUIRED: "1" },
  });
  assert.equal(result.status, 2, result.stderr);
  const evidence = JSON.parse(result.stdout);
  assert.equal(evidence.backend, "claude");
  assert.equal(evidence.status, "skip");
  assert.equal(evidence.reason, "quota unavailable");
});

test("required live mode refuses to fall back to source dist", () => {
  const result = spawnSync(process.execPath, [
    "--input-type=module", "--eval",
    "import { resolveLiveServer } from './test/live-support.mjs'; await resolveLiveServer();",
  ], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true,
    env: Object.fromEntries(Object.entries({ ...process.env, AGENT_BRIDGE_LIVE_REQUIRED: "1" })
      .filter(([name]) => !["AGENT_BRIDGE_SERVER_PATH", "AGENT_BRIDGE_EXPECTED_VERSION", "AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256", "AGENT_BRIDGE_INSTALL_ROOT"].includes(name))),
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /AGENT_BRIDGE_SERVER_PATH is required/);
});

function restore(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
