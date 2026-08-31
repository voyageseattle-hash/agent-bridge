import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

const VERSION = "0.3.0-rc.9";
const OPERATION_SOURCES = [
  "check-cutover-readiness.ps1",
  "cutover-release.ps1",
  "switch-release.ps1",
  "inspect-install.ps1",
  "protect-state.ps1",
  "configure-clients.ps1",
  "cutover-lock.psm1",
  "cutover-quiescence.psm1",
];

test("package transaction ignores its own temporary output and publishes from a clean Git fixture", async () => {
  const fixture = await createFixture("success");
  try {
    const result = runPackage(fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /package verified:/i);
    assert.equal(existsSync(fixture.output), true, "verified bundle was not published");
    assert.ok((await readFile(fixture.output)).byteLength > 0, "published bundle is empty");
    assert.deepEqual(await publicationTempFiles(fixture), [], "publication temp file survived success");
    assert.equal(existsSync(fixture.staging), true, "successful candidate staging was unexpectedly removed");
    assert.equal(git(fixture.repo, "status", "--porcelain"), "", "packager transaction dirtied the fixture repository");
  } finally {
    await fixture.cleanup();
  }
});

test("tracked-file drift during packaging fails without publishing and removes candidate staging and temp files", async () => {
  const fixture = await createFixture("drift");
  let watcher;
  try {
    const ready = join(fixture.outer, "watcher-ready");
    const fired = join(fixture.outer, "watcher-fired");
    watcher = spawn(process.execPath, [fixture.watcherScript, fixture.stagingRoot, fixture.staging, fixture.driftTarget, ready, fired], {
      cwd: fixture.outer,
      stdio: ["ignore", "ignore", "pipe"],
      windowsHide: true,
    });
    await waitForPath(ready, watcher, "drift watcher did not become ready");

    const result = runPackage(fixture);
    assert.notEqual(result.status, 0, "packager published despite tracked-file drift");
    assert.match(result.stderr, /(?:changed after collection|differs from committed|worktree changed during packaging)/i);
    await waitForPath(fired, watcher, "drift watcher did not inject the tracked-file change");
    await waitForExit(watcher);
    watcher = undefined;

    assert.equal(existsSync(fixture.output), false, "failed package was published");
    assert.equal(existsSync(fixture.staging), false, "failed candidate staging survived rollback");
    assert.deepEqual(await publicationTempFiles(fixture), [], "publication temp file survived failure");
    assert.deepEqual(await readdir(fixture.stagingRoot), [], "failed candidate left staging debris");
    assert.match(git(fixture.repo, "status", "--porcelain"), /scripts\/check-cutover-readiness\.ps1/i);
  } finally {
    if (watcher && watcher.exitCode === null) {
      watcher.kill();
      await waitForExit(watcher);
    }
    await fixture.cleanup();
  }
});

async function createFixture(label) {
  const outer = await mkdtemp(join(tmpdir(), `agent-bridge-package-${label}-`));
  const repo = join(outer, "repo");
  const scripts = join(repo, "scripts");
  const stagingRoot = join(repo, ".release-staging");
  const staging = join(stagingRoot, `agent-bridge-v${VERSION}`);
  const output = join(repo, `agent-bridge-v${VERSION}.mcpb`);
  const watcherScript = join(outer, "inject-drift.mjs");
  await mkdir(scripts, { recursive: true });
  await mkdir(stagingRoot, { recursive: true });
  await copyFile(resolve("scripts/package.mjs"), join(scripts, "package.mjs"));
  await copyFile(resolve("scripts/release-operations.mjs"), join(scripts, "release-operations.mjs"));
  await copyFile(resolve("scripts/scan-public.mjs"), join(scripts, "scan-public.mjs"));
  for (const [index, name] of OPERATION_SOURCES.entries()) {
    await writeFile(join(scripts, name), `# committed operation ${index + 1}: ${name}\n`);
  }
  await writeFile(join(scripts, "build.mjs"), String.raw`import { mkdirSync, writeFileSync } from "node:fs";
mkdirSync("dist", { recursive: true });
writeFileSync("dist/agent-bridge.mjs", "export const packaged = true;\n");
writeFileSync("dist/agent-bridge.mjs.map", "{}\n");
`);
  await writeFile(join(repo, "package.json"), `${JSON.stringify({ name: "agent-bridge-package-fixture", version: VERSION, type: "module" }, null, 2)}\n`);
  await writeFile(join(repo, "manifest.template.json"), `${JSON.stringify({
    manifest_version: "0.3",
    name: "agent-bridge-package-fixture",
    version: "__PACKAGE_VERSION__",
    description: "Disposable package transaction fixture.",
    author: { name: "test" },
    server: {
      type: "node",
      entry_point: "server/agent-bridge.mjs",
      mcp_config: { env: { AGENT_BRIDGE_BUNDLE_MODE: "1" } },
    },
    user_config: { allowed_root: { type: "directory", required: true } },
    _meta: { "com.agentbridge.release": { source_git_sha: "__GIT_SHA__", runtime_sha256: "__RUNTIME_SHA256__" } },
  }, null, 2)}\n`);
  await writeFile(join(repo, ".gitignore"), "dist/\n.release-staging/\n*.mcpb\n");
  await writeFile(watcherScript, driftWatcherSource());

  git(repo, "init");
  git(repo, "config", "core.autocrlf", "false");
  git(repo, "config", "user.email", "package-test@example.invalid");
  git(repo, "config", "user.name", "Package Test");
  git(repo, "add", ".");
  git(repo, "commit", "-m", "fixture");
  assert.equal(git(repo, "status", "--porcelain"), "");

  return {
    outer,
    repo,
    output,
    stagingRoot,
    staging,
    watcherScript,
    driftTarget: join(scripts, OPERATION_SOURCES[0]),
    cleanup: () => rm(outer, { recursive: true, force: true }),
  };
}

function runPackage(fixture) {
  return spawnSync(process.execPath, [join(fixture.repo, "scripts", "package.mjs"), fixture.output], {
    cwd: fixture.repo,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 4 * 1024 * 1024,
  });
}

function git(repo, ...args) {
  const result = spawnSync("git", args, { cwd: repo, encoding: "utf8", windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

async function publicationTempFiles(fixture) {
  return (await readdir(dirname(fixture.output))).filter((name) => /^\.agent-bridge-v.*\.tmp\.mcpb$/i.test(name));
}

async function waitForPath(path, child, failure) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (existsSync(path)) return;
    if (child.exitCode !== null) throw new Error(`${failure}; watcher exited ${child.exitCode}`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 20));
  }
  throw new Error(failure);
}

async function waitForExit(child) {
  if (child.exitCode !== null) return child.exitCode;
  return new Promise((resolveExit) => child.once("exit", resolveExit));
}

function driftWatcherSource() {
  return String.raw`import { existsSync, watch, writeFileSync } from "node:fs";
const [stagingRoot, candidateStaging, driftTarget, ready, fired] = process.argv.slice(2);
let injected = false;
const watcher = watch(stagingRoot, () => {
  if (injected || !existsSync(candidateStaging)) return;
  injected = true;
  writeFileSync(driftTarget, "# injected tracked drift\n");
  writeFileSync(fired, "fired\n");
  watcher.close();
});
writeFileSync(ready, "ready\n");
`;
}
