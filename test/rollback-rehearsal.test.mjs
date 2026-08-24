import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = join(process.cwd(), "scripts", "rehearse-rollback.ps1");

function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function run(args) {
  return spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, ...args], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true, timeout: 30_000,
  });
}

test("rollback rehearsal exposes no live install or client registration inputs", { skip: process.platform !== "win32" }, async () => {
  const source = await readFile(script, "utf8");
  const parameters = source.slice(source.indexOf("param("), source.indexOf("\n)\n"));
  assert.match(source, /CandidateBundlePath/);
  assert.match(source, /PriorBundlePath/);
  assert.doesNotMatch(parameters, /\$InstallRoot|UserProfile|AppData|LocalAppData/i);
  assert.doesNotMatch(source, /configure-clients\.ps1|cutover-release\.ps1/i);
  assert.match(source, /ReparsePoint/);
  assert.match(source, /Resolve-Path/);
  assert.match(source, /stable shim canary/);
  assert.match(source, /--entrypoint stable-shim/);
  assert.match(source, /--expected-stable-shim-sha256 \$switchResult\.shimSha256/);
  assert.match(source, /--expected-stable-config-sha256 \$configSha256/);
  assert.match(source, /artifact-manifest\.json/);
});

test("rollback rehearsal rejects a nested junction ancestor before fixture creation", { skip: process.platform !== "win32" }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-rollback-reparse-test-"));
  const candidate = join(root, "candidate.mcpb");
  const prior = join(root, "prior.mcpb");
  const alias = join(root, "alias");
  const evidence = join(alias, "ordinary-child", "evidence");
  try {
    await writeFile(candidate, "candidate bundle bytes\n");
    await writeFile(prior, "prior bundle bytes\n");
    try { await symlink(process.cwd(), alias, "junction"); }
    catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) return t.skip("junction unavailable: " + error.code);
      throw error;
    }
    const result = run([
      "-CandidateBundlePath", candidate, "-ExpectedCandidateBundleSha256", sha256(await readFile(candidate)),
      "-PriorBundlePath", prior, "-ExpectedPriorBundleSha256", sha256(await readFile(prior)),
      "-EvidenceDir", evidence,
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ancestor must not be a reparse point/i);
    assert.equal(existsSync(evidence), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rollback rehearsal rejects source-contained evidence and retains a failed external fixture record", { skip: process.platform !== "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-rollback-rehearsal-test-"));
  const candidate = join(root, "candidate.mcpb");
  const prior = join(root, "prior.mcpb");
  const externalEvidence = join(root, "external-evidence");
  const forbiddenEvidence = join(process.cwd(), "rollback-rehearsal-forbidden-evidence");
  try {
    await writeFile(candidate, "candidate bundle bytes\n");
    await writeFile(prior, "prior bundle bytes\n");
    const args = [
      "-CandidateBundlePath", candidate, "-ExpectedCandidateBundleSha256", sha256(await readFile(candidate)),
      "-PriorBundlePath", prior, "-ExpectedPriorBundleSha256", sha256(await readFile(prior)),
    ];
    const forbidden = run([...args, "-EvidenceDir", forbiddenEvidence]);
    assert.notEqual(forbidden.status, 0);
    assert.match(forbidden.stderr, /outside the source repository/i);
    assert.equal(existsSync(forbiddenEvidence), false);

    const failed = run([...args, "-EvidenceDir", externalEvidence]);
    assert.notEqual(failed.status, 0);
    const record = JSON.parse(await readFile(join(externalEvidence, "rollback-rehearsal.json"), "utf8"));
    assert.equal(record.status, "failed");
    assert.equal(record.candidateBundleSha256, sha256(await readFile(candidate)));
    assert.equal(record.priorBundleSha256, sha256(await readFile(prior)));
    assert.ok(existsSync(join(externalEvidence, "fixture")), "failure did not retain the disposable fixture");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(forbiddenEvidence, { recursive: true, force: true });
  }
});
