import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  assertReleaseOperationsMatchWorkingTree,
  collectReleaseOperations,
  IMMUTABLE_OPERATIONS_CAPABILITY,
  MAX_RELEASE_ENTRIES,
  MAX_RELEASE_FILE_BYTES,
  MAX_RELEASE_TOTAL_BYTES,
  RELEASE_OPERATION_CONTRACT,
  RELEASE_OPERATION_FILES,
} from "../scripts/release-operations.mjs";

const expectedTargets = [
  "operations/check-cutover-readiness.ps1",
  "operations/cutover-release.ps1",
  "operations/switch-release.ps1",
  "operations/inspect-install.ps1",
  "operations/protect-state.ps1",
  "operations/configure-clients.ps1",
  "operations/cutover-lock.psm1",
  "operations/cutover-quiescence.psm1",
];

test("immutable release operations are minimal, dependency-closed, and hashable", async () => {
  assert.deepEqual(RELEASE_OPERATION_FILES.map(({ target }) => target), expectedTargets);
  assert.equal(RELEASE_OPERATION_CONTRACT.capability, IMMUTABLE_OPERATIONS_CAPABILITY);
  assert.deepEqual(RELEASE_OPERATION_CONTRACT.payloads, ["server/agent-bridge.mjs", "server/agent-bridge.mjs.map", ...expectedTargets]);
  assert.deepEqual(Object.values(RELEASE_OPERATION_CONTRACT.entryPoints), expectedTargets.slice(0, 5));

  const operations = collectReleaseOperations(process.cwd());
  const packagedBasenames = new Set(operations.map(({ target }) => basename(target).toLowerCase()));
  assert.equal(packagedBasenames.size, operations.length, "operation target names must be unique");
  for (const operation of operations) {
    assert.equal(operation.sha256, sha256(operation.bytes));
    assert.equal(operation.byteLength, operation.bytes.length);
    assert.deepEqual(operation.bytes, await readFile(join(process.cwd(), operation.source)));
    const text = operation.bytes.toString("utf8");
    const dependencies = [...text.matchAll(/Join-Path\s+\$PSScriptRoot\s+['\"]([^'\"]+\.(?:ps1|psm1))['\"]/gi)].map((match) => match[1]);
    for (const dependency of dependencies) {
      assert.equal(dependency, basename(dependency), `${operation.target} has a non-local or traversing script dependency: ${dependency}`);
      assert.ok(packagedBasenames.has(dependency.toLowerCase()), `${operation.target} depends on unpackaged ${dependency}`);
    }
  }
});

test("immutable Windows release operations are checked out with committed LF bytes", () => {
  const sources = RELEASE_OPERATION_FILES.map(({ source }) => source);
  const attributes = execFileSync("git", ["check-attr", "eol", "--", ...sources], {
    cwd: process.cwd(), encoding: "utf8", windowsHide: true,
  }).trim().split(/\r?\n/);
  assert.equal(attributes.length, sources.length);
  for (const [index, line] of attributes.entries()) {
    assert.equal(line, `${sources[index]}: eol: lf`);
  }
});

test("operation collection uses committed bytes and rejects working-tree drift", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-operation-commit-"));
  try {
    await mkdir(join(root, "scripts"), { recursive: true });
    for (const { source } of RELEASE_OPERATION_FILES) await writeFile(join(root, source), `# ${source}\n`);
    git(root, "init", "-q"); git(root, "add", "-A");
    git(root, "-c", "user.name=Agent Bridge Test", "-c", "user.email=test@localhost", "commit", "-q", "-m", "fixture");
    const committed = collectReleaseOperations(root, { gitSha: "HEAD", requireWorkingTreeMatch: true });
    await writeFile(join(root, RELEASE_OPERATION_FILES[0].source), "# dirty mutation\n");
    assert.throws(
      () => collectReleaseOperations(root, { gitSha: "HEAD", requireWorkingTreeMatch: true }),
      /differs from committed HEAD/i,
    );
    assert.throws(
      () => assertReleaseOperationsMatchWorkingTree(root, committed, "HEAD"),
      /changed after collection or differs from committed HEAD/i,
    );
    assert.equal(committed[0].bytes.toString("utf8"), `# ${RELEASE_OPERATION_FILES[0].source}\n`);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("Windows installer preserves and verifies every immutable operation byte", { skip: process.platform !== "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-release-operations-"));
  try {
    const operations = collectReleaseOperations(process.cwd());
    const valid = createBundle(operations);
    const bundlePath = join(root, "candidate.mcpb");
    const installRoot = join(root, "install");
    await writeFile(bundlePath, valid.bundle);

    const installed = runInstaller(bundlePath, installRoot);
    assert.equal(installed.status, 0, installed.stderr);
    const report = JSON.parse(installed.stdout);
    assert.equal(report.releaseId, valid.releaseId);
    assert.equal(report.operationsPath, join(report.releasePath, "operations"));
    assert.deepEqual(report.operationEntryPoints, RELEASE_OPERATION_CONTRACT.entryPoints);
    for (const operation of operations) {
      assert.deepEqual(await readFile(join(report.releasePath, operation.target)), operation.bytes);
    }

    const tamperedRoot = join(root, "tampered-install");
    const tamperedOperations = operations.map((operation, index) => index === 0
      ? { ...operation, bytes: Buffer.concat([operation.bytes, Buffer.from("# tampered\n")]) }
      : operation);
    const tamperedPath = join(root, "tampered.mcpb");
    await writeFile(tamperedPath, createBundle(tamperedOperations, operations).bundle);
    const tampered = runInstaller(tamperedPath, tamperedRoot);
    assert.notEqual(tampered.status, 0, "installer accepted an operation whose bytes differed from release metadata");
    assert.match(tampered.stderr, /SHA-256 mismatch.*operations\/check-cutover-readiness\.ps1/i);

    const tamperedStateRoot = join(root, "tampered-state-install");
    const tamperedStateOperations = operations.map((operation) => operation.target === "operations/protect-state.ps1"
      ? { ...operation, bytes: Buffer.concat([operation.bytes, Buffer.from("# tampered state protection\n")]) }
      : operation);
    const tamperedStatePath = join(root, "tampered-state.mcpb");
    await writeFile(tamperedStatePath, createBundle(tamperedStateOperations, operations).bundle);
    const tamperedState = runInstaller(tamperedStatePath, tamperedStateRoot);
    assert.notEqual(tamperedState.status, 0, "installer accepted tampered immutable state protection");
    assert.match(tamperedState.stderr, /SHA-256 mismatch.*operations\/protect-state\.ps1/i);

    const unhashedRoot = join(root, "unhashed-install");
    const unhashedPath = join(root, "unhashed.mcpb");
    await writeFile(unhashedPath, createBundle(operations, operations, [{ relative: "operations/unpinned.ps1", bytes: Buffer.from("throw 'untrusted'\n") }]).bundle);
    const unhashed = runInstaller(unhashedPath, unhashedRoot);
    assert.notEqual(unhashed.status, 0, "installer accepted an unhashed operation payload");
    assert.match(unhashed.stderr, /unhashed payload entry: operations\/unpinned\.ps1/i);

    const extraHashedRoot = join(root, "extra-hashed-install");
    const extraHashedPath = join(root, "extra-hashed.mcpb");
    const extra = { target: "extensions/pinned.txt", bytes: Buffer.from("still forbidden\n") };
    const extraRecord = { ...extra, sha256: sha256(extra.bytes), byteLength: extra.bytes.length };
    await writeFile(extraHashedPath, createBundle(operations, [...operations, extraRecord], [{ relative: extra.target, bytes: extra.bytes }]).bundle);
    const extraHashed = runInstaller(extraHashedPath, extraHashedRoot);
    assert.notEqual(extraHashed.status, 0, "installer accepted an extra hash-listed RC5 payload");
    assert.match(extraHashed.stderr, /payload inventory mismatch/i);

    for (const [name, mutate, expected] of [
      ["uppercase-hash", (fixture) => { fixture.files[expectedTargets[0]].sha256 = fixture.files[expectedTargets[0]].sha256.toUpperCase(); }, /SHA-256 is invalid/i],
      ["fractional-bytes", (fixture) => { fixture.files[expectedTargets[0]].bytes += 0.5; }, /byte count is not an integer/i],
      ["missing-capability", (fixture) => { delete fixture.operations.capability; }, /unsupported immutable release operation contract/i],
      ["missing-payload", (fixture) => { fixture.operations.payloads.pop(); }, /payload inventory mismatch/i],
    ]) {
      const variantPath = join(root, `${name}.mcpb`);
      await writeFile(variantPath, createBundle(operations, operations, [], mutate).bundle);
      const result = runInstaller(variantPath, join(root, `${name}-install`));
      assert.notEqual(result.status, 0, `installer accepted invalid RC5 ${name}`);
      assert.match(result.stderr, expected);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Windows installer retains explicit legacy compatibility and enforces archive limits", { skip: process.platform !== "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-release-limits-"));
  try {
    const legacyPath = join(root, "legacy.mcpb");
    const legacy = createLegacyBundle();
    await writeFile(legacyPath, legacy.bundle);
    const installed = runInstaller(legacyPath, join(root, "legacy-install"));
    assert.equal(installed.status, 0, installed.stderr);
    const report = JSON.parse(installed.stdout);
    assert.equal(report.operationsPath, null);
    assert.equal(report.operationEntryPoints, null);

    const v1Operations = collectReleaseOperations(process.cwd()).filter(({ target }) => target !== "operations/protect-state.ps1");
    const v1Path = join(root, "operations-v1.mcpb");
    await writeFile(v1Path, createBundle(v1Operations, v1Operations, [], undefined, v1OperationContract()).bundle);
    const v1Installed = runInstaller(v1Path, join(root, "operations-v1-install"));
    assert.equal(v1Installed.status, 0, v1Installed.stderr);
    assert.deepEqual(JSON.parse(v1Installed.stdout).operationEntryPoints, v1OperationContract().entryPoints);

    const operations = collectReleaseOperations(process.cwd());
    const tooMany = Array.from({ length: MAX_RELEASE_ENTRIES }, (_, index) => ({ relative: `legacy-extra-${index}.txt`, bytes: Buffer.alloc(0) }));
    const tooManyPath = join(root, "too-many.mcpb");
    await writeFile(tooManyPath, createLegacyBundle(tooMany).bundle);
    const many = runInstaller(tooManyPath, join(root, "too-many-install"));
    assert.notEqual(many.status, 0); assert.match(many.stderr, /archive limit/i);

    const tooLargePath = join(root, "too-large.mcpb");
    const largeBytes = Buffer.alloc(MAX_RELEASE_FILE_BYTES + 1);
    await writeFile(tooLargePath, createLegacyBundle([{ relative: "large.bin", bytes: largeBytes }]).bundle);
    const large = runInstaller(tooLargePath, join(root, "too-large-install"));
    assert.notEqual(large.status, 0); assert.match(large.stderr, /size limit/i);

    const totalPath = join(root, "too-large-total.mcpb");
    const third = Buffer.alloc(Math.floor(MAX_RELEASE_TOTAL_BYTES / 3) + 1);
    await writeFile(totalPath, createLegacyBundle([{ relative: "large-a.bin", bytes: third }, { relative: "large-b.bin", bytes: third }, { relative: "large-c.bin", bytes: third }]).bundle);
    const total = runInstaller(totalPath, join(root, "too-large-total-install"));
    assert.notEqual(total.status, 0); assert.match(total.stderr, /extracted-size limit/i);
    assert.equal(operations.length, 8);
  } finally { await rm(root, { recursive: true, force: true }); }
});

function runInstaller(bundlePath, installRoot) {
  return spawnSync("powershell.exe", [
    "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/install-release.ps1",
    "-BundlePath", bundlePath, "-InstallRoot", installRoot,
  ], { cwd: process.cwd(), encoding: "utf8", windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
}

function createBundle(payloadOperations, metadataOperations = payloadOperations, extraEntries = [], mutateMetadata = undefined, contract = RELEASE_OPERATION_CONTRACT) {
  const version = "0.3.0-rc.5";
  const gitSha = "c".repeat(40);
  const releaseId = `${version}+${gitSha.slice(0, 7)}`;
  const runtime = Buffer.from("export const immutableOperations = true;\n");
  const sourceMap = Buffer.from("{}\n");
  const manifest = Buffer.from(`${JSON.stringify({
    manifest_version: "0.3", name: "agent-bridge", version,
    description: "test", author: { name: "test" },
    server: { type: "node", entry_point: "server/agent-bridge.mjs" },
    _meta: { "com.agentbridge.release": { source_git_sha: gitSha, runtime_sha256: sha256(runtime) } },
  })}\n`);
  const files = {
    "server/agent-bridge.mjs": { sha256: sha256(runtime), bytes: runtime.length },
    "server/agent-bridge.mjs.map": { sha256: sha256(sourceMap), bytes: sourceMap.length },
    ...Object.fromEntries(metadataOperations.map((operation) => [operation.target, { sha256: operation.sha256, bytes: operation.byteLength }])),
  };
  const metadataObject = { package: "agent-bridge-mcp", version, gitSha, operations: structuredClone(contract), files };
  mutateMetadata?.(metadataObject);
  const metadata = Buffer.from(`${JSON.stringify(metadataObject)}\n`);
  return {
    releaseId,
    bundle: zipStore([
      { relative: "manifest.json", bytes: manifest },
      { relative: "release-metadata.json", bytes: metadata },
      { relative: "server/agent-bridge.mjs", bytes: runtime },
      { relative: "server/agent-bridge.mjs.map", bytes: sourceMap },
      ...payloadOperations.map((operation) => ({ relative: operation.target, bytes: operation.bytes })),
      ...extraEntries,
    ]),
  };
}

function v1OperationContract() {
  const payloads = RELEASE_OPERATION_CONTRACT.payloads.filter((path) => path !== "operations/protect-state.ps1");
  return {
    capability: "immutable-release-operations-v1",
    schemaVersion: 1,
    platform: "windows",
    payloads,
    entryPoints: {
      readiness: "operations/check-cutover-readiness.ps1",
      cutover: "operations/cutover-release.ps1",
      rollback: "operations/switch-release.ps1",
      inspection: "operations/inspect-install.ps1",
    },
  };
}

function createLegacyBundle(extraEntries = []) {
  const version = "0.2.1"; const gitSha = "d".repeat(40);
  const runtime = Buffer.from("export const legacy = true;\n"); const sourceMap = Buffer.from("{}\n");
  const payload = [{ relative: "server/agent-bridge.mjs", bytes: runtime }, { relative: "server/agent-bridge.mjs.map", bytes: sourceMap }, ...extraEntries];
  const files = Object.fromEntries(payload.map(({ relative, bytes }) => [relative, { sha256: sha256(bytes), bytes: bytes.length }]));
  const manifest = Buffer.from(`${JSON.stringify({ manifest_version: "0.3", name: "agent-bridge", version, server: { type: "node", entry_point: "server/agent-bridge.mjs" }, _meta: { "com.agentbridge.release": { source_git_sha: gitSha, runtime_sha256: sha256(runtime) } } })}\n`);
  const metadata = Buffer.from(`${JSON.stringify({ package: "agent-bridge-mcp", version, gitSha, files })}\n`);
  return { bundle: zipStore([{ relative: "manifest.json", bytes: manifest }, { relative: "release-metadata.json", bytes: metadata }, ...payload]) };
}

function git(root, ...args) { return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); }

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function crc32(bytes) { let crc = 0xffffffff; for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1)); } return (crc ^ 0xffffffff) >>> 0; }
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
