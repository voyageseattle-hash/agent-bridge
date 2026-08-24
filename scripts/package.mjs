import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertReleaseOperationsMatchWorkingTree,
  collectReleaseOperations,
  RELEASE_OPERATION_CONTRACT,
} from "./release-operations.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const version = pkg.version;
const output = resolve(process.argv[2] ?? join(root, `agent-bridge-v${version}.mcpb`));
// Keep the publication temp file under the ignored MCPB suffix so the final
// clean-tree check does not mistake the packager's own transaction for drift.
const temporaryOutput = join(dirname(output), `.${basename(output)}.${process.pid}.tmp.mcpb`);
const stagingRoot = join(root, ".release-staging");
const staging = join(stagingRoot, `agent-bridge-v${version}`);
let ownsStaging = false;
let published = false;
process.once("exit", () => {
  if (!published && ownsStaging && existsSync(staging)) {
    try { rmSync(staging, { recursive: true, force: true }); } catch {}
  }
});
const gitSha = gitRequired("rev-parse", "HEAD");
if (!gitSha) throw new Error("release packaging requires a committed Git revision");
const worktree = gitRequired("status", "--porcelain");
if (worktree) throw new Error(`release packaging requires a clean worktree:\n${worktree}`);
execFileSync(process.execPath, [join(root, "scripts", "scan-public.mjs"), "--root", root], { cwd: root, stdio: "inherit" });

if (existsSync(output)) throw new Error(`refusing to overwrite existing package: ${output}`);
if (existsSync(temporaryOutput)) throw new Error(`refusing stale temporary package path: ${temporaryOutput}`);
if (existsSync(staging)) throw new Error(`refusing to overwrite existing staging directory: ${staging}`);
execFileSync(process.execPath, [join(root, "scripts", "build.mjs")], { cwd: root, stdio: "inherit" });

const runtime = join(root, "dist", "agent-bridge.mjs");
if (!existsSync(runtime)) throw new Error("build did not produce dist/agent-bridge.mjs");
const runtimeBytes = readFileSync(runtime);
const runtimeHash = sha256(runtimeBytes);
const sourceMap = `${runtime}.map`;
if (!existsSync(sourceMap)) throw new Error("build did not produce dist/agent-bridge.mjs.map");
const sourceMapBytes = readFileSync(sourceMap);
const sourceMapHash = sha256(sourceMapBytes);
const operations = collectReleaseOperations(root, { gitSha, requireWorkingTreeMatch: true });

mkdirSync(join(staging, "server"), { recursive: true });
ownsStaging = true;
mkdirSync(join(staging, "operations"), { recursive: true });
const manifest = readFileSync(join(root, "manifest.template.json"), "utf8")
  .replaceAll("__PACKAGE_VERSION__", version)
  .replaceAll("__GIT_SHA__", gitSha)
  .replaceAll("__RUNTIME_SHA256__", runtimeHash);
writeFileSync(join(staging, "manifest.json"), `${manifest.trim()}\n`, "utf8");
writeFileSync(join(staging, "server", "agent-bridge.mjs"), runtimeBytes);
writeFileSync(join(staging, "server", "agent-bridge.mjs.map"), sourceMapBytes);
for (const operation of operations) writeFileSync(join(staging, operation.target), operation.bytes);
const metadata = {
  package: pkg.name,
  version,
  builtAt: new Date().toISOString(),
  gitSha,
  operations: RELEASE_OPERATION_CONTRACT,
  files: {
    "server/agent-bridge.mjs": { sha256: runtimeHash, bytes: runtimeBytes.length },
    "server/agent-bridge.mjs.map": { sha256: sourceMapHash, bytes: sourceMapBytes.length },
    ...Object.fromEntries(operations.map((operation) => [operation.target, { sha256: operation.sha256, bytes: operation.byteLength }])),
  },
};
writeFileSync(join(staging, "release-metadata.json"), `${JSON.stringify(metadata, null, 2)}\n`, "utf8");

const files = ["manifest.json", "server/agent-bridge.mjs", "server/agent-bridge.mjs.map", ...operations.map((operation) => operation.target), "release-metadata.json"];
const archive = zipStore(files.map((relative) => ({ relative, bytes: readFileSync(join(staging, relative)) })));
mkdirSync(dirname(output), { recursive: true });
let bundleHash;
try {
  writeFileSync(temporaryOutput, archive, { flag: "wx" });
  verifyPackage(temporaryOutput, runtimeBytes, sourceMapBytes, operations, files);
  execFileSync(process.execPath, [join(root, "scripts", "scan-public.mjs"), "--no-tree", "--archive", temporaryOutput], { cwd: root, stdio: "inherit" });
  assertReleaseOperationsMatchWorkingTree(root, operations, gitSha);
  const publicationSha = gitRequired("rev-parse", "HEAD");
  if (publicationSha !== gitSha) throw new Error(`release HEAD changed during packaging: expected ${gitSha}, got ${publicationSha}`);
  const publicationWorktree = gitRequired("status", "--porcelain");
  if (publicationWorktree) throw new Error(`release worktree changed during packaging:\n${publicationWorktree}`);
  bundleHash = sha256(readFileSync(temporaryOutput));
  renameSync(temporaryOutput, output);
  published = true;
} finally {
  if (existsSync(temporaryOutput)) unlinkSync(temporaryOutput);
  if (!published && existsSync(staging)) rmSync(staging, { recursive: true, force: true });
}
console.log(`package verified: ${output}`);
console.log(`bundle sha256: ${bundleHash}`);
console.log(`runtime sha256: ${runtimeHash}`);
console.log(`git sha: ${gitSha}`);

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function gitRequired(...args) {
  try { return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim(); }
  catch (error) { throw new Error(`release packaging Git command failed: git ${args.join(" ")}`, { cause: error }); }
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function dosTime(date) { return ((date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2)) & 0xffff; }
function dosDate(date) { return (((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()) & 0xffff; }
function u16(value) { const b = Buffer.alloc(2); b.writeUInt16LE(value); return b; }
function u32(value) { const b = Buffer.alloc(4); b.writeUInt32LE(value >>> 0); return b; }
function zipStore(entries) {
  const now = new Date(); const local = []; const central = []; let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.relative.replaceAll("\\", "/")); const crc = crc32(entry.bytes);
    const header = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(0), u16(dosTime(now)), u16(dosDate(now)), u32(crc), u32(entry.bytes.length), u32(entry.bytes.length), u16(name.length), u16(0), name, entry.bytes]);
    local.push(header);
    central.push(Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(dosTime(now)), u16(dosDate(now)), u32(crc), u32(entry.bytes.length), u32(entry.bytes.length), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), name]));
    offset += header.length;
  }
  const centralBytes = Buffer.concat(central); const localBytes = Buffer.concat(local);
  return Buffer.concat([localBytes, centralBytes, u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(centralBytes.length), u32(localBytes.length), u16(0)]);
}
function verifyPackage(path, expectedRuntime, expectedSourceMap, expectedOperations, required) {
  const archive = readFileSync(path); const end = archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (end < 0) throw new Error("package verification failed: missing ZIP directory");
  const count = archive.readUInt16LE(end + 10); const centralOffset = archive.readUInt32LE(end + 16); let cursor = centralOffset; const contents = new Map();
  for (let index = 0; index < count; index += 1) {
    if (archive.readUInt32LE(cursor) !== 0x02014b50) throw new Error("package verification failed: malformed ZIP entry");
    const size = archive.readUInt32LE(cursor + 24); const nameLength = archive.readUInt16LE(cursor + 28); const extraLength = archive.readUInt16LE(cursor + 30); const commentLength = archive.readUInt16LE(cursor + 32); const localOffset = archive.readUInt32LE(cursor + 42); const name = archive.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    const localNameLength = archive.readUInt16LE(localOffset + 26); const localExtraLength = archive.readUInt16LE(localOffset + 28); const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    contents.set(name, archive.subarray(dataStart, dataStart + size)); cursor += 46 + nameLength + extraLength + commentLength;
  }
  for (const requiredName of required) if (!contents.has(requiredName)) throw new Error(`package verification failed: missing ${requiredName}`);
  const packagedRuntime = contents.get("server/agent-bridge.mjs");
  if (!packagedRuntime.equals(expectedRuntime)) throw new Error("package verification failed: packaged runtime differs from dist");
  const packagedSourceMap = contents.get("server/agent-bridge.mjs.map");
  if (!packagedSourceMap.equals(expectedSourceMap)) throw new Error("package verification failed: packaged source map differs from dist");
  for (const operation of expectedOperations) {
    if (!contents.get(operation.target).equals(operation.bytes)) throw new Error(`package verification failed: packaged operation differs from source: ${operation.target}`);
  }
  const manifest = JSON.parse(contents.get("manifest.json").toString("utf8"));
  const metadata = JSON.parse(contents.get("release-metadata.json").toString("utf8"));
  const releaseIdentity = manifest._meta?.["com.agentbridge.release"];
  if (manifest.version !== version || releaseIdentity?.source_git_sha !== gitSha || releaseIdentity?.runtime_sha256 !== sha256(expectedRuntime)) throw new Error("package verification failed: manifest metadata mismatch");
  if (manifest.manifest_version !== "0.3" || manifest.server?.mcp_config?.env?.AGENT_BRIDGE_BUNDLE_MODE !== "1" || !manifest.user_config?.allowed_root?.required) throw new Error("package verification failed: MCPB self-configuration contract is missing");
  if (JSON.stringify(metadata.operations) !== JSON.stringify(RELEASE_OPERATION_CONTRACT)) throw new Error("package verification failed: immutable operation contract mismatch");
  for (const operation of expectedOperations) {
    const pinned = metadata.files?.[operation.target];
    if (pinned?.sha256 !== operation.sha256 || pinned?.bytes !== operation.byteLength) throw new Error(`package verification failed: operation metadata mismatch: ${operation.target}`);
  }
  if (contents.has("server/config.json")) throw new Error("package verification failed: embedded mutable config is forbidden");
  if (statSync(path).size === 0) throw new Error("package verification failed: empty output");
}
