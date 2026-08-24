import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { extname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync, inflateRawSync } from "node:zlib";

const MAX_ARCHIVE_ENTRIES = 10_000;
const MAX_ENTRY_BYTES = 32 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const PRIVATE_STORAGE_MARKER = [".agent-bridge", "private"].join("-");
const ALLOWED_EXAMPLE_USERS = new Set([
  "alice",
  "bob",
  "example",
  "runner",
  "test",
  "tester",
  "user",
  "username",
  "yourname",
]);
const BINARY_EXTENSIONS = new Set([
  ".avif", ".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".pdf", ".png", ".webp",
  ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".wav", ".zip",
  ".gz", ".mcpb",
]);

const tokenDetectors = [
  ["openai-api-key", new RegExp("\\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\\b", "g")],
  ["github-token", new RegExp("\\bgh[pousr]_[A-Za-z0-9]{20,}\\b", "g")],
  ["github-fine-grained-token", new RegExp("\\bgithub_pat_[A-Za-z0-9_]{20,}\\b", "g")],
  ["aws-access-key", new RegExp("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b", "g")],
  ["google-api-key", new RegExp("\\bAIza[0-9A-Za-z_-]{30,}\\b", "g")],
  ["slack-token", new RegExp("\\bxox[baprs]-[A-Za-z0-9-]{20,}\\b", "g")],
  ["stripe-live-key", new RegExp("\\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\\b", "g")],
  ["jwt", new RegExp("\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{8,}\\b", "g")],
];

const credentialAssignment = /(?:["']?)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)(?:["']?)\s*[:=]\s*["']([^"'\r\n]{12,})["']/gi;
const bearerAssignment = /(?:authorization|auth[_-]?header)\s*[:=]\s*["']Bearer\s+([A-Za-z0-9._~-]{16,})["']/gi;
const signedUrlCredential = /[?&](?:access_token|api_key|key|signature|sig)=([^&\s"'<>]{12,})/gi;
const emailAddress = /\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,}|example\.invalid)\b/gi;
const windowsUserPath = /\b[A-Za-z]:[\\/]+Users[\\/]+([^\\/\s"'<>]+)/gi;
const posixUserPath = /(?:^|[\s"'(])\/(?:Users|home)\/([^/\s"'<>]+)/gim;

export function scanText(text, source = "input") {
  const findings = [];
  if (text.includes("-----BEGIN " + "PRIVATE KEY-----") ||
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH )PRIVATE KEY-----/.test(text)) {
    findings.push(finding("private-key", source, lineOf(text, text.indexOf("PRIVATE KEY-----"))));
  }

  for (const [category, detector] of tokenDetectors) {
    detector.lastIndex = 0;
    for (const match of text.matchAll(detector)) {
      if (!isPlaceholderSecret(match[0])) findings.push(finding(category, source, lineOf(text, match.index)));
    }
  }
  collectCaptured(text, source, credentialAssignment, "credential-assignment", findings);
  collectCaptured(text, source, bearerAssignment, "bearer-credential", findings);
  collectCaptured(text, source, signedUrlCredential, "signed-url-credential", findings);

  emailAddress.lastIndex = 0;
  for (const match of text.matchAll(emailAddress)) {
    const domain = match[1].toLowerCase();
    if (!isAllowedPublicEmailDomain(domain)) findings.push(finding("personal-email", source, lineOf(text, match.index)));
  }

  for (const detector of [windowsUserPath, posixUserPath]) {
    detector.lastIndex = 0;
    for (const match of text.matchAll(detector)) {
      if (!ALLOWED_EXAMPLE_USERS.has(match[1].toLowerCase())) {
        findings.push(finding("private-user-path", source, lineOf(text, match.index)));
      }
    }
  }

  const privateMarker = text.toLowerCase().indexOf(PRIVATE_STORAGE_MARKER);
  if (privateMarker >= 0) findings.push(finding("private-storage-path", source, lineOf(text, privateMarker)));
  return deduplicate(findings);
}

export function scanPath(relativePath, source = relativePath) {
  const normalized = relativePath.replaceAll("\\", "/").replace(/^\.\//, "");
  const lower = normalized.toLowerCase();
  const base = lower.split("/").at(-1) ?? lower;
  const parts = lower.split("/");
  const findings = [];
  if ((base === ".env" || base.startsWith(".env.")) && base !== ".env.example") {
    findings.push(finding("sensitive-file", source));
  }
  if ([".npmrc", "config.json", "credentials.json", "service-account.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"].includes(base)) {
    if (lower !== ".openai/hosting.json") findings.push(finding("sensitive-file", source));
  }
  if (/\.(?:pem|key|pfx|p12|p8|jks|keystore|kdbx|sqlite|sqlite3|db)$/i.test(base)) {
    findings.push(finding("sensitive-file", source));
  }
  if (parts.some((part) => ["secrets", "credentials", "state", "sessions", "evidence", "backups", PRIVATE_STORAGE_MARKER].includes(part))) {
    findings.push(finding("private-directory", source));
  }
  if (normalized.startsWith("/") || /^[A-Za-z]:[\\/]/.test(normalized) || normalized.split("/").includes("..")) {
    findings.push(finding("unsafe-archive-path", source));
  }
  return deduplicate(findings);
}

export function scanBuffer(bytes, source) {
  const logicalPath = source.includes("::") ? source.slice(source.lastIndexOf("::") + 2) : source;
  const findings = scanPath(logicalPath, source);
  if (isZip(bytes)) return findings.concat(scanZip(bytes, source));
  if (isGzip(bytes) && /\.t(?:ar\.)?gz$/i.test(logicalPath)) return findings.concat(scanTar(gunzipBounded(bytes), source));
  if (isProbablyText(bytes, logicalPath)) findings.push(...scanText(bytes.toString("utf8"), source));
  return deduplicate(findings);
}

export function scanArchive(path) {
  const bytes = readFileSync(path);
  if (bytes.length > MAX_ARCHIVE_BYTES) return [finding("oversized-archive", path)];
  if (isZip(bytes)) return scanZip(bytes, path);
  if (isGzip(bytes)) return scanTar(gunzipBounded(bytes), path);
  return [finding("unsupported-archive", path)];
}

export function scanTrackedTree(root) {
  const files = git(root, ["ls-files", "-z"]).split("\0").filter(Boolean);
  const findings = [];
  for (const name of files) {
    const absolute = resolve(root, name);
    if (!existsSync(absolute) || !statSync(absolute).isFile()) continue;
    findings.push(...scanBuffer(readFileSync(absolute), name));
  }
  return { findings: deduplicate(findings), files: files.length };
}

export function scanGitHistory(root) {
  const findings = [];
  const identities = git(root, ["log", "--all", "--format=%H%x00%ae%x00%ce"]).split("\n").filter(Boolean);
  for (const row of identities) {
    const [commit, authorEmail, committerEmail] = row.split("\0");
    for (const address of [authorEmail, committerEmail]) {
      const domain = address?.split("@").at(-1)?.toLowerCase();
      if (domain && !isAllowedPublicEmailDomain(domain)) findings.push(finding("history-personal-email", `git:${commit.slice(0, 12)}`));
    }
  }

  const objects = git(root, ["rev-list", "--objects", "--all"]).split("\n").filter(Boolean);
  const scanned = new Set();
  let blobs = 0;
  for (const row of objects) {
    const separator = row.indexOf(" ");
    if (separator < 0) continue;
    const objectId = row.slice(0, separator);
    const name = row.slice(separator + 1);
    if (scanned.has(objectId) || git(root, ["cat-file", "-t", objectId]) !== "blob") continue;
    scanned.add(objectId);
    blobs += 1;
    const size = Number(git(root, ["cat-file", "-s", objectId]));
    if (!Number.isSafeInteger(size) || size > MAX_ENTRY_BYTES) {
      findings.push(finding("oversized-history-blob", `history:${objectId.slice(0, 12)}:${name}`));
      continue;
    }
    const bytes = execFileSync("git", ["cat-file", "blob", objectId], { cwd: root, maxBuffer: MAX_ENTRY_BYTES + 1 });
    findings.push(...scanBuffer(bytes, `history:${objectId.slice(0, 12)}:${name}`));
  }
  return { findings: deduplicate(findings), blobs };
}

function scanZip(bytes, archiveName) {
  const findings = [];
  const end = findZipEnd(bytes);
  if (end < 0) return [finding("malformed-archive", archiveName)];
  const count = bytes.readUInt16LE(end + 10);
  const centralOffset = bytes.readUInt32LE(end + 16);
  if (count > MAX_ARCHIVE_ENTRIES || centralOffset >= bytes.length) return [finding("unsafe-archive-size", archiveName)];
  let cursor = centralOffset;
  let total = 0;
  for (let index = 0; index < count; index += 1) {
    if (cursor + 46 > bytes.length || bytes.readUInt32LE(cursor) !== 0x02014b50) return [finding("malformed-archive", archiveName)];
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const size = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const nameEnd = cursor + 46 + nameLength;
    if (nameEnd > bytes.length) return [finding("malformed-archive", archiveName)];
    const name = bytes.subarray(cursor + 46, nameEnd).toString("utf8");
    const source = `${archiveName}::${name}`;
    findings.push(...scanPath(name, source));
    total += size;
    if ((flags & 1) !== 0) findings.push(finding("encrypted-archive-entry", source));
    if (size > MAX_ENTRY_BYTES || total > MAX_ARCHIVE_BYTES) findings.push(finding("unsafe-archive-size", source));
    if (!name.endsWith("/") && size <= MAX_ENTRY_BYTES && total <= MAX_ARCHIVE_BYTES && (flags & 1) === 0) {
      const entry = extractZipEntry(bytes, localOffset, compressedSize, size, method);
      if (!entry) findings.push(finding("unsupported-archive-entry", source));
      else findings.push(...scanBuffer(entry, source));
    }
    cursor = nameEnd + extraLength + commentLength;
  }
  return deduplicate(findings);
}

function scanTar(bytes, archiveName) {
  const findings = [];
  let cursor = 0;
  let entries = 0;
  let total = 0;
  while (cursor + 512 <= bytes.length) {
    const header = bytes.subarray(cursor, cursor + 512);
    if (header.every((byte) => byte === 0)) break;
    entries += 1;
    if (entries > MAX_ARCHIVE_ENTRIES) return findings.concat(finding("unsafe-archive-size", archiveName));
    const name = tarString(header.subarray(0, 100));
    const prefix = tarString(header.subarray(345, 500));
    const fullName = prefix ? `${prefix}/${name}` : name;
    const size = Number.parseInt(tarString(header.subarray(124, 136)).trim() || "0", 8);
    const type = String.fromCharCode(header[156] || 48);
    const source = `${archiveName}::${fullName}`;
    findings.push(...scanPath(fullName, source));
    total += size;
    if (!Number.isSafeInteger(size) || size > MAX_ENTRY_BYTES || total > MAX_ARCHIVE_BYTES) findings.push(finding("unsafe-archive-size", source));
    const dataStart = cursor + 512;
    const dataEnd = dataStart + size;
    if ((type === "0" || type === "\0") && dataEnd <= bytes.length && size <= MAX_ENTRY_BYTES && total <= MAX_ARCHIVE_BYTES) {
      findings.push(...scanBuffer(bytes.subarray(dataStart, dataEnd), source));
    }
    cursor = dataStart + Math.ceil(size / 512) * 512;
  }
  return deduplicate(findings);
}

function extractZipEntry(bytes, localOffset, compressedSize, size, method) {
  if (localOffset + 30 > bytes.length || bytes.readUInt32LE(localOffset) !== 0x04034b50) return null;
  const nameLength = bytes.readUInt16LE(localOffset + 26);
  const extraLength = bytes.readUInt16LE(localOffset + 28);
  const start = localOffset + 30 + nameLength + extraLength;
  const end = start + compressedSize;
  if (end > bytes.length) return null;
  const compressed = bytes.subarray(start, end);
  let output;
  if (method === 0) output = compressed;
  else if (method === 8) output = inflateRawSync(compressed, { maxOutputLength: MAX_ENTRY_BYTES });
  else return null;
  return output.length === size ? output : null;
}

function findZipEnd(bytes) {
  return bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
}

function gunzipBounded(bytes) {
  return gunzipSync(bytes, { maxOutputLength: MAX_ARCHIVE_BYTES });
}

function collectCaptured(text, source, detector, category, findings) {
  detector.lastIndex = 0;
  for (const match of text.matchAll(detector)) {
    if (!isPlaceholderSecret(match[1])) findings.push(finding(category, source, lineOf(text, match.index)));
  }
}

function isPlaceholderSecret(value) {
  const lower = value.toLowerCase();
  if (["example", "sample", "fixture", "dummy", "fake", "placeholder", "redacted", "not-a-real", "not_real", "replace-me", "changeme"].some((marker) => lower.includes(marker))) return true;
  if (["exposed_secret_value", "diagnostic_budget_secret", "inspection-must-never-be-returned", "must-not-be-used", "must-not-pass", "secret-that-must-not-appear", "abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnop"].some((marker) => lower.includes(marker))) return true;
  if (lower.startsWith("sk-test-")) return true;
  const compact = lower.replace(/[^a-z0-9]/g, "");
  return compact.length >= 12 && new Set(compact).size <= 2;
}

function isAllowedPublicEmailDomain(domain) {
  return domain === "example.com" || domain === "example.org" || domain === "example.net" || domain === "example.invalid" || domain === "example.test" || domain === "manus.ai" || domain === "manus.im" || domain === "users.noreply.github.com";
}

function isProbablyText(bytes, source) {
  if (BINARY_EXTENSIONS.has(extname(source).toLowerCase())) return false;
  const sample = bytes.subarray(0, Math.min(bytes.length, 8192));
  if (sample.includes(0)) return false;
  let controls = 0;
  for (const byte of sample) if (byte < 9 || (byte > 13 && byte < 32)) controls += 1;
  return sample.length === 0 || controls / sample.length < 0.02;
}

function isZip(bytes) { return bytes.length >= 4 && bytes.readUInt32LE(0) === 0x04034b50; }
function isGzip(bytes) { return bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b; }
function tarString(bytes) { return bytes.toString("utf8").replace(/\0.*$/s, ""); }
function lineOf(text, index) { return index < 0 ? undefined : text.slice(0, index).split("\n").length; }
function finding(category, source, line) { return { category, source, ...(line ? { line } : {}) }; }
function deduplicate(findings) {
  return [...new Map(findings.map((item) => [`${item.category}\0${item.source}\0${item.line ?? 0}`, item])).values()];
}

function git(root, args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 }).trim();
}

function parseArgs(argv) {
  const options = { root: resolve(fileURLToPath(new URL("..", import.meta.url))), archives: [], tree: true, history: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--root") options.root = resolve(argv[++index]);
    else if (argument === "--archive") options.archives.push(resolve(argv[++index]));
    else if (argument === "--no-tree") options.tree = false;
    else if (argument === "--history") options.history = true;
    else throw new Error(`unknown argument: ${argument}`);
  }
  return options;
}

function run(argv) {
  const options = parseArgs(argv);
  const findings = [];
  let scannedFiles = 0;
  let scannedBlobs = 0;
  if (options.tree) {
    const tree = scanTrackedTree(options.root);
    findings.push(...tree.findings);
    scannedFiles += tree.files;
  }
  if (options.history) {
    const history = scanGitHistory(options.root);
    findings.push(...history.findings);
    scannedBlobs += history.blobs;
  }
  for (const archive of options.archives) findings.push(...scanArchive(archive));
  const unique = deduplicate(findings);
  if (unique.length > 0) {
    console.error(`privacy scan blocked: ${unique.length} finding(s); values are intentionally redacted`);
    for (const item of unique) console.error(`- ${item.category} ${item.source}${item.line ? `:${item.line}` : ""}`);
    process.exitCode = 1;
    return;
  }
  console.log(`privacy scan passed: ${scannedFiles} tracked file(s), ${scannedBlobs} historical blob(s), ${options.archives.length} archive(s)`);
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (invokedPath === import.meta.url) run(process.argv.slice(2));
