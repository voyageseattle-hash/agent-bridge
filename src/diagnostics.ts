import { createHash } from "node:crypto";
import { accessSync, constants, existsSync, lstatSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, normalize, posix, resolve, win32 } from "node:path";
import type { AgentAdapter, BridgeConfig } from "./types.js";

export interface DiagnosticsOptions {
  /** Supply these from the entrypoint or release metadata; no package read is required. */
  runtime?: { version?: string; gitSha?: string; sha256?: string; path?: string };
  platform?: NodeJS.Platform;
  userProfile?: string;
  pathEnv?: string;
  pathExt?: string;
  cwd?: string;
}

export interface BridgeDiagnostics {
  schemaVersion: 1;
  runtime: { version?: string; gitSha?: string; sha256?: string; path?: string };
  config: { pathSha256: string; contentSha256?: string; contentHashStatus: "verified" | "unavailable"; source: string; allowedRootCount: number; broadRootWarnings: string[] };
  state: { path: string; exists: boolean; sessionFiles: number; bytes: number; acl: { status: "not-assessed" | "mode-observed"; detail: string } };
  binaries: Array<{ agent: string; configuredPath: string; exists: boolean; resolvedPath?: string; driftHints: string[] }>;
  promotion: {
    status: "not-versioned-layout" | "marker-missing" | "current" | "drift" | "unreadable";
    releaseId?: string;
    markerPath?: string;
    detail: string;
  };
}

/** Build a machine-readable local report. It omits raw config bytes and credentials, but intentionally reports selected local paths. */
export function buildDiagnostics(config: BridgeConfig, registry: Map<string, AgentAdapter>, options: DiagnosticsOptions = {}): BridgeDiagnostics {
  const platform = options.platform ?? process.platform;
  const roots = config.allowedRoots.map((root) => broadRootWarning(root, options.userProfile ?? homedir(), platform)).filter((warning): warning is string => !!warning);
  const configContentSha256 = hashFile(config.configPath);
  const state = inspectState(config.stateDir, platform);
  const binaries = [...registry.values()]
    .filter((adapter) => !!adapter.bin)
    .map((adapter) => inspectBinary(adapter.id, adapter.bin!, {
      platform,
      pathEnv: options.pathEnv ?? process.env.PATH ?? "",
      pathExt: options.pathExt ?? process.env.PATHEXT,
      cwd: options.cwd ?? process.cwd(),
    }));
  return {
    schemaVersion: 1,
    runtime: { ...options.runtime },
    config: {
      pathSha256: sha256(config.configPath),
      ...(configContentSha256 ? { contentSha256: configContentSha256 } : {}),
      contentHashStatus: configContentSha256 ? "verified" : "unavailable",
      source: config.configSource,
      allowedRootCount: config.allowedRoots.length,
      broadRootWarnings: roots,
    },
    state,
    binaries,
    promotion: inspectPromotion(options.runtime, platform),
  };
}

function inspectPromotion(runtime: DiagnosticsOptions["runtime"], platform: NodeJS.Platform): BridgeDiagnostics["promotion"] {
  if (!runtime?.path) return { status: "not-versioned-layout", detail: "runtime path was not supplied" };
  const serverDir = dirname(runtime.path);
  const releaseDir = dirname(serverDir);
  const releasesDir = dirname(releaseDir);
  if (basename(serverDir).toLowerCase() !== "server" || basename(releasesDir).toLowerCase() !== "releases") {
    return { status: "not-versioned-layout", detail: "runtime is not under releases/<release-id>/server" };
  }
  const markerPath = join(dirname(releasesDir), "current-release.json");
  const releaseId = basename(releaseDir);
  if (!existsSync(markerPath)) return { status: "marker-missing", releaseId, markerPath, detail: "no promoted-release marker is present" };
  try {
    const raw = JSON.parse(readFileSync(markerPath, "utf8")) as unknown;
    if (!isRecord(raw) || raw.schemaVersion !== 1 || typeof raw.releaseId !== "string" || typeof raw.releasePath !== "string" || typeof raw.runtimeSha256 !== "string") {
      return { status: "unreadable", releaseId, markerPath, detail: "promoted-release marker has an invalid schema" };
    }
    const identityMatches = raw.releaseId === releaseId && normal(resolve(raw.releasePath), platform) === normal(resolve(releaseDir), platform);
    const hashMatches = !!runtime.sha256 && raw.runtimeSha256.toLowerCase() === runtime.sha256.toLowerCase();
    if (identityMatches && hashMatches) return { status: "current", releaseId, markerPath, detail: "runtime identity and SHA-256 match the promoted release" };
    const reasons = [identityMatches ? undefined : "release identity differs", hashMatches ? undefined : "runtime SHA-256 differs"].filter(Boolean).join("; ");
    return { status: "drift", releaseId, markerPath, detail: reasons };
  } catch {
    return { status: "unreadable", releaseId, markerPath, detail: "promoted-release marker is not valid readable JSON" };
  }
}

function inspectState(stateDir: string, platform: NodeJS.Platform): BridgeDiagnostics["state"] {
  if (!existsSync(stateDir)) {
    return { path: stateDir, exists: false, sessionFiles: 0, bytes: 0, acl: { status: "not-assessed", detail: "state directory does not exist" } };
  }
  const files = treeStats(stateDir);
  const stat = lstatSync(stateDir);
  const acl = platform === "win32"
    ? { status: "not-assessed" as const, detail: "Windows ACL inspection requires a host-specific command and is intentionally not run by diagnostics." }
    : { status: "mode-observed" as const, detail: `directory mode ${(stat.mode & 0o777).toString(8)}` };
  return { path: stateDir, exists: true, sessionFiles: files.sessionFiles, bytes: files.bytes, acl };
}

function treeStats(root: string): { sessionFiles: number; bytes: number } {
  let sessionFiles = 0;
  let bytes = 0;
  const visit = (path: string): void => {
    let entries;
    try { entries = readdirSync(path, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const child = join(path, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) { visit(child); continue; }
      if (!entry.isFile()) continue;
      try {
        const stat = lstatSync(child);
        bytes += stat.size;
        if (normalize(dirname(child)) === normalize(join(root, "sessions")) && entry.name.endsWith(".json")) sessionFiles += 1;
      } catch { /* file disappeared during inspection */ }
    }
  };
  visit(root);
  return { sessionFiles, bytes };
}

interface BinaryInspectionOptions {
  platform: NodeJS.Platform;
  pathEnv: string;
  pathExt?: string;
  cwd: string;
}

function inspectBinary(agent: string, configuredPath: string, options: BinaryInspectionOptions): BridgeDiagnostics["binaries"][number] {
  const pathQualified = isPathQualified(configuredPath, options.platform);
  const resolvedPath = resolveExecutable(configuredPath, options);
  const exists = resolvedPath !== undefined;
  const driftHints: string[] = [];
  if (/[\\/]bin[\\/][a-f0-9]{12,}[\\/]/i.test(resolvedPath ?? configuredPath)) driftHints.push("path contains a versioned/hash-like installation directory; rediscover after host updates");
  if (!exists) driftHints.push(pathQualified
    ? "configured executable path does not exist or is not executable"
    : "configured command could not be resolved on PATH");
  return { agent, configuredPath, exists, ...(resolvedPath ? { resolvedPath } : {}), driftHints };
}

function resolveExecutable(configuredPath: string, options: BinaryInspectionOptions): string | undefined {
  const pathApi = options.platform === "win32" ? win32 : posix;
  const candidates: string[] = [];
  if (isPathQualified(configuredPath, options.platform)) {
    candidates.push(pathApi.isAbsolute(configuredPath) ? configuredPath : pathApi.resolve(options.cwd, configuredPath));
  } else {
    const extensions = commandExtensions(configuredPath, options.platform, options.pathExt);
    const delimiter = options.platform === "win32" ? ";" : ":";
    for (const rawEntry of options.pathEnv.split(delimiter)) {
      const entry = stripOuterQuotes(rawEntry.trim()) || options.cwd;
      for (const extension of extensions) candidates.push(pathApi.resolve(entry, `${configuredPath}${extension}`));
    }
  }

  for (const candidate of [...new Set(candidates)]) {
    if (!isExecutableFile(candidate, options.platform)) continue;
    try { return realpathSync.native(candidate); } catch { return pathApi.resolve(candidate); }
  }
  return undefined;
}

function commandExtensions(command: string, platform: NodeJS.Platform, pathExt?: string): string[] {
  if (platform !== "win32") return [""];
  if (win32.extname(command)) return [""];
  const configured = (pathExt || ".COM;.EXE;.BAT;.CMD")
    .split(";")
    .map((extension) => extension.trim())
    .filter(Boolean)
    .map((extension) => extension.startsWith(".") ? extension : `.${extension}`);
  return ["", ...configured];
}

function isExecutableFile(path: string, platform: NodeJS.Platform): boolean {
  try {
    if (!statSync(path).isFile()) return false;
    accessSync(path, platform === "win32" ? constants.F_OK : constants.X_OK);
    return true;
  } catch { return false; }
}

function isPathQualified(value: string, platform: NodeJS.Platform): boolean {
  if (platform === "win32") return win32.isAbsolute(value) || /[\\/]/.test(value) || /^[A-Za-z]:/.test(value);
  return posix.isAbsolute(value) || value.includes("/");
}

function stripOuterQuotes(value: string): string {
  return value.length >= 2 && value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
}

function broadRootWarning(root: string, userProfile: string, platform: NodeJS.Platform): string | undefined {
  if (isFilesystemRoot(root, platform)) return `broad root: ${root} is a filesystem root; prefer a specific project directory`;
  const pathApi = platform === "win32" ? win32 : posix;
  const value = normal(pathApi.resolve(root), platform);
  const profile = normal(pathApi.resolve(userProfile), platform);
  if (value === profile || profile.startsWith(`${value}${pathApi.sep}`)) return `broad root: ${root} contains the user profile`;
  const known = ["documents", "downloads", pathApi.join("onedrive", "documents")].map((suffix) => normal(pathApi.join(userProfile, suffix), platform));
  if (known.includes(value)) return `broad root: ${root} is a user content library; prefer a specific project directory`;
  return undefined;
}

function isFilesystemRoot(value: string, platform: NodeJS.Platform): boolean {
  const trimmed = value.trim();
  if (trimmed === "/" || trimmed === "\\") return true;
  if (/^[A-Za-z]:[\\/]*$/.test(trimmed)) return true;
  const pathApi = platform === "win32" ? win32 : posix;
  if (!pathApi.isAbsolute(trimmed)) return false;
  const normalized = pathApi.normalize(trimmed);
  return normal(pathApi.parse(normalized).root, platform) === normal(normalized, platform);
}

/** Redact credential-shaped fragments before including untrusted provider detail in diagnostics. */
export function sanitizeDiagnosticDetail(value: unknown, maxChars = 512): string {
  const limit = Number.isSafeInteger(maxChars) && maxChars > 0 ? maxChars : 512;
  let text = value instanceof Error ? value.message : String(value ?? "");
  text = text
    // Provider and CLI output is untrusted terminal text. Remove ANSI/control
    // bytes first so an escape sequence cannot hide a credential prefix.
    .replace(/\u001b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, "")
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b(Bearer|Basic)\s+[^\s,;]+/gi, "$1 [REDACTED]")
    .replace(/\b(authorization|api[-_ ]?key|access[-_ ]?token|token|secret|password)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, "$1=[REDACTED]")
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]")
    .replace(/([?&](?:api[-_]?key|access[-_]?token|token|secret|password)=)[^&#\s]*/gi, "$1[REDACTED]")
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, "$1[REDACTED]@");
  if (text.length <= limit) return text;
  return `${text.slice(0, Math.max(0, limit - 1))}…`;
}

function normal(value: string, platform: NodeJS.Platform): string { return platform === "win32" ? value.toLowerCase() : value; }
function sha256(value: string): string { return createHash("sha256").update(value, "utf8").digest("hex"); }
function hashFile(path: string): string | undefined {
  try { return createHash("sha256").update(readFileSync(path)).digest("hex"); }
  catch { return undefined; }
}
function isRecord(value: unknown): value is Record<string, any> { return typeof value === "object" && value !== null && !Array.isArray(value); }
