import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";

export const liveRequired = process.env.AGENT_BRIDGE_LIVE_REQUIRED === "1";

export async function resolveLiveServer() {
  const configured = process.env.AGENT_BRIDGE_SERVER_PATH;
  if (liveRequired && !configured) {
    throw new Error("AGENT_BRIDGE_SERVER_PATH is required when AGENT_BRIDGE_LIVE_REQUIRED=1");
  }
  const path = configured ?? join(process.cwd(), "dist", "agent-bridge.mjs");
  if (configured && !isAbsolute(configured)) throw new Error("AGENT_BRIDGE_SERVER_PATH must be absolute");
  const absolute = resolve(path);
  if (!existsSync(absolute) || !statSync(absolute).isFile()) throw new Error(`Agent Bridge server does not exist: ${absolute}`);
  const canonicalPath = await realpath(absolute);
  const actualSha256 = createHash("sha256").update(readFileSync(canonicalPath)).digest("hex");
  if (!configured) return { path: canonicalPath, expectedVersion: undefined, expectedSha256: actualSha256, releaseMode: false };
  const expectedVersion = process.env.AGENT_BRIDGE_EXPECTED_VERSION;
  const expectedSha256 = process.env.AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256?.toLowerCase();
  const configuredInstallRoot = process.env.AGENT_BRIDGE_INSTALL_ROOT;
  if (!expectedVersion) throw new Error("AGENT_BRIDGE_EXPECTED_VERSION is required with AGENT_BRIDGE_SERVER_PATH");
  if (!expectedSha256 || !/^[a-f0-9]{64}$/.test(expectedSha256)) {
    throw new Error("AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256 is required with AGENT_BRIDGE_SERVER_PATH");
  }
  if (!configuredInstallRoot || !isAbsolute(configuredInstallRoot)) {
    throw new Error("AGENT_BRIDGE_INSTALL_ROOT must be an absolute path with AGENT_BRIDGE_SERVER_PATH");
  }
  if (!existsSync(configuredInstallRoot) || !statSync(configuredInstallRoot).isDirectory()) {
    throw new Error(`AGENT_BRIDGE_INSTALL_ROOT does not exist: ${configuredInstallRoot}`);
  }
  const installRoot = await realpath(configuredInstallRoot);
  const releasesRoot = await realpath(join(installRoot, "releases"));
  const serverDir = dirname(canonicalPath);
  const releasePath = dirname(serverDir);
  if (basename(serverDir).toLowerCase() !== "server" || basename(canonicalPath).toLowerCase() !== "agent-bridge.mjs"
      || !samePath(dirname(releasePath), releasesRoot) || !isInsideOrEqual(releasePath, canonicalPath)) {
    throw new Error("AGENT_BRIDGE_SERVER_PATH must identify one immutable runtime under AGENT_BRIDGE_INSTALL_ROOT/releases/<release-id>/server");
  }
  assert.equal(actualSha256, expectedSha256, "configured server bytes differ from expected release runtime hash");
  return { path: canonicalPath, releasePath, releaseId: basename(releasePath), installRoot, expectedVersion, expectedSha256, releaseMode: true };
}

export async function assertRuntimeIdentity(client, identity) {
  const result = await client.callTool({ name: "diagnose_install", arguments: {} });
  assert.notEqual(result.isError, true, "diagnose_install failed before live delegation");
  const runtime = result.structuredContent?.diagnostics?.runtime;
  assert.ok(runtime, "diagnose_install omitted runtime identity");
  assert.equal(await realpath(runtime.path), identity.path, "live test connected to an unexpected runtime path");
  assert.equal(runtime.sha256, identity.expectedSha256, "live runtime hash differs from preflight evidence");
  if (identity.expectedVersion) assert.equal(runtime.version, identity.expectedVersion, "live runtime version differs from release evidence");
  return result.structuredContent.diagnostics;
}

export function emitLiveResult(backend, status, detail = {}) {
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, backend, status, at: new Date().toISOString(), ...detail })}\n`);
}

export function skipLive(backend, reason) {
  emitLiveResult(backend, "skip", { reason });
  process.exitCode = liveRequired ? 2 : 0;
}

export function failLive(backend, error) {
  emitLiveResult(backend, "fail", { error: safeMessage(error) });
  process.exitCode = 1;
}

function safeMessage(error) {
  return (error instanceof Error ? error.message : String(error))
    .replace(/\b(?:authorization|api[-_ ]?key|access[-_ ]?token|token|secret|password)\b\s*[:=]\s*\S+/gi, "$1=[REDACTED]")
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]")
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ")
    .slice(0, 512);
}
function samePath(left, right) { return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right; }
function isInsideOrEqual(parent, child) { const value = relative(parent, child); return value === "" || (!value.startsWith("..") && !isAbsolute(value)); }
