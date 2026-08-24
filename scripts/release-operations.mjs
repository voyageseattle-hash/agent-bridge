import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const IMMUTABLE_OPERATIONS_CAPABILITY = "immutable-release-operations-v2";
export const MAX_RELEASE_ENTRIES = 32;
export const MAX_RELEASE_FILE_BYTES = 20 * 1024 * 1024;
export const MAX_RELEASE_TOTAL_BYTES = 40 * 1024 * 1024;

export const RELEASE_OPERATION_FILES = Object.freeze([
  Object.freeze({ source: "scripts/check-cutover-readiness.ps1", target: "operations/check-cutover-readiness.ps1" }),
  Object.freeze({ source: "scripts/cutover-release.ps1", target: "operations/cutover-release.ps1" }),
  Object.freeze({ source: "scripts/switch-release.ps1", target: "operations/switch-release.ps1" }),
  Object.freeze({ source: "scripts/inspect-install.ps1", target: "operations/inspect-install.ps1" }),
  Object.freeze({ source: "scripts/protect-state.ps1", target: "operations/protect-state.ps1" }),
  Object.freeze({ source: "scripts/configure-clients.ps1", target: "operations/configure-clients.ps1" }),
  Object.freeze({ source: "scripts/cutover-lock.psm1", target: "operations/cutover-lock.psm1" }),
  Object.freeze({ source: "scripts/cutover-quiescence.psm1", target: "operations/cutover-quiescence.psm1" }),
]);

export const RELEASE_OPERATION_CONTRACT = Object.freeze({
  capability: IMMUTABLE_OPERATIONS_CAPABILITY,
  schemaVersion: 2,
  platform: "windows",
  payloads: Object.freeze([
    "server/agent-bridge.mjs",
    "server/agent-bridge.mjs.map",
    ...RELEASE_OPERATION_FILES.map(({ target }) => target),
  ]),
  entryPoints: Object.freeze({
    readiness: "operations/check-cutover-readiness.ps1",
    cutover: "operations/cutover-release.ps1",
    rollback: "operations/switch-release.ps1",
    inspection: "operations/inspect-install.ps1",
    stateProtection: "operations/protect-state.ps1",
  }),
});

export function collectReleaseOperations(root, { gitSha, requireWorkingTreeMatch = false } = {}) {
  return RELEASE_OPERATION_FILES.map(({ source, target }) => {
    const bytes = gitSha ? gitBlob(root, gitSha, source) : readFileSync(join(root, source));
    if (requireWorkingTreeMatch && gitSha) {
      const workingBytes = readFileSync(join(root, source));
      if (!workingBytes.equals(bytes)) throw new Error(`release operation differs from committed ${gitSha}: ${source}`);
    }
    return Object.freeze({ source, target, bytes, sha256: sha256(bytes), byteLength: bytes.length });
  });
}

export function assertReleaseOperationsMatchWorkingTree(root, operations, gitSha = "HEAD") {
  for (const operation of operations) {
    const committedBytes = gitBlob(root, gitSha, operation.source);
    const workingBytes = readFileSync(join(root, operation.source));
    if (!committedBytes.equals(operation.bytes) || !workingBytes.equals(operation.bytes)) {
      throw new Error(`release operation changed after collection or differs from committed ${gitSha}: ${operation.source}`);
    }
  }
}

function gitBlob(root, gitSha, source) {
  try {
    return execFileSync("git", ["show", `${gitSha}:${source.replaceAll("\\", "/")}`], {
      cwd: root,
      encoding: "buffer",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: MAX_RELEASE_FILE_BYTES,
    });
  } catch {
    throw new Error(`release packaging requires committed operation bytes at ${gitSha}:${source}`);
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
