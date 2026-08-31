#!/usr/bin/env node

import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  unlink,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import { RELEASE_OPERATION_CONTRACT, RELEASE_OPERATION_FILES } from "./release-operations.mjs";

const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^[a-f0-9]{40}$/;
const SAFE_ID = /^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$/;
const UTC_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_TEXT_BYTES = 10 * 1024 * 1024;
const MANUS_TASK_ID = /(^|[^A-Za-z0-9])([A-Za-z0-9]{22})(?=$|[^A-Za-z0-9])/g;
const BENIGN_TASK_ID_SHAPED_TOKENS = new Set(["implementationPriority"]);
const JSON_NARRATIVE_KEY_WORDS = new Set(["prompt", "prompts", "transcript", "transcripts", "conversation", "conversations", "response", "responses", "result", "results", "output", "outputs", "message", "messages", "turn", "turns"]);
const JSON_NARRATIVE_VALUE_WORDS = new Set(["text", "content", "body", "value"]);
const PRIVATE_EVIDENCE_PATH_SEGMENTS = new Set(["state", "session", "sessions"]);
const GATES = new Set(["automated", "local-cli", "remote-service", "client-restart", "human-visible"]);
const STATUSES = new Set(["pass", "fail", "blocked", "not-run"]);
const SOURCES = new Set(["operator-attested", "external-artifact"]);
const DISPOSITIONS = new Set([
  "candidate-ready-promotion-blocked",
  "accepted",
  "accepted-with-residual-risks",
  "rejected",
]);
const LEGACY_ACCEPTANCE_PROFILE = Object.freeze([
  ["repository-verify", "automated"],
  ["production-dependency-audit", "automated"],
  ["mcpb-manifest-validation", "automated"],
  ["immutable-operations-integrity", "automated"],
  ["installed-provider-disabled-canary", "automated"],
  ["windows-npm-shim-installed-runtime", "automated"],
  ["codex-installed-runtime", "local-cli"],
  ["claude-installed-runtime", "local-cli"],
  ["registration-normalization", "client-restart"],
  ["release-promotion", "client-restart"],
  ["manus-remote-canary", "remote-service"],
  ["manus-waiting-action-canary", "remote-service"],
  ["codex-restarted-client", "client-restart"],
  ["claude-code-restarted-client", "client-restart"],
  ["claude-desktop-restarted-client", "client-restart"],
  ["creator-visible-acceptance", "human-visible"],
  ["rollback-canary", "automated"],
]);
const CORE_ACCEPTANCE_PROFILE = Object.freeze([
  ["repository-verify", "automated"],
  ["production-dependency-audit", "automated"],
  ["mcpb-manifest-validation", "automated"],
  ["immutable-operations-integrity", "automated"],
  ["installed-provider-disabled-canary", "automated"],
  ["windows-npm-shim-installed-runtime", "automated"],
  ["codex-installed-runtime", "local-cli"],
  ["claude-installed-runtime", "local-cli"],
  ["registration-normalization", "client-restart"],
  ["release-promotion", "client-restart"],
  ["codex-restarted-client", "client-restart"],
  ["claude-code-restarted-client", "client-restart"],
  ["claude-desktop-restarted-client", "client-restart"],
  ["creator-visible-acceptance", "human-visible"],
  ["rollback-canary", "automated"],
]);
const ACCEPTANCE_PROFILES = Object.freeze({
  "windows-local-core": CORE_ACCEPTANCE_PROFILE,
  "windows-local-manus": LEGACY_ACCEPTANCE_PROFILE,
});
const SANDBOX_MODES = ["read-only", "workspace-write", "full-access"];
const DATA_CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"];
const RELEASE_AGENT_SCHEMA = z.object({
  enabled: z.boolean().optional(),
  bin: z.string().min(1).optional(),
  defaultModel: z.string().min(1).optional(),
  extraArgs: z.array(z.string()).optional(),
  extraEnv: z.record(z.string()).optional(),
  credentialFile: z.string().min(1).optional(),
  baseUrl: z.string().url().optional(),
  allowDevelopmentBaseUrl: z.boolean().optional(),
  acknowledgeAccountDefaultCapabilities: z.boolean().optional(),
  accountCapabilityProfile: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/).optional(),
  sandboxCeiling: z.enum(SANDBOX_MODES).optional(),
}).strict();
const RELEASE_CONFIG_SCHEMA = z.object({
  agents: z.record(RELEASE_AGENT_SCHEMA).optional(),
  defaults: z.object({
    timeoutSec: z.number().int().positive().max(7200).optional(),
    sandbox: z.enum(SANDBOX_MODES).optional(),
    cwd: z.string().min(1).optional(),
  }).strict().optional(),
  allowedRoots: z.array(z.string().min(1)).min(1),
  policy: z.object({
    sandboxCeiling: z.enum(SANDBOX_MODES).optional(),
    remoteEgress: z.object({
      enabled: z.boolean().optional(),
      allowedAgents: z.array(z.string().min(1)).max(32).optional(),
      allowedRoots: z.array(z.string().min(1)).max(64).optional(),
      allowedDataClasses: z.array(z.enum(DATA_CLASSIFICATIONS)).max(DATA_CLASSIFICATIONS.length).optional(),
    }).strict().optional(),
    cumulativeRemoteCost: z.object({
      currency: z.literal("USD"),
      maxReservedCents: z.number().int().min(1).max(100_000_000_000),
    }).strict().optional(),
  }).strict().optional(),
  handoffMaxChars: z.number().int().min(1000).max(1_000_000).optional(),
  stateDir: z.string().min(1).optional(),
  sessionLockWaitMs: z.number().int().min(0).max(300_000).optional(),
  sessionLockStaleMs: z.number().int().min(60_000).max(86_400_000).optional(),
  _notes: z.unknown().optional(),
}).strict();

export async function exportReleaseEvidence(
  { descriptorPath, outputDir, requireAccepted = false },
  { testOnlyBeforeFinalLiveBindingCheck, testOnlyBeforeCutoverLockRelease } = {},
) {
  assert.ok(
    testOnlyBeforeFinalLiveBindingCheck === undefined || typeof testOnlyBeforeFinalLiveBindingCheck === "function",
    "testOnlyBeforeFinalLiveBindingCheck must be a function when provided",
  );
  assert.ok(
    testOnlyBeforeCutoverLockRelease === undefined || typeof testOnlyBeforeCutoverLockRelease === "function",
    "testOnlyBeforeCutoverLockRelease must be a function when provided",
  );
  const descriptorFile = await requireRegularFile(descriptorPath, "descriptor");
  const descriptor = JSON.parse(await readFile(descriptorFile, "utf8"));
  validateDescriptor(descriptor);

  const candidate = await verifyCandidate(descriptor.candidate, descriptor.schemaVersion);
  if (descriptor.schemaVersion === 2) {
    assert.equal(
      descriptor.acceptancePolicy.expectedProfile,
      candidate.acceptance.profile,
      `descriptor expected profile ${descriptor.acceptancePolicy.expectedProfile} differs from derived profile ${candidate.acceptance.profile}`,
    );
    assertNoContradictoryCapabilityClaims(descriptor, candidate.acceptance);
  }
  const evidenceRoot = await requireDirectory(descriptor.evidenceRoot, "descriptor.evidenceRoot");
  assert.ok(!isInsideOrEqual(candidate.installRoot, evidenceRoot), "descriptor.evidenceRoot must be outside the Agent Bridge install root");
  assert.ok(isInsideOrEqual(evidenceRoot, descriptorFile), "descriptor file must be contained by descriptor.evidenceRoot");
  const output = requiredAbsolutePath(outputDir, "output-dir");
  assert.equal(basename(output), descriptor.packetId, "--output-dir basename must equal descriptor.packetId so packet identities cannot be silently reused");
  await validateNewOutputDirectory(output, candidate.installRoot, evidenceRoot);
  if (requireAccepted) await assertAccepted(descriptor, candidate, evidenceRoot);

  const parent = dirname(output);
  const staging = join(parent, `.${basename(output)}.staging-${randomUUID()}`);
  const lockPath = `${output}.lock`;
  const lockToken = randomUUID();
  let lockHandle;
  let lockOwned = false;
  let cutoverLock = null;
  let staged = false;
  try {
    lockHandle = await open(lockPath, "wx", 0o600);
    lockOwned = true;
    await lockHandle.writeFile(`${JSON.stringify({ schemaVersion: 1, packetId: descriptor.packetId, pid: process.pid, token: lockToken })}\n`, "utf8");
    await lockHandle.sync();
    await mkdir(staging, { recursive: false, mode: 0o700 });
    staged = true;
    const artifactsDir = join(staging, "artifacts");
    await mkdir(artifactsDir, { mode: 0o700 });
    const redactions = await buildRedactions(descriptor.sanitization.redactions, candidate);
    const artifacts = await copyEvidenceArtifacts(descriptor.checks, artifactsDir, redactions, evidenceRoot);
    const createdAt = new Date().toISOString();
    const packet = sanitizeJsonValue(buildPacket(descriptor, candidate, artifacts, createdAt), redactions);
    assertNoManusTaskIdInJsonValue(packet, "evidence report");
    const jsonBytes = Buffer.from(`${JSON.stringify(packet, null, 2)}\n`, "utf8");
    const jsonHash = sha256(jsonBytes);
    const markdownBytes = Buffer.from(renderMarkdown(packet, jsonHash), "utf8");
    assertNoManusTaskId(markdownBytes.toString("utf8"), "Markdown evidence report");
    const packetJsonPath = join(staging, "evidence-report.json");
    const packetMarkdownPath = join(staging, "evidence-report.md");
    await writePrivateFile(packetJsonPath, jsonBytes);
    await writePrivateFile(packetMarkdownPath, markdownBytes);
    const manifest = {
      schemaVersion: 1,
      packetId: packet.packetId,
      createdAt,
      files: {
        "evidence-report.json": { sha256: jsonHash, bytes: jsonBytes.byteLength },
        "evidence-report.md": { sha256: sha256(markdownBytes), bytes: markdownBytes.byteLength },
        ...Object.fromEntries(artifacts.map((artifact) => [artifact.uri.replace("artifact://", ""), {
          sha256: artifact.sha256,
          bytes: artifact.bytes,
        }])),
      },
    };
    await writePrivateFile(join(staging, "manifest.json"), Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8"));
    await syncDirectory(staging);
    assert.ok(!existsSync(output), `refusing destination created during export: ${output}`);
    assert.ok(samePath(await realpath(parent), parent), "output parent identity changed during export");
    if (requireAccepted) {
      cutoverLock = await acquireAcceptedExportCutoverLock(candidate.installRoot);
      if (testOnlyBeforeFinalLiveBindingCheck) await testOnlyBeforeFinalLiveBindingCheck();
      await verifyAcceptedLiveBinding(descriptor.schemaVersion, candidate);
    } else {
      if (testOnlyBeforeFinalLiveBindingCheck) await testOnlyBeforeFinalLiveBindingCheck();
      await verifySharedConfigBinding(candidate);
    }
    await rename(staging, output);
    staged = false;
    try {
      await syncDirectory(parent);
      if (cutoverLock) {
        if (testOnlyBeforeCutoverLockRelease) await testOnlyBeforeCutoverLockRelease();
        await releaseAcceptedExportCutoverLock(cutoverLock);
        cutoverLock = null;
      }
    } catch (error) {
      if (cutoverLock) {
        const uncertainLock = cutoverLock;
        cutoverLock = null;
        await releaseAcceptedExportCutoverLock(uncertainLock).catch(() => {});
      }
      let removalError = null;
      try {
        await rm(output, { recursive: true, force: true });
      } catch (candidateRemovalError) {
        removalError = candidateRemovalError;
      }
      if (removalError || existsSync(output)) {
        throw new Error(`release evidence publication failed after packet rename and the uncommitted packet could not be removed: ${removalError?.message ?? error.message}`);
      }
      await syncDirectory(parent).catch(() => {});
      throw new Error(`release evidence publication failed after packet rename; the uncommitted packet was removed: ${error.message}`);
    }
    return {
      status: requireAccepted ? "accepted" : "exported",
      disposition: packet.disposition,
      packetId: packet.packetId,
      outputDir: output,
      reportPath: join(output, "evidence-report.json"),
      markdownPath: join(output, "evidence-report.md"),
      manifestPath: join(output, "manifest.json"),
      reportSha256: jsonHash,
      artifactCount: artifacts.length,
      acceptanceProfile: candidate.acceptance?.profile ?? "legacy-windows-manus-required",
    };
  } finally {
    if (staged) await rm(staging, { recursive: true, force: true });
    if (lockHandle) await lockHandle.close().catch(() => {});
    if (lockOwned && existsSync(lockPath)) {
      const lock = await readFile(lockPath, "utf8").catch(() => null);
      if (lock !== null) {
        const record = JSON.parse(lock);
        if (record.token === lockToken) await unlink(lockPath).catch(() => {});
      }
    }
    if (cutoverLock) await releaseAcceptedExportCutoverLock(cutoverLock);
  }
}

export async function verifyReleaseEvidence({ packetDir }) {
  const packetPath = await requireDirectory(packetDir, "packet-dir");
  const manifestPath = await requireRegularFile(join(packetPath, "manifest.json"), "packet manifest");
  assert.ok(isInsideOrEqual(packetPath, manifestPath), "packet manifest escaped the packet directory");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  exactObject(manifest, ["schemaVersion", "packetId", "createdAt", "files"], "packet manifest");
  assert.equal(manifest.schemaVersion, 1, "packet manifest schemaVersion must be 1");
  safeId(manifest.packetId, "packet manifest packetId");
  assert.equal(basename(packetPath), manifest.packetId, "packet directory basename differs from manifest packetId");
  canonicalTimestamp(manifest.createdAt, "packet manifest createdAt");
  assert.ok(manifest.files !== null && typeof manifest.files === "object" && !Array.isArray(manifest.files), "packet manifest files must be an object");
  const names = Object.keys(manifest.files);
  assert.ok(names.length >= 2 && names.length <= 2_002, "packet manifest file count is invalid");
  assert.ok(names.includes("evidence-report.json") && names.includes("evidence-report.md"), "packet manifest omits a required report");
  const expectedRootEntries = new Set(["manifest.json", "evidence-report.json", "evidence-report.md", "artifacts"]);
  for (const name of names) {
    assert.ok(name === "evidence-report.json" || name === "evidence-report.md" || /^artifacts\/[a-zA-Z0-9][a-zA-Z0-9._+-]{0,255}$/.test(name), `packet manifest has an unsafe file name: ${name}`);
    const record = manifest.files[name];
    exactObject(record, ["sha256", "bytes"], `packet manifest file ${name}`);
    assert.match(record.sha256, SHA256, `packet manifest hash is invalid: ${name}`);
    assert.ok(Number.isSafeInteger(record.bytes) && record.bytes >= 0 && record.bytes <= MAX_TEXT_BYTES, `packet manifest byte count is invalid: ${name}`);
    const path = await requireRegularFile(join(packetPath, ...name.split("/")), `packet file ${name}`);
    assert.ok(isInsideOrEqual(packetPath, path), `packet file escaped the packet directory: ${name}`);
    const bytes = await readFile(path);
    assert.equal(bytes.byteLength, record.bytes, `packet file byte count differs: ${name}`);
    assert.equal(sha256(bytes), record.sha256, `packet file hash differs: ${name}`);
    if (!name.startsWith("artifacts/")) expectedRootEntries.add(name);
  }
  const rootEntries = await readdir(packetPath, { withFileTypes: true });
  assert.deepEqual(new Set(rootEntries.map((entry) => entry.name)), expectedRootEntries, "packet directory has missing or unmanifested entries");
  for (const entry of rootEntries) {
    assert.ok(!entry.isSymbolicLink(), `packet entry must not be a symbolic link: ${entry.name}`);
    if (entry.name === "artifacts") assert.ok(entry.isDirectory(), "packet artifacts entry must be a directory");
    else assert.ok(entry.isFile(), `packet root entry must be a file: ${entry.name}`);
  }
  const artifactNames = names.filter((name) => name.startsWith("artifacts/")).map((name) => name.slice("artifacts/".length)).sort();
  const artifactEntries = await readdir(join(packetPath, "artifacts"), { withFileTypes: true });
  assert.deepEqual(artifactEntries.map((entry) => entry.name).sort(), artifactNames, "packet artifacts directory has missing or unmanifested entries");
  assert.ok(artifactEntries.every((entry) => entry.isFile() && !entry.isSymbolicLink()), "packet artifacts must be regular non-link files");
  const report = JSON.parse(await readFile(join(packetPath, "evidence-report.json"), "utf8"));
  assert.ok(report !== null && typeof report === "object" && !Array.isArray(report), "evidence report must be an object");
  assert.ok([1, 2].includes(report.schemaVersion), "evidence report schemaVersion must be 1 or 2");
  const reportKeys = [
    "schemaVersion", "packetId", "createdAt", "sanitization", "candidate", "checks", "approvals",
    "agentRuns", "recommendations", "workboard", "budget", "residualRisks", "rollback", "disposition",
  ];
  if (report.schemaVersion === 2) reportKeys.splice(4, 0, "acceptance");
  exactObject(report, reportKeys, "evidence report");
  if (report.schemaVersion === 2) validateAcceptanceReport(report.acceptance, report.candidate);
  assert.equal(report.packetId, manifest.packetId, "evidence report packetId differs from manifest");
  assert.equal(report.createdAt, manifest.createdAt, "evidence report timestamp differs from manifest");
  assert.ok(DISPOSITIONS.has(report.disposition), "evidence report disposition is invalid");
  const markdown = await readFile(join(packetPath, "evidence-report.md"), "utf8");
  assert.ok(markdown.includes(`\`${manifest.packetId}\``), "Markdown report omits the packet ID");
  assert.ok(markdown.includes(`\`${manifest.files["evidence-report.json"].sha256}\``), "Markdown report omits the JSON report hash");
  if (report.schemaVersion === 2) assert.ok(markdown.includes(`\`${report.acceptance.profile}\``), "Markdown report omits the derived acceptance profile");
  return {
    status: "verified",
    packetId: manifest.packetId,
    disposition: report.disposition,
    packetDir: packetPath,
    fileCount: names.length + 1,
    reportSha256: manifest.files["evidence-report.json"].sha256,
    acceptanceProfile: report.acceptance?.profile ?? "legacy-windows-manus-required",
  };
}

function validateDescriptor(value) {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), "descriptor must be an object");
  assert.ok([1, 2].includes(value.schemaVersion), "descriptor.schemaVersion must be 1 or 2");
  const descriptorKeys = [
    "schemaVersion", "packetId", "evidenceRoot", "sanitization", "candidate", "checks", "approvals",
    "agentRuns", "recommendations", "workboard", "budget", "residualRisks", "rollback", "disposition",
  ];
  if (value.schemaVersion === 2) descriptorKeys.splice(3, 0, "acceptancePolicy");
  exactObject(value, descriptorKeys, "descriptor");
  if (value.schemaVersion === 2) {
    exactObject(value.acceptancePolicy, ["schemaVersion", "derivation", "expectedProfile"], "descriptor.acceptancePolicy");
    assert.equal(value.acceptancePolicy.schemaVersion, 1, "descriptor.acceptancePolicy.schemaVersion must be 1");
    assert.equal(value.acceptancePolicy.derivation, "hash-verified-shared-config", "descriptor.acceptancePolicy.derivation is unsupported");
    assert.ok(Object.hasOwn(ACCEPTANCE_PROFILES, value.acceptancePolicy.expectedProfile), "descriptor.acceptancePolicy.expectedProfile is unsupported");
  }
  safeId(value.packetId, "descriptor.packetId");
  requiredAbsolutePath(value.evidenceRoot, "descriptor.evidenceRoot");
  assert.ok(DISPOSITIONS.has(value.disposition), "descriptor.disposition is invalid");

  exactObject(value.sanitization, ["method", "redactions"], "descriptor.sanitization");
  boundedString(value.sanitization.method, "descriptor.sanitization.method", 1, 1000);
  assert.ok(Array.isArray(value.sanitization.redactions), "descriptor.sanitization.redactions must be an array");
  assert.ok(value.sanitization.redactions.length <= 32, "too many redactions");
  for (const [index, item] of value.sanitization.redactions.entries()) {
    exactObject(item, ["path", "replacement"], `redactions[${index}]`);
    requiredAbsolutePath(item.path, `redactions[${index}].path`);
    assert.match(item.replacement, /^<[a-z0-9-]+>$/, `redactions[${index}].replacement must be a documented placeholder`);
  }

  exactObject(value.candidate, [
    "version", "gitSha", "releaseId", "installRoot", "releasePath", "bundlePath", "bundleSha256",
    "runtimeSha256", "configPath", "configSha256", "liveAtStart", "liveAtEnd",
  ], "descriptor.candidate");
  boundedString(value.candidate.version, "candidate.version", 1, 100);
  assert.match(value.candidate.gitSha, GIT_SHA, "candidate.gitSha must be a lower-case 40-character Git SHA");
  safeId(value.candidate.releaseId, "candidate.releaseId");
  assert.equal(value.candidate.releaseId, `${value.candidate.version}+${value.candidate.gitSha.slice(0, 7)}`, "candidate.releaseId does not match version and Git SHA");
  for (const key of ["installRoot", "releasePath", "bundlePath", "configPath"]) requiredAbsolutePath(value.candidate[key], `candidate.${key}`);
  for (const key of ["bundleSha256", "runtimeSha256", "configSha256"]) assert.match(value.candidate[key], SHA256, `candidate.${key} must be a lower-case SHA-256 digest`);
  nullableSafeId(value.candidate.liveAtStart, "candidate.liveAtStart");
  nullableSafeId(value.candidate.liveAtEnd, "candidate.liveAtEnd");

  assert.ok(Array.isArray(value.checks) && value.checks.length > 0 && value.checks.length <= 100, "descriptor.checks must contain 1-100 checks");
  const checkIds = new Set();
  for (const [index, check] of value.checks.entries()) validateCheck(check, index, checkIds);
  assertUnique(value.approvals, "id", "approvals", 100, validateApproval);
  assertUnique(value.agentRuns, "id", "agentRuns", 100, validateAgentRun);
  assertUnique(value.recommendations, "id", "recommendations", 100, validateRecommendation);
  validateWorkboard(value.workboard);
  validateBudget(value.budget);
  assertUnique(value.residualRisks, "id", "residualRisks", 100, validateResidualRisk);
  validateRollback(value.rollback);
}

function validateCheck(check, index, ids) {
  const label = `checks[${index}]`;
  exactObject(check, ["id", "gate", "status", "source", "required", "performedAt", "reason", "command", "exitCode", "evidence"], label);
  safeId(check.id, `${label}.id`);
  assert.ok(!ids.has(check.id), `duplicate check id: ${check.id}`);
  ids.add(check.id);
  assert.ok(GATES.has(check.gate), `${label}.gate is invalid`);
  assert.ok(STATUSES.has(check.status), `${label}.status is invalid`);
  assert.ok(SOURCES.has(check.source), `${label}.source is invalid`);
  assert.equal(typeof check.required, "boolean", `${label}.required must be boolean`);
  if (check.status === "pass") {
    canonicalTimestamp(check.performedAt, `${label}.performedAt`);
    assert.equal(check.reason, null, `${label}.reason must be null for a pass`);
  } else {
    assert.equal(check.performedAt === null || typeof check.performedAt === "string", true, `${label}.performedAt must be null or a timestamp`);
    if (typeof check.performedAt === "string") canonicalTimestamp(check.performedAt, `${label}.performedAt`);
    boundedString(check.reason, `${label}.reason`, 1, 1000);
  }
  if (check.command !== null) boundedString(check.command, `${label}.command`, 1, 2000);
  assert.ok(check.exitCode === null || Number.isSafeInteger(check.exitCode), `${label}.exitCode must be null or a safe integer`);
  if (check.status === "pass" && ["automated", "local-cli"].includes(check.gate) && check.exitCode !== null) assert.equal(check.exitCode, 0, `${label} passed with a nonzero exit code`);
  assert.ok(Array.isArray(check.evidence) && check.evidence.length <= 20, `${label}.evidence must be an array of at most 20 items`);
  if (check.status === "pass") assert.ok(check.evidence.length > 0, `${label} pass requires evidence`);
  const evidenceIds = new Set();
  for (const [evidenceIndex, evidence] of check.evidence.entries()) {
    const evidenceLabel = `${label}.evidence[${evidenceIndex}]`;
    exactObject(evidence, ["id", "path", "mediaType", "dataClass", "expectedSha256"], evidenceLabel);
    safeId(evidence.id, `${evidenceLabel}.id`);
    assert.ok(!evidenceIds.has(evidence.id), `duplicate evidence id in ${check.id}: ${evidence.id}`);
    evidenceIds.add(evidence.id);
    requiredAbsolutePath(evidence.path, `${evidenceLabel}.path`);
    assert.ok(["application/json", "text/plain", "text/markdown"].includes(evidence.mediaType), `${evidenceLabel}.mediaType is unsupported`);
    assert.ok(["public", "internal", "confidential", "restricted"].includes(evidence.dataClass), `${evidenceLabel}.dataClass is invalid`);
    assert.ok(!["confidential", "restricted"].includes(evidence.dataClass), `${evidenceLabel}.dataClass cannot be copied to a shareable packet`);
    if (check.status === "pass") assert.match(evidence.expectedSha256, SHA256, `${evidenceLabel}.expectedSha256 is required for a passing check`);
    else if (evidence.expectedSha256 !== null) assert.match(evidence.expectedSha256, SHA256, `${evidenceLabel}.expectedSha256 is invalid`);
  }
}

function validateApproval(value, index) {
  const label = `approvals[${index}]`;
  exactObject(value, ["id", "category", "state", "sourceRef"], label);
  safeId(value.id, `${label}.id`);
  boundedString(value.category, `${label}.category`, 1, 100);
  assert.ok(["approved", "denied", "consumed", "expired", "revoked"].includes(value.state), `${label}.state is invalid`);
  nullableBoundedString(value.sourceRef, `${label}.sourceRef`, 200);
}

function validateAgentRun(value, index) {
  const label = `agentRuns[${index}]`;
  exactObject(value, ["id", "agent", "boundary", "status", "reason", "sessionRef", "outputCheckId"], label);
  safeId(value.id, `${label}.id`);
  safeId(value.agent, `${label}.agent`);
  assert.ok(["local-cli", "remote-service", "client-restart"].includes(value.boundary), `${label}.boundary is invalid`);
  assert.ok(STATUSES.has(value.status), `${label}.status is invalid`);
  if (value.status === "pass") assert.equal(value.reason, null, `${label}.reason must be null for a pass`);
  else boundedString(value.reason, `${label}.reason`, 1, 1000);
  nullableBoundedString(value.sessionRef, `${label}.sessionRef`, 200);
  nullableSafeId(value.outputCheckId, `${label}.outputCheckId`);
}

function validateRecommendation(value, index) {
  const label = `recommendations[${index}]`;
  exactObject(value, ["id", "title", "priority", "sources", "decision", "reason", "workItemKey"], label);
  safeId(value.id, `${label}.id`);
  boundedString(value.title, `${label}.title`, 1, 300);
  assert.ok(["P0", "P1", "P2", "P3"].includes(value.priority), `${label}.priority is invalid`);
  assert.ok(Array.isArray(value.sources) && value.sources.length > 0 && value.sources.length <= 10, `${label}.sources is invalid`);
  value.sources.forEach((source, sourceIndex) => safeId(source, `${label}.sources[${sourceIndex}]`));
  assert.ok(["accepted", "rejected", "deferred"].includes(value.decision), `${label}.decision is invalid`);
  boundedString(value.reason, `${label}.reason`, 1, 1000);
  nullableSafeId(value.workItemKey, `${label}.workItemKey`);
}

function validateWorkboard(value) {
  if (value === null) return;
  exactObject(value, ["id", "status", "revision"], "workboard");
  safeId(value.id, "workboard.id");
  assert.ok(["active", "paused", "completed", "canceled", "archived"].includes(value.status), "workboard.status is invalid");
  assert.ok(Number.isSafeInteger(value.revision) && value.revision >= 0, "workboard.revision is invalid");
}

function validateBudget(value) {
  exactObject(value, ["enabled", "currency", "maxReservedCents", "reservedCents"], "budget");
  assert.equal(typeof value.enabled, "boolean", "budget.enabled must be boolean");
  if (!value.enabled) {
    assert.equal(value.currency, null, "disabled budget currency must be null");
    assert.equal(value.maxReservedCents, null, "disabled budget maxReservedCents must be null");
    assert.equal(value.reservedCents, null, "disabled budget reservedCents must be null");
    return;
  }
  assert.equal(value.currency, "USD", "budget.currency must be USD");
  for (const key of ["maxReservedCents", "reservedCents"]) assert.ok(Number.isSafeInteger(value[key]) && value[key] >= 0, `budget.${key} must be a non-negative safe integer`);
  assert.ok(value.reservedCents <= value.maxReservedCents, "budget reservation exceeds its ceiling");
}

function validateResidualRisk(value, index) {
  const label = `residualRisks[${index}]`;
  exactObject(value, ["id", "risk", "owner", "disposition", "reviewAfter"], label);
  safeId(value.id, `${label}.id`);
  boundedString(value.risk, `${label}.risk`, 1, 1000);
  boundedString(value.owner, `${label}.owner`, 1, 200);
  assert.ok(["accepted", "mitigated", "deferred"].includes(value.disposition), `${label}.disposition is invalid`);
  canonicalTimestamp(value.reviewAfter, `${label}.reviewAfter`);
}

function validateRollback(value) {
  exactObject(value, ["priorReleaseId", "priorRuntimeSha256", "backupRef", "canaryStatus"], "rollback");
  nullableSafeId(value.priorReleaseId, "rollback.priorReleaseId");
  if (value.priorRuntimeSha256 !== null) assert.match(value.priorRuntimeSha256, SHA256, "rollback.priorRuntimeSha256 is invalid");
  nullableBoundedString(value.backupRef, "rollback.backupRef", 500);
  assert.ok(STATUSES.has(value.canaryStatus), "rollback.canaryStatus is invalid");
}

async function verifyCandidate(value, descriptorSchemaVersion) {
  const installRoot = await requireDirectory(value.installRoot, "candidate.installRoot");
  const releasePath = await requireDirectory(value.releasePath, "candidate.releasePath");
  const expectedReleasePath = join(installRoot, "releases", value.releaseId);
  assert.ok(samePath(releasePath, expectedReleasePath), "candidate.releasePath is not the named immutable release directly under installRoot/releases");
  const releaseRelative = relative(join(installRoot, "releases"), releasePath);
  assert.ok(releaseRelative === value.releaseId && !releaseRelative.startsWith("..") && !isAbsolute(releaseRelative), "candidate release escaped the immutable releases directory");
  const metadataPath = await requireRegularFile(join(releasePath, "release-metadata.json"), "release metadata");
  const metadataBytes = await readFile(metadataPath);
  const metadata = JSON.parse(metadataBytes.toString("utf8"));
  assert.equal(metadata.version, value.version, "release metadata version differs from descriptor");
  assert.equal(metadata.gitSha, value.gitSha, "release metadata Git SHA differs from descriptor");
  assert.deepEqual(metadata.operations, RELEASE_OPERATION_CONTRACT, "release metadata immutable-operation contract is missing or unsupported");
  const expectedPayloadNames = [
    "server/agent-bridge.mjs",
    "server/agent-bridge.mjs.map",
    ...RELEASE_OPERATION_FILES.map(({ target }) => target),
  ].sort();
  assert.deepEqual(Object.keys(metadata.files ?? {}).sort(), expectedPayloadNames, "release metadata payload inventory is incomplete or contains unexpected files");
  const expectedReleaseFiles = ["manifest.json", "release-metadata.json", ...expectedPayloadNames].sort();
  assert.deepEqual(await listReleaseFiles(releasePath), expectedReleaseFiles, "installed release inventory is incomplete or contains unexpected files");
  const installedPayloads = new Map();
  for (const name of expectedPayloadNames) {
    assertSafeReleaseRelativePath(name, `release metadata payload ${name}`);
    const record = metadata.files[name];
    exactObject(record, ["sha256", "bytes"], `release metadata payload ${name}`);
    assert.match(record.sha256, SHA256, `release metadata payload ${name} has an invalid SHA-256`);
    assert.ok(Number.isSafeInteger(record.bytes) && record.bytes >= 0 && record.bytes <= 20 * 1024 * 1024, `release metadata payload ${name} has an invalid byte count`);
    const installedPath = await requireRegularFile(join(releasePath, ...name.split("/")), `installed payload ${name}`);
    const bytes = await readFile(installedPath);
    assert.equal(bytes.byteLength, record.bytes, `installed payload byte count differs from metadata: ${name}`);
    assert.equal(sha256(bytes), record.sha256, `installed payload hash differs from metadata: ${name}`);
    installedPayloads.set(name, { path: installedPath, bytes, sha256: record.sha256 });
  }
  assert.equal(metadata.files["server/agent-bridge.mjs"].sha256, value.runtimeSha256, "release metadata runtime hash differs from descriptor");
  const runtimePath = installedPayloads.get("server/agent-bridge.mjs").path;
  const runtimeBytes = installedPayloads.get("server/agent-bridge.mjs").bytes;
  const manifestPath = await requireRegularFile(join(releasePath, "manifest.json"), "installed manifest");
  const manifestBytes = await readFile(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const manifestIdentity = manifest?._meta?.["com.agentbridge.release"];
  assert.equal(manifest.version, value.version, "installed manifest version differs from descriptor");
  assert.equal(manifestIdentity?.source_git_sha, value.gitSha, "installed manifest Git SHA differs from descriptor");
  assert.equal(manifestIdentity?.runtime_sha256, value.runtimeSha256, "installed manifest runtime hash differs from descriptor");
  const bundlePath = await requireRegularFile(value.bundlePath, "candidate bundle");
  const bundle = await readFile(bundlePath);
  assert.equal(sha256(bundle), value.bundleSha256, "bundle hash differs from descriptor");
  const archive = readStoredZip(bundle);
  assert.deepEqual([...archive.keys()].sort(), expectedReleaseFiles, "candidate bundle inventory is incomplete or contains unexpected files");
  assert.deepEqual(archive.get("release-metadata.json"), metadataBytes, "candidate bundle metadata differs from the installed release");
  assert.deepEqual(archive.get("manifest.json"), manifestBytes, "candidate bundle manifest differs from the installed release");
  for (const name of expectedPayloadNames) {
    assert.deepEqual(archive.get(name), installedPayloads.get(name).bytes, `candidate bundle payload differs from the installed release: ${name}`);
  }
  const configPath = await requireRegularFile(value.configPath, "shared config");
  assert.ok(samePath(configPath, join(installRoot, "config.json")), "candidate.configPath must be the shared config directly under installRoot");
  const configBytes = await readFile(configPath);
  assert.equal(sha256(configBytes), value.configSha256, "shared config hash differs from descriptor");
  const acceptance = descriptorSchemaVersion === 2
    ? await deriveAcceptanceFromConfig(configBytes, value)
    : null;
  const operations = RELEASE_OPERATION_FILES.map(({ target }) => ({
    path: target,
    bytes: installedPayloads.get(target).bytes.byteLength,
    sha256: installedPayloads.get(target).sha256,
  }));
  return { ...value, installRoot, releasePath, runtimePath, bundlePath, bundleBytes: bundle.byteLength, configPath, operations, acceptance };
}

async function deriveAcceptanceFromConfig(configBytes, candidate) {
  let config;
  try { config = JSON.parse(configBytes.toString("utf8")); }
  catch (error) { throw new Error(`shared config is invalid JSON: ${error.message}`); }
  const parsed = RELEASE_CONFIG_SCHEMA.safeParse(config);
  if (!parsed.success) throw new Error(`shared config fails the RC9 release schema mirrored from the runtime config contract: ${parsed.error.issues.map((issue) => `${issue.path.join(".") || "root"}: ${issue.message}`).join("; ")}`);
  config = parsed.data;
  const agents = config.agents ?? {};
  for (const [id, agent] of Object.entries(agents)) {
    if (agent.allowDevelopmentBaseUrl && id !== "manus") throw new Error(`shared config agent ${id}.allowDevelopmentBaseUrl is only valid for Manus`);
    if (agent.acknowledgeAccountDefaultCapabilities !== undefined && id !== "manus") throw new Error(`shared config agent ${id}.acknowledgeAccountDefaultCapabilities is only valid for Manus`);
    if (agent.accountCapabilityProfile !== undefined && id !== "manus") throw new Error(`shared config agent ${id}.accountCapabilityProfile is only valid for Manus`);
    if (id === "manus" && agent.acknowledgeAccountDefaultCapabilities === true && !agent.accountCapabilityProfile) {
      throw new Error("shared config agents.manus.accountCapabilityProfile is required when account-default capabilities are acknowledged");
    }
    if (id === "manus" && agent.baseUrl) validateManusBaseUrl(agent.baseUrl, agent.allowDevelopmentBaseUrl === true);
  }
  const allowedRoots = [];
  for (const [index, root] of config.allowedRoots.entries()) allowedRoots.push(await canonicalConfigDirectory(root, `shared config allowedRoots[${index}]`));
  if (config.defaults?.cwd) {
    const cwd = await canonicalConfigDirectory(config.defaults.cwd, "shared config defaults.cwd");
    assert.ok(allowedRoots.some((root) => isInsideOrEqual(root, cwd)), "shared config defaults.cwd is outside allowedRoots");
  }
  const configuredSandbox = config.defaults?.sandbox ?? "read-only";
  const configuredCeiling = config.policy?.sandboxCeiling ?? "workspace-write";
  assert.ok(SANDBOX_MODES.indexOf(configuredSandbox) <= SANDBOX_MODES.indexOf(configuredCeiling), "shared config defaults.sandbox exceeds policy.sandboxCeiling");
  const enabled = (id, fallback) => agents[id]?.enabled ?? fallback;
  const codexEnabled = enabled("codex", true);
  const claudeEnabled = enabled("claude", true);
  const geminiEnabled = enabled("gemini", false);
  const manusEnabled = enabled("manus", false);
  const unknownEnabledAgents = Object.entries(agents)
    .filter(([id, agent]) => !["codex", "claude", "gemini", "manus"].includes(id) && agent.enabled !== false)
    .map(([id]) => id);
  assert.deepEqual(unknownEnabledAgents, [], `no acceptance profile supports enabled unknown agents: ${unknownEnabledAgents.join(", ")}`);
  assert.equal(codexEnabled, true, "no acceptance profile supports disabled Codex");
  assert.equal(claudeEnabled, true, "no acceptance profile supports disabled Claude");
  assert.equal(geminiEnabled, false, "no acceptance profile supports enabled Gemini");

  const policy = config.policy ?? {};
  const remote = policy.remoteEgress ?? {};
  const directRemoteEgressEnabled = remote.enabled ?? false;
  const allowedAgents = remote.allowedAgents ?? [];
  const uniqueAllowedAgents = [...new Set(allowedAgents)];
  const manusRemoteAllowed = uniqueAllowedAgents.includes("manus");
  const remoteRoots = [];
  for (const [index, root] of (remote.allowedRoots ?? []).entries()) {
    const canonical = await canonicalConfigDirectory(root, `shared config policy.remoteEgress.allowedRoots[${index}]`);
    assert.ok(allowedRoots.some((allowedRoot) => isInsideOrEqual(allowedRoot, canonical)), `shared config remote allowed root ${index} is outside allowedRoots`);
    remoteRoots.push(canonical);
  }
  if (directRemoteEgressEnabled) {
    assert.ok(uniqueAllowedAgents.length > 0, "shared config remote egress requires allowedAgents");
    assert.ok(remoteRoots.length > 0, "shared config remote egress requires allowedRoots");
    assert.ok((remote.allowedDataClasses ?? []).length > 0, "shared config remote egress requires allowedDataClasses");
  }
  const manusAgent = agents.manus ?? {};
  const manusAccountCapabilitiesAcknowledged = manusAgent.acknowledgeAccountDefaultCapabilities === true;
  const manusAccountProfileConfigured = typeof manusAgent.accountCapabilityProfile === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(manusAgent.accountCapabilityProfile);

  let profile;
  if (!manusEnabled && !directRemoteEgressEnabled && uniqueAllowedAgents.length === 0) {
    profile = "windows-local-core";
  } else if (manusEnabled && directRemoteEgressEnabled && manusRemoteAllowed && uniqueAllowedAgents.every((id) => id === "manus")) {
    assert.equal(manusAccountCapabilitiesAcknowledged, true, "Manus profile requires account-default capability acknowledgement");
    assert.equal(manusAccountProfileConfigured, true, "Manus profile requires a valid non-secret account capability profile label");
    profile = "windows-local-manus";
  } else {
    throw new Error("shared config capability state is ambiguous: core requires Manus and remote egress disabled with an empty allowlist; the recognized Manus profile requires both enabled with only Manus allowed");
  }
  const capabilities = {
    codexEnabled,
    claudeEnabled,
    geminiEnabled,
    manusEnabled,
    directRemoteEgressEnabled,
    directRemoteAllowedAgentCount: uniqueAllowedAgents.length,
    manusRemoteAllowed,
    manusAccountCapabilitiesAcknowledged,
    manusAccountProfileConfigured,
  };
  const digestInput = {
    schemaVersion: 1,
    releaseId: candidate.releaseId,
    runtimeSha256: candidate.runtimeSha256,
    configSha256: candidate.configSha256,
    profile,
    capabilities,
  };
  return {
    schemaVersion: 1,
    derivation: "hash-verified-shared-config",
    profile,
    profileInputSha256: sha256(Buffer.from(JSON.stringify(digestInput), "utf8")),
    capabilities,
  };
}

function assertNoContradictoryCapabilityClaims(descriptor, acceptance) {
  const checkIds = new Set(descriptor.checks.map((check) => check.id));
  const knownAgents = new Set(["codex", "claude", "gemini", "manus"]);
  for (const run of descriptor.agentRuns) {
    assert.ok(knownAgents.has(run.agent), `schema-v2 agent run uses an unsupported or non-canonical backend id: ${run.agent}`);
    if (run.outputCheckId !== null) assert.ok(checkIds.has(run.outputCheckId), `agent run ${run.id} references a missing output check: ${run.outputCheckId}`);
  }
  if (!acceptance.capabilities.manusEnabled) {
    const passingManusChecks = descriptor.checks
      .filter((check) => /manus/i.test(check.id) && check.status === "pass")
      .map((check) => check.id);
    assert.deepEqual(passingManusChecks, [], `disabled Manus profile cannot contain passing Manus checks: ${passingManusChecks.join(", ")}`);
    const passingManusRuns = descriptor.agentRuns.filter((run) => run.agent === "manus" && run.status === "pass").map((run) => run.id);
    assert.deepEqual(passingManusRuns, [], `disabled Manus profile cannot contain passing Manus agent runs: ${passingManusRuns.join(", ")}`);
  }
  if (!acceptance.capabilities.geminiEnabled) {
    const passingGeminiChecks = descriptor.checks.filter((check) => /gemini/i.test(check.id) && check.status === "pass").map((check) => check.id);
    assert.deepEqual(passingGeminiChecks, [], `disabled Gemini profile cannot contain passing Gemini checks: ${passingGeminiChecks.join(", ")}`);
    const passingGeminiRuns = descriptor.agentRuns.filter((run) => run.agent === "gemini" && run.status === "pass").map((run) => run.id);
    assert.deepEqual(passingGeminiRuns, [], `disabled Gemini profile cannot contain passing Gemini agent runs: ${passingGeminiRuns.join(", ")}`);
  }
  if (acceptance.profile === "windows-local-core") {
    const passingRemoteChecks = descriptor.checks.filter((check) => check.gate === "remote-service" && check.status === "pass").map((check) => check.id);
    assert.deepEqual(passingRemoteChecks, [], `core profile cannot contain passing remote-service checks: ${passingRemoteChecks.join(", ")}`);
    const passingRemoteRuns = descriptor.agentRuns.filter((run) => run.boundary === "remote-service" && run.status === "pass").map((run) => run.id);
    assert.deepEqual(passingRemoteRuns, [], `core profile cannot contain passing remote-service agent runs: ${passingRemoteRuns.join(", ")}`);
  }
}

async function listReleaseFiles(root, relativeRoot = "") {
  const directory = relativeRoot ? join(root, ...relativeRoot.split("/")) : root;
  const entries = await readdir(directory, { withFileTypes: true });
  assert.ok(entries.length <= 100, `installed release directory contains too many entries: ${relativeRoot || "."}`);
  const files = [];
  for (const entry of entries) {
    assert.ok(entry.name.length > 0 && !entry.name.includes("/") && !entry.name.includes("\\"), "installed release contains an unsafe entry name");
    const relativePath = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
    assertSafeReleaseRelativePath(relativePath, "installed release entry");
    const info = await lstat(join(directory, entry.name));
    assert.ok(!info.isSymbolicLink(), `installed release entry must not be a symbolic link or junction: ${relativePath}`);
    if (info.isDirectory()) files.push(...await listReleaseFiles(root, relativePath));
    else {
      assert.ok(info.isFile(), `installed release entry must be a regular file: ${relativePath}`);
      files.push(relativePath);
    }
    assert.ok(files.length <= 100, "installed release contains too many files");
  }
  return files.sort();
}

function assertSafeReleaseRelativePath(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.ok(value.length > 0 && !value.startsWith("/") && !value.endsWith("/") && !value.includes("\\") && !value.includes(":") && !value.split("/").includes(".."), `${label} is unsafe: ${value}`);
}

async function assertAccepted(descriptor, candidate, evidenceRoot) {
  assert.ok(["accepted", "accepted-with-residual-risks"].includes(descriptor.disposition), "--require-accepted requires an accepted disposition");
  const incomplete = descriptor.checks.filter((check) => check.required && check.status !== "pass");
  assert.deepEqual(incomplete.map((check) => check.id), [], `required checks are incomplete: ${incomplete.map((check) => check.id).join(", ")}`);
  const byId = new Map(descriptor.checks.map((check) => [check.id, check]));
  const acceptanceProfile = descriptor.schemaVersion === 1
    ? LEGACY_ACCEPTANCE_PROFILE
    : ACCEPTANCE_PROFILES[candidate.acceptance.profile];
  for (const [id, gate] of acceptanceProfile) {
    const check = byId.get(id);
    assert.equal(check?.required && check?.status === "pass", true, `accepted evidence requires the passing required check ${id}`);
    assert.equal(check.gate, gate, `accepted evidence requires ${id} to use the ${gate} gate`);
  }
  if (descriptor.schemaVersion === 2 && candidate.acceptance.profile === "windows-local-manus") {
    throw new Error("RC9 cannot accept the windows-local-manus profile until Manus live-canary artifacts are bound to the shared-config profile input");
  }
  const selectedGates = new Set(acceptanceProfile.map(([, gate]) => gate));
  for (const gate of selectedGates) assert.ok(descriptor.checks.some((check) => check.required && check.gate === gate && check.status === "pass"), `accepted evidence requires a passing required ${gate} gate`);
  if (descriptor.schemaVersion === 2) await assertProviderDisabledCanaryEvidence(byId.get("installed-provider-disabled-canary"), candidate, evidenceRoot);
  assert.equal(descriptor.rollback.canaryStatus, "pass", "accepted evidence requires a passing rollback canary");
  assert.equal(candidate.liveAtEnd, candidate.releaseId, "accepted evidence requires candidate.liveAtEnd to equal the candidate release");
  await verifyAcceptedLiveBinding(descriptor.schemaVersion, candidate);
  assert.ok(descriptor.rollback.priorReleaseId && descriptor.rollback.priorRuntimeSha256, "accepted evidence requires a named prior release and runtime hash");
  assert.notEqual(descriptor.rollback.priorReleaseId, candidate.releaseId, "rollback release must differ from the candidate");
  const priorRuntime = await requireRegularFile(join(candidate.installRoot, "releases", descriptor.rollback.priorReleaseId, "server", "agent-bridge.mjs"), "rollback runtime");
  assert.equal(sha256(await readFile(priorRuntime)), descriptor.rollback.priorRuntimeSha256, "rollback runtime hash differs from the descriptor");
  if (descriptor.disposition === "accepted-with-residual-risks") assert.ok(descriptor.residualRisks.length > 0, "accepted-with-residual-risks requires at least one residual risk");
}

async function verifySharedConfigBinding(candidate) {
  const configPath = await requireRegularFile(candidate.configPath, "shared config final verification");
  assert.ok(samePath(configPath, candidate.configPath), "shared config identity changed during evidence export");
  assert.equal(sha256(await readFile(configPath)), candidate.configSha256, "shared config changed during evidence export");
}

async function acquireAcceptedExportCutoverLock(installRoot) {
  const lockPath = join(installRoot, ".agent-bridge-cutover.lock");
  const token = randomUUID().replaceAll("-", "");
  const record = {
    schemaVersion: 1,
    status: "active",
    pid: process.pid,
    token,
    acquiredAt: new Date().toISOString(),
  };
  let handle;
  let complete = false;
  try {
    try { handle = await open(lockPath, "wx", 0o600); }
    catch (error) {
      if (error?.code === "EEXIST") {
        throw new Error(`another Agent Bridge cutover mutation owns the install lock: ${lockPath}; do not delete or reclaim it automatically`);
      }
      throw error;
    }
    await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
    await handle.sync();
    complete = true;
  } finally {
    if (handle) await handle.close().catch(() => {});
    if (handle && !complete) await unlink(lockPath).catch(() => {});
  }
  return { path: lockPath, token, pid: process.pid };
}

async function releaseAcceptedExportCutoverLock(lock) {
  const lockPath = await requireRegularFile(lock.path, "accepted-export cutover lock");
  assert.ok(samePath(lockPath, lock.path), "accepted-export cutover lock identity changed while owned");
  let record;
  try { record = JSON.parse(await readFile(lockPath, "utf8")); }
  catch (error) { throw new Error(`accepted-export cutover lock is unreadable while owned: ${error.message}`); }
  exactObject(record, ["schemaVersion", "status", "pid", "token", "acquiredAt"], "accepted-export cutover lock");
  assert.equal(record.schemaVersion, 1, "accepted-export cutover lock schemaVersion changed while owned");
  assert.equal(record.status, "active", "accepted-export cutover lock status changed while owned");
  assert.equal(record.pid, lock.pid, "accepted-export cutover lock PID changed while owned");
  assert.equal(record.token, lock.token, "accepted-export cutover lock token changed while owned");
  canonicalTimestamp(record.acquiredAt, "accepted-export cutover lock acquiredAt");
  await unlink(lockPath);
}

async function verifyAcceptedLiveBinding(descriptorSchemaVersion, candidate) {
  await verifySharedConfigBinding(candidate);
  const runtimePath = await requireRegularFile(candidate.runtimePath, "candidate runtime final verification");
  assert.ok(samePath(runtimePath, candidate.runtimePath), "candidate runtime identity changed during evidence export");
  assert.equal(sha256(await readFile(runtimePath)), candidate.runtimeSha256, "candidate runtime changed during evidence export");
  const markerPath = await requireRegularFile(join(candidate.installRoot, "current-release.json"), "promotion marker");
  const marker = JSON.parse(await readFile(markerPath, "utf8"));
  const markerKeys = ["schemaVersion", "releaseId", "releasePath", "runtimeSha256", "promotedAt", "backupPath"];
  if (descriptorSchemaVersion === 2) markerKeys.splice(4, 0, "shimSha256", "configSha256");
  exactObject(marker, markerKeys, "promotion marker");
  assert.equal(marker.schemaVersion, 1, "promotion marker schemaVersion must be 1");
  assert.equal(marker.releaseId, candidate.releaseId, "promotion marker does not name the candidate release");
  assert.ok(samePath(await requireDirectory(marker.releasePath, "promotion marker releasePath"), candidate.releasePath), "promotion marker releasePath differs from the candidate");
  assert.equal(marker.runtimeSha256, candidate.runtimeSha256, "promotion marker runtime hash differs from the candidate");
  if (descriptorSchemaVersion === 2) assert.equal(marker.configSha256, candidate.configSha256, "promotion marker config hash differs from the candidate");
  assert.equal(typeof marker.promotedAt, "string", "promotion marker promotedAt must be a timestamp");
  assert.ok(Number.isFinite(Date.parse(marker.promotedAt)) && marker.promotedAt.endsWith("Z"), "promotion marker promotedAt must be a valid UTC timestamp");
  await requireDirectory(marker.backupPath, "promotion marker backupPath");
  const shimPath = await requireRegularFile(join(candidate.installRoot, "agent-bridge.mjs"), "stable shim");
  const shimBytes = await readFile(shimPath);
  if (descriptorSchemaVersion === 2) assert.equal(marker.shimSha256, sha256(shimBytes), "promotion marker shim hash differs from the stable shim");
  const shim = shimBytes.toString("utf8");
  const imports = [...shim.matchAll(/^await import\(new URL\("(\.\/releases\/[^"\r\n]+\/server\/agent-bridge\.mjs)", import\.meta\.url\)\.href\);$/gm)];
  assert.equal(imports.length, 1, "stable shim must contain exactly one recognized release import statement");
  const shimRuntime = resolve(candidate.installRoot, ...imports[0][1].split("/"));
  assert.ok(samePath(await requireRegularFile(shimRuntime, "stable shim runtime"), candidate.runtimePath), "stable shim does not resolve to the candidate runtime");
}

async function assertProviderDisabledCanaryEvidence(check, candidate, evidenceRoot) {
  const records = check.evidence.filter((item) => item.mediaType === "application/json");
  assert.equal(records.length, 1, "installed-provider-disabled-canary requires exactly one structured JSON evidence record");
  const record = records[0];
  const path = await requireRegularFile(record.path, "installed-provider-disabled-canary evidence");
  assert.ok(isInsideOrEqual(evidenceRoot, path), "installed-provider-disabled-canary evidence escapes descriptor.evidenceRoot");
  const bytes = await readFile(path);
  assert.equal(sha256(bytes), record.expectedSha256, "installed-provider-disabled-canary evidence hash differs from the descriptor");
  const evidence = JSON.parse(bytes.toString("utf8"));
  assert.equal(evidence.schemaVersion, 2, "installed-provider-disabled-canary evidence schemaVersion must be 2");
  assert.equal(evidence.status, "pass", "installed-provider-disabled-canary evidence did not pass");
  assert.equal(evidence.version, candidate.version, "installed-provider-disabled-canary version differs from the candidate");
  assert.equal(evidence.runtimeSha256, candidate.runtimeSha256, "installed-provider-disabled-canary runtime hash differs from the candidate");
  assert.ok(samePath(await requireDirectory(evidence.releasePath, "installed-provider-disabled-canary releasePath"), candidate.releasePath), "installed-provider-disabled-canary release path differs from the candidate");
  assert.ok(samePath(await requireRegularFile(evidence.runtimePath, "installed-provider-disabled-canary runtimePath"), candidate.runtimePath), "installed-provider-disabled-canary runtime path differs from the candidate");
  assert.equal(evidence.serverVersion?.version, candidate.version, "installed-provider-disabled-canary MCP version differs from the candidate");
  assert.equal(evidence.entrypoint, "runtime", "installed-provider-disabled-canary must launch the immutable runtime directly");
  assert.equal(evidence.profile, "strict", "installed-provider-disabled-canary must use the strict profile");
  assert.equal(evidence.expectedPromotion, "unpromoted", "installed-provider-disabled-canary must be captured before promotion");
  assert.notEqual(evidence.promotionStatus, "current", "installed-provider-disabled-canary unexpectedly ran after promotion");
  assert.equal(evidence.localPromotion?.current, false, "installed-provider-disabled-canary local promotion state is current");
  assert.equal(evidence.providerCount, 0, "installed-provider-disabled-canary enabled a provider");
  assert.equal(evidence.sessionCount, 0, "installed-provider-disabled-canary created a session");
  assert.equal(evidence.approvalCount, 0, "installed-provider-disabled-canary created an approval");
  assert.deepEqual(evidence.budget, { enabled: false }, "installed-provider-disabled-canary enabled a remote-cost budget");
  assert.deepEqual(evidence.stableFilesAfter, evidence.stableFilesBefore, "installed-provider-disabled-canary changed stable files");
  assert.ok(Array.isArray(evidence.disabledDelegationChecks), "installed-provider-disabled-canary omitted disabled delegation checks");
  const disabled = [...evidence.disabledDelegationChecks].sort((left, right) => String(left.agent).localeCompare(String(right.agent)));
  assert.deepEqual(disabled, [
    { agent: "gemini", rejected: true, sessionCreated: false, adapterResolutionRejected: true },
    { agent: "manus", rejected: true, sessionCreated: false, adapterResolutionRejected: true },
  ], "installed-provider-disabled-canary disabled delegation results are invalid");
}

async function copyEvidenceArtifacts(checks, artifactsDir, redactions, evidenceRoot) {
  const results = [];
  const seenNames = new Set();
  for (const check of checks) {
    for (const evidence of check.evidence) {
      const sourcePath = await requireRegularFile(evidence.path, `evidence ${check.id}/${evidence.id}`);
      assert.ok(isInsideOrEqual(evidenceRoot, sourcePath), `evidence ${check.id}/${evidence.id} escapes descriptor.evidenceRoot`);
      assertShareableEvidencePath(evidenceRoot, sourcePath, "evidence " + check.id + "/" + evidence.id);
      const sourceBytes = await readFile(sourcePath);
      assert.ok(sourceBytes.byteLength <= MAX_TEXT_BYTES, `evidence file exceeds ${MAX_TEXT_BYTES} bytes: ${sourcePath}`);
      assert.ok(!sourceBytes.includes(0), `binary evidence is not allowed: ${sourcePath}`);
      const sourceSha256 = sha256(sourceBytes);
      if (evidence.expectedSha256 !== null) assert.equal(sourceSha256, evidence.expectedSha256, `evidence source hash mismatch: ${check.id}/${evidence.id}`);
      const extension = evidence.mediaType === "application/json" ? ".json" : evidence.mediaType === "text/markdown" ? ".md" : ".txt";
      const name = `${check.id}--${evidence.id}${extension}`;
      assert.ok(!seenNames.has(name), `evidence artifact name collision: ${name}`);
      seenNames.add(name);
      let text = sourceBytes.toString("utf8");
      if (evidence.mediaType === "application/json") {
        const parsed = JSON.parse(text);
        const sanitized = sanitizeJsonValue(parsed, redactions);
        assertNoManusTaskIdInJsonValue(sanitized, "evidence " + check.id + "/" + evidence.id);
        text = `${JSON.stringify(sanitized, null, 2)}\n`;
      } else {
        text = sanitizeText(text, redactions);
        assertNoManusTaskId(text, "evidence " + check.id + "/" + evidence.id);
      }
      const exportedBytes = Buffer.from(text, "utf8");
      const destination = join(artifactsDir, name);
      await writePrivateFile(destination, exportedBytes);
      results.push({
        checkId: check.id,
        evidenceId: evidence.id,
        uri: `artifact://artifacts/${name}`,
        mediaType: evidence.mediaType,
        dataClass: evidence.dataClass,
        sourceSha256,
        sha256: sha256(exportedBytes),
        bytes: exportedBytes.byteLength,
        verification: "hash-verified",
        sanitized: !sourceBytes.equals(exportedBytes),
      });
    }
  }
  return results;
}

function assertShareableEvidencePath(evidenceRoot, sourcePath, label) {
  const segments = relative(evidenceRoot, sourcePath).split(/[\\/]+/).map((segment) => segment.toLowerCase());
  assert.ok(!segments.some((segment) => PRIVATE_EVIDENCE_PATH_SEGMENTS.has(segment)), label + " is private state/session evidence and cannot be exported");
}

function assertNoManusTaskId(text, label) {
  for (const match of text.matchAll(MANUS_TASK_ID)) {
    assert.ok(BENIGN_TASK_ID_SHAPED_TOKENS.has(match[2]), label + " contains a provider-native Manus task ID and cannot be exported");
  }
}

function assertNoManusTaskIdInJsonValue(value, label, depth = 0) {
  assert.ok(depth <= 50, label + " exceeds the maximum nesting depth");
  if (typeof value === "string") {
    assertNoManusTaskId(value, label);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertNoManusTaskIdInJsonValue(item, label, depth + 1);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      assertNoManusTaskId(key, label + " JSON key");
      assertNoManusTaskIdInJsonValue(item, label, depth + 1);
    }
  }
}

async function buildRedactions(configured, candidate) {
  const entries = configured.map((item) => ({ value: resolve(item.path), replacement: item.replacement }));
  entries.push({ value: candidate.installRoot, replacement: "<install-root>" });
  if (process.env.USERPROFILE && isAbsolute(process.env.USERPROFILE)) entries.push({ value: resolve(process.env.USERPROFILE), replacement: "<redacted-user-root>" });
  const unique = new Map();
  for (const entry of entries) unique.set(normalizeForComparison(entry.value), entry);
  return [...unique.values()].sort((left, right) => right.value.length - left.value.length);
}

function sanitizeText(text, redactions) {
  let result = text;
  for (const { value, replacement } of redactions) result = result.replace(new RegExp(escapeRegExp(value), process.platform === "win32" ? "gi" : "g"), replacement);
  result = result
    .replace(/\bsk-[A-Za-z0-9_-]{20,}\b/g, "<redacted-secret>")
    .replace(/(x-manus-api-key\s*[:=]\s*)[^\s,}\"]+/gi, "$1<redacted-secret>")
    .replace(/(authorization\s*[:=]\s*[\"']?bearer\s+)[A-Za-z0-9._~+\/-]{12,}/gi, "$1<redacted-secret>")
    .replace(/([\"']?(?:api[_-]?key|access[_-]?token|password|secret)[\"']?\s*[:=]\s*[\"'])[^\"'\r\n]{8,}([\"'])/gi, "$1<redacted-secret>$2")
    .replace(/\b(?:prompt|transcript)\s*[:=]\s*[^\r\n]{1,2000}/gi, "<redacted-narrative>")
    .replace(/https?:\/\/[^\s)\]>\"']+/gi, "<redacted-url>")
    .replace(/\b[A-Za-z]:\\(?:[^\s<>:"|?*]+\\)*[^\s<>:"|?*]*/g, "<redacted-path>")
    .replace(/(^|[\s([{])\/(?:[^\s<>]+\/)*[^\s<>]*/g, "$1<redacted-path>");
  return result;
}

function sanitizeJsonValue(value, redactions, depth = 0) {
  assert.ok(depth <= 50, "JSON evidence exceeds the maximum nesting depth");
  if (typeof value === "string") return sanitizeText(value, redactions);
  if (Array.isArray(value)) return value.map((item) => sanitizeJsonValue(item, redactions, depth + 1));
  if (value !== null && typeof value === "object") {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      const sanitizedKey = sanitizeText(key, redactions);
      assert.ok(!Object.hasOwn(result, sanitizedKey), `JSON evidence keys collide after sanitization: ${sanitizedKey}`);
      if (item !== null && /(?:api[-_]?key|authorization|credential|password|secret|token)/i.test(key)) {
        result[sanitizedKey] = "<redacted-secret>";
      } else if (item !== null && isNarrativeJsonKey(key)) {
        result[sanitizedKey] = "<redacted-narrative>";
      } else if (item !== null && isProviderNativeIdentifierJsonKey(key)) {
        result[sanitizedKey] = "<redacted-provider-identifier>";
      } else {
        result[sanitizedKey] = sanitizeJsonValue(item, redactions, depth + 1);
      }
    }
    return result;
  }
  return value;
}

function isNarrativeJsonKey(key) {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  if (words.length === 0) return false;
  if (words.length === 1 && JSON_NARRATIVE_VALUE_WORDS.has(words[0]) && words[0] !== "value") return true;
  if (JSON_NARRATIVE_KEY_WORDS.has(words.at(-1))) return true;
  return words.length > 1 && JSON_NARRATIVE_VALUE_WORDS.has(words.at(-1))
    && words.slice(0, -1).some((word) => JSON_NARRATIVE_KEY_WORDS.has(word));
}

function isProviderNativeIdentifierJsonKey(key) {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]+/g, "");
  return /^(?:(?:manus|provider)?native(?:sessions?|tasks?)(?:ids?|identifiers?|refs?)?|(?:manus|provider)(?:sessions?|tasks?)(?:ids?|identifiers?|refs?)|(?:sessions?|threads?|tasks?|events?)(?:ids?|identifiers?|refs?))$/.test(normalized);
}

function buildPacket(descriptor, candidate, artifacts, createdAt) {
  const refsByCheck = new Map();
  for (const artifact of artifacts) {
    const refs = refsByCheck.get(artifact.checkId) ?? [];
    refs.push(Object.fromEntries(Object.entries(artifact).filter(([key]) => key !== "checkId" && key !== "evidenceId")));
    refsByCheck.set(artifact.checkId, refs);
  }
  return {
    schemaVersion: descriptor.schemaVersion,
    packetId: descriptor.packetId,
    createdAt,
    sanitization: {
      performed: true,
      method: descriptor.sanitization.method,
      omittedFields: ["credentials", "environment", "prompts", "transcripts", "raw-provider-details"],
    },
    ...(descriptor.schemaVersion === 2 ? { acceptance: candidate.acceptance } : {}),
    candidate: {
      version: candidate.version,
      gitSha: candidate.gitSha,
      releaseId: candidate.releaseId,
      bundle: { name: basename(candidate.bundlePath), bytes: candidate.bundleBytes, sha256: candidate.bundleSha256 },
      runtimeSha256: candidate.runtimeSha256,
      operations: candidate.operations,
      configSha256: candidate.configSha256,
      liveAtStart: candidate.liveAtStart,
      liveAtEnd: candidate.liveAtEnd,
    },
    checks: descriptor.checks.map((check) => ({
      id: check.id,
      gate: check.gate,
      status: check.status,
      source: check.source,
      required: check.required,
      performedAt: check.performedAt,
      reason: check.reason,
      command: check.command,
      exitCode: check.exitCode,
      evidenceRefs: refsByCheck.get(check.id) ?? [],
    })),
    approvals: descriptor.approvals,
    agentRuns: descriptor.agentRuns,
    recommendations: descriptor.recommendations,
    workboard: descriptor.workboard,
    budget: descriptor.budget,
    residualRisks: descriptor.residualRisks,
    rollback: descriptor.rollback,
    disposition: descriptor.disposition,
  };
}

function renderMarkdown(packet, jsonHash) {
  const rows = packet.checks.map((check) => `| ${markdown(check.id)} | ${check.gate} | ${check.status} | ${check.evidenceRefs.map((ref) => `\`${ref.uri}\``).join(", ") || markdown(check.reason ?? "No artifact")} |`).join("\n");
  const runs = packet.agentRuns.length === 0 ? "No agent-run records were exported." : packet.agentRuns.map((run) => `- **${markdown(run.agent)}:** ${run.status}${run.reason ? ` — ${markdown(run.reason)}` : ""}`).join("\n");
  const risks = packet.residualRisks.length === 0 ? "No residual risks were recorded." : packet.residualRisks.map((risk) => `- **${markdown(risk.id)}:** ${markdown(risk.risk)} (${risk.disposition}; owner: ${markdown(risk.owner)}; review after ${risk.reviewAfter})`).join("\n");
  const operations = packet.candidate.operations.map((operation) => `- \`${operation.path}\`: \`${operation.sha256}\` (${operation.bytes} bytes)`).join("\n");
  const acceptance = packet.acceptance
    ? `\n## Capability-scoped acceptance\n\n| Field | Value |\n| --- | --- |\n| Derived profile | \`${packet.acceptance.profile}\` |\n| Derivation | \`${packet.acceptance.derivation}\` |\n| Profile-input SHA-256 | \`${packet.acceptance.profileInputSha256}\` |\n| Manus | ${packet.acceptance.capabilities.manusEnabled ? "enabled; live Manus gates required" : "disabled; not live-certified"} |\n| Gemini | ${packet.acceptance.capabilities.geminiEnabled ? "enabled" : "disabled; not certified by this profile"} |\n\nThis profile is derived from the hash-verified shared config. It is not selected or waived by the descriptor.\n`
    : "";
  return `# Agent Bridge release evidence\n\n**Packet:** \`${packet.packetId}\`  \n**Disposition:** ${packet.disposition}  \n**Machine record:** \`evidence-report.json\`  \n**Machine-record SHA-256:** \`${jsonHash}\`${acceptance}\n\n## Candidate\n\n| Field | Value |\n| --- | --- |\n| Version | \`${packet.candidate.version}\` |\n| Source commit | \`${packet.candidate.gitSha}\` |\n| Immutable release | \`${packet.candidate.releaseId}\` |\n| Live at start | \`${packet.candidate.liveAtStart ?? "none"}\` |\n| Live at end | \`${packet.candidate.liveAtEnd ?? "none"}\` |\n| Bundle SHA-256 | \`${packet.candidate.bundle.sha256}\` |\n| Runtime SHA-256 | \`${packet.candidate.runtimeSha256}\` |\n| Config SHA-256 | \`${packet.candidate.configSha256}\` |\n\n### Immutable operations\n\n${operations}\n\n## Gate results\n\n| Check | Gate | Status | Evidence or reason |\n| --- | --- | --- | --- |\n${rows}\n\n## Agent runs\n\n${runs}\n\n## Approvals\n\n${packet.approvals.length === 0 ? "No approval records were exported." : packet.approvals.map((approval) => `- \`${approval.id}\`: ${approval.category}, ${approval.state}`).join("\n")}\n\n## Recommendation decisions\n\n${packet.recommendations.length === 0 ? "No recommendation decisions were exported." : packet.recommendations.map((recommendation) => `- **${recommendation.priority} ${markdown(recommendation.title)}:** ${recommendation.decision} — ${markdown(recommendation.reason)}`).join("\n")}\n\n## Workboard\n\n${packet.workboard === null ? "No workboard snapshot was included." : `\`${packet.workboard.id}\` is ${packet.workboard.status} at revision ${packet.workboard.revision}.`}\n\n## Budget\n\n${packet.budget.enabled ? `USD reserved ceiling: ${packet.budget.maxReservedCents} cents; committed reservations: ${packet.budget.reservedCents} cents.` : "The cumulative remote-cost breaker was disabled for this snapshot."}\n\n## Residual risks\n\n${risks}\n\n## Rollback\n\nPrior release: \`${packet.rollback.priorReleaseId ?? "not-recorded"}\`; rollback canary: **${packet.rollback.canaryStatus}**; backup: ${markdown(packet.rollback.backupRef ?? "not-recorded")}.\n\n## Redaction statement\n\n${markdown(packet.sanitization.method)} Bounded pattern and path redaction is not semantic DLP; operator inspection is required before sharing. Artifact hashes and byte counts are recorded in \`manifest.json\`.\n`;
}

async function validateNewOutputDirectory(output, installRoot, evidenceRoot) {
  assert.ok(!existsSync(output), `refusing to overwrite existing output directory: ${output}`);
  const canonicalParent = await requireDirectory(dirname(output), "output directory parent");
  const prospective = resolve(canonicalParent, basename(output));
  assert.ok(!isInsideOrEqual(installRoot, prospective), "--output-dir must be outside the Agent Bridge install root and immutable releases");
  assert.ok(isInsideOrEqual(evidenceRoot, prospective), "--output-dir must be contained by descriptor.evidenceRoot");
  const parentInfo = await lstat(canonicalParent);
  assert.ok(!parentInfo.isSymbolicLink(), "output directory parent must not be a symbolic link or junction");
}

async function requireRegularFile(value, label) {
  const path = requiredAbsolutePath(value, label);
  assert.ok(existsSync(path), `${label} does not exist: ${path}`);
  const info = await lstat(path);
  assert.ok(info.isFile() && !info.isSymbolicLink(), `${label} must be a regular non-link file: ${path}`);
  return realpath(path);
}

async function requireDirectory(value, label) {
  const path = requiredAbsolutePath(value, label);
  assert.ok(existsSync(path), `${label} does not exist: ${path}`);
  const info = await lstat(path);
  assert.ok(info.isDirectory() && !info.isSymbolicLink(), `${label} must be a non-link directory: ${path}`);
  const canonical = await realpath(path);
  assert.ok((await stat(canonical)).isDirectory(), `${label} is not a directory: ${canonical}`);
  return canonical;
}

async function writePrivateFile(path, bytes) {
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  if (process.platform !== "win32") await chmod(path, 0o600);
}

async function syncDirectory(path) {
  try {
    const handle = await open(path, "r");
    try { await handle.sync(); } finally { await handle.close(); }
  } catch (error) {
    if (process.platform !== "win32" || !["EACCES", "EPERM", "EINVAL", "EBADF"].includes(error?.code)) throw error;
  }
}

function exactObject(value, keys, label) {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label} has missing or unknown fields`);
}
async function canonicalConfigDirectory(value, label) {
  const expanded = value === "~"
    ? homedir()
    : value.startsWith(`~${sep}`) || value.startsWith("~/") || value.startsWith("~\\")
      ? join(homedir(), value.slice(2))
      : value;
  return requireDirectory(resolve(expanded), label);
}
function validateManusBaseUrl(value, allowDevelopmentBaseUrl) {
  const url = new URL(value);
  assert.ok(!url.username && !url.password, "shared config Manus baseUrl must not contain credentials");
  assert.ok(!url.search && !url.hash, "shared config Manus baseUrl must not contain a query or fragment");
  if (allowDevelopmentBaseUrl) {
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    assert.ok(["localhost", "127.0.0.1", "::1"].includes(hostname) && ["http:", "https:"].includes(url.protocol), "shared config development Manus baseUrl must be an HTTP(S) loopback endpoint");
    return;
  }
  const hostname = url.hostname.toLowerCase();
  assert.ok(url.protocol === "https:" && (hostname === "api.manus.ai" || hostname.endsWith(".api.manus.ai")) && !url.port && ["", "/"].includes(url.pathname), "shared config Manus baseUrl must be the HTTPS api.manus.ai endpoint or subdomain");
}
function validateAcceptanceReport(value, candidate) {
  exactObject(value, ["schemaVersion", "derivation", "profile", "profileInputSha256", "capabilities"], "evidence report acceptance");
  assert.equal(value.schemaVersion, 1, "evidence report acceptance schemaVersion must be 1");
  assert.equal(value.derivation, "hash-verified-shared-config", "evidence report acceptance derivation is unsupported");
  assert.ok(Object.hasOwn(ACCEPTANCE_PROFILES, value.profile), "evidence report acceptance profile is unsupported");
  assert.match(value.profileInputSha256, SHA256, "evidence report acceptance profileInputSha256 is invalid");
  exactObject(value.capabilities, [
    "codexEnabled", "claudeEnabled", "geminiEnabled", "manusEnabled", "directRemoteEgressEnabled",
    "directRemoteAllowedAgentCount", "manusRemoteAllowed", "manusAccountCapabilitiesAcknowledged", "manusAccountProfileConfigured",
  ], "evidence report acceptance capabilities");
  for (const key of [
    "codexEnabled", "claudeEnabled", "geminiEnabled", "manusEnabled", "directRemoteEgressEnabled",
    "manusRemoteAllowed", "manusAccountCapabilitiesAcknowledged", "manusAccountProfileConfigured",
  ]) assert.equal(typeof value.capabilities[key], "boolean", `evidence report acceptance capabilities.${key} must be boolean`);
  assert.ok(Number.isSafeInteger(value.capabilities.directRemoteAllowedAgentCount) && value.capabilities.directRemoteAllowedAgentCount >= 0 && value.capabilities.directRemoteAllowedAgentCount <= 32, "evidence report acceptance capabilities.directRemoteAllowedAgentCount is invalid");
  assert.equal(value.capabilities.codexEnabled, true, "evidence report acceptance requires Codex enabled");
  assert.equal(value.capabilities.claudeEnabled, true, "evidence report acceptance requires Claude enabled");
  assert.equal(value.capabilities.geminiEnabled, false, "evidence report acceptance does not support Gemini enabled");
  const derivedProfile = !value.capabilities.manusEnabled && !value.capabilities.directRemoteEgressEnabled
      && value.capabilities.directRemoteAllowedAgentCount === 0 && !value.capabilities.manusRemoteAllowed
    ? "windows-local-core"
    : value.capabilities.manusEnabled && value.capabilities.directRemoteEgressEnabled && value.capabilities.manusRemoteAllowed
      && value.capabilities.directRemoteAllowedAgentCount === 1
      && value.capabilities.manusAccountCapabilitiesAcknowledged && value.capabilities.manusAccountProfileConfigured
      ? "windows-local-manus"
      : null;
  assert.equal(value.profile, derivedProfile, "evidence report acceptance profile differs from its capability projection");
  const digestInput = {
    schemaVersion: 1,
    releaseId: candidate.releaseId,
    runtimeSha256: candidate.runtimeSha256,
    configSha256: candidate.configSha256,
    profile: value.profile,
    capabilities: value.capabilities,
  };
  assert.equal(value.profileInputSha256, sha256(Buffer.from(JSON.stringify(digestInput), "utf8")), "evidence report acceptance profile-input digest differs");
}

function assertUnique(value, key, label, maximum, validator) {
  assert.ok(Array.isArray(value) && value.length <= maximum, `${label} must be an array of at most ${maximum} items`);
  const ids = new Set();
  value.forEach((item, index) => {
    validator(item, index);
    assert.ok(!ids.has(item[key]), `duplicate ${label} ${key}: ${item[key]}`);
    ids.add(item[key]);
  });
}

function safeId(value, label) { assert.match(value, SAFE_ID, `${label} is invalid`); }
function nullableSafeId(value, label) { if (value !== null) safeId(value, label); }
function boundedString(value, label, minimum, maximum) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.ok(value.length >= minimum && value.length <= maximum, `${label} must contain ${minimum}-${maximum} characters`);
  assert.ok(!/[\0\u0001-\u0008\u000b\u000c\u000e-\u001f]/.test(value), `${label} contains control characters`);
}
function nullableBoundedString(value, label, maximum) { if (value !== null) boundedString(value, label, 1, maximum); }
function canonicalTimestamp(value, label) {
  assert.equal(typeof value, "string", `${label} must be a timestamp`);
  assert.match(value, UTC_ISO, `${label} must be a UTC ISO 8601 timestamp with milliseconds`);
  assert.equal(new Date(value).toISOString(), value, `${label} is not a canonical timestamp`);
}
function requiredAbsolutePath(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.ok(isAbsolute(value), `${label} must be an absolute path`);
  return resolve(value);
}
function samePath(left, right) { return normalizeForComparison(left) === normalizeForComparison(right); }
function normalizeForComparison(value) { const normalized = resolve(value); return process.platform === "win32" ? normalized.toLowerCase() : normalized; }
function isInsideOrEqual(parent, child) { const value = relative(parent, child); return value === "" || (!value.startsWith("..") && !isAbsolute(value)); }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function escapeRegExp(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function markdown(value) {
  return String(value)
    .replace(/[\r\n]+/g, " ")
    .replace(/([\\`*_[\]{}()<>#+.!|\-])/g, "\\$1");
}

function readStoredZip(archive) {
  const minimumEnd = Math.max(0, archive.length - 65_557);
  let end = -1;
  for (let cursor = archive.length - 22; cursor >= minimumEnd; cursor -= 1) {
    if (archive.readUInt32LE(cursor) === 0x06054b50) { end = cursor; break; }
  }
  assert.ok(end >= 0 && end + 22 <= archive.length, "candidate bundle has no valid ZIP end record");
  const disk = archive.readUInt16LE(end + 4);
  const centralDisk = archive.readUInt16LE(end + 6);
  const diskCount = archive.readUInt16LE(end + 8);
  const count = archive.readUInt16LE(end + 10);
  const centralSize = archive.readUInt32LE(end + 12);
  const centralOffset = archive.readUInt32LE(end + 16);
  const commentLength = archive.readUInt16LE(end + 20);
  assert.equal(end + 22 + commentLength, archive.length, "candidate bundle has trailing or malformed ZIP data");
  assert.equal(disk, 0, "multi-disk ZIP bundles are not supported");
  assert.equal(centralDisk, 0, "multi-disk ZIP bundles are not supported");
  assert.equal(diskCount, count, "candidate bundle ZIP entry counts disagree");
  assert.ok(count > 0 && count <= 100, "candidate bundle ZIP entry count is invalid");
  assert.equal(centralOffset + centralSize, end, "candidate bundle ZIP central directory bounds are invalid");
  const contents = new Map();
  let cursor = centralOffset;
  for (let index = 0; index < count; index += 1) {
    assert.ok(cursor + 46 <= end && archive.readUInt32LE(cursor) === 0x02014b50, "candidate bundle has a malformed central entry");
    const flags = archive.readUInt16LE(cursor + 8);
    const method = archive.readUInt16LE(cursor + 10);
    const compressedSize = archive.readUInt32LE(cursor + 20);
    const size = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const entryCommentLength = archive.readUInt16LE(cursor + 32);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const next = cursor + 46 + nameLength + extraLength + entryCommentLength;
    assert.ok(next <= end, "candidate bundle central entry exceeds its directory");
    const name = archive.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    assert.ok(name.length > 0 && !name.startsWith("/") && !name.includes("\\") && !name.includes(":") && !name.split("/").includes(".."), `candidate bundle has an unsafe entry name: ${name}`);
    assert.equal(flags & 1, 0, `candidate bundle entry is encrypted: ${name}`);
    assert.equal(method, 0, `candidate bundle entry is compressed with an unsupported method: ${name}`);
    assert.equal(compressedSize, size, `candidate bundle stored entry sizes disagree: ${name}`);
    assert.ok(size <= 20 * 1024 * 1024, `candidate bundle entry is too large: ${name}`);
    assert.ok(localOffset + 30 <= centralOffset && archive.readUInt32LE(localOffset) === 0x04034b50, `candidate bundle local entry is malformed: ${name}`);
    const localFlags = archive.readUInt16LE(localOffset + 6);
    const localMethod = archive.readUInt16LE(localOffset + 8);
    const localNameLength = archive.readUInt16LE(localOffset + 26);
    const localExtraLength = archive.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    assert.equal(localFlags, flags, `candidate bundle local flags differ: ${name}`);
    assert.equal(localMethod, method, `candidate bundle local method differs: ${name}`);
    assert.ok(dataStart + size <= centralOffset, `candidate bundle entry data exceeds local region: ${name}`);
    assert.equal(archive.subarray(localOffset + 30, localOffset + 30 + localNameLength).toString("utf8"), name, `candidate bundle local name differs: ${name}`);
    const key = name.toLowerCase();
    assert.ok(!contents.has(key), `candidate bundle has a duplicate case-insensitive entry: ${name}`);
    contents.set(key, archive.subarray(dataStart, dataStart + size));
    cursor = next;
  }
  assert.equal(cursor, end, "candidate bundle central directory has unparsed bytes");
  return contents;
}

function parseArgs(values) {
  const result = { requireAccepted: false };
  for (let index = 0; index < values.length; index += 1) {
    const flag = values[index];
    if (flag === "--require-accepted") {
      assert.equal(result.requireAccepted, false, "duplicate --require-accepted");
      result.requireAccepted = true;
      continue;
    }
    assert.ok(["--descriptor", "--output-dir"].includes(flag), `unknown argument: ${flag ?? "(end)"}`);
    const value = values[index + 1];
    assert.ok(value !== undefined && !value.startsWith("--"), `missing value for ${flag}`);
    const key = flag === "--descriptor" ? "descriptorPath" : "outputDir";
    assert.equal(result[key], undefined, `duplicate ${flag}`);
    result[key] = value;
    index += 1;
  }
  assert.ok(result.descriptorPath, "--descriptor is required");
  assert.ok(result.outputDir, "--output-dir is required");
  return result;
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  exportReleaseEvidence(parseArgs(process.argv.slice(2)))
    .then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
    .catch((error) => {
      process.stderr.write(`evidence export failed: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
}
