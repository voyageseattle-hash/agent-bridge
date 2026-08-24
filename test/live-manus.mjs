import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { mkdir, readFile, readdir, realpath, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { emitLiveResult, failLive, resolveLiveServer } from "./live-support.mjs";

const TICKET_FILE = "pending-ticket.json";
const CONSUMED_TICKET_FILE = "consumed-ticket.json";
const PREVIEW_RESULT_FILE = "preview-result.json";
const CONSUMPTION_FILE = "ticket-consumption.json";
const RESULT_FILE = "result.json";
const CONFIG_FILE = "config.json";
const DATA_CLASSIFICATION = "public";
const TICKET_LIFETIME_MS = 15 * 60 * 1_000;
const PROMPT_TEMPLATE_VERSION = 1;
const PROVIDER_ENDPOINT = "https://api.manus.ai";
const PROVIDER_CAPABILITY_POLICY = "manus-v2-empty-connectors-default-skills-v1";
const PROVIDER_ACCOUNT_PROFILE = "live-canary-account-defaults-acknowledged-v1";

async function main() {
  const evidenceArg = argumentValue("--evidence-dir");
  if (!evidenceArg || !isAbsolute(evidenceArg)) throw new Error("--evidence-dir must be a new absolute directory");
  rejectUnknownArguments();
  if (process.argv.includes("--execute")) await executeTicket(evidenceArg, argumentValue("--confirm-ticket-sha256"));
  else await previewTicket(evidenceArg);
}

async function previewTicket(evidenceArg) {
  if (existsSync(evidenceArg)) throw new Error("preview evidence directory already exists; use a new absolute directory");
  // These are local-only preflights. Do them before claiming the durable
  // evidence directory so a missing local prerequisite leaves no partial run.
  const identity = await resolveLiveServer();
  const credentialFile = await resolveCredentialFile();
  const model = parseModel(process.env.AGENT_BRIDGE_MANUS_MODEL ?? "manus-1.6-lite");
  const timeoutSec = parseTimeout(process.env.AGENT_BRIDGE_MANUS_TIMEOUT_SEC ?? "180");
  const maxCostUsd = parseCost(process.env.AGENT_BRIDGE_MANUS_MAX_COST_USD ?? "0.50");
  await mkdir(evidenceArg, { recursive: false, mode: 0o700 });
  const evidenceDir = await realpath(evidenceArg);
  const workDir = join(evidenceDir, "work");
  const stateDir = join(evidenceDir, "state");
  await mkdir(workDir, { mode: 0o700 });
  await mkdir(stateDir, { mode: 0o700 });

  // This resolves only local files and hashes. Preview deliberately does not
  // start the bridge, probe Manus health, or make any provider request.
  const nonce = randomBytes(32).toString("hex");
  const expectedReply = `LIVE_MANUS_FRESH_OK_${nonce}`;
  const prompt = promptFor(expectedReply);
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.parse(createdAt) + TICKET_LIFETIME_MS).toISOString();
  const paths = evidencePaths(evidenceDir);
  const binding = {
    schemaVersion: 1,
    promptTemplateVersion: PROMPT_TEMPLATE_VERSION,
    nonce,
    expectedReply,
    promptSha256: sha256(prompt),
    model,
    timeoutSec,
    dataClassification: DATA_CLASSIFICATION,
    providerEndpoint: PROVIDER_ENDPOINT,
    providerCapabilityPolicy: PROVIDER_CAPABILITY_POLICY,
    providerAccountProfile: PROVIDER_ACCOUNT_PROFILE,
    maximumApprovedCostUsd: maxCostUsd,
    maximumReservedCents: Math.round(maxCostUsd * 100),
    credentialFile,
    runtime: runtimeBinding(identity),
    evidence: paths,
    createdAt,
    expiresAt,
  };
  const confirmationSha256 = confirmationDigestForBinding(binding);
  const ticket = { schemaVersion: 1, state: "pending", confirmationSha256, binding };
  validateTicket(ticket, paths);
  await writeJsonExclusive(paths.pendingTicketPath, ticket);

  const preview = {
    schemaVersion: 1,
    backend: "manus",
    status: "preview",
    at: createdAt,
    confirmationSha256,
    expectedReplySha256: sha256(expectedReply),
    promptSha256: binding.promptSha256,
    model,
    timeoutSec,
    dataClassification: DATA_CLASSIFICATION,
    providerEndpoint: binding.providerEndpoint,
    providerCapabilityPolicy: binding.providerCapabilityPolicy,
    providerAccountProfile: binding.providerAccountProfile,
    maximumApprovedCostUsd: maxCostUsd,
    maximumReservedCents: binding.maximumReservedCents,
    runtime: binding.runtime,
    evidenceDir,
    pendingTicketPath: paths.pendingTicketPath,
    expiresAt,
    providerContacted: false,
    next: `node test/live-manus.mjs --execute --evidence-dir ${JSON.stringify(evidenceDir)} --confirm-ticket-sha256 ${confirmationSha256}`,
  };
  await writeJsonExclusive(paths.previewResultPath, preview);
  emitLiveResult("manus", "preview", preview);
}

async function executeTicket(evidenceArg, confirmation) {
  if (!confirmation || !/^[a-f0-9]{64}$/.test(confirmation)) {
    throw new Error("--confirm-ticket-sha256 must be the exact digest from this ticket's preview");
  }
  const evidenceDir = await realpath(evidenceArg);
  const paths = evidencePaths(evidenceDir);
  if (existsSync(paths.consumedTicketPath)) throw new Error("Manus live ticket was already consumed; create a new preview");
  const ticket = JSON.parse(await readFile(paths.pendingTicketPath, "utf8"));
  validateTicket(ticket, paths);
  assert.equal(ticket.confirmationSha256, confirmation, "ticket confirmation digest mismatch");
  assert.equal(confirmationDigestForBinding(ticket.binding), confirmation, "ticket binding was modified after preview");
  if (Date.parse(ticket.binding.expiresAt) <= Date.now()) throw new Error("Manus live ticket expired; create a new preview");

  const identity = await resolveLiveServer();
  assert.deepEqual(runtimeBinding(identity), ticket.binding.runtime, "runtime identity changed after preview");
  const credentialFile = await realpath(ticket.binding.credentialFile);
  assert.equal(credentialFile, ticket.binding.credentialFile, "credential file identity changed after preview");
  assert.equal(statSync(credentialFile).isFile(), true, "configured Manus credential is not a regular file");

  // Rename is the one-way authorization boundary. It occurs before starting
  // the bridge, requesting approvals, probing Manus, or creating a paid task.
  await consumePendingTicket(paths, confirmation);
  await writeJsonExclusive(paths.consumptionPath, {
    schemaVersion: 1,
    status: "consumed",
    confirmationSha256: confirmation,
    consumedAt: new Date().toISOString(),
    runtime: ticket.binding.runtime,
  });

  try {
    const result = await runConsumedTicket(ticket, identity, paths);
    await writeJsonExclusive(paths.resultPath, result);
    emitLiveResult("manus", "pass", result);
  } catch (error) {
    const failure = {
      schemaVersion: 1,
      backend: "manus",
      status: "fail",
      at: new Date().toISOString(),
      confirmationSha256: confirmation,
      runtime: ticket.binding.runtime,
      evidenceDir,
      error: safeMessage(error),
    };
    await writeJsonExclusive(paths.resultPath, failure).catch(() => {});
    throw error;
  }
}

async function runConsumedTicket(ticket, identity, paths) {
  const binding = ticket.binding;
  const prompt = promptFor(binding.expectedReply);
  assert.equal(sha256(prompt), binding.promptSha256, "ticket prompt identity is invalid");
  const config = {
    agents: {
      codex: { enabled: false }, claude: { enabled: false }, gemini: { enabled: false },
      manus: {
        enabled: true,
        credentialFile: binding.credentialFile,
        defaultModel: binding.model,
        sandboxCeiling: "read-only",
        acknowledgeAccountDefaultCapabilities: true,
        accountCapabilityProfile: binding.providerAccountProfile,
        baseUrl: binding.providerEndpoint,
      },
    },
    defaults: { cwd: paths.workDir, sandbox: "read-only", timeoutSec: binding.timeoutSec },
    allowedRoots: [paths.workDir],
    stateDir: paths.stateDir,
    policy: {
      sandboxCeiling: "read-only",
      remoteEgress: { enabled: true, allowedAgents: ["manus"], allowedRoots: [paths.workDir], allowedDataClasses: [binding.dataClassification] },
      cumulativeRemoteCost: { currency: "USD", maxReservedCents: binding.maximumReservedCents },
    },
  };
  await writeJsonExclusive(paths.configPath, config);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [identity.path],
    env: { ...scrubManusEnvironment(process.env), AGENT_BRIDGE_CONFIG: paths.configPath },
  });
  const client = new Client({ name: "agent-bridge-live-manus", version: "1.0.0" }, { capabilities: { elicitation: { form: {} } } });
  let expectedElicitation;
  client.setRequestHandler(ElicitRequestSchema, async (request) => {
    assert.ok(expectedElicitation, "unexpected approval elicitation");
    const approvalId = approvalIdFromMessage(request.params.message);
    assert.equal(approvalId, expectedElicitation.record.id, "elicitation named an unexpected approval id");
    assertApprovalRecord(expectedElicitation.record, expectedElicitation.spec, "elicitation");
    assertElicitationMessage(request.params.message, expectedElicitation.record, expectedElicitation.spec);
    expectedElicitation.seen += 1;
    return { action: "accept", content: { approvalId, approve: true } };
  });

  try {
    await client.connect(transport);
    const diagnostics = await client.callTool({ name: "diagnose_install", arguments: {} });
    assert.notEqual(diagnostics.isError, true, "diagnose_install failed before live delegation");
    const runtime = diagnostics.structuredContent?.diagnostics?.runtime;
    assert.equal(await realpath(runtime?.path), identity.path, "live test connected to an unexpected runtime path");
    assert.equal(runtime?.sha256, identity.expectedSha256, "live runtime hash differs from preview");
    if (identity.expectedVersion) assert.equal(runtime?.version, identity.expectedVersion, "live runtime version differs from preview");

    // The first provider access is after the durable ticket has been consumed.
    const health = await client.callTool({ name: "list_agents", arguments: {} });
    const agent = health.structuredContent?.agents?.find((entry) => entry.id === "manus");
    assert.ok(agent, "list_agents omitted Manus");
    assert.equal(agent.health?.auth?.status, "authenticated", "Manus API key was not accepted");

    const preview = await client.callTool({ name: "preview_turn_approval", arguments: {
      agent: "manus", prompt, cwd: paths.workDir, model: binding.model, sandbox: "read-only",
      timeout_sec: binding.timeoutSec, allow_remote_egress: true, data_classification: binding.dataClassification,
    } });
    assert.notEqual(preview.isError, true, "Manus canary approval preview failed");
    const scope = preview.structuredContent?.approval_scope;
    assert.equal(preview.structuredContent?.prompt_sha256, binding.promptSha256, "bridge preview changed the bound prompt digest");
    assert.match(preview.structuredContent?.payload_sha256 ?? "", /^[a-f0-9]{64}$/, "bridge preview omitted the approval-envelope digest");
    const executionEnvelope = preview.structuredContent?.execution_envelope;
    assert.deepEqual(executionEnvelope, {
      schemaVersion: 2,
      model: binding.model,
      sandbox: "read-only",
      timeoutMs: binding.timeoutSec * 1_000,
      continuity: "new",
      contextDeltaApplied: false,
      forceFresh: false,
      nativeResume: false,
      bridgeSessionId: null,
      sessionRevision: null,
      allowAgentConfigExtensions: true,
      providerCapabilityPolicy: binding.providerCapabilityPolicy,
      providerEndpoint: binding.providerEndpoint,
      providerAccountProfile: binding.providerAccountProfile,
      promptSha256: binding.promptSha256,
    }, "bridge preview returned an unexpected execution envelope");
    assert.deepEqual(scope, {
      subject: "agent-bridge:delegate_task",
      action: "delegate:manus",
      dataClass: binding.dataClassification,
      root: paths.workDir,
      agent: "manus",
      payloadSha256: preview.structuredContent?.payload_sha256,
    }, "bridge preview returned an unexpected approval scope");

    const egressSpec = approvalSpec("remote_egress", scope, null);
    const egress = await createAndApprove(client, egressSpec, (value) => { expectedElicitation = value; });
    const costSpec = approvalSpec("paid_or_unknown_cost", scope, binding.maximumApprovedCostUsd);
    const cost = await createAndApprove(client, costSpec, (value) => { expectedElicitation = value; });
    expectedElicitation = undefined;

    const before = await budgetStatus(client);
    const delegated = await client.callTool({ name: "delegate_task", arguments: {
      agent: "manus", prompt, cwd: paths.workDir, model: binding.model, sandbox: "read-only", timeout_sec: binding.timeoutSec,
      allow_remote_egress: true, data_classification: binding.dataClassification, approval_ids: [egress.id, cost.id],
      estimated_cost: binding.maximumApprovedCostUsd, estimated_currency: "USD",
    } });
    const after = await budgetStatus(client);
    assert.notEqual(delegated.isError, true, "Manus canary delegation failed");
    assert.equal((delegated.structuredContent?.output ?? "").trim(), binding.expectedReply, "Manus did not return the exact nonce-bound canary response");
    const taskStatus = delegated.structuredContent?.meta?.taskStatus ?? "stopped";
    assert.equal(taskStatus, "stopped", "Manus task did not reach stopped status");
    assert.equal(after.committedCents - before.committedCents, binding.maximumReservedCents, "approved-cost reservation delta is incorrect");
    assert.equal(after.remainingCents, before.remainingCents - binding.maximumReservedCents, "remaining budget delta is incorrect");

    const correlation = delegated.structuredContent?.meta?.providerRequestSha256;
    assert.match(correlation ?? "", /^[a-f0-9]{64}$/, "Manus result omitted a sanitized provider request correlation");
    const approvals = await listExactApprovals(client, [egressSpec, costSpec], [egress.id, cost.id]);
    assert.equal((await readdir(paths.workDir)).length, 0, "Manus canary changed the retained workspace");

    return {
      schemaVersion: 1,
      backend: "manus",
      status: "pass",
      at: new Date().toISOString(),
      confirmationSha256: ticket.confirmationSha256,
      expectedReplySha256: sha256(binding.expectedReply),
      taskStatus,
      providerRequestSha256: correlation,
      providerErrorRequestSha256: delegated.structuredContent?.meta?.providerErrorRequestSha256,
      budgetBefore: before,
      budgetAfter: after,
      approvalRecords: approvals,
      executionEnvelope,
      version: runtime.version,
      runtimeSha256: runtime.sha256,
      runtimePath: identity.path,
      releaseId: identity.releaseId,
      releaseMode: identity.releaseMode,
      evidenceDir: paths.evidenceDir,
      retained: { configPath: paths.configPath, stateDir: paths.stateDir, workDir: paths.workDir, consumedTicketPath: paths.consumedTicketPath },
    };
  } finally {
    await client.close().catch(() => {});
  }
}

async function createAndApprove(client, spec, setExpected) {
  const requested = await client.callTool({ name: "request_approval", arguments: {
    category: spec.category,
    subject: spec.scope.subject,
    action: spec.scope.action,
    data_classification: spec.scope.dataClass,
    root: spec.scope.root,
    agent: spec.scope.agent,
    payload_sha256: spec.scope.payloadSha256,
    requested_by: "live-manus-harness",
    reason: "Exact nonce-bound public, read-only Agent Bridge Manus connection canary",
    expires_in_sec: 300,
    consume_once: true,
    ...(spec.estimatedCost === null ? {} : { estimated_cost: spec.estimatedCost, currency: "USD" }),
  } });
  assert.notEqual(requested.isError, true, `${spec.category} approval request failed`);
  const record = requested.structuredContent?.approval;
  assertApprovalRecord(record, spec, "requested");
  const expected = { record, spec, seen: 0 };
  setExpected(expected);
  const decided = await client.callTool({ name: "decide_approval", arguments: { approval_id: record.id } });
  assert.equal(expected.seen, 1, `${spec.category} did not receive exactly one verified elicitation`);
  assert.notEqual(decided.isError, true, `${spec.category} approval decision failed`);
  const approved = decided.structuredContent?.approval;
  assertApprovalRecord(approved, spec, "approved");
  assert.equal(approved.state, "approved", `${spec.category} approval was not accepted`);
  return approved;
}

async function listExactApprovals(client, specs, ids) {
  const listed = await client.callTool({ name: "list_approvals", arguments: { subject: "agent-bridge:delegate_task", agent: "manus", limit: 10 } });
  assert.notEqual(listed.isError, true, "approval audit listing failed");
  return ids.map((id, index) => {
    const record = listed.structuredContent?.approvals?.find((candidate) => candidate.id === id);
    assertApprovalRecord(record, specs[index], "consumed");
    assert.equal(record.state, "consumed", `${specs[index].category} approval was not consumed`);
    assert.equal(record.useCount, 1, `${specs[index].category} approval use count is incorrect`);
    return record;
  });
}

function approvalSpec(category, scope, estimatedCost) {
  return { category, scope, estimatedCost, currency: estimatedCost === null ? null : "USD" };
}

function assertApprovalRecord(record, spec, phase) {
  assert.ok(record, `${phase} ${spec.category} approval record is absent`);
  assert.match(record.id ?? "", /^[A-Za-z0-9_-]+$/, `${phase} approval id is invalid`);
  assert.equal(record.category, spec.category, `${phase} approval category changed`);
  assert.deepEqual(record.scope, spec.scope, `${phase} approval scope changed`);
  assert.equal(record.estimatedCost, spec.estimatedCost, `${phase} approval cost changed`);
  assert.equal(record.currency, spec.currency, `${phase} approval currency changed`);
  assert.equal(record.consumeOnce, true, `${phase} approval is not one-time`);
  assert.equal(record.maxUses, 1, `${phase} approval maxUses changed`);
  const expectedState = phase === "consumed" ? "consumed" : phase === "approved" ? "approved" : "pending";
  assert.equal(record.state, expectedState, `${phase} approval state changed`);
  assert.equal(record.useCount, phase === "consumed" ? 1 : 0, `${phase} approval use count changed`);
}

function assertElicitationMessage(message, record, spec) {
  for (const expected of [
    `Approval ID: ${JSON.stringify(record.id)}`,
    `Category: ${JSON.stringify(spec.category)}`,
    `  subject: ${JSON.stringify(spec.scope.subject)}`,
    `  action: ${JSON.stringify(spec.scope.action)}`,
    `  dataClass: ${JSON.stringify(spec.scope.dataClass)}`,
    `  root: ${JSON.stringify(spec.scope.root)}`,
    `  agent: ${JSON.stringify(spec.scope.agent)}`,
    `  payloadSha256: ${JSON.stringify(spec.scope.payloadSha256)}`,
    `Cost: ${spec.estimatedCost === null ? "not specified" : `${spec.estimatedCost} ${spec.currency}`}`,
    "Use count: 0/1 (one-time)",
  ]) assert.ok(message.includes(expected), `elicitation omitted or changed: ${expected}`);
}

async function budgetStatus(client) {
  const result = await client.callTool({ name: "get_budget_status", arguments: {} });
  assert.notEqual(result.isError, true, "budget status failed");
  return result.structuredContent?.budget;
}

export async function createPendingTicket(root, input) {
  if (!isAbsolute(root)) throw new Error("ticket root must be absolute");
  if (existsSync(root)) throw new Error("ticket root already exists");
  await mkdir(root, { recursive: false, mode: 0o700 });
  const evidenceDir = await realpath(root);
  await mkdir(join(evidenceDir, "work"), { mode: 0o700 });
  await mkdir(join(evidenceDir, "state"), { mode: 0o700 });
  const paths = evidencePaths(evidenceDir);
  const binding = structuredClone(input.binding);
  binding.evidence = paths;
  const confirmationSha256 = confirmationDigestForBinding(binding);
  const ticket = { schemaVersion: 1, state: "pending", confirmationSha256, binding };
  validateTicket(ticket, paths);
  await writeJsonExclusive(paths.pendingTicketPath, ticket);
  return ticket;
}

export async function consumePendingTicket(pathsOrRoot, confirmationSha256) {
  const paths = typeof pathsOrRoot === "string" ? evidencePaths(await realpath(pathsOrRoot)) : pathsOrRoot;
  if (existsSync(paths.consumedTicketPath)) throw new Error("Manus live ticket was already consumed; create a new preview");
  let ticket;
  try { ticket = JSON.parse(await readFile(paths.pendingTicketPath, "utf8")); }
  catch (error) {
    if (!existsSync(paths.pendingTicketPath)) throw new Error("Manus live ticket is absent or already consumed; create a new preview", { cause: error });
    throw error;
  }
  validateTicket(ticket, paths);
  assert.equal(ticket.confirmationSha256, confirmationSha256, "ticket confirmation digest mismatch");
  assert.equal(confirmationDigestForBinding(ticket.binding), confirmationSha256, "ticket binding was modified after preview");
  try { await rename(paths.pendingTicketPath, paths.consumedTicketPath); }
  catch (error) {
    if (existsSync(paths.consumedTicketPath) || !existsSync(paths.pendingTicketPath)) {
      throw new Error("Manus live ticket was already consumed; create a new preview", { cause: error });
    }
    throw error;
  }
  return ticket;
}

export function confirmationDigestForBinding(binding) {
  return sha256(JSON.stringify(binding));
}

export function scrubManusEnvironment(environment) {
  return Object.fromEntries(Object.entries(environment).filter(([name, value]) => value !== undefined
    && !["MANUS_API_KEY", "MANUS_API_BASE_URL", "AGENT_BRIDGE_CONFIG"].includes(name.toUpperCase())));
}

function validateTicket(ticket, expectedPaths) {
  assert.equal(ticket?.schemaVersion, 1, "unsupported Manus live ticket schema");
  assert.equal(ticket?.state, "pending", "Manus live ticket is not pending");
  assert.match(ticket?.confirmationSha256 ?? "", /^[a-f0-9]{64}$/, "ticket confirmation digest is invalid");
  const binding = ticket.binding;
  assert.equal(binding?.schemaVersion, 1, "ticket binding schema is invalid");
  assert.equal(binding?.promptTemplateVersion, PROMPT_TEMPLATE_VERSION, "ticket prompt template is unsupported");
  assert.match(binding?.nonce ?? "", /^[a-f0-9]{64}$/, "ticket nonce is invalid");
  assert.equal(binding?.expectedReply, `LIVE_MANUS_FRESH_OK_${binding.nonce}`, "ticket expected reply is invalid");
  assert.equal(binding?.promptSha256, sha256(promptFor(binding.expectedReply)), "ticket prompt digest is invalid");
  parseModel(binding?.model);
  parseTimeout(String(binding?.timeoutSec));
  parseCost(String(binding?.maximumApprovedCostUsd));
  assert.equal(binding?.maximumReservedCents, Math.round(binding.maximumApprovedCostUsd * 100), "ticket reserved cents are invalid");
  assert.equal(binding?.dataClassification, DATA_CLASSIFICATION, "ticket data classification is invalid");
  assert.equal(binding?.providerEndpoint, PROVIDER_ENDPOINT, "ticket provider endpoint is invalid");
  assert.equal(binding?.providerCapabilityPolicy, PROVIDER_CAPABILITY_POLICY, "ticket capability policy is invalid");
  assert.equal(binding?.providerAccountProfile, PROVIDER_ACCOUNT_PROFILE, "ticket account capability profile is invalid");
  assert.ok(isAbsolute(binding?.credentialFile ?? ""), "ticket credential path is not absolute");
  assert.ok(isAbsolute(binding?.runtime?.path ?? ""), "ticket runtime path is not absolute");
  assert.match(binding?.runtime?.sha256 ?? "", /^[a-f0-9]{64}$/, "ticket runtime hash is invalid");
  assert.equal(typeof binding?.runtime?.releaseMode, "boolean", "ticket runtime mode is invalid");
  assert.deepEqual(binding?.evidence, expectedPaths, "ticket evidence paths changed");
  assert.ok(Date.parse(binding?.createdAt) < Date.parse(binding?.expiresAt), "ticket timestamps are invalid");
  assert.equal(confirmationDigestForBinding(binding), ticket.confirmationSha256, "ticket binding digest is invalid");
}

function evidencePaths(evidenceDir) {
  return {
    evidenceDir,
    workDir: join(evidenceDir, "work"),
    stateDir: join(evidenceDir, "state"),
    configPath: join(evidenceDir, CONFIG_FILE),
    previewResultPath: join(evidenceDir, PREVIEW_RESULT_FILE),
    pendingTicketPath: join(evidenceDir, TICKET_FILE),
    consumedTicketPath: join(evidenceDir, CONSUMED_TICKET_FILE),
    consumptionPath: join(evidenceDir, CONSUMPTION_FILE),
    resultPath: join(evidenceDir, RESULT_FILE),
  };
}

function runtimeBinding(identity) {
  return {
    path: identity.path,
    version: identity.expectedVersion ?? null,
    sha256: identity.expectedSha256,
    releaseId: identity.releaseId ?? null,
    releaseMode: identity.releaseMode,
  };
}

async function resolveCredentialFile() {
  const configured = process.env.AGENT_BRIDGE_MANUS_CREDENTIAL_FILE;
  if (configured && !isAbsolute(configured)) throw new Error("AGENT_BRIDGE_MANUS_CREDENTIAL_FILE must be absolute");
  const path = resolve(configured ?? join(homedir(), ".agent-bridge", "secrets", "manus-api-key"));
  if (!existsSync(path) || !statSync(path).isFile()) throw new Error("configured Manus credential file is absent");
  return realpath(path);
}

function promptFor(expectedReply) {
  return `Public connection canary only. Do not use browsers, connectors, files, credentials, purchases, messages, or external actions. Reply with exactly this text and nothing else: ${expectedReply}`;
}

function parseModel(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_.-]{1,100}$/.test(value)) throw new Error("AGENT_BRIDGE_MANUS_MODEL is invalid");
  return value;
}

function parseTimeout(value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 30 || parsed > 7_200) throw new Error("AGENT_BRIDGE_MANUS_TIMEOUT_SEC must be an integer from 30 to 7200");
  return parsed;
}

function parseCost(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0.01 || parsed > 10 || Math.round(parsed * 100) !== parsed * 100) {
    throw new Error("AGENT_BRIDGE_MANUS_MAX_COST_USD must be 0.01 to 10.00 with at most two decimals");
  }
  return parsed;
}

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function rejectUnknownArguments() {
  const allowed = new Set(["--execute", "--evidence-dir", "--confirm-ticket-sha256"]);
  for (let index = 2; index < process.argv.length; index += 1) {
    const value = process.argv[index];
    if (!allowed.has(value)) throw new Error(`unknown argument: ${value}`);
    if (value !== "--execute") index += 1;
  }
  if (!process.argv.includes("--execute") && argumentValue("--confirm-ticket-sha256") !== undefined) {
    throw new Error("--confirm-ticket-sha256 is valid only with --execute");
  }
}

function approvalIdFromMessage(message) {
  const match = /^Approval ID: "([A-Za-z0-9_-]+)"$/m.exec(message);
  assert.ok(match, "elicitation must display an exact approval id");
  return match[1];
}

async function writeJsonExclusive(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
}

function safeMessage(error) {
  return (error instanceof Error ? error.message : String(error))
    .replace(/\b(?:authorization|api[-_ ]?key|access[-_ ]?token|token|secret|password)\b\s*[:=]\s*\S+/gi, "$1=[REDACTED]")
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]")
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ")
    .slice(0, 512);
}

function sha256(value) { return createHash("sha256").update(value, "utf8").digest("hex"); }

const isDirect = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isDirect) main().catch((error) => failLive("manus", error));
