import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createHash } from "node:crypto";
import { opendirSync, readFileSync, statSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { buildRegistry } from "./adapters/index.js";
import { APPROVAL_CATEGORIES, APPROVAL_STATES, ApprovalStore, projectApproval } from "./approvals.js";
import { buildApprovalElicitationRequest, buildCliApprovalChallenge, verifyApprovalElicitationResult, verifyCliApprovalResult } from "./approval-confirmation.js";
import { Bridge, payloadSha256 } from "./bridge.js";
import { RemoteCostBudgetStore } from "./budgets.js";
import { assertAllowedCwd, loadConfig } from "./config.js";
import { buildDiagnostics, sanitizeDiagnosticDetail } from "./diagnostics.js";
import { projectSession, SessionStore } from "./sessions.js";
import { integratorBrief, projectWorkboard, WorkboardStore, type WorkItem, type Workboard } from "./workboards.js";
import { parseReview, parseSubmission, reviewPrompt, workItemPrompt } from "./workboard-prompts.js";
import { assertWorkItemAgentCompatible, DATA_CLASSIFICATIONS } from "./policy.js";
import { recommendationPayload, RecommendationCollector, renderRecommendationCollection } from "./recommendations.js";
import { pageTurnText, renderTurn } from "./render.js";
import type { ManusConfirmationInput } from "./adapters/manus.js";

declare const __AGENT_BRIDGE_VERSION__: string;
declare const __AGENT_BRIDGE_GIT_SHA__: string;

const VERSION = __AGENT_BRIDGE_VERSION__;
const GIT_SHA = __AGENT_BRIDGE_GIT_SHA__;
const runtimePath = fileURLToPath(import.meta.url);

const config = loadConfig();
const approvals = new ApprovalStore(config.stateDir, config.sessionLockWaitMs, config.sessionLockStaleMs);
const remoteCostBudget = config.policy?.cumulativeRemoteCost
  ? new RemoteCostBudgetStore(config.stateDir, config.policy.cumulativeRemoteCost, config.sessionLockWaitMs, config.sessionLockStaleMs)
  : undefined;
const sessionStore = new SessionStore(config.stateDir, config.sessionLockWaitMs, config.sessionLockStaleMs);
const bridge = new Bridge(
  config,
  buildRegistry(config),
  sessionStore,
  approvals,
  remoteCostBudget,
);
const workboards = new WorkboardStore(config.stateDir, config.sessionLockWaitMs, config.sessionLockStaleMs);
const recommendations = new RecommendationCollector(bridge);

const server = new McpServer(
  { name: "agent-bridge", version: VERSION },
  { instructions: "Delegate work to configured agent backends, continue a backend session, or hand an in-progress bridge session to another backend. Delegated local CLI agents run with filesystem access determined by sandbox and allowedRoots. Remote backends may not have local filesystem access; inspect list_agents capabilities and health first." },
);

const sandboxSchema = z.enum(["read-only", "workspace-write", "full-access"]);
const dataClassificationSchema = z.enum(DATA_CLASSIFICATIONS);
const approvalCategorySchema = z.enum(APPROVAL_CATEGORIES);
const approvalStateSchema = z.enum(APPROVAL_STATES);
const manusDecisionSchema = z.enum(["browser_skip", "email_save_draft", "video_standard", "high_credit_reject"]);

function diagnostics() {
  return buildDiagnostics(config, bridge.registry, {
    runtime: {
      version: VERSION,
      gitSha: GIT_SHA,
      path: runtimePath,
      sha256: createHash("sha256").update(readFileSync(runtimePath)).digest("hex"),
    },
  });
}

function diagnosticAgentEvidence(agents: Awaited<ReturnType<Bridge["listAgents"]>>) {
  return agents.map((agent) => ({
    id: agent.id,
    health: {
      binaryOk: agent.health.binary.ok,
      authStatus: agent.health.auth.status,
      usable: agent.health.usable,
    },
    capabilities: agent.capabilities,
    cooperativeReady: agent.cooperativeReady,
    cooperativeReason: agent.cooperativeReason,
  }));
}

function sanitizedAgentListing(agent: Awaited<ReturnType<Bridge["listAgents"]>>[number]) {
  const version = agent.health.binary.version;
  const binaryError = agent.health.binary.error;
  const authDetail = agent.health.auth.detail;
  return {
    ...agent,
    health: {
      binary: {
        ok: agent.health.binary.ok,
        ...(version !== undefined ? { version: sanitizeDiagnosticDetail(version, 256) } : {}),
        ...(binaryError !== undefined ? { error: sanitizeDiagnosticDetail(binaryError, 512) } : {}),
      },
      auth: {
        status: agent.health.auth.status,
        ...(authDetail !== undefined ? { detail: sanitizeDiagnosticDetail(authDetail, 512) } : {}),
      },
      usable: agent.health.usable,
    },
  };
}

function diagnosticBudgetStatus() {
  try { return bridge.budgetStatus(); }
  catch (error) {
    return { enabled: true as const, status: "error" as const, detail: sanitizeDiagnosticDetail(error, 256) };
  }
}

const CREATOR_STATUS_RECORD_LIMIT = 200;
const CREATOR_STATUS_FILE_LIMIT_BYTES = 4 * 1024 * 1024;
const WORKBOARD_STATES = new Set(["active", "paused", "completed", "canceled", "archived"]);
const WORK_ITEM_STATES = new Set(["ready", "running", "submitted", "accepted", "rejected", "blocked", "failed", "canceled"]);

function scanLocalJson(directoryPath: string, fileName: RegExp, visit: (value: unknown) => void) {
  let scanned = 0;
  let unreadable = 0;
  let truncated = false;
  let directory;
  try { directory = opendirSync(directoryPath); }
  catch { return { scanned, unreadable: 1, truncated: false }; }
  try {
    for (;;) {
      const entry = directory.readSync();
      if (!entry) break;
      if (!entry.isFile() || !fileName.test(entry.name)) continue;
      if (scanned >= CREATOR_STATUS_RECORD_LIMIT) { truncated = true; break; }
      scanned += 1;
      try {
        const path = `${directoryPath}${directoryPath.endsWith("\\") || directoryPath.endsWith("/") ? "" : "/"}${entry.name}`;
        if (statSync(path).size > CREATOR_STATUS_FILE_LIMIT_BYTES) { unreadable += 1; continue; }
        visit(JSON.parse(readFileSync(path, "utf8")));
      } catch { unreadable += 1; }
    }
  } finally { directory.closeSync(); }
  return { scanned, unreadable, truncated };
}

function safeTimestamp(value: unknown): string | null {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) return null;
  return new Date(value).toISOString();
}

function creatorStatus() {
  const report = diagnostics();
  const budget = diagnosticBudgetStatus();
  const backendCapabilities = [...bridge.registry.values()].slice(0, 20).map((adapter) => ({
    id: adapter.id,
    displayName: adapter.displayName,
    capabilities: Object.fromEntries(Object.entries(adapter.capabilities).filter(([, enabled]) => enabled).slice(0, 20)),
  }));
  const configuredBackendIds = new Set(backendCapabilities.map((backend) => backend.id));
  let invalidSessionRecords = 0;
  const sessions: Array<{ updatedAt: string; revision: number; turns: number; agents: string[] }> = [];
  const sessionSample = scanLocalJson(sessionStore.dir, /^[A-Za-z0-9_-]+\.json$/, (value) => {
    const record = value !== null && typeof value === "object" ? value as Record<string, unknown> : {};
    const turns = Array.isArray(record.turns) ? record.turns : [];
    const updatedAt = safeTimestamp(record.updatedAt);
    const revision = Number.isSafeInteger(record.revision) && Number(record.revision) >= 0 ? Number(record.revision) : null;
    if (updatedAt === null || revision === null || !Array.isArray(record.turns)) {
      invalidSessionRecords += 1;
      return;
    }
    sessions.push({
      updatedAt,
      revision,
      turns: turns.length,
      agents: [...new Set(turns.map((turn) => turn !== null && typeof turn === "object" ? (turn as Record<string, unknown>).agentId : undefined)
        .filter((agent): agent is string => typeof agent === "string" && configuredBackendIds.has(agent)))].slice(0, 20),
    });
  });
  const approvalCounts: Record<string, number> = {};
  let invalidApprovalRecords = 0;
  const approvalSample = scanLocalJson(approvals.dir, /^[A-Za-z0-9_-]+\.json$/, (value) => {
    const state = value !== null && typeof value === "object" ? (value as Record<string, unknown>).state : undefined;
    if (typeof state !== "string" || !APPROVAL_STATES.includes(state as typeof APPROVAL_STATES[number])) { invalidApprovalRecords += 1; return; }
    approvalCounts[state] = (approvalCounts[state] ?? 0) + 1;
  });
  const workboardCounts: Record<string, number> = {};
  const workItemCounts: Record<string, number> = {};
  let invalidWorkboardRecords = 0;
  const workboardSample = scanLocalJson(workboards.dir, /^[A-Za-z0-9_-]+\.json$/, (value) => {
    const board = value !== null && typeof value === "object" ? value as Record<string, unknown> : {};
    if (typeof board.status !== "string" || !WORKBOARD_STATES.has(board.status) || !Array.isArray(board.items)) { invalidWorkboardRecords += 1; return; }
    workboardCounts[board.status] = (workboardCounts[board.status] ?? 0) + 1;
    for (const value of board.items) {
      const status = value !== null && typeof value === "object" ? (value as Record<string, unknown>).status : undefined;
      if (typeof status !== "string" || !WORK_ITEM_STATES.has(status)) { invalidWorkboardRecords += 1; continue; }
      workItemCounts[status] = (workItemCounts[status] ?? 0) + 1;
    }
  });
  const localStateIncomplete = sessionSample.truncated || approvalSample.truncated || workboardSample.truncated
    || sessionSample.unreadable + invalidSessionRecords > 0 || approvalSample.unreadable + invalidApprovalRecords > 0
    || workboardSample.unreadable + invalidWorkboardRecords > 0;
  const blocked = (budget.enabled && "status" in budget) || report.promotion.status === "unreadable";
  const reservationExhausted = budget.enabled && !("status" in budget) && budget.remainingCents === 0;
  const attention = blocked || report.promotion.status !== "current" || report.config.contentHashStatus !== "verified"
    || report.config.broadRootWarnings.length > 0 || (approvalCounts.pending ?? 0) > 0 || (approvalCounts.approved ?? 0) > 0
    || reservationExhausted || localStateIncomplete
    || (workboardCounts.paused ?? 0) > 0 || (workItemCounts.blocked ?? 0) > 0 || (workItemCounts.failed ?? 0) > 0;
  const status = blocked ? "blocked" as const : attention ? "needs-attention" as const : "ready" as const;
  const nextSafeActions: string[] = [];
  if (blocked) nextSafeActions.push("Resolve the local promotion-marker or cumulative-budget error before starting new work.");
  if (!backendCapabilities.length) nextSafeActions.push("Configure at least one backend before delegating work.");
  if (report.promotion.status !== "current" && !blocked) nextSafeActions.push("Review installed release identity before treating this runtime as the active release.");
  if (report.config.broadRootWarnings.length) nextSafeActions.push("Review broad allowed-root warnings before granting workspace access.");
  if ((approvalCounts.pending ?? 0) > 0) nextSafeActions.push("Review pending approvals individually; this status does not approve or consume them.");
  if ((approvalCounts.approved ?? 0) > 0) nextSafeActions.push("Review approved but unused authority before it expires; execute only the exact previewed action.");
  if ((workItemCounts.blocked ?? 0) > 0 || (workItemCounts.failed ?? 0) > 0) nextSafeActions.push("Inspect blocked or failed workboard items before retrying work.");
  if (reservationExhausted) nextSafeActions.push("Direct-remote reservation budget is exhausted; raise the configured ceiling only after review.");
  if (localStateIncomplete) nextSafeActions.push("Local status was truncated or found unreadable state; inspect the dedicated session, approval, and workboard tools before acting.");
  nextSafeActions.push("Run list_agents separately to check backend health, authentication, and reachability.");
  return {
    status,
    healthChecked: false,
    diagnostics: {
      runtimeVersion: report.runtime.version ?? null,
      promotion: { status: report.promotion.status, detail: sanitizeDiagnosticDetail(report.promotion.detail, 256) },
      config: {
        contentHashStatus: report.config.contentHashStatus,
        allowedRootCount: report.config.allowedRootCount,
        broadRootWarnings: report.config.broadRootWarnings.slice(0, 20).map((warning) => sanitizeDiagnosticDetail(warning, 256)),
      },
      state: { exists: report.state.exists, sessionFiles: report.state.sessionFiles, bytes: report.state.bytes, aclStatus: report.state.acl.status },
    },
    configuredBackends: backendCapabilities,
    budget: budget.enabled && "status" in budget
      ? { enabled: true, status: "error", detail: sanitizeDiagnosticDetail(budget.detail, 256), billing: "not provider billing" }
      : budget.enabled
        ? { ...budget, billing: "approved maximum-cost reservations, not provider billing" }
        : { enabled: false, billing: "not provider billing" },
    sessions: { scanned: sessionSample.scanned, truncated: sessionSample.truncated, unreadable: sessionSample.unreadable + invalidSessionRecords, sample: sessions },
    approvals: { scanned: approvalSample.scanned, truncated: approvalSample.truncated, unreadable: approvalSample.unreadable + invalidApprovalRecords, byState: approvalCounts },
    workboards: { scanned: workboardSample.scanned, truncated: workboardSample.truncated, unreadable: workboardSample.unreadable + invalidWorkboardRecords, byLifecycle: workboardCounts, itemCounts: workItemCounts },
    nextSafeActions: nextSafeActions.slice(0, 8),
  };
}

function fail(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return { content: [{ type: "text" as const, text: `agent-bridge error: ${message}` }], isError: true };
}

function mapReference(reference: {
  id: string; kind: "source" | "report" | "image" | "video" | "audio" | "document" | "dataset" | "build" | "link" | "other";
  uri?: string; path?: string; hash?: string; media_type?: string;
  data_class: "public" | "internal" | "confidential" | "restricted";
  accessibility: "local" | "remote" | "inline" | "unavailable";
}) {
  return {
    id: reference.id, kind: reference.kind, uri: reference.uri, path: reference.path, hash: reference.hash,
    mediaType: reference.media_type, dataClass: reference.data_class, accessibility: reference.accessibility,
  };
}

function manusDecisionInput(decision: "browser_skip" | "email_save_draft" | "video_standard" | "high_credit_reject"): ManusConfirmationInput {
  if (decision === "browser_skip") return { action: "skip" };
  if (decision === "email_save_draft") return { accept: true, save_draft: true };
  if (decision === "video_standard") return { choice: "standard" };
  return { action: "reject" };
}

function boardSummary(board: Workboard): string {
  const counts = new Map<string, number>();
  for (const item of board.items) counts.set(item.status, (counts.get(item.status) ?? 0) + 1);
  const itemCounts = [...counts.entries()].map(([status, count]) => `${status}=${count}`).join(", ") || "no items";
  return `${board.id}: ${board.status} · ${itemCounts} · revision ${board.revision}`;
}

server.registerTool("list_agents", {
  title: "List agent backends and connection health",
  description: "Report each enabled backend's binary/API reachability, authentication state, usability and capabilities. This performs non-billable version/auth checks, not a paid functional task.",
  inputSchema: {},
}, async (_args, extra) => {
  try {
    const agents = (await bridge.listAgents(extra.signal)).map(sanitizedAgentListing);
    const text = agents.map((agent) => {
      const binary = agent.health.binary.ok ? `ok (${agent.health.binary.version ?? "version unknown"})` : `FAILED (${agent.health.binary.error})`;
      return `- ${agent.id} (${agent.displayName})\n  binary/api: ${binary}\n  auth: ${agent.health.auth.status}${agent.health.auth.detail ? ` — ${agent.health.auth.detail}` : ""}\n  usable: ${agent.health.usable}\n  cooperative-ready: ${agent.cooperativeReady}${agent.cooperativeReason ? ` — ${agent.cooperativeReason}` : ""}\n  capabilities: ${Object.entries(agent.capabilities).filter(([, enabled]) => enabled).map(([name]) => name).join(", ") || "none"}`;
    }).join("\n");
    return { content: [{ type: "text" as const, text: text || "No agent backends are enabled." }], structuredContent: { agents } };
  } catch (error) { return fail(error); }
});

server.registerTool("diagnose_install", {
  title: "Diagnose the bridge installation without running a task",
  description: "Return sanitized runtime, configuration, state, root-scope and executable-drift evidence. Selected local paths are reported; raw config bytes, credentials, prompts and transcripts are omitted. This is passive and does not delegate work or change configuration.",
  inputSchema: {},
}, async (_args, extra) => {
  try {
    const report = diagnostics();
    const agents = await bridge.listAgents(extra.signal);
    const agentEvidence = diagnosticAgentEvidence(agents);
    const budget = diagnosticBudgetStatus();
    const warnings = report.config.broadRootWarnings.length
      ? report.config.broadRootWarnings.map((warning) => `- ${warning}`).join("\n")
      : "- none";
    const text = [
      `Agent Bridge ${report.runtime.version ?? "unknown"}`,
      `runtime sha256: ${report.runtime.sha256 ?? "unknown"}`,
      `config identity: ${report.config.pathSha256}`,
      `config content: ${report.config.contentSha256 ?? "unavailable"}`,
      `promotion: ${report.promotion.status} — ${report.promotion.detail}`,
      `allowed roots: ${report.config.allowedRootCount}`,
      `state: ${report.state.sessionFiles} session file(s), ${report.state.bytes} byte(s), ACL ${report.state.acl.status}`,
      `direct-remote budget: ${budget.enabled && "status" in budget ? `ERROR — ${budget.detail}` : budget.enabled ? `${budget.committedCents}/${budget.maxReservedCents} ${budget.currency} cent(s) reserved` : "disabled"}`,
      "broad-root warnings:", warnings,
      "backend evidence:",
      ...agentEvidence.map((agent) => `- ${agent.id}: ${agent.health.usable ? "usable" : "NOT USABLE"}; auth=${agent.health.authStatus}; binary/api=${agent.health.binaryOk}`),
    ].join("\n");
    return { content: [{ type: "text" as const, text }], structuredContent: { diagnostics: report, agents: agentEvidence, budget } };
  } catch (error) { return fail(error); }
});

server.registerTool("get_budget_status", {
  title: "Get direct-remote cost budget status",
  description: "Report the optional cumulative pre-launch cost reservation breaker for direct remote APIs. This is approved maximum-cost accounting, not provider billing reconciliation, and it does not cover local CLI provider accounts.",
  inputSchema: {},
}, async () => {
  try {
    const budget = bridge.budgetStatus();
    const text = budget.enabled
      ? `direct-remote reservations: ${budget.committedCents}/${budget.maxReservedCents} ${budget.currency} cent(s); ${budget.remainingCents} remain across ${budget.reservationCount} reservation(s)`
      : "direct-remote cumulative cost breaker: disabled";
    return { content: [{ type: "text" as const, text }], structuredContent: { budget } };
  } catch (error) { return fail(error); }
});

server.registerTool("get_creator_status", {
  title: "Get local creator status without backend health probes",
  description: "Aggregate local bridge diagnostics, configured capabilities, reservations, session metadata, approval counts, and workboard counts. It does not call a backend, provider, CLI health check, or list_agents; run list_agents separately for health, authentication, and reachability.",
  inputSchema: {},
}, async () => {
  try {
    const summary = creatorStatus();
    const text = [
      `creator status: ${summary.status}`,
      "backend health: not checked; run list_agents separately.",
      `configured backends: ${summary.configuredBackends.map((backend) => backend.id).join(", ") || "none"}`,
      `local records scanned: sessions=${summary.sessions.scanned}; approvals=${summary.approvals.scanned}; workboards=${summary.workboards.scanned}`,
      `direct-remote budget: ${summary.budget.enabled ? "approved reservation accounting only; not provider billing" : "disabled; not provider billing"}`,
      "next safe actions:",
      ...summary.nextSafeActions.map((action) => `- ${action}`),
    ].join("\n");
    return { content: [{ type: "text" as const, text }], structuredContent: summary };
  } catch (error) { return fail(error); }
});

const referenceSchema = z.object({
  id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
  kind: z.enum(["source", "report", "image", "video", "audio", "document", "dataset", "build", "link", "other"]),
  uri: z.string().min(1).max(10_000).optional(),
  path: z.string().min(1).max(10_000).optional(),
  hash: z.string().min(1).max(1_000).optional(),
  media_type: z.string().min(1).max(500).optional(),
  data_class: dataClassificationSchema,
  accessibility: z.enum(["local", "remote", "inline", "unavailable"]),
}).strict();

const workItemSchema = z.object({
  key: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/),
  title: z.string().min(1).max(500),
  instructions: z.string().min(1).max(100_000),
  depends_on: z.array(z.string()).max(32).optional(),
  kind: z.enum(["research", "implementation", "review", "design", "content", "validation", "other"]).optional(),
  acceptance_criteria: z.array(z.string().min(1).max(4_000)).max(256).optional(),
  requirements: z.object({
    data_class: dataClassificationSchema.optional(),
    filesystem: z.enum(["none", "metadata-only", "read-only"]).optional(),
    network: z.enum(["none", "restricted", "required"]).optional(),
    capabilities: z.array(z.string().min(1).max(500)).max(256).optional(),
  }).strict().optional(),
  artifacts: z.array(referenceSchema).max(1_000).optional(),
  evidence: z.array(referenceSchema).max(1_000).optional(),
  approval: z.object({ required: z.boolean(), reason: z.string().min(1).max(2_000).optional() }).strict().optional(),
  budget: z.object({
    max_attempts: z.number().int().min(1).max(10).optional(),
    max_wall_sec: z.number().int().min(1).max(7_200).optional(),
    token_budget_hint: z.number().int().positive().optional(),
  }).strict().optional(),
}).strict();

server.registerTool("create_workboard", {
  title: "Create a cooperative read-only workboard",
  description: "Create bounded dependency-aware work items. Work items run in isolated bridge sessions and are always forced read-only.",
  inputSchema: {
    title: z.string().min(1).max(500), objective: z.string().min(1).max(100_000), cwd: z.string().optional(),
    max_parallel: z.number().int().min(1).max(32).optional(), items: z.array(workItemSchema).min(1).max(32),
  },
}, async (args) => {
  try {
    const target = args.cwd ?? config.defaults.cwd;
    if (!target) throw new Error("cwd is required; pass an allowed project directory or set defaults.cwd");
    const board = workboards.create({
      title: args.title, objective: args.objective, cwd: assertAllowedCwd(target, config), maxParallel: args.max_parallel,
      items: args.items.map((item) => ({
        key: item.key, title: item.title, instructions: item.instructions, dependsOn: item.depends_on,
        kind: item.kind, acceptanceCriteria: item.acceptance_criteria,
        requirements: item.requirements ? {
          dataClass: item.requirements.data_class, filesystem: item.requirements.filesystem,
          network: item.requirements.network, capabilities: item.requirements.capabilities,
        } : undefined,
        artifacts: item.artifacts?.map(mapReference), evidence: item.evidence?.map(mapReference), approval: item.approval,
        budget: item.budget ? { maxAttempts: item.budget.max_attempts, maxWallSec: item.budget.max_wall_sec, tokenBudgetHint: item.budget.token_budget_hint } : undefined,
      })),
    });
    return { content: [{ type: "text" as const, text: `created workboard ${board.id} with ${board.items.length} read-only item(s)` }], structuredContent: { workboard: projectWorkboard(board) } };
  } catch (error) { return fail(error); }
});

server.registerTool("run_work_item", {
  title: "Run one cooperative work item",
  description: "Atomically claim a ready work item and run it in an isolated read-only agent session. Separate ready items may run concurrently up to the board limit.",
  inputSchema: {
    workboard_id: z.string(), item_key: z.string(), agent: z.string(), model: z.string().optional(), retry_failed: z.boolean().optional(),
  },
}, async (args, extra) => {
  try {
    assertWorkItemAgentCompatible(workboards.get(args.workboard_id).items.find((item) => item.key === args.item_key) ?? (() => { throw new Error(`no such work item: ${args.item_key}`); })(), bridge.cooperativeAdapter(args.agent));
    const board = await workboards.run(args.workboard_id, args.item_key, args.agent, async ({ workboard, item, agentId, timeoutSec }) => {
      const outcome = await bridge.runTurn({ agentId, prompt: workItemPrompt(workboard, item), cwd: workboard.cwd, model: args.model, sandbox: "read-only", timeoutSec, allowAgentConfigExtensions: false, signal: extra.signal });
      if (outcome.result.isError) throw new Error(outcome.result.text || `${agentId} work item failed`);
      return { sessionId: outcome.session.id, ...parseSubmission(outcome.result.text) };
    }, { retryFailed: args.retry_failed });
    const projected = projectWorkboard(board);
    const item = projected.items.find((candidate) => candidate.key === args.item_key)!;
    const text = `work item ${item.key}: ${item.status} after attempt ${item.attempts}/${item.budget.maxAttempts}`;
    return { content: [{ type: "text" as const, text }], structuredContent: { workboard: projected, item }, isError: item.status === "failed" };
  } catch (error) { return fail(error); }
});

server.registerTool("review_work_item", {
  title: "Run an independent review of a submitted work item",
  description: "Ask a different agent to accept or reject a submission using its recorded evidence. The review runs read-only in a separate bridge session.",
  inputSchema: {
    workboard_id: z.string(), item_key: z.string(), reviewer_agent: z.string(), model: z.string().optional(),
    timeout_sec: z.number().int().positive().max(7_200).optional(),
  },
}, async (args, extra) => {
  try {
    assertWorkItemAgentCompatible(workboards.get(args.workboard_id).items.find((item) => item.key === args.item_key) ?? (() => { throw new Error(`no such work item: ${args.item_key}`); })(), bridge.cooperativeAdapter(args.reviewer_agent));
    const board = await workboards.runReview(args.workboard_id, args.item_key, args.reviewer_agent, async ({ workboard, item, reviewerAgentId, timeoutSec }) => {
      const outcome = await bridge.runTurn({
        agentId: reviewerAgentId, prompt: reviewPrompt(workboard, item), cwd: workboard.cwd, model: args.model,
        sandbox: "read-only", timeoutSec: Math.min(args.timeout_sec ?? 600, timeoutSec), allowAgentConfigExtensions: false, signal: extra.signal,
      });
      if (outcome.result.isError) throw new Error(outcome.result.text || `${reviewerAgentId} review failed`);
      return { ...parseReview(outcome.result.text), sessionId: outcome.session.id };
    });
    const projected = projectWorkboard(board);
    const item = projected.items.find((candidate) => candidate.key === args.item_key)!;
    if (item.failure?.code === "REVIEW_FAILED") throw new Error(`${item.failure.code}: ${item.failure.message}`);
    return {
      content: [{ type: "text" as const, text: `${args.item_key}: ${item.review!.verdict}\n\n${item.review!.rationale}` }],
      structuredContent: { workboard: projected, verdict: item.review!.verdict, rationale: item.review!.rationale },
    };
  } catch (error) { return fail(error); }
});

server.registerTool("get_workboard", {
  title: "Read cooperative workboard status and integrator context",
  description: "Return clipped work-item status, submissions and reviews plus a bounded briefing assembled only from accepted items.",
  inputSchema: { workboard_id: z.string(), max_chars: z.number().int().positive().max(100_000).optional() },
}, async (args) => {
  try {
    const maxChars = args.max_chars ?? 24_000;
    const board = projectWorkboard(workboards.get(args.workboard_id), Math.min(4_000, maxChars));
    const briefing = integratorBrief(board, maxChars);
    const statuses = board.items.map((item) => `- ${item.key}: ${item.status} (${item.attempts}/${item.budget.maxAttempts} attempt(s))`).join("\n");
    return { content: [{ type: "text" as const, text: `${statuses}\n\n${briefing}` }], structuredContent: { workboard: board, integrator_brief: briefing } };
  } catch (error) { return fail(error); }
});

server.registerTool("list_workboards", {
  title: "List cooperative workboards",
  description: "List bounded workboard metadata and lifecycle state without returning full instructions, submissions, or evidence.",
  inputSchema: {
    status: z.enum(["active", "paused", "completed", "canceled", "archived"]).optional(),
    limit: z.number().int().positive().max(200).optional(),
  },
}, async (args) => {
  try {
    const boards = workboards.list().filter((board) => !args.status || board.status === args.status).slice(0, args.limit ?? 50);
    const projected = boards.map((board) => ({
      id: board.id, title: board.title, objective: board.objective.slice(0, 1_000), cwd: board.cwd,
      status: board.status, revision: board.revision, updatedAt: board.updatedAt,
      items: board.items.length, itemStatus: Object.fromEntries([...new Set(board.items.map((item) => item.status))].map((status) => [status, board.items.filter((item) => item.status === status).length])),
    }));
    return { content: [{ type: "text" as const, text: boards.length ? boards.map(boardSummary).join("\n") : "No matching workboards." }], structuredContent: { workboards: projected } };
  } catch (error) { return fail(error); }
});

server.registerTool("pause_workboard", {
  title: "Pause a workboard",
  description: "Pause an active workboard after all live item leases have ended. This does not cancel or reset work.",
  inputSchema: { workboard_id: z.string(), reason: z.string().min(1).max(2_000) },
}, async (args) => {
  try { const board = await workboards.pause(args.workboard_id, args.reason); return { content: [{ type: "text" as const, text: boardSummary(board) }], structuredContent: { workboard: projectWorkboard(board) } }; }
  catch (error) { return fail(error); }
});

server.registerTool("resume_workboard", {
  title: "Resume a paused workboard",
  description: "Return a paused workboard to active execution without changing item budgets.",
  inputSchema: { workboard_id: z.string(), reason: z.string().min(1).max(2_000).optional() },
}, async (args) => {
  try { const board = await workboards.resume(args.workboard_id, args.reason); return { content: [{ type: "text" as const, text: boardSummary(board) }], structuredContent: { workboard: projectWorkboard(board) } }; }
  catch (error) { return fail(error); }
});

server.registerTool("complete_workboard", {
  title: "Complete a workboard",
  description: "Mark a board complete only when every item is accepted or explicitly canceled and no live lease remains.",
  inputSchema: { workboard_id: z.string(), reason: z.string().min(1).max(2_000).optional() },
}, async (args) => {
  try { const board = await workboards.complete(args.workboard_id, args.reason); return { content: [{ type: "text" as const, text: boardSummary(board) }], structuredContent: { workboard: projectWorkboard(board) } }; }
  catch (error) { return fail(error); }
});

server.registerTool("cancel_workboard", {
  title: "Cancel a workboard",
  description: "Cancel a board and every nonterminal item. Requires an explicit reason and refuses while a live lease exists.",
  inputSchema: { workboard_id: z.string(), reason: z.string().min(1).max(2_000) },
}, async (args) => {
  try { const board = await workboards.cancel(args.workboard_id, args.reason); return { content: [{ type: "text" as const, text: boardSummary(board) }], structuredContent: { workboard: projectWorkboard(board) } }; }
  catch (error) { return fail(error); }
});

server.registerTool("archive_workboard", {
  title: "Archive a terminal workboard",
  description: "Archive a completed or canceled workboard while preserving its full history and evidence metadata.",
  inputSchema: { workboard_id: z.string(), reason: z.string().min(1).max(2_000).optional() },
}, async (args) => {
  try { const board = await workboards.archive(args.workboard_id, args.reason); return { content: [{ type: "text" as const, text: boardSummary(board) }], structuredContent: { workboard: projectWorkboard(board) } }; }
  catch (error) { return fail(error); }
});

server.registerTool("cancel_work_item", {
  title: "Cancel one work item",
  description: "Cancel a nonterminal work item without canceling its board. History and consumed budgets remain intact.",
  inputSchema: { workboard_id: z.string(), item_key: z.string(), reason: z.string().min(1).max(2_000) },
}, async (args) => {
  try { const board = await workboards.cancelItem(args.workboard_id, args.item_key, args.reason); return { content: [{ type: "text" as const, text: boardSummary(board) }], structuredContent: { workboard: projectWorkboard(board) } }; }
  catch (error) { return fail(error); }
});

server.registerTool("retry_work_item", {
  title: "Retry a failed or rejected work item",
  description: "Reset prior outcomes for an eligible item without replenishing execution attempts, review attempts, wall time, or token hints.",
  inputSchema: { workboard_id: z.string(), item_key: z.string() },
}, async (args) => {
  try { const board = await workboards.retry(args.workboard_id, args.item_key); return { content: [{ type: "text" as const, text: boardSummary(board) }], structuredContent: { workboard: projectWorkboard(board) } }; }
  catch (error) { return fail(error); }
});

server.registerTool("decide_work_item_approval", {
  title: "Record a workflow decision for a gated work item",
  description: "Record an asserted approve/reject workflow decision. This gate organizes cooperative work but is not a security authorization; use the durable approval flow for remote egress, cost, publishing, or authority changes.",
  inputSchema: {
    workboard_id: z.string(), item_key: z.string(), decision: z.enum(["approved", "rejected"]),
    decided_by: z.string().min(1).max(200), rationale: z.string().min(1).max(2_000),
  },
}, async (args) => {
  try {
    const board = await workboards.decideApproval(args.workboard_id, args.item_key, args.decided_by, args.decision, args.rationale);
    return { content: [{ type: "text" as const, text: `${args.item_key}: approval ${args.decision}\n${boardSummary(board)}` }], structuredContent: { workboard: projectWorkboard(board) } };
  } catch (error) { return fail(error); }
});

server.registerTool("request_approval", {
  title: "Request a scoped human approval",
  description: "Create a pending, expiring approval record for one exact subject/action/data/root/agent scope. This requests authority but never grants it.",
  inputSchema: {
    category: approvalCategorySchema,
    subject: z.string().min(1).max(500), action: z.string().min(1).max(500),
    data_classification: dataClassificationSchema, root: z.string().optional(), agent: z.string().min(1).max(200),
    payload: z.string().min(1).max(1_000_000).optional(), payload_sha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    requested_by: z.string().min(1).max(200), reason: z.string().min(1).max(4_000),
    expires_in_sec: z.number().int().min(30).max(2_592_000).optional(),
    estimated_cost: z.number().nonnegative().max(1_000_000_000).optional(), currency: z.string().regex(/^[A-Za-z]{3}$/).optional(),
    consume_once: z.boolean().optional(), max_uses: z.number().int().min(1).max(1_000).optional(),
  },
}, async (args) => {
  try {
    const target = args.root ?? config.defaults.cwd;
    if (!target) throw new Error("root is required; pass an allowed project directory or set defaults.cwd");
    if ((args.payload === undefined) === (args.payload_sha256 === undefined)) throw new Error("APPROVAL_PAYLOAD_REQUIRED: pass exactly one of payload or payload_sha256");
    const root = assertAllowedCwd(target, config);
    const record = approvals.create({
      category: args.category,
      scope: { subject: args.subject, action: args.action, dataClass: args.data_classification, root, agent: args.agent, payloadSha256: args.payload_sha256 ?? payloadSha256(args.payload!) },
      requestedBy: args.requested_by, reason: args.reason,
      expiresAt: new Date(Date.now() + (args.expires_in_sec ?? 900) * 1_000).toISOString(),
      estimatedCost: args.estimated_cost, currency: args.currency,
      consumeOnce: args.consume_once, maxUses: args.max_uses,
    });
    const text = [
      `approval ${record.id}: pending`, `category: ${record.category}`,
      `subject: ${record.scope.subject}`, `action: ${record.scope.action}`, `agent: ${record.scope.agent}`,
      `root: ${record.scope.root}`, `data class: ${record.scope.dataClass}`, `payload sha256: ${record.scope.payloadSha256}`, `expires: ${record.expiresAt}`,
      `cost: ${record.estimatedCost === null ? "unknown" : record.estimatedCost} ${record.currency ?? "unspecified"}`,
      `uses: ${record.consumeOnce ? "one-time" : `up to ${record.maxUses}`}`,
      `approve interactively: agent-bridge.mjs --approve ${record.id}`,
    ].join("\n");
    return { content: [{ type: "text" as const, text }], structuredContent: { approval: projectApproval(record) } };
  } catch (error) { return fail(error); }
});

server.registerTool("decide_approval", {
  title: "Request a host-mediated human approval decision",
  description: "Display the exact pending approval through MCP form elicitation. Only the host's explicit accept plus exact approval ID and true confirmation can approve it; unsupported hosts fail closed. Use the interactive --approve CLI as the out-of-band fallback.",
  inputSchema: { approval_id: z.string() },
}, async (args, extra) => {
  try {
    const pending = approvals.get(args.approval_id);
    if (pending.state !== "pending") throw new Error(`APPROVAL_INVALID_TRANSITION: approval ${pending.id} is ${pending.state}`);
    const elicited = await server.server.elicitInput(buildApprovalElicitationRequest(pending), { signal: extra.signal, timeout: 300_000 });
    const confirmation = verifyApprovalElicitationResult(pending, elicited);
    const record = confirmation.accepted
      ? await approvals.approve(pending.id, { approvedBy: "mcp-host-user", reason: "exact MCP form elicitation accepted" })
      : confirmation.reason === "declined"
        ? await approvals.deny(pending.id, { deniedBy: "mcp-host-user", reason: "MCP form elicitation declined" })
        : confirmation.reason === "canceled"
          ? await approvals.cancel(pending.id, { canceledBy: "mcp-host-user", reason: "MCP form elicitation canceled" })
          : (() => { throw new Error("APPROVAL_CONFIRMATION_MISMATCH: host response did not exactly confirm this approval"); })();
    return { content: [{ type: "text" as const, text: `approval ${record.id}: ${record.state}` }], structuredContent: { approval: projectApproval(record) } };
  } catch (error) { return fail(error); }
});

server.registerTool("list_approvals", {
  title: "List scoped approval records",
  description: "List bounded approval and audit metadata. This never authorizes or consumes an approval.",
  inputSchema: {
    state: approvalStateSchema.optional(), category: approvalCategorySchema.optional(), subject: z.string().max(500).optional(),
    agent: z.string().max(200).optional(), limit: z.number().int().positive().max(200).optional(),
  },
}, async (args) => {
  try {
    const records = approvals.list({ state: args.state, category: args.category, subject: args.subject, agent: args.agent, limit: args.limit });
    const projected = records.map((record) => projectApproval(record));
    const text = projected.length
      ? projected.map((record) => `- ${record.id}: ${record.state} · ${record.category} · ${record.scope.action} · expires ${record.expiresAt} · uses ${record.useCount}/${record.maxUses}`).join("\n")
      : "No matching approvals.";
    return { content: [{ type: "text" as const, text }], structuredContent: { approvals: projected } };
  } catch (error) { return fail(error); }
});

server.registerTool("preview_recommendation_approval", {
  title: "Preview an exact recommendation review packet",
  description: "Compute the exact prompt and inline-brief identities used by collect_recommendations. When a remote agent is supplied, also return the complete hash-bound one-time approval scope after policy/root checks. No agent is called and the brief is not persisted.",
  inputSchema: {
    objective: z.string().min(1).max(100_000), scope: z.enum(["workspace", "brief"]),
    brief: z.string().min(1).max(100_000).optional(),
    agent: z.string().min(1).optional(), cwd: z.string().optional(), model: z.string().optional(), timeout_sec: z.number().int().min(1).max(7_200).optional(),
    allow_remote_egress: z.literal(true).optional(), data_classification: dataClassificationSchema.optional(),
  },
}, async (args, extra) => {
  try {
    if (args.scope === "brief" && !args.brief) throw new Error("RECOMMENDATION_BRIEF_REQUIRED: brief scope requires a non-empty brief");
    if (args.scope === "workspace" && args.brief !== undefined) throw new Error("RECOMMENDATION_INPUT_INVALID: brief is only valid for brief scope");
    const prompt = recommendationPayload(args.objective, args.scope, args.brief);
    const digest = payloadSha256(prompt);
    const briefDigest = args.scope === "brief" ? payloadSha256(args.brief!.trim()) : null;
    if (!args.agent) {
      if (args.cwd !== undefined || args.model !== undefined || args.timeout_sec !== undefined || args.allow_remote_egress !== undefined || args.data_classification !== undefined) {
        throw new Error("RECOMMENDATION_PREVIEW_INPUT_INVALID: agent is required with remote preview fields");
      }
      return {
        content: [{ type: "text" as const, text: `recommendation payload sha256: ${digest}\ninline brief sha256: ${briefDigest ?? "none"}\nNo agent was called. Pass a remote agent, cwd, consent, and classification to obtain its exact approval scope.` }],
        structuredContent: { payload_sha256: digest, brief_sha256: briefDigest, scope: args.scope, approval_scope: null },
      };
    }
    if (args.scope !== "brief") throw new Error("RECOMMENDATION_REMOTE_BRIEF_REQUIRED: remote recommendation previews require scope=brief");
    if (args.allow_remote_egress !== true || !args.data_classification) {
      throw new Error("RECOMMENDATION_REMOTE_CONSENT_REQUIRED: remote preview requires allow_remote_egress=true and data_classification");
    }
    const preview = await bridge.previewTurnApproval({
      agentId: args.agent,
      prompt,
      cwd: args.cwd,
      model: args.model,
      sandbox: "read-only",
      timeoutSec: args.timeout_sec,
      forceFresh: true,
      allowAgentConfigExtensions: false,
      allowRemoteEgress: args.allow_remote_egress,
      dataClassification: args.data_classification,
      signal: extra.signal,
    });
    if (preview.promptSha256 !== digest) throw new Error("RECOMMENDATION_PREVIEW_MISMATCH: remote approval prompt did not match the recommendation payload");
    const budget = bridge.budgetStatus();
    return {
      content: [{ type: "text" as const, text: [
        `recommendation payload sha256: ${digest}`,
        `inline brief sha256: ${briefDigest}`,
        `agent: ${preview.agentId}`,
        `root: ${preview.cwd}`,
        `provider endpoint: ${preview.executionEnvelope.providerEndpoint ?? "not applicable"}`,
        `provider capability policy: ${preview.executionEnvelope.providerCapabilityPolicy}`,
        `provider account profile: ${preview.executionEnvelope.providerAccountProfile ?? "not applicable"}`,
        "No provider was called and the brief was not persisted. Request fresh one-time remote_egress and paid_or_unknown_cost approvals with this exact scope.",
      ].join("\n") }],
      structuredContent: {
        payload_sha256: preview.payloadSha256,
        recommendation_payload_sha256: digest,
        brief_sha256: briefDigest,
        scope: args.scope,
        approval_scope: preview.scope,
        cwd: preview.cwd,
        agent: preview.agentId,
        execution_envelope: preview.executionEnvelope,
        budget,
      },
    };
  } catch (error) { return fail(error); }
});

server.registerTool("preview_turn_approval", {
  title: "Preview an exact remote-turn approval scope",
  description: "Plan a direct remote API turn without calling a provider, persisting a session, or consuming authority. Returns the digest of the exact finalized outbound prompt, including injected handoff context. Pass the returned session revision to execution so a concurrent session change fails with an explicit re-preview error.",
  inputSchema: {
    agent: z.string().min(1), prompt: z.string().min(1).max(1_000_000), cwd: z.string().optional(),
    session_id: z.string().optional(), model: z.string().optional(), sandbox: sandboxSchema.optional(),
    timeout_sec: z.number().int().min(1).max(7_200).optional(),
    allow_remote_egress: z.literal(true), data_classification: dataClassificationSchema,
  },
}, async (args, extra) => {
  try {
    const preview = await bridge.previewTurnApproval({
      agentId: args.agent, prompt: args.prompt, cwd: args.cwd, sessionId: args.session_id,
      model: args.model, sandbox: args.sandbox, timeoutSec: args.timeout_sec, allowRemoteEgress: args.allow_remote_egress,
      dataClassification: args.data_classification, signal: extra.signal,
    });
    const budget = bridge.budgetStatus();
    const revision = preview.sessionRevision === null ? "new session" : String(preview.sessionRevision);
    return {
      content: [{ type: "text" as const, text: [
        `remote turn prompt sha256: ${preview.promptSha256}`,
        `remote approval envelope sha256: ${preview.payloadSha256}`,
        `agent: ${preview.agentId}`,
        `root: ${preview.cwd}`,
        `continuity: ${preview.continuity}`,
        `context delta applied: ${preview.contextDeltaApplied}`,
        `provider endpoint: ${preview.executionEnvelope.providerEndpoint ?? "not applicable"}`,
        `provider capability policy: ${preview.executionEnvelope.providerCapabilityPolicy}`,
        `provider account profile: ${preview.executionEnvelope.providerAccountProfile ?? "not applicable"}`,
        `session revision: ${revision}`,
        `direct-remote budget: ${budget.enabled ? `${budget.committedCents}/${budget.maxReservedCents} ${budget.currency} cent(s) reserved` : "disabled"}`,
        "No provider was called, no session was persisted, and no approval was consumed. Request fresh one-time remote_egress and paid_or_unknown_cost approvals with this exact scope.",
      ].join("\n") }],
      structuredContent: {
        approval_scope: preview.scope,
        payload_sha256: preview.payloadSha256,
        prompt_sha256: preview.promptSha256,
        continuity: preview.continuity,
        context_delta_applied: preview.contextDeltaApplied,
        session_revision: preview.sessionRevision,
        cwd: preview.cwd,
        agent: preview.agentId,
        execution_envelope: preview.executionEnvelope,
        budget,
      },
    };
  } catch (error) { return fail(error); }
});

server.registerTool("get_manus_waiting_action", {
  title: "Inspect a persisted Manus waiting action",
  description: "Read the bridge's last sanitized Manus waiting-action state. This does not call Manus, expose the native task id or provider schema, persist state, or consume approval.",
  inputSchema: { session_id: z.string() },
}, async (args) => {
  try {
    const snapshot = bridge.getManusWaitingAction(args.session_id);
    return {
      content: [{ type: "text" as const, text: [
        `Manus action: ${snapshot.action.eventType}`,
        `event id: ${snapshot.action.eventId}`,
        `session revision: ${snapshot.sessionRevision}`,
        `root: ${snapshot.cwd}`,
        "No provider was called and no approval was consumed.",
      ].join("\n") }],
      structuredContent: {
        bridge_session_id: snapshot.sessionId,
        session_revision: snapshot.sessionRevision,
        cwd: snapshot.cwd,
        action: { event_id: snapshot.action.eventId, event_type: snapshot.action.eventType },
      },
    };
  } catch (error) { return fail(error); }
});

server.registerTool("reconcile_manus_task", {
  title: "Reconcile an unresolved Manus task",
  description: "Poll a persisted timed-out, aborted, errored, or unknown Manus task without sending a new user message. Requires explicit remote-egress consent and a current session revision; a local timeout never stops the provider task.",
  inputSchema: {
    session_id: z.string(), expected_session_revision: z.number().int().nonnegative(),
    allow_remote_egress: z.literal(true), data_classification: dataClassificationSchema,
    timeout_sec: z.number().int().min(1).max(300).optional(),
  },
}, async (args, extra) => {
  try {
    return renderTurn(await bridge.reconcileManusTask({
      sessionId: args.session_id,
      expectedSessionRevision: args.expected_session_revision,
      allowRemoteEgress: args.allow_remote_egress,
      dataClassification: args.data_classification,
      timeoutSec: args.timeout_sec,
      signal: extra.signal,
    }));
  } catch (error) { return fail(error); }
});

server.registerTool("preview_manus_confirmation", {
  title: "Preview an exact Manus action confirmation",
  description: "Build the exact approval scope for one of four fixed safe Manus decisions without contacting Manus or changing state. Use the returned scope to request both fresh one-time approvals, then pass the revision to confirm_manus_action.",
  inputSchema: {
    session_id: z.string(), event_id: z.string(), decision: manusDecisionSchema,
    allow_remote_egress: z.literal(true), data_classification: dataClassificationSchema,
  },
}, async (args, extra) => {
  try {
    const preview = await bridge.previewManusConfirmation({
      sessionId: args.session_id,
      eventId: args.event_id,
      input: manusDecisionInput(args.decision),
      allowRemoteEgress: args.allow_remote_egress,
      dataClassification: args.data_classification,
      signal: extra.signal,
    });
    return {
      content: [{ type: "text" as const, text: [
        `Manus confirmation payload sha256: ${preview.payloadSha256}`,
        `action: ${preview.action.eventType}`,
        `event id: ${preview.action.eventId}`,
        `session revision: ${preview.sessionRevision}`,
        `required approvals: ${preview.requiredCategories.join(", ")}`,
        `provider endpoint: ${preview.executionEnvelope.providerEndpoint}`,
        `provider capability policy: ${preview.executionEnvelope.providerCapabilityPolicy}`,
        `provider account profile: ${preview.executionEnvelope.providerAccountProfile}`,
        `direct-remote budget: ${preview.budget.enabled ? `${preview.budget.committedCents}/${preview.budget.maxReservedCents} ${preview.budget.currency} cent(s) reserved` : "disabled"}`,
        "No provider was called, no state was changed, and no approval was consumed.",
      ].join("\n") }],
      structuredContent: {
        bridge_session_id: preview.sessionId,
        session_revision: preview.sessionRevision,
        cwd: preview.cwd,
        action: { event_id: preview.action.eventId, event_type: preview.action.eventType },
        approval_scope: preview.scope,
        payload_sha256: preview.payloadSha256,
        required_categories: preview.requiredCategories,
        execution_envelope: preview.executionEnvelope,
        budget: preview.budget,
      },
    };
  } catch (error) { return fail(error); }
});

server.registerTool("confirm_manus_action", {
  title: "Confirm one exact safe Manus waiting action",
  description: "Submit one fixed decision after exact preview, session-revision, remote-egress, action-specific, and cost checks. Never accepts a native task id, dynamic provider input, secrets, sends, deploys, terminal commands, connector grants, or persistent permissions.",
  inputSchema: {
    session_id: z.string(), event_id: z.string(), decision: manusDecisionSchema,
    allow_remote_egress: z.literal(true), data_classification: dataClassificationSchema,
    approval_ids: z.array(z.string()).length(2),
    expected_session_revision: z.number().int().nonnegative(),
    estimated_cost: z.number().nonnegative().max(1_000_000_000).optional(),
    estimated_currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    timeout_sec: z.number().int().positive().max(7_200).optional(),
  },
}, async (args, extra) => {
  try {
    return renderTurn(await bridge.confirmManusAction({
      sessionId: args.session_id,
      eventId: args.event_id,
      input: manusDecisionInput(args.decision),
      allowRemoteEgress: args.allow_remote_egress,
      dataClassification: args.data_classification,
      approval_ids: args.approval_ids,
      expectedSessionRevision: args.expected_session_revision,
      estimatedCost: args.estimated_cost,
      estimatedCurrency: args.estimated_currency,
      timeoutSec: args.timeout_sec,
      signal: extra.signal,
    }));
  } catch (error) { return fail(error); }
});

server.registerTool("collect_recommendations", {
  title: "Collect independent agent recommendations",
  description: "Ask 2-4 local agents to inspect a workspace, or 1-4 no-filesystem agents to review an explicit brief, then aggregate matching title/change variants. This never applies changes; remote brief review still requires policy, consent, classification, and approval gates.",
  inputSchema: {
    objective: z.string().min(1).max(100_000), cwd: z.string().optional(), scope: z.enum(["workspace", "brief"]),
    brief: z.string().min(1).max(100_000).optional(), timeout_sec: z.number().int().positive().max(7_200).optional(),
    max_parallel: z.number().int().min(1).max(4).optional(),
    targets: z.array(z.object({
      agent: z.string().min(1), model: z.string().optional(), allow_remote_egress: z.boolean().optional(),
      data_classification: dataClassificationSchema.optional(), approval_ids: z.array(z.string()).min(1).max(4).optional(),
      estimated_cost: z.number().nonnegative().max(1_000_000_000).optional(),
      estimated_currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    }).strict()).min(1).max(4),
  },
}, async (args, extra) => {
  try {
    const target = args.cwd ?? config.defaults.cwd;
    if (!target) throw new Error("cwd is required; pass an allowed project directory or set defaults.cwd");
    const result = await recommendations.collect({
      objective: args.objective, cwd: assertAllowedCwd(target, config), scope: args.scope, brief: args.brief,
      timeoutSec: args.timeout_sec, maxParallel: args.max_parallel, signal: extra.signal,
      targets: args.targets.map((entry) => ({
        agentId: entry.agent, model: entry.model, allowRemoteEgress: entry.allow_remote_egress,
        dataClassification: entry.data_classification, approvalIds: entry.approval_ids, estimatedCost: entry.estimated_cost, estimatedCurrency: entry.estimated_currency,
      })),
    });
    const text = renderRecommendationCollection(result);
    return { content: [{ type: "text" as const, text }], structuredContent: { collection: result } };
  } catch (error) { return fail(error); }
});

server.registerTool("delegate_task", {
  title: "Delegate a task to another agent",
  description: "Start a task on an enabled backend. Pass an exact allowed cwd. Defaults to read-only unless the bridge config deliberately chooses otherwise.",
  inputSchema: {
    agent: z.string().min(1), prompt: z.string().min(1).max(1_000_000), cwd: z.string().optional(),
    model: z.string().optional(), sandbox: sandboxSchema.optional(),
    timeout_sec: z.number().int().positive().max(7200).optional(), session_id: z.string().optional(),
    allow_remote_egress: z.boolean().optional(), data_classification: dataClassificationSchema.optional(),
    approval_ids: z.array(z.string()).min(1).max(4).optional(),
    estimated_cost: z.number().nonnegative().max(1_000_000_000).optional(),
    estimated_currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    expected_session_revision: z.number().int().nonnegative().optional().describe("Required for a direct remote API turn on an existing session; use preview_turn_approval"),
  },
}, async (args, extra) => {
  try { return renderTurn(await bridge.runTurn({ agentId: args.agent, prompt: args.prompt, cwd: args.cwd, model: args.model, sandbox: args.sandbox, timeoutSec: args.timeout_sec, sessionId: args.session_id, signal: extra.signal, allowRemoteEgress: args.allow_remote_egress, dataClassification: args.data_classification, approval_ids: args.approval_ids, estimatedCost: args.estimated_cost, estimatedCurrency: args.estimated_currency, expectedSessionRevision: args.expected_session_revision })); }
  catch (error) { return fail(error); }
});

server.registerTool("continue_session", {
  title: "Continue an existing bridge session",
  description: "Continue a backend in a bridge session. Native resume is used only when compatible; unseen cross-agent turns are injected as a delta briefing.",
  inputSchema: {
    session_id: z.string(), prompt: z.string().min(1).max(1_000_000), agent: z.string().optional(),
    model: z.string().optional(), sandbox: sandboxSchema.optional(), timeout_sec: z.number().int().positive().max(7200).optional(),
    allow_remote_egress: z.boolean().optional(), data_classification: dataClassificationSchema.optional(),
    approval_ids: z.array(z.string()).min(1).max(4).optional(),
    estimated_cost: z.number().nonnegative().max(1_000_000_000).optional(),
    estimated_currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    expected_session_revision: z.number().int().nonnegative().optional().describe("Required for a direct remote API continuation; use preview_turn_approval"),
  },
}, async (args, extra) => {
  try {
    const session = bridge.getSession(args.session_id);
    const agentId = args.agent ?? session.turns.at(-1)?.agentId;
    if (!agentId) throw new Error(`session ${args.session_id} has no turns; use delegate_task`);
    return renderTurn(await bridge.runTurn({ agentId, prompt: args.prompt, sessionId: args.session_id, model: args.model, sandbox: args.sandbox, timeoutSec: args.timeout_sec, signal: extra.signal, allowRemoteEgress: args.allow_remote_egress, dataClassification: args.data_classification, approval_ids: args.approval_ids, estimatedCost: args.estimated_cost, estimatedCurrency: args.estimated_currency, expectedSessionRevision: args.expected_session_revision }));
  } catch (error) { return fail(error); }
});

server.registerTool("handoff", {
  title: "Hand a session to another agent",
  description: "Move an in-progress session to another backend with bridge transcript context. A backend returning after another agent receives every unseen intervening turn.",
  inputSchema: {
    session_id: z.string(), to_agent: z.string(), prompt: z.string().max(1_000_000).optional(),
    model: z.string().optional(), sandbox: sandboxSchema.optional(), timeout_sec: z.number().int().positive().max(7200).optional(),
    allow_remote_egress: z.boolean().optional(), data_classification: dataClassificationSchema.optional(),
    approval_ids: z.array(z.string()).min(1).max(4).optional(),
    estimated_cost: z.number().nonnegative().max(1_000_000_000).optional(),
    estimated_currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    expected_session_revision: z.number().int().nonnegative().optional().describe("Required for a direct remote API handoff; use preview_turn_approval"),
  },
}, async (args, extra) => {
  try {
    const session = bridge.getSession(args.session_id);
    const prompt = args.prompt ?? "Review the work so far, verify the prior conclusions, and continue the task. Call out anything that is incorrect.";
    const same = session.turns.at(-1)?.agentId === args.to_agent;
    const outcome = await bridge.runTurn({ agentId: args.to_agent, prompt, sessionId: args.session_id, model: args.model, sandbox: args.sandbox, timeoutSec: args.timeout_sec, signal: extra.signal, allowRemoteEgress: args.allow_remote_egress, dataClassification: args.data_classification, approval_ids: args.approval_ids, estimatedCost: args.estimated_cost, estimatedCurrency: args.estimated_currency, expectedSessionRevision: args.expected_session_revision });
    return renderTurn(outcome, same ? `note: ${args.to_agent} already held the last turn; this continued it.` : undefined);
  } catch (error) { return fail(error); }
});

server.registerTool("list_sessions", {
  title: "List bridge sessions",
  description: "List recent session metadata without transcript contents or native backend session identifiers.",
  inputSchema: { limit: z.number().int().positive().max(200).optional() },
}, async (args) => {
  try {
    const sessions = bridge.listSessions(args.limit ?? 20).map((session) => ({
      id: session.id, title: session.title, cwd: session.cwd, updatedAt: session.updatedAt,
      revision: session.revision, turns: session.turns.length, agents: [...new Set(session.turns.map((turn) => turn.agentId))],
    }));
    const text = sessions.length ? sessions.map((session) => `- ${session.id}\n  "${session.title}"\n  ${session.turns} turn(s) via ${session.agents.join(" → ")} · revision ${session.revision} · ${session.updatedAt}\n  cwd: ${session.cwd}`).join("\n") : "No bridge sessions yet.";
    return { content: [{ type: "text" as const, text }], structuredContent: { sessions } };
  } catch (error) { return fail(error); }
});

server.registerTool("get_session", {
  title: "Read a projected bridge transcript",
  description: "Read a size-limited transcript. Native backend session ids and unbounded metadata are never returned.",
  inputSchema: { session_id: z.string(), max_chars_per_turn: z.number().int().positive().max(100_000).optional() },
}, async (args) => {
  try {
    const session = projectSession(bridge.getSession(args.session_id), args.max_chars_per_turn ?? 4_000);
    const text = [`session ${session.id} — "${session.title}"`, `cwd: ${session.cwd}`, `revision: ${session.revision}`, "", ...session.turns.map((turn) => `### turn ${turn.index} · ${turn.agentId}${turn.isError ? " · ERROR" : ""}\n**prompt:**\n${turn.prompt}\n\n**response:**\n${turn.response}${turn.stderr ? `\n\n**stderr:**\n${turn.stderr}` : ""}`)].join("\n");
    return { content: [{ type: "text" as const, text }], structuredContent: { session } };
  } catch (error) { return fail(error); }
});

server.registerTool("get_turn_output", {
  title: "Page through a stored bridge turn output",
  description: "Retrieve a bounded page from the full output or stderr stored for one bridge turn. Use output_ref from delegation results when their inline preview was clipped.",
  inputSchema: {
    session_id: z.string(), turn: z.number().int().nonnegative(), field: z.enum(["output", "stderr"]).optional(),
    offset: z.number().int().nonnegative().optional(), max_chars: z.number().int().positive().max(100_000).optional(),
  },
}, async (args) => {
  try {
    const field = args.field ?? "output";
    const page = pageTurnText(bridge.getSession(args.session_id), args.turn, field, args.offset ?? 0, args.max_chars ?? 24_000);
    const header = [
      `bridge_session_id: ${args.session_id}`,
      `turn: ${args.turn}`,
      `field: ${field}`,
      `offset: ${page.offset}`,
      `next_offset: ${page.nextOffset ?? "none"}`,
      `total_chars: ${page.totalChars}`,
    ].join("\n");
    return {
      content: [{ type: "text" as const, text: `${header}\n\n${page.text}` }],
      structuredContent: {
        bridge_session_id: args.session_id, turn: args.turn, field, text: page.text,
        offset: page.offset, next_offset: page.nextOffset, total_chars: page.totalChars, complete: page.complete,
      },
    };
  } catch (error) { return fail(error); }
});

async function doctor(): Promise<number> {
  if (process.argv.includes("--json")) {
    const agents = await bridge.listAgents();
    process.stdout.write(`${JSON.stringify({ diagnostics: diagnostics(), agents: diagnosticAgentEvidence(agents) }, null, 2)}\n`);
    return agents.every((agent) => agent.health.usable) ? 0 : 1;
  }
  process.stdout.write(`agent-bridge doctor\n  node: ${process.version} on ${process.platform}\n  config: ${config.configPath} (${config.configSource})\n  state: ${config.stateDir}\n  sandbox: ${config.defaults.sandbox}\n  allowedRoots:\n    ${config.allowedRoots.join("\n    ")}\n\n`);
  const agents = await bridge.listAgents();
  for (const agent of agents) {
    process.stdout.write(`${agent.health.usable ? "[ok]" : "[NOT USABLE]"} ${agent.id}: binary/api=${agent.health.binary.ok}, auth=${agent.health.auth.status}\n`);
  }
  return agents.every((agent) => agent.health.usable) ? 0 : 1;
}

async function approveFromTty(): Promise<number> {
  const flag = process.argv.indexOf("--approve");
  const id = flag >= 0 ? process.argv[flag + 1] : undefined;
  if (!id) throw new Error("--approve requires an approval id");
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("APPROVAL_TTY_REQUIRED: interactive approval requires a real terminal");
  const record = approvals.get(id);
  if (record.state !== "pending") throw new Error(`APPROVAL_INVALID_TRANSITION: approval ${record.id} is ${record.state}`);
  process.stdout.write(`${buildCliApprovalChallenge(record)}\n\n`);
  const terminal = createInterface({ input: process.stdin, output: process.stdout });
  let response: string | undefined;
  try { response = await terminal.question("> "); }
  finally { terminal.close(); }
  const confirmation = verifyCliApprovalResult(record, response);
  const actor = process.env.USERNAME ?? process.env.USER ?? "interactive-user";
  if (confirmation.accepted) {
    const approved = await approvals.approve(record.id, { approvedBy: actor, reason: "exact interactive TTY challenge accepted" });
    process.stdout.write(`approval ${approved.id}: approved\n`);
    return 0;
  }
  if (confirmation.reason === "declined") {
    const denied = await approvals.deny(record.id, { deniedBy: actor, reason: "interactive TTY challenge declined" });
    process.stdout.write(`approval ${denied.id}: denied\n`);
    return 2;
  }
  process.stderr.write(`approval ${record.id}: not approved (${confirmation.reason})\n`);
  return 2;
}

async function main(): Promise<void> {
  if (process.argv.includes("--approve")) process.exit(await approveFromTty());
  if (process.argv.includes("--doctor")) process.exit(await doctor());
  await server.connect(new StdioServerTransport());
  process.stderr.write(`[agent-bridge] ready · backends: ${bridge.agentIds.join(", ") || "none"} · state: ${config.stateDir} · default sandbox: ${config.defaults.sandbox}\n`);
}

main().catch((error) => {
  process.stderr.write(`[agent-bridge] fatal: ${error instanceof Error ? error.stack : String(error)}\n`);
  process.exit(1);
});
