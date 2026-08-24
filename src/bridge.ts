import { createHash } from "node:crypto";
import type {
  AgentAdapter, AgentHealth, AgentResult, BridgeConfig, BridgeSession,
  NativeSessionPolicy, RunRequest, SandboxMode,
} from "./types.js";
import { assertAllowedCwd } from "./config.js";
import { probe, runProcess } from "./runner.js";
import { buildContextBrief, SessionStore } from "./sessions.js";
import {
  assertCooperativeAgentCompatible, assertRemoteEgressAllowed, assertSandboxAllowed,
  type DataClassification,
} from "./policy.js";
import type { ApprovalCategory, ApprovalDataClass, ApprovalRecord, ApprovalScope, ApprovalStore } from "./approvals.js";
import { approvedCostToCents, type RemoteCostBudgetSnapshot, type RemoteCostBudgetStore } from "./budgets.js";
import {
  isAllowedManusConfirmationInput,
  isSupportedManusWaitingEventType,
  isValidManusEventId,
  isValidManusTaskId,
  ManusAdapter,
  manusConfirmationApprovalCategory,
  type ManusConfirmationInput,
  type ManusWaitingAction,
} from "./adapters/manus.js";

export interface RunTurnOptions {
  agentId: string;
  prompt: string;
  cwd?: string;
  model?: string;
  sandbox?: SandboxMode;
  timeoutSec?: number;
  sessionId?: string;
  forceFresh?: boolean;
  /** Disable configured extraArgs/extraEnv for strict execution paths such as cooperative read-only work. */
  allowAgentConfigExtensions?: boolean;
  /** Cancellation from the MCP caller or daemon request. */
  signal?: AbortSignal;
  /** Fresh caller confirmation required for every remote turn. */
  allowRemoteEgress?: boolean;
  /** Sensitivity of content transmitted to a remote backend. */
  dataClassification?: DataClassification;
  /** Exact approval records authorizing this turn. Remote approvals are consumed immediately before execution. */
  approval_ids?: string[];
  /** Expected provider cost. Omission means unknown and requires paid-or-unknown-cost approval. */
  estimatedCost?: number;
  /** Uppercase ISO-style three-letter currency for the provider cost, including zero-cost estimates. */
  estimatedCurrency?: string;
  /** Optional revision returned by previewTurnApproval; stale previews fail before authorization or launch. */
  expectedSessionRevision?: number;
}

export interface RunTurnOutcome {
  session: BridgeSession;
  result: AgentResult & { durationMs: number };
  continuity: "new" | "native-resume" | "context-replay";
  contextDeltaApplied: boolean;
  agent: AgentAdapter;
}

export interface TurnApprovalPreview {
  scope: ApprovalScope;
  /** Hash of the finalized prompt alone, for operator comparison. */
  promptSha256: string;
  /** Hash of the complete execution envelope; this is the approval payload. */
  payloadSha256: string;
  continuity: RunTurnOutcome["continuity"];
  contextDeltaApplied: boolean;
  sessionRevision: number | null;
  cwd: string;
  agentId: string;
  /** Non-secret fields whose canonical form is covered by payloadSha256. */
  executionEnvelope: TurnApprovalInspectionEnvelope;
}

export interface ManusWaitingSnapshot {
  sessionId: string;
  sessionRevision: number;
  cwd: string;
  action: Omit<ManusWaitingAction, "taskId">;
}

export interface ManusReconciliationOptions {
  sessionId: string;
  allowRemoteEgress: true;
  dataClassification: DataClassification;
  expectedSessionRevision: number;
  timeoutSec?: number;
  signal?: AbortSignal;
}

export interface ManusConfirmationOptions {
  sessionId: string;
  eventId: string;
  input: ManusConfirmationInput;
  allowRemoteEgress: true;
  dataClassification: DataClassification;
  approval_ids?: string[];
  estimatedCost?: number;
  estimatedCurrency?: string;
  expectedSessionRevision?: number;
  timeoutSec?: number;
  signal?: AbortSignal;
}

export interface ManusConfirmationPreview extends ManusWaitingSnapshot {
  scope: ApprovalScope;
  payloadSha256: string;
  requiredCategories: ApprovalCategory[];
  budget: RemoteCostBudgetSnapshot | { enabled: false };
  executionEnvelope: ManusConfirmationInspectionEnvelope;
}

interface TurnPlan {
  expectedRevision: number;
  requestedPolicy: NativeSessionPolicy;
  request: RunRequest;
  continuity: RunTurnOutcome["continuity"];
  contextDeltaApplied: boolean;
}

export interface RemoteTurnApprovalEnvelope {
  schemaVersion: 2;
  prompt: string;
  model: string | null;
  sandbox: SandboxMode;
  timeoutMs: number;
  continuity: RunTurnOutcome["continuity"];
  contextDeltaApplied: boolean;
  forceFresh: boolean;
  nativeResume: boolean;
  bridgeSessionId: string | null;
  sessionRevision: number | null;
  allowAgentConfigExtensions: boolean;
  providerCapabilityPolicy: "manus-v2-empty-connectors-default-skills-v1" | "provider-default";
  providerEndpoint: string | null;
  providerAccountProfile: string | null;
}

export type TurnApprovalInspectionEnvelope = Omit<RemoteTurnApprovalEnvelope, "prompt"> & { promptSha256: string };

export interface ManusConfirmationApprovalEnvelope {
  schemaVersion: 2;
  taskId: string;
  eventId: string;
  eventType: ManusWaitingAction["eventType"];
  input: ManusConfirmationInput;
  providerCapabilityPolicy: "manus-v2-empty-connectors-default-skills-v1";
  providerEndpoint: string;
  providerAccountProfile: string;
}

export type ManusConfirmationInspectionEnvelope = Omit<ManusConfirmationApprovalEnvelope, "taskId">;

export class Bridge {
  constructor(
    readonly config: BridgeConfig,
    readonly registry: Map<string, AgentAdapter>,
    readonly store: SessionStore,
    readonly approvals?: ApprovalStore,
    readonly remoteCostBudget?: RemoteCostBudgetStore,
  ) {}

  get agentIds(): string[] { return [...this.registry.keys()]; }

  budgetStatus(): RemoteCostBudgetSnapshot | { enabled: false } {
    return this.remoteCostBudget?.status() ?? { enabled: false };
  }

  adapter(id: string): AgentAdapter {
    const adapter = this.registry.get(id);
    if (!adapter) throw new Error(`unknown agent "${id}". Available: ${this.agentIds.join(", ") || "(none enabled)"}`);
    return adapter;
  }

  cooperativeAdapter(id: string): AgentAdapter {
    return assertCooperativeAgentCompatible(this.adapter(id));
  }

  async listAgents(signal?: AbortSignal): Promise<Array<{
    id: string;
    displayName: string;
    bin: string;
    health: AgentHealth;
    capabilities: AgentAdapter["capabilities"];
    cooperativeReady: boolean;
    cooperativeReason?: string;
    defaultModel?: string;
  }>> {
    return Promise.all([...this.registry.values()].map(async (adapter) => {
      let health: AgentHealth;
      try {
        const remoteHealth = (adapter as any).health as undefined | ((options?: { signal?: AbortSignal }) => Promise<AgentHealth>);
        if (remoteHealth) {
          health = await remoteHealth.call(adapter, { signal });
        } else {
          if (!adapter.bin || !adapter.versionArgs) throw new Error(`adapter ${adapter.id} has neither remote health nor a local binary probe`);
          const version = await probe(adapter.bin, adapter.versionArgs, adapter.id, signal);
          const versionText = (version.stdout || version.stderr).trim().split("\n")[0];
          const binary = version.exitCode === 0
            ? { ok: true, version: versionText || "version unknown" }
            : { ok: false, error: versionText || `exit ${version.exitCode}` };
          let auth: AgentHealth["auth"] = { status: "unknown", detail: "adapter has no authentication probe" };
          if (binary.ok && adapter.authSpec && adapter.parseAuth) {
            const spec = adapter.authSpec();
            const raw = await runProcess(spec, { cwd: process.cwd(), timeoutMs: 10_000, agentId: adapter.id, signal });
            auth = adapter.parseAuth(raw);
          }
          // An unrecognised authentication response is not evidence that a
          // backend can accept delegated work. Treat it as unavailable until an
          // adapter explicitly proves authentication.
          health = { binary, auth, usable: binary.ok && auth.status === "authenticated" };
        }
      } catch {
        // One broken or unreadable backend must not suppress evidence for all
        // other adapters. Do not surface provider/CLI exception text here.
        health = { binary: { ok: false, error: "health probe failed" }, auth: { status: "unknown" }, usable: false };
      }
      return {
        id: adapter.id,
        displayName: adapter.displayName,
        bin: adapter.bin ?? "remote API",
        health,
        capabilities: adapter.capabilities,
        ...cooperativeReadiness(adapter),
        defaultModel: this.config.agents[adapter.id]?.defaultModel,
      };
    }));
  }

  getSession(id: string): BridgeSession { return this.store.get(id); }
  listSessions(limit: number): BridgeSession[] { return this.store.list(limit); }

  getManusWaitingAction(sessionId: string): ManusWaitingSnapshot {
    const session = this.store.get(sessionId);
    const action = persistedManusWaitingAction(session);
    return {
      sessionId: session.id,
      sessionRevision: session.revision,
      cwd: session.cwd,
      action: publicManusWaitingAction(action),
    };
  }

  async reconcileManusTask(options: ManusReconciliationOptions): Promise<RunTurnOutcome> {
    options.signal?.throwIfAborted();
    return this.store.withLock(options.sessionId, async () => {
      const session = this.store.get(options.sessionId);
      if (!Number.isSafeInteger(options.expectedSessionRevision) || options.expectedSessionRevision < 0) {
        throw new Error("SESSION_REVISION_INVALID: expectedSessionRevision must be a non-negative integer");
      }
      if (session.revision !== options.expectedSessionRevision) {
        throw new Error(`SESSION_REVISION_MISMATCH: expected revision ${options.expectedSessionRevision}, current revision ${session.revision}; inspect again`);
      }
      const latest = [...session.turns].reverse().find((turn) => turn.agentId === "manus");
      const status = latest?.meta?.taskStatus;
      if (status === "waiting") throw new Error("MANUS_WAITING_ACTION_REQUIRES_CONFIRMATION: use the dedicated waiting-action flow");
      if (status === "stopped") throw new Error("MANUS_RECONCILIATION_NOT_REQUIRED: the task is already stopped and may be continued normally");
      const taskId = session.nativeSessions.manus;
      if (!taskId || !isValidManusTaskId(taskId)) throw new Error("MANUS_RECONCILIATION_TASK_MISSING: session has no valid persisted Manus task");
      const cwd = assertAllowedCwd(session.cwd, this.config);
      assertRemoteEgressAllowed({
        config: this.config,
        agentId: "manus",
        cwd,
        allowRemoteEgress: options.allowRemoteEgress,
        dataClassification: options.dataClassification,
      });
      const agent = this.adapter("manus");
      if (!isManusAdapter(agent)) throw new Error("MANUS_ADAPTER_REQUIRED: configured manus backend cannot reconcile tasks");
      agent.assertProviderReady();
      const timeoutSec = options.timeoutSec ?? Math.min(this.config.defaults.timeoutSec, 120);
      if (!Number.isSafeInteger(timeoutSec) || timeoutSec < 1 || timeoutSec > 300) {
        throw new Error("MANUS_RECONCILIATION_TIMEOUT_INVALID: timeoutSec must be an integer from 1 to 300");
      }
      const startedAt = new Date().toISOString();
      const result = await agent.reconcileTask(taskId, timeoutSec * 1_000, { signal: options.signal });
      const finalized = { ...result, durationMs: result.durationMs ?? 0 };
      this.store.record(session, "manus", "[Manus reconciliation poll; no user message sent]", finalized, startedAt, session.revision);
      return { session, result: finalized, continuity: "native-resume", contextDeltaApplied: false, agent };
    });
  }

  async previewManusConfirmation(options: Omit<ManusConfirmationOptions, "approval_ids" | "estimatedCost" | "estimatedCurrency" | "expectedSessionRevision" | "timeoutSec">): Promise<ManusConfirmationPreview> {
    options.signal?.throwIfAborted();
    return this.store.withLock(options.sessionId, async () => {
      const session = this.store.get(options.sessionId);
      const action = persistedManusWaitingAction(session);
      assertManusConfirmationMatches(action, options.eventId, options.input);
      assertRemoteEgressAllowed({
        config: this.config,
        agentId: "manus",
        cwd: assertAllowedCwd(session.cwd, this.config),
        allowRemoteEgress: options.allowRemoteEgress,
        dataClassification: options.dataClassification,
      });
      const cwd = assertAllowedCwd(session.cwd, this.config);
      const agent = this.adapter("manus");
      if (!isManusAdapter(agent)) throw new Error("MANUS_ADAPTER_REQUIRED: configured manus backend cannot confirm actions");
      agent.assertProviderReady();
      const identity = agent.approvalCapabilityIdentity();
      const envelope = manusConfirmationApprovalEnvelope(action, options.input, identity);
      const scope = deriveManusConfirmationApprovalScope(session, action, options.input, options.dataClassification, cwd, identity);
      return {
        sessionId: session.id,
        sessionRevision: session.revision,
        cwd: session.cwd,
        action: publicManusWaitingAction(action),
        scope,
        payloadSha256: scope.payloadSha256,
        requiredCategories: manusConfirmationCategories(action),
        budget: this.budgetStatus(),
        executionEnvelope: inspectManusConfirmationApprovalEnvelope(envelope),
      };
    });
  }

  async confirmManusAction(options: ManusConfirmationOptions): Promise<RunTurnOutcome> {
    options.signal?.throwIfAborted();
    return this.store.withLock(options.sessionId, async () => {
      const session = this.store.get(options.sessionId);
      if (options.expectedSessionRevision === undefined) {
        throw new Error("SESSION_REVISION_REQUIRED: Manus confirmation requires expectedSessionRevision from preview_manus_confirmation");
      }
      if (!Number.isSafeInteger(options.expectedSessionRevision) || options.expectedSessionRevision < 0) {
        throw new Error("SESSION_REVISION_INVALID: expectedSessionRevision must be a non-negative integer");
      }
      if (session.revision !== options.expectedSessionRevision) {
        throw new Error(`SESSION_REVISION_MISMATCH: expected revision ${options.expectedSessionRevision}, current revision ${session.revision}; preview again`);
      }
      const action = persistedManusWaitingAction(session);
      assertManusConfirmationMatches(action, options.eventId, options.input);
      const cwd = assertAllowedCwd(session.cwd, this.config);
      assertRemoteEgressAllowed({
        config: this.config,
        agentId: "manus",
        cwd,
        allowRemoteEgress: options.allowRemoteEgress,
        dataClassification: options.dataClassification,
      });
      const agent = this.adapter("manus");
      if (!isManusAdapter(agent)) throw new Error("MANUS_ADAPTER_REQUIRED: configured manus backend cannot confirm actions");
      agent.assertProviderReady();
      const timeoutSec = options.timeoutSec ?? this.config.defaults.timeoutSec;
      if (!Number.isSafeInteger(timeoutSec) || timeoutSec < 1 || timeoutSec > 7_200) {
        throw new Error("MANUS_CONFIRMATION_TIMEOUT_INVALID: timeoutSec must be an integer from 1 to 7200");
      }
      const identity = agent.approvalCapabilityIdentity();
      const scope = deriveManusConfirmationApprovalScope(session, action, options.input, options.dataClassification, cwd, identity);
      const commitAuthority = this.prepareManusConfirmationAuthorization(session, action, scope, options);
      const startedAt = new Date().toISOString();
      const started = Date.now();
      await agent.confirmActionAuthorized(action.taskId, action.eventId, options.input, async () => {
        await commitAuthority();
        const attempted: AgentResult & { durationMs: number } = {
          text: "Manus confirmation authority was consumed; provider acceptance is not yet known.",
          nativeSessionId: action.taskId,
          exitCode: null,
          isError: true,
          stderr: "",
          timedOut: false,
          durationMs: Date.now() - started,
          meta: { taskStatus: "confirmation_attempted", eventId: action.eventId, eventType: action.eventType, payloadSha256: scope.payloadSha256 },
        };
        // Persist after live revalidation but before the non-idempotent POST.
        // A lost response therefore requires provider-side reconciliation,
        // while a stale live action consumes no authority.
        this.store.record(
          session,
          "manus",
          `[Manus confirmation attempt authorized: ${action.eventType}; payload sha256 ${scope.payloadSha256}]`,
          attempted,
          startedAt,
          session.revision,
        );
      }, { signal: options.signal });
      const accepted: AgentResult & { durationMs: number } = {
        text: "Manus accepted the exact waiting-action confirmation; completion is pending.",
        nativeSessionId: action.taskId,
        exitCode: 0,
        isError: false,
        stderr: "",
        timedOut: false,
        durationMs: Date.now() - started,
        meta: { taskStatus: "confirmation_accepted", eventId: action.eventId, eventType: action.eventType, payloadSha256: scope.payloadSha256 },
      };
      this.store.record(
        session,
        "manus",
        `[Manus waiting action accepted: ${action.eventType}; payload sha256 ${scope.payloadSha256}]`,
        accepted,
        startedAt,
        session.revision,
      );
      const timeoutMs = timeoutSec * 1_000;
      const result = await agent.waitForTask(action.taskId, timeoutMs, { signal: options.signal });
      const durationMs = result.durationMs ?? 0;
      const finalized = { ...result, durationMs };
      this.store.record(
        session,
        "manus",
        `[Manus task result after confirmed action: ${action.eventType}; payload sha256 ${scope.payloadSha256}]`,
        finalized,
        startedAt,
        session.revision,
      );
      return { session, result: finalized, continuity: "native-resume", contextDeltaApplied: false, agent };
    });
  }

  async previewTurnApproval(options: RunTurnOptions): Promise<TurnApprovalPreview> {
    options.signal?.throwIfAborted();
    const agent = this.adapter(options.agentId);
    this.assertRemoteAdapterLocallyReady(agent);
    if (!(agent.capabilities.directRemoteApi ?? agent.capabilities.remote ?? false)) {
      throw new Error(`APPROVAL_PREVIEW_NOT_REMOTE: ${agent.id} is not a direct remote API backend`);
    }
    if (options.expectedSessionRevision !== undefined) {
      throw new Error("APPROVAL_PREVIEW_INPUT_INVALID: expectedSessionRevision is an execution guard, not a preview input");
    }
    if (options.sessionId) {
      return this.store.withLock(options.sessionId, async () => {
        const session = this.store.get(options.sessionId!);
        return this.previewLocked(session, agent, options, session.revision);
      });
    }
    const cwd = this.resolveCwd(options.cwd);
    const now = new Date().toISOString();
    const ephemeral: BridgeSession = {
      schemaVersion: 1, id: "approval-preview", title: "Approval preview", cwd,
      createdAt: now, updatedAt: now, revision: 0, nativeSessions: {},
      nativeSessionPolicies: {}, lastSeenTurnByAgent: {}, turns: [],
    };
    return this.previewLocked(ephemeral, agent, options, null);
  }

  async runTurn(options: RunTurnOptions): Promise<RunTurnOutcome> {
    options.signal?.throwIfAborted();
    const agent = this.adapter(options.agentId);
    let sessionId = options.sessionId;
    let createdNew = false;
    if (!sessionId) {
      if (options.expectedSessionRevision !== undefined) {
        throw new Error("SESSION_REVISION_MISMATCH: expectedSessionRevision requires an existing session");
      }
      const cwd = this.resolveCwd(options.cwd);
      const session = this.store.create({ title: options.prompt.split("\n")[0] ?? "Untitled", cwd });
      sessionId = session.id;
      createdNew = true;
    }
    const lockedSessionId = sessionId;
    try {
      return await this.store.withLock(lockedSessionId, async () => {
        const session = this.store.get(lockedSessionId);
        return this.runLocked(session, agent, options);
      });
    } catch (error) {
      if (createdNew) {
        try {
          const current = this.store.get(lockedSessionId);
          if (current.turns.length === 0) this.store.delete(lockedSessionId);
        } catch { /* best-effort rollback */ }
      }
      throw error;
    }
  }

  private async runLocked(session: BridgeSession, agent: AgentAdapter, options: RunTurnOptions): Promise<RunTurnOutcome> {
    const plan = this.planLocked(session, agent, options);
    const { expectedRevision, requestedPolicy, request, continuity, contextDeltaApplied } = plan;
    const { cwd, timeoutMs } = request;
    const execute = agent.execute;
    const buildSpawn = agent.buildSpawn;
    const parse = agent.parse;
    if (!execute && (!buildSpawn || !parse)) throw new Error(`adapter ${agent.id} has no execution implementation`);
    const manus = isManusAdapter(agent) ? agent : undefined;
    if (agent.capabilities.directRemoteApi ?? agent.capabilities.remote ?? false) {
      options.signal?.throwIfAborted();
      this.assertRemoteAdapterLocallyReady(agent, request);
      if (!manus) await this.authorizeRemoteTurn(session, agent.id, plan, options);
    }
    options.signal?.throwIfAborted();
    const startedAt = new Date().toISOString();
    const started = Date.now();
    let parsed: AgentResult;
    if (execute) {
      try {
        parsed = manus
          ? await manus.executeAuthorized(request, () => this.authorizeRemoteTurn(session, agent.id, plan, options), { signal: options.signal })
          : await execute.call(agent, request, { signal: options.signal });
      } catch (error: any) {
        if (error?.code === "waiting" && typeof error?.taskId === "string") {
          parsed = {
            text: error.message,
            nativeSessionId: error.taskId,
            exitCode: null,
            isError: true,
            stderr: "",
            timedOut: false,
            meta: { waiting: true, code: error.code },
          };
        } else {
          throw error;
        }
      }
    } else {
      const spec = buildSpawn!.call(agent, request);
      const raw = await runProcess(spec, { cwd, timeoutMs, agentId: agent.id, signal: options.signal });
      parsed = parse!.call(agent, raw);
    }
    const result = { ...parsed, durationMs: Date.now() - started };
    session.nativeSessionPolicies[agent.id] = requestedPolicy;
    this.store.record(session, agent.id, options.prompt, result, startedAt, expectedRevision);
    return { session, result, continuity, contextDeltaApplied, agent };
  }

  private planLocked(session: BridgeSession, agent: AgentAdapter, options: RunTurnOptions, preview = false): TurnPlan {
    const expectedRevision = session.revision;
    const directRemoteApi = agent.capabilities.directRemoteApi ?? agent.capabilities.remote ?? false;
    if (!preview && directRemoteApi && options.sessionId && options.expectedSessionRevision === undefined) {
      throw new Error("SESSION_REVISION_REQUIRED: direct remote turns on an existing session require expectedSessionRevision from previewTurnApproval");
    }
    if (options.expectedSessionRevision !== undefined) {
      if (!Number.isSafeInteger(options.expectedSessionRevision) || options.expectedSessionRevision < 0) {
        throw new Error("SESSION_REVISION_INVALID: expectedSessionRevision must be a non-negative integer");
      }
      if (options.expectedSessionRevision !== expectedRevision) {
        throw new Error(`SESSION_REVISION_MISMATCH: expected revision ${options.expectedSessionRevision}, current revision ${expectedRevision}; preview again`);
      }
    }
    const requestedCwd = options.cwd ? this.resolveCwd(options.cwd) : session.cwd;
    if (normalize(requestedCwd) !== normalize(session.cwd)) {
      throw new Error(`a bridge session cannot change cwd from "${session.cwd}" to "${requestedCwd}"; start a new session`);
    }
    // Canonicalize again immediately before launch to catch a junction target
    // changed after config startup.
    const cwd = assertAllowedCwd(session.cwd, this.config);
    const agentConfig = this.config.agents[agent.id] ?? {};
    const model = options.model ?? agentConfig.defaultModel;
    const sandbox = assertSandboxAllowed(options.sandbox ?? this.config.defaults.sandbox, this.config, agent.id);
    if (agent.capabilities.directRemoteApi ?? agent.capabilities.remote ?? false) {
      assertRemoteEgressAllowed({
        config: this.config,
        agentId: agent.id,
        cwd,
        allowRemoteEgress: options.allowRemoteEgress,
        dataClassification: options.dataClassification,
      });
    }
    const timeoutMs = (options.timeoutSec ?? this.config.defaults.timeoutSec) * 1_000;
    const requestedPolicy: NativeSessionPolicy = { cwd, sandbox, model };
    const nativeId = session.nativeSessions[agent.id];
    const priorPolicy = session.nativeSessionPolicies[agent.id];
    const nativePolicyCompatible = !priorPolicy || samePolicy(priorPolicy, requestedPolicy);

    let continuity: RunTurnOutcome["continuity"] = "new";
    let prompt = options.prompt;
    let resumeSessionId: string | undefined;
    let contextDeltaApplied = false;
    if (!options.forceFresh && session.turns.length > 0) {
      if (nativeId && isManusAdapter(agent)) assertManusNativeResumeEligible(session, agent.id);
      if (nativeId && agent.capabilities.resume && nativePolicyCompatible) {
        resumeSessionId = nativeId;
        continuity = "native-resume";
        const lastSeen = session.lastSeenTurnByAgent[agent.id] ?? -1;
        const unseenOtherTurns = session.turns.some((turn) => turn.index > lastSeen && turn.agentId !== agent.id);
        if (unseenOtherTurns) {
          const delta = buildContextBrief(session, this.config.handoffMaxChars, lastSeen);
          prompt = `${delta}${options.prompt}`;
          contextDeltaApplied = true;
        }
      } else {
        const brief = buildContextBrief(session, this.config.handoffMaxChars);
        if (brief) prompt = `${brief}${options.prompt}`;
        continuity = "context-replay";
        contextDeltaApplied = true;
      }
    }

    const request: RunRequest = {
      prompt,
      cwd,
      model,
      sandbox,
      timeoutMs,
      resumeSessionId,
      extraArgs: options.allowAgentConfigExtensions === false ? undefined : agentConfig.extraArgs,
      extraEnv: options.allowAgentConfigExtensions === false ? undefined : agentConfig.extraEnv,
    };
    return { expectedRevision, requestedPolicy, request, continuity, contextDeltaApplied };
  }

  private previewLocked(session: BridgeSession, agent: AgentAdapter, options: RunTurnOptions, sessionRevision: number | null): TurnApprovalPreview {
    const plan = this.planLocked(session, agent, options, true);
    this.assertRemoteAdapterLocallyReady(agent, plan.request);
    if (!options.dataClassification) throw new Error("REMOTE_EGRESS_DATA_CLASS_REQUIRED");
    const envelope = this.remoteTurnApprovalEnvelope(session, agent.id, plan, options);
    const scope = deriveRemoteTurnApprovalScope({
      agentId: agent.id,
      cwd: plan.request.cwd,
      dataClassification: options.dataClassification,
      envelope,
    });
    return {
      scope,
      promptSha256: payloadSha256(plan.request.prompt),
      payloadSha256: scope.payloadSha256,
      continuity: plan.continuity,
      contextDeltaApplied: plan.contextDeltaApplied,
      sessionRevision,
      cwd: plan.request.cwd,
      agentId: agent.id,
      executionEnvelope: inspectRemoteTurnApprovalEnvelope(envelope),
    };
  }

  private resolveCwd(value?: string): string {
    const target = value ?? this.config.defaults.cwd;
    if (!target) throw new Error("cwd is required; pass an allowed project directory or set defaults.cwd");
    return assertAllowedCwd(target, this.config);
  }

  private assertRemoteAdapterLocallyReady(agent: AgentAdapter, request?: Pick<RunRequest, "prompt" | "model">): void {
    if (!isManusAdapter(agent)) return;
    if (request) agent.assertRequestSupported(request);
    else agent.assertProviderReady();
  }

  private remoteTurnApprovalEnvelope(
    session: BridgeSession,
    agentId: string,
    plan: TurnPlan,
    options: RunTurnOptions,
  ): RemoteTurnApprovalEnvelope {
    const adapter = this.adapter(agentId);
    const manusIdentity = isManusAdapter(adapter) ? adapter.approvalCapabilityIdentity() : undefined;
    return {
      schemaVersion: 2,
      prompt: plan.request.prompt,
      model: plan.request.model ?? null,
      sandbox: plan.request.sandbox,
      timeoutMs: plan.request.timeoutMs,
      continuity: plan.continuity,
      contextDeltaApplied: plan.contextDeltaApplied,
      forceFresh: options.forceFresh === true,
      nativeResume: plan.request.resumeSessionId !== undefined,
      bridgeSessionId: options.sessionId ?? null,
      sessionRevision: options.sessionId ? plan.expectedRevision : null,
      allowAgentConfigExtensions: options.allowAgentConfigExtensions !== false,
      providerCapabilityPolicy: manusIdentity?.policyVersion ?? "provider-default",
      providerEndpoint: manusIdentity?.endpoint ?? null,
      providerAccountProfile: manusIdentity?.accountProfile ?? null,
    };
  }

  private async authorizeRemoteTurn(session: BridgeSession, agentId: string, plan: TurnPlan, options: RunTurnOptions): Promise<void> {
    if (!this.approvals) throw new Error("APPROVAL_STORE_REQUIRED: remote egress cannot run without a configured approval store");
    if (options.estimatedCost !== undefined && (!Number.isFinite(options.estimatedCost) || options.estimatedCost < 0)) {
      throw new Error("APPROVAL_INVALID_COST: estimatedCost must be a finite non-negative number");
    }
    if (typeof options.estimatedCurrency !== "string" || !/^[A-Z]{3}$/.test(options.estimatedCurrency)) {
      throw new Error("APPROVAL_INVALID_CURRENCY: remote turns require an uppercase three-letter estimatedCurrency");
    }
    const dataClass = options.dataClassification;
    if (!dataClass) throw new Error("REMOTE_EGRESS_DATA_CLASS_REQUIRED");
    const envelope = this.remoteTurnApprovalEnvelope(session, agentId, plan, options);
    const scope = deriveRemoteTurnApprovalScope({ agentId, cwd: plan.request.cwd, dataClassification: dataClass, envelope });
    const requiredCategories: ApprovalCategory[] = ["remote_egress", "paid_or_unknown_cost"];
    const ids = options.approval_ids ?? [];
    if (ids.length !== requiredCategories.length || new Set(ids).size !== ids.length) {
      throw new Error(`APPROVAL_REQUIRED: remote turn requires one distinct approval for each category: ${requiredCategories.join(", ")}`);
    }

    // Preflight every record before consuming any. ApprovalStore.consume takes
    // the per-record lock and revalidates state, expiry, scope, and use limits.
    // Records are separate files, so consumption cannot be transactional across
    // categories; deterministic category/ID ordering limits the failure surface.
    const records = ids.map((id) => this.approvals!.get(id));
    const byCategory = new Map<ApprovalCategory, ApprovalRecord>();
    for (const record of records) {
      if (!requiredCategories.includes(record.category)) {
        throw new Error(`APPROVAL_CATEGORY_MISMATCH: approval ${record.id} has category ${record.category}`);
      }
      if (byCategory.has(record.category)) {
        throw new Error(`APPROVAL_REQUIRED: duplicate ${record.category} approval supplied`);
      }
      prevalidateApproval(record, scope);
      byCategory.set(record.category, record);
    }
    for (const category of requiredCategories) {
      if (!byCategory.has(category)) throw new Error(`APPROVAL_REQUIRED: missing ${category} approval`);
    }
    const paid = byCategory.get("paid_or_unknown_cost");
    if (paid) validateCostApproval(paid, options.estimatedCost, options.estimatedCurrency);

    const budgetPolicy = this.config.policy?.cumulativeRemoteCost;
    if (budgetPolicy) {
      if (!this.remoteCostBudget) throw new Error("CUMULATIVE_BUDGET_STORE_REQUIRED: configured remote-cost policy has no ledger");
      if (!paid) throw new Error("CUMULATIVE_BUDGET_APPROVAL_REQUIRED");
      const cents = approvedCostToCents(paid.estimatedCost, paid.currency);
      await this.remoteCostBudget.reserve({
        approvalId: paid.id,
        agentId,
        sessionId: session.id,
        turnIndex: session.turns.length,
        cents,
      });
    }

    const ordered = requiredCategories
      .map((category) => byCategory.get(category)!)
      .sort((left, right) => left.category.localeCompare(right.category) || left.id.localeCompare(right.id));
    for (const record of ordered) {
      await this.approvals.consume(record.id, {
        consumedBy: "agent-bridge",
        scope,
        reason: `authorized remote delegated turn for ${agentId}`,
      });
    }
  }

  private prepareManusConfirmationAuthorization(
    session: BridgeSession,
    action: ManusWaitingAction,
    scope: ApprovalScope,
    options: ManusConfirmationOptions,
  ): () => Promise<void> {
    if (!this.approvals) throw new Error("APPROVAL_STORE_REQUIRED: Manus confirmation requires a configured approval store");
    const requiredCategories = manusConfirmationCategories(action);
    const ids = options.approval_ids ?? [];
    if (ids.length !== requiredCategories.length || new Set(ids).size !== ids.length) {
      throw new Error(`APPROVAL_REQUIRED: Manus confirmation requires one distinct approval for each category: ${requiredCategories.join(", ")}`);
    }
    const records = ids.map((id) => this.approvals!.get(id));
    const byCategory = new Map<ApprovalCategory, ApprovalRecord>();
    for (const record of records) {
      if (!requiredCategories.includes(record.category)) throw new Error(`APPROVAL_CATEGORY_MISMATCH: approval ${record.id} has category ${record.category}`);
      if (byCategory.has(record.category)) throw new Error(`APPROVAL_REQUIRED: duplicate ${record.category} approval supplied`);
      prevalidateApproval(record, scope);
      byCategory.set(record.category, record);
    }
    for (const category of requiredCategories) if (!byCategory.has(category)) throw new Error(`APPROVAL_REQUIRED: missing ${category} approval`);

    const actionCategory = manusConfirmationApprovalCategory(action);
    if (actionCategory === "paid_or_unknown_cost") {
      const paid = byCategory.get("paid_or_unknown_cost")!;
      if (typeof options.estimatedCurrency !== "string" || !/^[A-Z]{3}$/.test(options.estimatedCurrency)) {
        throw new Error("APPROVAL_INVALID_CURRENCY: paid Manus confirmations require an uppercase three-letter estimatedCurrency");
      }
      if (action.eventType === "apiHighCreditNotice") {
        if (options.estimatedCost !== 0 || options.estimatedCurrency !== "USD" || paid.estimatedCost !== 0 || paid.currency !== "USD") {
          throw new Error("APPROVAL_COST_MISMATCH: rejecting a Manus high-credit notice requires an exact zero USD approval");
        }
      } else {
        if (options.estimatedCost === undefined || !Number.isFinite(options.estimatedCost) || options.estimatedCost <= 0) {
          throw new Error("APPROVAL_BOUNDED_COST_REQUIRED: Manus video confirmation requires a positive bounded cost estimate");
        }
        validateCostApproval(paid, options.estimatedCost, options.estimatedCurrency);
        if (this.config.policy?.cumulativeRemoteCost && !this.remoteCostBudget) {
          throw new Error("CUMULATIVE_BUDGET_STORE_REQUIRED: configured remote-cost policy has no ledger");
        }
      }
    } else if (options.estimatedCost !== undefined || options.estimatedCurrency !== undefined) {
      throw new Error("APPROVAL_COST_NOT_APPLICABLE: this Manus confirmation does not accept cost fields");
    }

    const ordered = requiredCategories
      .map((category) => byCategory.get(category)!)
      .sort((left, right) => left.category.localeCompare(right.category) || left.id.localeCompare(right.id));
    return async () => {
      // Re-read exact authority after live provider revalidation and before any
      // budget or approval mutation.
      for (const record of ordered) prevalidateApproval(this.approvals!.get(record.id), scope);
      if (actionCategory === "paid_or_unknown_cost" && action.eventType === "videoGenerate" && this.config.policy?.cumulativeRemoteCost) {
        const paid = byCategory.get("paid_or_unknown_cost")!;
        const cents = approvedCostToCents(paid.estimatedCost, paid.currency);
        await this.remoteCostBudget!.reserve({
          approvalId: paid.id,
          agentId: "manus",
          sessionId: session.id,
          turnIndex: session.turns.length,
          cents,
        });
      }
      for (const record of ordered) {
        await this.approvals!.consume(record.id, {
          consumedBy: "agent-bridge",
          scope,
          reason: `authorized exact Manus waiting action ${action.eventType}`,
        });
      }
    };
  }
}

function normalize(value: string): string { return process.platform === "win32" ? value.toLowerCase() : value; }

function prevalidateApproval(record: ApprovalRecord, scope: ApprovalScope): void {
  if (record.state !== "approved") throw new Error(`APPROVAL_NOT_APPROVED: approval ${record.id} is ${record.state}`);
  if (!record.consumeOnce || record.maxUses !== 1 || record.useCount !== 0) {
    throw new Error(`APPROVAL_REUSABLE_FORBIDDEN: ${record.category} approval ${record.id} must be fresh and one-time`);
  }
  if (Date.parse(record.expiresAt) <= Date.now()) throw new Error(`APPROVAL_EXPIRED: approval ${record.id} expired before execution`);
  if (record.useCount >= record.maxUses) throw new Error(`APPROVAL_USE_LIMIT: approval ${record.id} has no uses remaining`);
  if (!sameApprovalScope(record.scope, scope)) {
    throw new Error(`APPROVAL_SCOPE_MISMATCH: approval ${record.id} does not authorize this remote turn`);
  }
}

function validateCostApproval(record: ApprovalRecord, estimatedCost: number | undefined, estimatedCurrency: string): void {
  if (record.currency !== estimatedCurrency) {
    throw new Error(`APPROVAL_CURRENCY_MISMATCH: approval ${record.id} is denominated in ${record.currency ?? "no currency"}, not ${estimatedCurrency}`);
  }
  if (estimatedCost === undefined) {
    if (record.estimatedCost !== null) throw new Error(`APPROVAL_COST_MISMATCH: approval ${record.id} does not authorize unknown cost`);
    return;
  }
  if (estimatedCost > 0 && (record.estimatedCost === null || record.estimatedCost < estimatedCost)) {
    throw new Error(`APPROVAL_COST_MISMATCH: approval ${record.id} does not cover estimated cost`);
  }
}

function sameApprovalScope(left: ApprovalScope, right: ApprovalScope): boolean {
  return left.subject === right.subject && left.action === right.action && left.dataClass === right.dataClass
    && left.root === right.root && left.agent === right.agent && left.payloadSha256 === right.payloadSha256;
}

export function payloadSha256(payload: string): string {
  return createHash("sha256").update(payload, "utf8").digest("hex");
}

/** Derive the exact scope a remote turn must present after its outbound prompt is finalized. */
export function deriveRemoteTurnApprovalScope(input: {
  agentId: string;
  cwd: string;
  dataClassification: ApprovalDataClass;
  envelope: RemoteTurnApprovalEnvelope;
}): ApprovalScope {
  return {
    subject: "agent-bridge:delegate_task",
    action: `delegate:${input.agentId}`,
    dataClass: input.dataClassification,
    root: input.cwd,
    agent: input.agentId,
    payloadSha256: payloadSha256(JSON.stringify(input.envelope)),
  };
}

export function inspectRemoteTurnApprovalEnvelope(envelope: RemoteTurnApprovalEnvelope): TurnApprovalInspectionEnvelope {
  const { prompt, ...visible } = envelope;
  return { ...visible, promptSha256: payloadSha256(prompt) };
}


export function deriveManusConfirmationApprovalScope(
  session: BridgeSession,
  action: ManusWaitingAction,
  input: ManusConfirmationInput,
  dataClassification: ApprovalDataClass,
  canonicalCwd: string,
  providerIdentity: ReturnType<ManusAdapter["approvalCapabilityIdentity"]>,
): ApprovalScope {
  const envelope = manusConfirmationApprovalEnvelope(action, input, providerIdentity);
  return {
    subject: "agent-bridge:manus_confirm_action",
    action: `confirm:${action.eventType}`,
    dataClass: dataClassification,
    root: canonicalCwd,
    agent: "manus",
    payloadSha256: payloadSha256(JSON.stringify(envelope)),
  };
}

export function manusConfirmationApprovalEnvelope(
  action: ManusWaitingAction,
  input: ManusConfirmationInput,
  providerIdentity: ReturnType<ManusAdapter["approvalCapabilityIdentity"]>,
): ManusConfirmationApprovalEnvelope {
  return {
    schemaVersion: 2,
    taskId: action.taskId,
    eventId: action.eventId,
    eventType: action.eventType,
    input,
    providerCapabilityPolicy: providerIdentity.policyVersion,
    providerEndpoint: providerIdentity.endpoint,
    providerAccountProfile: providerIdentity.accountProfile,
  };
}

export function inspectManusConfirmationApprovalEnvelope(envelope: ManusConfirmationApprovalEnvelope): ManusConfirmationInspectionEnvelope {
  const { taskId: _taskId, ...visible } = envelope;
  return visible;
}

function persistedManusWaitingAction(session: BridgeSession): ManusWaitingAction {
  const nativeTaskId = session.nativeSessions.manus;
  if (!nativeTaskId) throw new Error(`MANUS_WAITING_ACTION_MISSING: session ${session.id} has no Manus task`);
  const turn = [...session.turns].reverse().find((candidate) => candidate.agentId === "manus");
  const raw = turn?.meta?.waitingAction;
  if (turn?.meta?.taskStatus !== "waiting" || !raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`MANUS_WAITING_ACTION_MISSING: session ${session.id} has no persisted confirmable Manus action`);
  }
  const value = raw as Record<string, unknown>;
  const keys = Object.keys(value).sort();
  const allowed = ["eventId", "eventType", "taskId"];
  if (keys.some((key) => !allowed.includes(key)) || value.taskId !== nativeTaskId
      || typeof value.taskId !== "string" || !isValidManusTaskId(value.taskId)
      || typeof value.eventId !== "string" || !isValidManusEventId(value.eventId)
      || typeof value.eventType !== "string" || !isSupportedManusWaitingEventType(value.eventType)) {
    throw new Error(`MANUS_WAITING_ACTION_INVALID: session ${session.id} has corrupt waiting-action metadata`);
  }
  const action = value as unknown as ManusWaitingAction;
  if (!isAllowedManusConfirmationInput(action.eventType, defaultManusConfirmationInput(action.eventType))) {
    throw new Error(`MANUS_WAITING_ACTION_UNSUPPORTED: session ${session.id} has an unsupported Manus action`);
  }
  return action;
}

function defaultManusConfirmationInput(eventType: ManusWaitingAction["eventType"]): ManusConfirmationInput {
  if (eventType === "needConnectMyBrowser") return { action: "skip" };
  if (eventType === "gmailSendAction" || eventType === "outlookSendMailsAction") return { accept: true, save_draft: true };
  if (eventType === "videoGenerate") return { choice: "standard" };
  return { action: "reject" };
}

function assertManusConfirmationMatches(action: ManusWaitingAction, eventId: string, input: ManusConfirmationInput): void {
  if (eventId !== action.eventId) throw new Error("MANUS_WAITING_ACTION_STALE: event id changed; inspect and preview again");
  if (!isAllowedManusConfirmationInput(action.eventType, input)) {
    throw new Error(`MANUS_CONFIRMATION_INPUT_DENIED: input is not allowed for ${action.eventType}`);
  }
}

function manusConfirmationCategories(action: ManusWaitingAction): ApprovalCategory[] {
  return ["remote_egress", manusConfirmationApprovalCategory(action)];
}

function publicManusWaitingAction(action: ManusWaitingAction): Omit<ManusWaitingAction, "taskId"> {
  return { eventId: action.eventId, eventType: action.eventType };
}

function isManusAdapter(adapter: AgentAdapter): adapter is ManusAdapter {
  const candidate = adapter as ManusAdapter;
  return adapter.id === "manus"
    && typeof candidate.assertProviderReady === "function"
    && typeof candidate.assertRequestSupported === "function"
    && typeof candidate.approvalCapabilityIdentity === "function"
    && typeof candidate.executeAuthorized === "function"
    && typeof candidate.confirmActionAuthorized === "function"
    && typeof candidate.reconcileTask === "function";
}

function assertManusNativeResumeEligible(session: BridgeSession, agentId: string): void {
  const latest = [...session.turns].reverse().find((turn) => turn.agentId === agentId);
  const status = latest?.meta?.taskStatus;
  if (status === "stopped") return;
  if (status === "waiting") {
    throw new Error("MANUS_WAITING_ACTION_REQUIRES_CONFIRMATION: inspect and confirm the persisted waiting action; ordinary continuation is denied");
  }
  throw new Error(`MANUS_RECONCILIATION_REQUIRED: last provider state is ${typeof status === "string" ? status : "unknown"}; reconcile the existing task or start a force-fresh task`);
}
function samePolicy(a: NativeSessionPolicy, b: NativeSessionPolicy): boolean {
  return normalize(a.cwd) === normalize(b.cwd) && a.sandbox === b.sandbox && a.model === b.model;
}

function cooperativeReadiness(adapter: AgentAdapter): { cooperativeReady: boolean; cooperativeReason?: string } {
  try {
    assertCooperativeAgentCompatible(adapter);
    return { cooperativeReady: true };
  } catch (error) {
    return { cooperativeReady: false, cooperativeReason: (error as Error).message };
  }
}
