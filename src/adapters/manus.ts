import type { AgentAdapter, AgentHealth, AgentResult, RunRequest } from "../types.js";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { normalizeManusBaseUrl } from "../policy.js";

const DEFAULT_BASE_URL = "https://api.manus.ai";
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const DEFAULT_CREATION_VISIBILITY_GRACE_MS = 15_000;
const MANUS_MODELS = new Set(["manus-1.6", "manus-1.6-lite", "manus-1.6-max"]);

/**
 * Deliberately small subset of Manus confirmation inputs that this adapter can
 * submit. Higher-level policy must still obtain the appropriate approvals.
 * Persistent provider permissions, connector selection, secret submission,
 * deploys, and terminal execution are intentionally not represented here.
 */
export type ManusConfirmationInput =
  | { action: "skip" }
  | { accept: true; save_draft: true }
  | { choice: "standard" }
  | { action: "reject" };

export interface ManusWaitingAction {
  taskId: string;
  eventId: string;
  eventType: "needConnectMyBrowser" | "gmailSendAction" | "outlookSendMailsAction" | "videoGenerate" | "apiHighCreditNotice";
}

export type ManusConfirmationApprovalCategory = "browser_or_connectors" | "paid_or_unknown_cost";

/** The additional high-level approval class required for each safe subset action. */
export function manusConfirmationApprovalCategory(action: ManusWaitingAction): ManusConfirmationApprovalCategory {
  return action.eventType === "videoGenerate" || action.eventType === "apiHighCreditNotice"
    ? "paid_or_unknown_cost"
    : "browser_or_connectors";
}

export class ManusApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "ManusApiError";
  }
}

export class ManusWaitingError extends ManusApiError {
  constructor(readonly taskId: string, readonly action: ManusWaitingAction) {
    super(`Manus task ${taskId} is waiting for input.`, undefined, "waiting");
    this.name = "ManusWaitingError";
  }
}

export class ManusTimeoutError extends Error {
  constructor(readonly taskId?: string) {
    super(`Manus task${taskId ? ` ${taskId}` : ""} timed out.`);
    this.name = "ManusTimeoutError";
  }
}

export class ManusAbortError extends Error {
  constructor() {
    super("Manus request was aborted.");
    this.name = "ManusAbortError";
  }
}

export interface ManusAdapterOptions {
  apiKey?: string;
  apiKeyFile?: string;
  baseUrl?: string;
  allowDevelopmentBaseUrl?: boolean;
  fetch?: typeof globalThis.fetch;
  pollIntervalMs?: number;
  creationVisibilityGraceMs?: number;
  acknowledgeAccountDefaultCapabilities?: boolean;
  accountCapabilityProfile?: string;
}

interface ManusTaskReceipt {
  taskId: string;
  requestId?: string;
}

interface ManusTaskDetail {
  status: "running" | "stopped" | "waiting" | "error";
  requestId?: string;
}

interface ManusMessagePage {
  messages: Record<string, unknown>[];
  requestId?: string;
  hasMore: boolean;
  nextCursor?: string;
}

interface ManusResumeBoundary {
  baselineEventIds: string[];
  frontierTimestamp: number;
  prompt: string;
}

/** Manus API v2 task adapter. The API key is retained only in memory. */
export class ManusAdapter implements AgentAdapter {
  readonly id = "manus";
  readonly displayName = "Manus API";
  readonly capabilities = {
    resume: true, model: true, sandbox: false, structuredOutput: false,
    directRemoteApi: true, offMachineEgress: true, remote: true,
    localFilesystem: false, independentLocalCodeReview: false,
  };
  private readonly apiKey: string | undefined;
  private readonly apiKeyFile: string | undefined;
  private readonly baseUrl: string;
  private readonly request: typeof globalThis.fetch;
  private readonly pollIntervalMs: number;
  private readonly creationVisibilityGraceMs: number;
  private readonly accountDefaultCapabilitiesAcknowledged: boolean;
  private readonly accountCapabilityProfile: string | undefined;
  private readonly allowAmbientApiKey: boolean;
  private readonly taskLocks = new Map<string, Promise<void>>();

  constructor(options: ManusAdapterOptions = {}) {
    this.apiKey = options.apiKey?.trim() || undefined;
    this.apiKeyFile = options.apiKeyFile;
    this.allowAmbientApiKey = options.apiKey === undefined && options.apiKeyFile === undefined;
    this.baseUrl = normalizeManusBaseUrl(
      options.baseUrl ?? (options.apiKeyFile ? DEFAULT_BASE_URL : process.env.MANUS_API_BASE_URL) ?? DEFAULT_BASE_URL,
      options.allowDevelopmentBaseUrl,
    );
    this.request = options.fetch ?? globalThis.fetch;
    this.pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.creationVisibilityGraceMs = options.creationVisibilityGraceMs ?? DEFAULT_CREATION_VISIBILITY_GRACE_MS;
    this.accountDefaultCapabilitiesAcknowledged = options.acknowledgeAccountDefaultCapabilities === true;
    this.accountCapabilityProfile = options.accountCapabilityProfile;
    if (this.accountCapabilityProfile !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(this.accountCapabilityProfile)) {
      throw new Error("Manus account capability profile must be a stable 1-128 character identifier.");
    }
    if (!Number.isSafeInteger(this.creationVisibilityGraceMs) || this.creationVisibilityGraceMs < 0 || this.creationVisibilityGraceMs > 120_000) {
      throw new Error("Manus creation visibility grace must be an integer from 0 to 120000 milliseconds.");
    }
  }

  async execute(req: RunRequest, options: { signal?: AbortSignal } = {}): Promise<AgentResult> {
    return this.executeAuthorized(req, async () => {}, options);
  }

  /** Run local/provider lifecycle preflight before consuming caller authority, then send exactly once. */
  async executeAuthorized(
    req: RunRequest,
    authorize: () => Promise<void>,
    options: { signal?: AbortSignal } = {},
  ): Promise<AgentResult> {
    this.assertRequestSupported(req);
    if (req.resumeSessionId) {
      assertManusTaskId(req.resumeSessionId);
      return this.withTaskLock(req.resumeSessionId, () => this.executeUnlocked(req, options, authorize));
    }
    return this.executeUnlocked(req, options, authorize);
  }

  private async executeUnlocked(req: RunRequest, options: { signal?: AbortSignal }, authorize: () => Promise<void>): Promise<AgentResult> {
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), req.timeoutMs);
    const signal = combineSignals(options.signal, deadline.signal);
    let taskId: string | undefined;
    let providerRequestId: string | undefined;
    let turnAcknowledged = false;
    const startedAt = Date.now();
    try {
      // Preserve a known native id even if sending the next message fails. The
      // bridge must retain that id so a caller can safely retry the turn.
      const resumedTaskId = req.resumeSessionId;
      if (resumedTaskId) assertManusTaskId(resumedTaskId);
      taskId = resumedTaskId;
      let boundary: ManusResumeBoundary | undefined;
      if (taskId) boundary = await this.captureResumeBoundary(taskId, req.prompt, signal);
      await authorize();
      signal.throwIfAborted();
      const receipt = taskId
        ? await this.sendMessage(taskId, req, signal)
        : await this.createTask(req, signal);
      turnAcknowledged = true;
      taskId = receipt.taskId;
      providerRequestId = receipt.requestId;
      const text = await this.pollForResult(taskId, signal, this.creationVisibilityGraceMs, boundary);
      return {
        text,
        nativeSessionId: taskId,
        exitCode: 0,
        isError: false,
        stderr: "",
        timedOut: false,
        durationMs: Date.now() - startedAt,
        meta: { taskStatus: "stopped", ...providerCorrelation(providerRequestId) },
      };
    } catch (error) {
      // A failure before this turn is acknowledged must not be recorded as if
      // the prompt was sent, and must never stop a pre-existing task. After
      // acknowledgement, return a recordable result so the task is retained.
      if (!turnAcknowledged || !taskId) throw error;
      if (deadline.signal.aborted) {
        await this.stopTask(taskId);
        return failedResult(taskId, "timed_out", "Manus task timed out; a stop request was sent.", startedAt, { timedOut: true, stopRequested: true, ...providerCorrelation(providerRequestId) });
      }
      if (options.signal?.aborted || isAbortError(error)) {
        await this.stopTask(taskId);
        return failedResult(taskId, "aborted", "Manus task was aborted; a stop request was sent.", startedAt, { stopRequested: true, ...providerCorrelation(providerRequestId) });
      }
      if (error instanceof ManusWaitingError) {
        return failedResult(taskId, "waiting", "Manus task is waiting for input.", startedAt, { resumable: true, waitingAction: error.action, ...providerCorrelation(providerRequestId) });
      }
      if (error instanceof ManusApiError) {
        const correlation = providerCorrelation(providerRequestId, error.requestId);
        if (error.status === 404 || error.code === "not_found") {
          return failedResult(
            taskId,
            "not_found",
            "Manus accepted the task request, but the returned task is not retrievable. Check Manus API account provisioning and credits, or contact api-support@manus.ai.",
            startedAt,
            { resumable: false, ...correlation },
          );
        }
        const status = error.code === "task_error" ? "error" : "unknown";
        return failedResult(taskId, status, `Manus task did not complete (${safeApiFailure(error)}).`, startedAt, { resumable: status === "unknown", ...correlation });
      }
      return failedResult(taskId, "unknown", "Manus task did not complete due to an unexpected bridge error.", startedAt, { resumable: true, ...providerCorrelation(providerRequestId) });
    } finally {
      clearTimeout(timer);
    }
  }

  async health(options: { signal?: AbortSignal } = {}): Promise<AgentHealth> {
    const apiKey = this.apiKeyValue();
    if (!apiKey) {
      return { binary: { ok: true, version: "Manus API v2" }, auth: { status: "unauthenticated", detail: "credential file or MANUS_API_KEY is not configured" }, usable: false };
    }
    if (!this.hasAcknowledgedAccountDefaultCapabilities()) {
      return {
        binary: { ok: true, version: "Manus API v2" },
        auth: { status: "unknown", detail: "account-default skills are not explicitly acknowledged in bridge config" },
        usable: false,
      };
    }
    if (options.signal?.aborted) throw new ManusAbortError();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    try {
      await this.json("/v2/task.list?limit=1", { method: "GET", signal: combineSignals(options.signal, controller.signal) });
      return { binary: { ok: true, version: "Manus API v2" }, auth: { status: "authenticated", detail: "API key accepted" }, usable: true };
    } catch (error) {
      if (error instanceof ManusApiError && (error.status === 401 || error.status === 403)) {
        return { binary: { ok: true, version: "Manus API v2" }, auth: { status: "unauthenticated", detail: error.message }, usable: false };
      }
      return { binary: { ok: false, error: (error as Error).message }, auth: { status: "unknown" }, usable: false };
    } finally {
      clearTimeout(timer);
    }
  }

  /** Local-only credential preflight. The credential value is never returned. */
  hasConfiguredCredential(): boolean {
    return this.apiKeyValue() !== undefined;
  }

  /** Local-only provider-capability preflight; makes no network request. */
  hasAcknowledgedAccountDefaultCapabilities(): boolean {
    return this.accountDefaultCapabilitiesAcknowledged && this.accountCapabilityProfile !== undefined;
  }

  /** Local-only provider prompt-size preflight; makes no network request. */
  assertPromptSupported(prompt: string): void {
    assertManusPromptWithinProviderLimit(prompt);
  }

  /** Complete side-effect-free request preflight used before approvals or budget reservations. */
  assertRequestSupported(req: Pick<RunRequest, "prompt" | "model">): void {
    this.assertProviderReady();
    assertManusModelSupported(req.model);
    assertManusPromptWithinProviderLimit(req.prompt);
  }

  /** Side-effect-free account and credential preflight for non-turn operations. */
  assertProviderReady(): void {
    this.assertAccountDefaultCapabilitiesAcknowledged();
    if (!this.hasConfiguredCredential()) {
      throw new ManusApiError("Manus API credential is not configured.", 401, "missing_api_key");
    }
  }

  /** Stable non-secret capability identity bound into remote approval envelopes. */
  approvalCapabilityIdentity(): { endpoint: string; policyVersion: "manus-v2-empty-connectors-default-skills-v1"; accountProfile: string } {
    this.assertAccountDefaultCapabilitiesAcknowledged();
    return {
      endpoint: this.baseUrl,
      policyVersion: "manus-v2-empty-connectors-default-skills-v1",
      accountProfile: this.accountCapabilityProfile!,
    };
  }

  /**
   * Inspect the currently pending action without confirming it. The provider's
   * arbitrary event payload and dynamic input schema are never reflected.
   */
  async getWaitingAction(taskId: string, options: { signal?: AbortSignal } = {}): Promise<ManusWaitingAction> {
    this.assertAccountDefaultCapabilitiesAcknowledged();
    const messages = await this.listMessages(taskId, options.signal);
    return waitingActionFrom(messages, taskId);
  }

  /**
   * Re-reads the current waiting event immediately before submitting a narrow,
   * typed confirmation. Callers cannot confirm a stale event or widen this
   * adapter into a generic provider-action proxy.
   */
  async confirmAction(taskId: string, eventId: string, input: ManusConfirmationInput, options: { signal?: AbortSignal } = {}): Promise<void> {
    return this.confirmActionAuthorized(taskId, eventId, input, async () => {}, options);
  }

  /** Revalidate the live action before consuming caller authority, then submit exactly once under the task lock. */
  async confirmActionAuthorized(
    taskId: string,
    eventId: string,
    input: ManusConfirmationInput,
    authorize: () => Promise<void>,
    options: { signal?: AbortSignal } = {},
  ): Promise<void> {
    this.assertProviderReady();
    assertManusTaskId(taskId);
    return this.withTaskLock(taskId, async () => {
      const current = await this.getWaitingAction(taskId, options);
      if (current.eventId !== eventId) throw new ManusApiError("Manus waiting action changed; inspect it again.", undefined, "waiting_action_stale");
      assertConfirmationInput(current.eventType, input);
      await authorize();
      options.signal?.throwIfAborted();
      let body: unknown;
      try {
        body = await this.json("/v2/task.confirmAction", {
          method: "POST",
          body: { task_id: taskId, event_id: eventId, input },
          signal: options.signal ?? new AbortController().signal,
        });
      } catch (error) {
        if (error instanceof ManusApiError) {
          throw new ManusApiError("Manus confirmation request failed.", error.status, safeConfirmationCode(error.code));
        }
        throw error;
      }
      const result = record(body);
      if (result?.ok !== true || result.confirmed !== true || result.task_id !== taskId) {
        throw new ManusApiError("Manus did not accept the requested confirmation.", undefined, "confirmation_unaccepted");
      }
    });
  }

  /** Poll an already acknowledged task without sending another user message. */
  async waitForTask(taskId: string, timeoutMs: number, options: { signal?: AbortSignal } = {}): Promise<AgentResult> {
    this.assertAccountDefaultCapabilitiesAcknowledged();
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new ManusApiError("Manus wait timeout is invalid.", undefined, "invalid_timeout");
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), timeoutMs);
    const signal = combineSignals(options.signal, deadline.signal);
    const startedAt = Date.now();
    try {
      const text = await this.pollForResult(taskId, signal, this.creationVisibilityGraceMs);
      return { text, nativeSessionId: taskId, exitCode: 0, isError: false, stderr: "", timedOut: false, durationMs: Date.now() - startedAt };
    } catch (error) {
      if (deadline.signal.aborted) {
        await this.stopTask(taskId);
        return failedResult(taskId, "timed_out", "Manus task timed out after confirmation; a stop request was sent.", startedAt, { timedOut: true, stopRequested: true });
      }
      if (options.signal?.aborted || isAbortError(error)) {
        await this.stopTask(taskId);
        return failedResult(taskId, "aborted", "Manus task was aborted after confirmation; a stop request was sent.", startedAt, { stopRequested: true });
      }
      if (error instanceof ManusWaitingError) {
        return failedResult(taskId, "waiting", "Manus task is waiting for another explicit action decision.", startedAt, { resumable: true, waitingAction: error.action });
      }
      if (error instanceof ManusApiError) {
        const status = error.code === "task_error" ? "error" : error.status === 404 || error.code === "not_found" ? "not_found" : "unknown";
        return failedResult(taskId, status, `Manus task did not complete after confirmation (${safeApiFailure(error)}).`, startedAt, { resumable: status === "unknown" });
      }
      return failedResult(taskId, "unknown", "Manus task did not complete after confirmation due to an unexpected bridge error.", startedAt, { resumable: true });
    } finally {
      clearTimeout(timer);
    }
  }

  /** Poll an existing task without sending a message or stopping it on a local reconciliation timeout. */
  async reconcileTask(taskId: string, timeoutMs: number, options: { signal?: AbortSignal } = {}): Promise<AgentResult> {
    this.assertProviderReady();
    assertManusTaskId(taskId);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new ManusApiError("Manus reconciliation timeout is invalid.", undefined, "invalid_timeout");
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), timeoutMs);
    const signal = combineSignals(options.signal, deadline.signal);
    const startedAt = Date.now();
    try {
      const text = await this.pollForResult(taskId, signal);
      return { text, nativeSessionId: taskId, exitCode: 0, isError: false, stderr: "", timedOut: false, durationMs: Date.now() - startedAt, meta: { taskStatus: "stopped", reconciled: true } };
    } catch (error) {
      if (deadline.signal.aborted) {
        return failedResult(taskId, "unknown", "Manus task is still unresolved after the local reconciliation window; no message or stop request was sent.", startedAt, { resumable: true, reconciliationTimedOut: true });
      }
      if (options.signal?.aborted || isAbortError(error)) throw new ManusAbortError();
      if (error instanceof ManusWaitingError) {
        return failedResult(taskId, "waiting", "Manus task is waiting for an explicit action decision.", startedAt, { resumable: true, waitingAction: error.action, reconciled: true });
      }
      if (error instanceof ManusApiError) {
        const status = error.code === "task_error" ? "error" : error.status === 404 || error.code === "not_found" ? "not_found" : "unknown";
        return failedResult(taskId, status, `Manus task reconciliation failed (${safeApiFailure(error)}).`, startedAt, { resumable: status === "unknown", reconciled: true, ...providerCorrelation(undefined, error.requestId) });
      }
      return failedResult(taskId, "unknown", "Manus task reconciliation failed due to an unexpected bridge error.", startedAt, { resumable: true, reconciled: true });
    } finally {
      clearTimeout(timer);
    }
  }

  private async createTask(req: RunRequest, signal: AbortSignal): Promise<ManusTaskReceipt> {
    const payload: Record<string, unknown> = {
      message: { content: req.prompt, connectors: [], force_skills: [], task_references: [] },
      interactive_mode: false,
      hide_in_task_list: false,
      share_visibility: "private",
    };
    if (req.model) payload.agent_profile = req.model;
    const body = await this.json("/v2/task.create", { method: "POST", body: payload, signal });
    return taskReceiptFrom(body);
  }

  private async sendMessage(taskId: string, req: RunRequest, signal: AbortSignal): Promise<ManusTaskReceipt> {
    assertManusTaskId(taskId);
    const body = await this.json("/v2/task.sendMessage", {
      method: "POST",
      body: {
        task_id: taskId,
        message: { content: req.prompt, force_skills: [], task_references: [] },
        clear_connectors: true,
        ...(req.model ? { agent_profile: req.model } : {}),
      },
      signal,
    });
    return taskReceiptFrom(body, taskId);
  }

  private async pollForResult(taskId: string, signal: AbortSignal, visibilityGraceMs?: number, boundary?: ManusResumeBoundary): Promise<string> {
    const hasVisibilityGrace = visibilityGraceMs !== undefined;
    let visibilityDeadline = hasVisibilityGrace ? Date.now() + visibilityGraceMs : 0;
    for (;;) {
      let messages: Record<string, unknown>[];
      let messageRequestId: string | undefined;
      try {
        const page = boundary
          ? await this.messagesAfterBoundary(taskId, boundary, signal)
          : await this.listMessagePage(taskId, signal);
        messages = page.messages;
        messageRequestId = page.requestId;
        visibilityDeadline = 0;
      } catch (error) {
        if (!hasVisibilityGrace || !isManusNotFound(error)) throw error;
        const messagesError = error;
        let detail: ManusTaskDetail;
        try {
          detail = await this.taskDetail(taskId, signal);
        } catch (detailError) {
          if (!isManusNotFound(detailError)) throw detailError;
          if (visibilityDeadline <= Date.now()) throw detailError;
          const remaining = visibilityDeadline - Date.now();
          await delay(visibilityRetryDelay(remaining, this.pollIntervalMs), signal);
          continue;
        }
        if (detail.status === "error") {
          throw new ManusApiError("Manus task reported an error.", undefined, "task_error", detail.requestId);
        }
        if (visibilityDeadline <= Date.now()) {
          throw new ManusApiError(
            "Manus task exists, but its messages are not visible yet.",
            undefined,
            "messages_not_visible",
            messagesError.requestId ?? detail.requestId,
          );
        }
        const remaining = visibilityDeadline - Date.now();
        await delay(visibilityRetryDelay(remaining, this.pollIntervalMs), signal);
        continue;
      }
      const status = latestStatus(messages);
      if (status === "waiting") throw new ManusWaitingError(taskId, waitingActionFrom(messages, taskId));
      if (status === "error") throw new ManusApiError(`Manus task ${taskId} reported an error.`, undefined, "task_error", messageRequestId);
      if (status === "stopped") return assistantText(messages, taskId);
      await delay(this.pollIntervalMs, signal);
    }
  }

  private async listMessages(taskId: string, signal?: AbortSignal): Promise<Record<string, unknown>[]> {
    return (await this.listMessagePage(taskId, signal)).messages;
  }

  private async listMessagePage(taskId: string, signal?: AbortSignal, cursor?: string): Promise<ManusMessagePage> {
    assertManusTaskId(taskId);
    const query = new URLSearchParams({ task_id: taskId, order: "desc", limit: "200" });
    if (cursor) query.set("cursor", cursor);
    const body = await this.json(`/v2/task.listMessages?${query}`, { method: "GET", signal: signal ?? new AbortController().signal });
    assertMatchingTaskId(body, taskId, "Manus message response task_id is invalid or mismatched.");
    const object = record(body);
    const hasMore = object?.has_more;
    const nextCursor = object?.next_cursor;
    if (hasMore !== undefined && typeof hasMore !== "boolean") throw new ManusApiError("Manus message response has invalid pagination metadata.", undefined, "messages_contract_invalid", requestIdFrom(body));
    if (hasMore === true && (typeof nextCursor !== "string" || !nextCursor || nextCursor.length > 2_000)) {
      throw new ManusApiError("Manus message response omitted a valid pagination cursor.", undefined, "messages_contract_invalid", requestIdFrom(body));
    }
    return {
      messages: messagesFrom(body),
      requestId: requestIdFrom(body),
      hasMore: hasMore === true,
      ...(typeof nextCursor === "string" && nextCursor ? { nextCursor } : {}),
    };
  }

  private async captureResumeBoundary(taskId: string, prompt: string, signal: AbortSignal): Promise<ManusResumeBoundary> {
    let page = await this.listMessagePage(taskId, signal);
    const newest = page.messages[0];
    const frontierTimestamp = eventTimestampFrom(newest);
    if (frontierTimestamp === undefined) {
      throw new ManusApiError("Manus resume cannot establish a valid pre-send event boundary.", undefined, "turn_boundary_unavailable", page.requestId);
    }
    const baselineEventIds: string[] = [];
    const seen = new Set<string>();
    const latestStatuses = new Set<string>();
    let latestStatusTimestamp: number | undefined;
    let frontierComplete = false;
    let statusGroupComplete = false;
    for (let pageIndex = 0; pageIndex < 100; pageIndex++) {
      for (const message of page.messages) {
        const timestamp = eventTimestampFrom(message);
        const id = eventIdFrom(message);
        if (timestamp === undefined || !id) {
          throw new ManusApiError("Manus resume returned an event without a valid identity or timestamp.", undefined, "turn_boundary_invalid", page.requestId);
        }
        if (timestamp > frontierTimestamp) {
          throw new ManusApiError("Manus resume baseline ordering is unstable.", undefined, "turn_boundary_invalid", page.requestId);
        }
        if (timestamp < frontierTimestamp) frontierComplete = true;
        else if (!seen.has(id)) { seen.add(id); baselineEventIds.push(id); }

        const status = statusValueFrom(message);
        if (status !== undefined) {
          if (latestStatusTimestamp === undefined) latestStatusTimestamp = timestamp;
          if (timestamp === latestStatusTimestamp) latestStatuses.add(status);
        }
        if (latestStatusTimestamp !== undefined && timestamp < latestStatusTimestamp) statusGroupComplete = true;
        if (frontierComplete && statusGroupComplete) break;
      }
      if (!page.hasMore || !page.nextCursor) {
        frontierComplete = true;
        statusGroupComplete = true;
      }
      if (frontierComplete && statusGroupComplete) {
        if (!baselineEventIds.length) throw new ManusApiError("Manus resume cannot establish a valid pre-send event boundary.", undefined, "turn_boundary_unavailable", page.requestId);
        if (latestStatuses.size !== 1) {
          throw new ManusApiError("Manus latest task status is missing or ambiguous at the provider timestamp frontier.", undefined, "resume_reconciliation_required", page.requestId);
        }
        const [status] = latestStatuses;
        if (status === "waiting") {
          throw new ManusApiError("Manus task is waiting for an explicit action decision; ordinary continuation is denied.", undefined, "resume_requires_confirmation", page.requestId);
        }
        if (status !== "stopped") {
          throw new ManusApiError("Manus task state is not safely resumable; reconcile it before sending another message.", undefined, "resume_reconciliation_required", page.requestId);
        }
        return { baselineEventIds, frontierTimestamp, prompt };
      }
      page = await this.listMessagePage(taskId, signal, page.nextCursor);
    }
    throw new ManusApiError("Manus resume baseline exceeds the supported pagination bound.", undefined, "turn_boundary_unavailable");
  }

  private async messagesAfterBoundary(taskId: string, boundary: ManusResumeBoundary, signal: AbortSignal): Promise<ManusMessagePage> {
    const newer: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    const baseline = new Set(boundary.baselineEventIds);
    const observedBaseline = new Set<string>();
    let cursor: string | undefined;
    for (let pageIndex = 0; pageIndex < 100; pageIndex++) {
      const page = await this.listMessagePage(taskId, signal, cursor);
      let crossedFrontier = false;
      for (const message of page.messages) {
        const id = eventIdFrom(message);
        const timestamp = eventTimestampFrom(message);
        if (!id || timestamp === undefined) throw new ManusApiError("Manus resume returned an event without a valid identity or timestamp.", undefined, "turn_boundary_invalid", page.requestId);
        if (seen.has(id)) continue;
        seen.add(id);
        if (timestamp < boundary.frontierTimestamp) { crossedFrontier = true; break; }
        if (baseline.has(id)) {
          observedBaseline.add(id);
          continue;
        }
        newer.push(message);
      }
      if (crossedFrontier || !page.hasMore || !page.nextCursor) {
        if (observedBaseline.size !== baseline.size) break;
        return { messages: validatePostSendSegment(newer, boundary.prompt, page.requestId), requestId: page.requestId, hasMore: false };
      }
      cursor = page.nextCursor;
    }
    throw new ManusApiError("Manus resume could not locate the pre-send event boundary.", undefined, "turn_boundary_lost");
  }

  private async withTaskLock<T>(taskId: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.taskLocks.get(taskId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    const queued = previous.then(() => current);
    this.taskLocks.set(taskId, queued);
    await previous;
    try { return await fn(); }
    finally {
      release();
      if (this.taskLocks.get(taskId) === queued) this.taskLocks.delete(taskId);
    }
  }

  private async taskDetail(taskId: string, signal: AbortSignal): Promise<ManusTaskDetail> {
    assertManusTaskId(taskId);
    const query = new URLSearchParams({ task_id: taskId });
    const body = await this.json(`/v2/task.detail?${query}`, { method: "GET", signal });
    const object = record(body);
    const data = record(object?.data);
    const task = record(object?.task) ?? record(data?.task);
    const id = task?.id;
    const status = task?.status;
    if (typeof id !== "string" || !isValidManusTaskId(id) || id !== taskId) {
      throw new ManusApiError("Manus task detail returned an invalid or mismatched task id.", undefined, "task_detail_mismatch");
    }
    if (status !== "running" && status !== "stopped" && status !== "waiting" && status !== "error") {
      throw new ManusApiError("Manus task detail returned an invalid status.", undefined, "task_detail_invalid");
    }
    return { status, requestId: requestIdFrom(body) };
  }

  private async json(path: string, init: { method: "GET" | "POST"; body?: Record<string, unknown>; signal: AbortSignal }): Promise<unknown> {
    const apiKey = this.apiKeyValue();
    if (!apiKey) throw new ManusApiError("Manus API credential is not configured.", 401, "missing_api_key");
    let response: Response;
    try {
      response = await this.request(`${this.baseUrl}${path}`, {
        method: init.method,
        headers: { "content-type": "application/json", "x-manus-api-key": apiKey },
        ...(init.body ? { body: JSON.stringify(init.body) } : {}),
        signal: init.signal,
      });
    } catch (error) {
      if (isAbortError(error)) throw error;
      throw new ManusApiError(`Manus request failed: ${(error as Error).message}`);
    }
    const raw = await response.text();
    let data: unknown;
    try { data = raw ? JSON.parse(raw) : {}; } catch { throw new ManusApiError(`Manus returned invalid JSON (HTTP ${response.status}).`, response.status); }
    const requestId = requestIdFrom(data);
    if (!response.ok) throw new ManusApiError(apiErrorMessage(data, response.status), response.status, apiCode(data), requestId);
    if (apiFailed(data)) throw new ManusApiError(apiErrorMessage(data), undefined, apiCode(data), requestId);
    return data;
  }

  private async stopTask(taskId: string): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2_000);
    try {
      await this.json("/v2/task.stop", { method: "POST", body: { task_id: taskId }, signal: controller.signal });
    } catch { /* best-effort cost containment */ }
    finally { clearTimeout(timer); }
  }

  private apiKeyValue(): string | undefined {
    if (this.apiKey) return this.apiKey;
    if (this.apiKeyFile) return readApiKey(this.apiKeyFile);
    return this.allowAmbientApiKey ? process.env.MANUS_API_KEY?.trim() || undefined : undefined;
  }

  private assertAccountDefaultCapabilitiesAcknowledged(): void {
    if (this.accountDefaultCapabilitiesAcknowledged && this.accountCapabilityProfile) return;
    throw new ManusApiError(
      "Manus account-default capabilities are not acknowledged. Set agents.manus.acknowledgeAccountDefaultCapabilities=true and a stable accountCapabilityProfile only after reviewing the account's enabled skills.",
      undefined,
      "account_capabilities_unacknowledged",
    );
  }
}

function failedResult(
  taskId: string,
  taskStatus: "waiting" | "timed_out" | "aborted" | "error" | "not_found" | "unknown",
  text: string,
  startedAt: number,
  flags: {
    timedOut?: boolean;
    stopRequested?: boolean;
    resumable?: boolean;
    waitingAction?: ManusWaitingAction;
    reconciled?: boolean;
    reconciliationTimedOut?: boolean;
    providerRequestSha256?: string;
    providerErrorRequestSha256?: string;
  } = {},
): AgentResult {
  return {
    text,
    nativeSessionId: taskId,
    exitCode: null,
    isError: true,
    stderr: "",
    timedOut: flags.timedOut ?? false,
    durationMs: Date.now() - startedAt,
    meta: { taskStatus, ...flags },
  };
}

function safeApiFailure(error: ManusApiError): string {
  if (error.code && /^[A-Za-z0-9_.-]{1,64}$/.test(error.code)) return `API ${error.code}`;
  if (error.status) return `HTTP ${error.status}`;
  return "API error";
}

function safeConfirmationCode(value: string | undefined): string | undefined {
  return value && /^[A-Za-z0-9_.-]{1,64}$/.test(value) ? value : undefined;
}

function isManusNotFound(error: unknown): error is ManusApiError {
  return error instanceof ManusApiError && (error.status === 404 || error.code === "not_found");
}

function visibilityRetryDelay(remainingMs: number, pollIntervalMs: number): number {
  return Math.min(remainingMs, Math.max(10, Math.min(pollIntervalMs || 250, 1_000)));
}

function taskReceiptFrom(body: unknown, fallback?: string): ManusTaskReceipt {
  const object = record(body);
  const data = record(object?.data);
  const id = object?.task_id ?? object?.taskId ?? data?.task_id ?? data?.taskId ?? fallback;
  if (typeof id !== "string" || !isValidManusTaskId(id)) throw new ManusApiError("Manus task response did not include a valid task_id.");
  if (fallback !== undefined && id !== fallback) throw new ManusApiError("Manus task response task_id did not match the requested task.", undefined, "task_id_mismatch");
  return { taskId: id, requestId: requestIdFrom(body) };
}

function assertManusTaskId(value: string): void {
  if (!isValidManusTaskId(value)) throw new ManusApiError("Manus task id is invalid.", undefined, "invalid_task_id");
}

function assertMatchingTaskId(body: unknown, expected: string, message: string): void {
  const object = record(body);
  const data = record(object?.data);
  const value = object?.task_id ?? object?.taskId ?? data?.task_id ?? data?.taskId;
  if (value !== undefined && (typeof value !== "string" || !isValidManusTaskId(value) || value !== expected)) {
    throw new ManusApiError(message, undefined, "task_id_mismatch");
  }
}

function requestIdFrom(body: unknown): string | undefined {
  const object = record(body);
  const data = record(object?.data);
  const value = object?.request_id ?? object?.requestId ?? data?.request_id ?? data?.requestId;
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,200}$/.test(value) ? value : undefined;
}

function providerCorrelation(providerRequestId?: string, providerErrorRequestId?: string): {
  providerRequestSha256?: string;
  providerErrorRequestSha256?: string;
} {
  return {
    ...(providerRequestId ? { providerRequestSha256: sha256(providerRequestId) } : {}),
    ...(providerErrorRequestId ? { providerErrorRequestSha256: sha256(providerErrorRequestId) } : {}),
  };
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function messagesFrom(body: unknown): Record<string, unknown>[] {
  const object = record(body);
  const data = record(object?.data);
  const rawData = object?.data;
  const values = Array.isArray(object?.messages) ? object?.messages : Array.isArray(data?.messages) ? data?.messages : Array.isArray(rawData) ? rawData : undefined;
  if (!values) throw new ManusApiError("Manus message response omitted the messages array.", undefined, "messages_contract_invalid", requestIdFrom(body));
  if (values.some((item) => !record(item))) throw new ManusApiError("Manus message response contained an invalid event.", undefined, "messages_contract_invalid", requestIdFrom(body));
  return values as Record<string, unknown>[];
}

function eventIdFrom(message: Record<string, unknown> | undefined): string | undefined {
  if (!message) return undefined;
  const id = message.id;
  const type = message.type;
  const timestamp = message.timestamp;
  if (typeof id !== "string" || !/^[A-Za-z0-9_-]{1,200}$/.test(id)) return undefined;
  if (typeof type !== "string" || !["user_message", "assistant_message", "error_message", "status_update", "user_stop", "structured_output_result"].includes(type)) return undefined;
  if (!Number.isSafeInteger(timestamp) || Number(timestamp) < 0) return undefined;
  return id;
}

function eventTimestampFrom(message: Record<string, unknown> | undefined): number | undefined {
  const value = message?.timestamp;
  return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : undefined;
}

function validatePostSendSegment(messagesDesc: Record<string, unknown>[], prompt: string, requestId?: string): Record<string, unknown>[] {
  const userMessages: Record<string, unknown>[] = [];
  for (const message of messagesDesc) {
    if (message.type !== "user_message") continue;
    const user = record(message.user_message);
    if (typeof user?.content !== "string") {
      throw new ManusApiError("Manus resume returned a malformed user-message anchor.", undefined, "turn_boundary_invalid", requestId);
    }
    userMessages.push(message);
    if (user.content !== prompt) {
      throw new ManusApiError("Manus resume observed an unexpected concurrent user message.", undefined, "turn_boundary_ambiguous", requestId);
    }
  }
  if (userMessages.length === 0) return [];
  if (userMessages.length !== 1) throw new ManusApiError("Manus resume observed multiple matching user messages.", undefined, "turn_boundary_ambiguous", requestId);
  // All returned IDs were absent from the complete pre-send frontier. Do not
  // infer causal order among events that share the provider's millisecond
  // timestamp; simply exclude the validated user anchor from result polling.
  return messagesDesc.filter((message) => message.type !== "user_message");
}

function latestStatus(messages: Record<string, unknown>[]): string | undefined {
  const candidates: Array<{ status: string; timestamp?: number }> = [];
  for (const message of messages) {
    const status = statusValueFrom(message);
    if (status !== undefined) candidates.push({ status, timestamp: eventTimestampFrom(message) });
  }
  if (!candidates.length) return undefined;
  const stamped = candidates.filter((candidate) => candidate.timestamp !== undefined);
  // Compatibility for creation responses using the older un-timestamped
  // envelope. A v2 response that supplies timestamps must do so consistently.
  if (!stamped.length) return candidates[0]!.status;
  if (stamped.length !== candidates.length) {
    throw new ManusApiError("Manus task status events mix timestamped and un-timestamped contracts.", undefined, "task_status_ambiguous");
  }
  const latestTimestamp = Math.max(...stamped.map((candidate) => candidate.timestamp!));
  const statuses = new Set(stamped.filter((candidate) => candidate.timestamp === latestTimestamp).map((candidate) => candidate.status));
  if (statuses.size !== 1) {
    throw new ManusApiError("Manus task status is ambiguous at the provider timestamp frontier.", undefined, "task_status_ambiguous");
  }
  return [...statuses][0];
}

function statusValueFrom(message: Record<string, unknown>): string | undefined {
  const isStatus = message.type === "status_update" || message.message_type === "status_update";
  const status = record(message.status_update) ?? (isStatus ? contentObject(message.content) ?? message : undefined);
  return typeof status?.agent_status === "string" ? status.agent_status.toLowerCase() : undefined;
}

function waitingActionFrom(messages: Record<string, unknown>[], taskId: string): ManusWaitingAction {
  for (const message of messages) {
    const isStatus = message.type === "status_update" || message.message_type === "status_update";
    const status = record(message.status_update) ?? (isStatus ? contentObject(message.content) ?? message : undefined);
    if (!status || typeof status.agent_status !== "string") continue;
    if (status.agent_status.toLowerCase() !== "waiting") {
      throw new ManusApiError("Manus task has no current confirmable waiting action.", undefined, "waiting_action_missing");
    }
    const detail = record(status.status_detail);
    const eventId = detail?.waiting_for_event_id;
    const eventType = detail?.waiting_for_event_type;
    if (typeof eventId !== "string" || !isValidManusEventId(eventId) || typeof eventType !== "string") {
      throw new ManusApiError("Manus waiting action is incomplete and cannot be confirmed.", undefined, "waiting_action_invalid");
    }
    if (eventType === "messageAskUser") {
      throw new ManusApiError("Manus is requesting a message, not an action confirmation.", undefined, "waiting_message_required");
    }
    if (eventType === "webdevRequestSecrets") {
      throw new ManusApiError("Manus requested secrets; this adapter will not expose or submit them.", undefined, "waiting_secrets_denied");
    }
    if (!isSupportedManusWaitingEventType(eventType)) {
      throw new ManusApiError("Manus waiting action type is unsupported and cannot be confirmed.", undefined, "waiting_action_unsupported");
    }
    // Provider descriptions and dynamic schemas are intentionally excluded:
    // both are untrusted and may contain credentials, PII, or new authority.
    return { taskId, eventId, eventType };
  }
  throw new ManusApiError("Manus task has no current confirmable waiting action.", undefined, "waiting_action_missing");
}

export function isSupportedManusWaitingEventType(value: string): value is ManusWaitingAction["eventType"] {
  return value === "needConnectMyBrowser" || value === "gmailSendAction" || value === "outlookSendMailsAction"
    || value === "videoGenerate" || value === "apiHighCreditNotice";
}

export function isAllowedManusConfirmationInput(eventType: ManusWaitingAction["eventType"], input: unknown): input is ManusConfirmationInput {
  if (!record(input)) return false;
  const value = input as Record<string, unknown>;
  const keys = Object.keys(value).sort();
  const exact = (...expected: string[]) => keys.length === expected.length && keys.every((key, index) => key === expected.slice().sort()[index]);
  return (eventType === "needConnectMyBrowser" && exact("action") && value.action === "skip")
    || ((eventType === "gmailSendAction" || eventType === "outlookSendMailsAction") && exact("accept", "save_draft") && value.accept === true && value.save_draft === true)
    || (eventType === "videoGenerate" && exact("choice") && value.choice === "standard")
    || (eventType === "apiHighCreditNotice" && exact("action") && value.action === "reject");
}

function assertConfirmationInput(eventType: ManusWaitingAction["eventType"], input: unknown): asserts input is ManusConfirmationInput {
  if (!isAllowedManusConfirmationInput(eventType, input)) {
    throw new ManusApiError("Manus confirmation input is not allowed for this action.", undefined, "confirmation_input_denied");
  }
}

export function isValidManusTaskId(value: string): boolean {
  return /^[A-Za-z0-9]{22}$/.test(value);
}

export function assertManusPromptWithinProviderLimit(prompt: string): void {
  const utf8Bytes = Buffer.byteLength(prompt, "utf8");
  if (utf8Bytes > 4_500) {
    throw new ManusApiError(
      `Manus finalized prompt is too large for the conservative provider preflight (${utf8Bytes} UTF-8 bytes; maximum 4500). Shorten the request or handoff context.`,
      undefined,
      "prompt_too_large",
    );
  }
}

export function assertManusModelSupported(model: string | undefined): void {
  if (model === undefined || MANUS_MODELS.has(model)) return;
  throw new ManusApiError(
    `Unsupported Manus model ${JSON.stringify(model)}. Choose manus-1.6, manus-1.6-lite, or manus-1.6-max.`,
    undefined,
    "model_unsupported",
  );
}

export function isValidManusEventId(value: string): boolean {
  return /^[A-Za-z0-9_-]{1,200}$/.test(value);
}

/** @deprecated Use the task- or event-specific validator. */
export const isValidManusOpaqueId = isValidManusEventId;

function assistantText(messages: Record<string, unknown>[], taskId: string): string {
  const texts: string[] = [];
  for (const message of messages) {
    const isAssistant = message.type === "assistant_message" || message.message_type === "assistant_message" || message.role === "assistant";
    const assistant = record(message.assistant_message) ?? (isAssistant ? message : undefined);
    const nested = contentObject(assistant?.content);
    const direct = assistant?.content ?? assistant?.text;
    const content = typeof direct === "string" ? direct : nested?.text ?? nested?.content;
    if (typeof content === "string" && content.trim()) texts.push(content.trim());
  }
  if (texts.length) return texts.reverse().join("\n\n");
  throw new ManusApiError(`Manus task ${taskId} stopped without an assistant message.`, undefined, "missing_assistant_message");
}

function record(value: unknown): Record<string, any> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, any> : undefined;
}

function contentObject(value: unknown): Record<string, any> | undefined {
  const direct = record(value);
  if (direct) return direct;
  if (typeof value !== "string") return undefined;
  try { return record(JSON.parse(value)); } catch { return undefined; }
}

function apiFailed(value: unknown): boolean {
  const object = record(value);
  return object?.ok === false || object?.success === false || (typeof object?.code === "number" && object.code !== 0) || (typeof object?.status === "number" && object.status !== 0);
}

function apiCode(value: unknown): string | undefined {
  const object = record(value);
  const code = object?.code ?? record(object?.error)?.code;
  return code === undefined ? undefined : String(code);
}

function apiErrorMessage(value: unknown, status?: number): string {
  const object = record(value);
  const error = record(object?.error);
  const message = object?.message ?? error?.message ?? (typeof object?.error === "string" ? object.error : undefined) ?? record(object?.data)?.message;
  return typeof message === "string" && message ? message : `Manus API request failed${status ? ` (HTTP ${status})` : ""}.`;
}

function combineSignals(external: AbortSignal | undefined, timeout: AbortSignal): AbortSignal {
  if (!external) return timeout;
  if (typeof AbortSignal.any === "function") return AbortSignal.any([external, timeout]);
  const controller = new AbortController();
  const abort = () => controller.abort();
  external.addEventListener("abort", abort, { once: true });
  timeout.addEventListener("abort", abort, { once: true });
  return controller.signal;
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(done, ms);
    const abort = () => { clearTimeout(timer); reject(new DOMException("Aborted", "AbortError")); };
    function done(): void { signal.removeEventListener("abort", abort); resolve(); }
    signal.addEventListener("abort", abort, { once: true });
  });
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError" || (error as { name?: string } | undefined)?.name === "AbortError";
}

function readApiKey(path: string | undefined): string | undefined {
  if (!path) return undefined;
  try {
    const value = readFileSync(path, "utf8").trim();
    return value || undefined;
  } catch (error: any) {
    if (error?.code === "ENOENT") return undefined;
    throw new ManusApiError(`cannot read configured Manus credential file: ${error.message}`, undefined, "credential_file_error");
  }
}
