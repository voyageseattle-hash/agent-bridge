import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";

export type WorkItemStatus = "ready" | "running" | "submitted" | "accepted" | "rejected" | "blocked" | "failed" | "canceled";
export type WorkboardStatus = "active" | "paused" | "completed" | "canceled" | "archived";
export type WorkItemKind = "research" | "implementation" | "review" | "design" | "content" | "validation" | "other";
export type DataClass = "public" | "internal" | "confidential" | "restricted";
export type ReferenceAccessibility = "local" | "remote" | "inline" | "unavailable";
export type ReferenceKind = "source" | "report" | "image" | "video" | "audio" | "document" | "dataset" | "build" | "link" | "other";

/** Metadata only. The workboard layer never resolves, reads, or uploads a reference. */
export interface ArtifactReference {
  id: string;
  kind: ReferenceKind;
  uri?: string;
  path?: string;
  hash?: string;
  mediaType?: string;
  dataClass: DataClass;
  accessibility: ReferenceAccessibility;
}

/** Evidence uses the same inert metadata envelope as an artifact. */
export interface EvidenceReference extends ArtifactReference {}

export interface WorkItemRequirements {
  dataClass: DataClass;
  filesystem: "none" | "metadata-only" | "read-only";
  network: "none" | "restricted" | "required";
  capabilities: string[];
}

export interface WorkItemApproval {
  state: "not-required" | "pending" | "approved" | "rejected";
  reason?: string;
  requestedAt?: string;
  decidedAt?: string;
  decidedBy?: string;
  rationale?: string;
}

export interface WorkItemInput {
  key: string;
  title: string;
  instructions: string;
  dependsOn?: string[];
  kind?: WorkItemKind;
  acceptanceCriteria?: string[];
  requirements?: Partial<WorkItemRequirements>;
  artifacts?: ArtifactReference[];
  evidence?: EvidenceReference[];
  approval?: { required: boolean; reason?: string };
  budget?: { maxAttempts?: number; maxWallSec?: number; tokenBudgetHint?: number };
}

export interface WorkItem {
  key: string;
  title: string;
  instructions: string;
  dependsOn: string[];
  kind: WorkItemKind;
  acceptanceCriteria: string[];
  requirements: WorkItemRequirements;
  artifacts: ArtifactReference[];
  evidence: EvidenceReference[];
  approval: WorkItemApproval;
  status: WorkItemStatus;
  owner?: { agentId: string; leaseId: string; claimedAt: string; expiresAt: string };
  sessionId?: string;
  attempts: number;
  /** maxReviewAttempts is derived internally from maxAttempts; review invocation has no public schema knob. */
  reviewAttempts: number;
  budget: { maxAttempts: number; maxReviewAttempts: number; maxWallSec: number; tokenBudgetHint?: number };
  spent: { wallMs: number; turns: number };
  /** Usage attributable to the independent review executor. It is deliberately separate from work execution spent. */
  reviewSpent: { wallMs: number; turns: number };
  submission?: { summary: string; evidence: string; risks: string; submittedAt: string; submittedByAgentId: string };
  review?: { reviewerAgentId: string; verdict: "accepted" | "rejected"; rationale: string; reviewedAt: string; sessionId?: string };
  reviewOwner?: { agentId: string; leaseId: string; claimedAt: string; expiresAt: string };
  failure?: { code: string; message: string; at: string };
  cancellation?: { at: string; reason: string };
}

export interface Workboard {
  schemaVersion: 2;
  id: string;
  title: string;
  objective: string;
  cwd: string;
  createdAt: string;
  updatedAt: string;
  revision: number;
  maxParallel: number;
  status: WorkboardStatus;
  lifecycle: {
    stateChangedAt: string;
    reason?: string;
    pausedAt?: string;
    resumedAt?: string;
    completedAt?: string;
    canceledAt?: string;
    archivedAt?: string;
  };
  items: WorkItem[];
}

export interface WorkExecutor {
  (input: { workboard: Workboard; item: WorkItem; agentId: string; timeoutSec: number; sandbox: "read-only" }): Promise<{ sessionId?: string; summary: string; evidence?: string; risks?: string; artifacts?: ArtifactReference[]; evidenceRefs?: EvidenceReference[] }>;
}
export interface ReviewExecutor {
  (input: { workboard: Workboard; item: WorkItem; reviewerAgentId: string; timeoutSec: number; sandbox: "read-only" }): Promise<{ verdict: "accepted" | "rejected"; rationale: string; sessionId?: string }>;
}

export class WorkboardStore {
  readonly dir: string;
  readonly lockDir: string;
  constructor(stateDir: string, private readonly lockWaitMs = 30_000, private readonly lockStaleMs = 7_500_000) {
    this.dir = join(stateDir, "workboards"); this.lockDir = join(stateDir, "workboard-locks");
    mkdirSync(this.dir, { recursive: true }); mkdirSync(this.lockDir, { recursive: true });
  }

  create(input: { title: string; objective: string; cwd: string; maxParallel?: number; items: WorkItemInput[] }): Workboard {
    validateInputs(input.items);
    const now = new Date().toISOString();
    const board: Workboard = {
      schemaVersion: 2,
      id: randomUUID(),
      title: clip(input.title, 200),
      objective: input.objective,
      cwd: input.cwd,
      createdAt: now,
      updatedAt: now,
      revision: 0,
      maxParallel: input.maxParallel ?? 3,
      status: "active",
      lifecycle: { stateChangedAt: now },
      items: input.items.map((item) => {
        const maxAttempts = item.budget?.maxAttempts ?? 2;
        return {
          key: item.key,
          title: item.title,
          instructions: item.instructions,
          dependsOn: [...(item.dependsOn ?? [])],
          kind: item.kind ?? "other",
          acceptanceCriteria: [...(item.acceptanceCriteria ?? [])],
          requirements: normalizeRequirements(item.requirements),
          artifacts: structuredClone(item.artifacts ?? []),
          evidence: structuredClone(item.evidence ?? []),
          approval: item.approval?.required
            ? { state: "pending" as const, reason: item.approval.reason, requestedAt: now }
            : { state: "not-required" as const },
          status: "ready" as const,
          attempts: 0,
          reviewAttempts: 0,
          budget: { maxAttempts, maxReviewAttempts: maxAttempts, maxWallSec: item.budget?.maxWallSec ?? 600, tokenBudgetHint: item.budget?.tokenBudgetHint },
          spent: { wallMs: 0, turns: 0 },
          reviewSpent: { wallMs: 0, turns: 0 },
        };
      }),
    };
    if (!Number.isInteger(board.maxParallel) || board.maxParallel < 1 || board.maxParallel > 32) throw new Error("maxParallel must be an integer from 1 to 32");
    this.save(board); return board;
  }
  path(id: string): string { return join(this.dir, `${safeId(id)}.json`); }
  list(): Workboard[] {
    return readdirSync(this.dir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && /^[A-Za-z0-9_-]+\.json$/.test(entry.name))
      .map((entry) => this.get(entry.name.slice(0, -5)))
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }
  get(id: string): Workboard {
    const path = this.path(id); if (!existsSync(path)) throw new Error(`no such workboard: ${id}`);
    let raw: unknown;
    try { raw = JSON.parse(readFileSync(path, "utf8")); } catch (error) { throw corrupt(id, `invalid JSON: ${error instanceof Error ? error.message : String(error)}`); }
    const migrated = migratePersistedWorkboard(raw, id);
    validatePersistedWorkboard(migrated.board, id);
    // Do not rewrite from an unlocked read: a concurrent locked run/save could
    // otherwise be replaced by the stale migrated snapshot. The next normal
    // save persists the migrated schema while holding the board lock.
    return migrated.board;
  }
  save(board: Workboard, expectedRevision?: number): void {
    const path = this.path(board.id);
    if (expectedRevision !== undefined && existsSync(path) && this.get(board.id).revision !== expectedRevision) throw new Error(`WORKBOARD_CONFLICT: workboard ${board.id} changed`);
    if (expectedRevision !== undefined) board.revision = expectedRevision + 1;
    board.updatedAt = new Date().toISOString(); validatePersistedWorkboard(board, board.id); writeAtomic(path, board);
  }
  async withLock<T>(id: string, operation: () => Promise<T>): Promise<T> {
    const lock = join(this.lockDir, `${safeId(id)}.lock`), started = Date.now(); let beat: NodeJS.Timeout | undefined;
    while (true) try { mkdirSync(lock); beat = setInterval(() => { try { utimesSync(lock, new Date(), new Date()); } catch {} }, Math.min(30_000, Math.max(1_000, this.lockStaleMs / 4))); beat.unref(); break; }
    catch (error: any) { if (error?.code !== "EEXIST") throw error; if (stale(lock, this.lockStaleMs)) { rmSync(lock, { recursive: true, force: true }); continue; } if (Date.now() - started >= this.lockWaitMs) throw new Error(`WORKBOARD_BUSY: ${id}`); await sleep(50); }
    try { return await operation(); } finally { if (beat) clearInterval(beat); rmSync(lock, { recursive: true, force: true }); }
  }

  async pause(id: string, reason: string): Promise<Workboard> {
    return this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision; reclaimAllExpired(board); requireBoardState(board, ["active"], "pause"); requireNoLiveLeases(board);
      const now = new Date().toISOString(); board.status = "paused"; board.lifecycle = { ...board.lifecycle, stateChangedAt: now, pausedAt: now, reason: requiredReason(reason) };
      this.save(board, revision); return board;
    });
  }

  async resume(id: string, reason?: string): Promise<Workboard> {
    return this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision; reclaimAllExpired(board); requireBoardState(board, ["paused"], "resume"); requireNoLiveLeases(board);
      const now = new Date().toISOString(); board.status = "active"; board.lifecycle = { ...board.lifecycle, stateChangedAt: now, resumedAt: now, ...(reason ? { reason: clip(reason, 2_000) } : { reason: undefined }) };
      this.save(board, revision); return board;
    });
  }

  async complete(id: string, reason?: string): Promise<Workboard> {
    return this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision; reclaimAllExpired(board); requireBoardState(board, ["active", "paused"], "complete"); requireNoLiveLeases(board);
      const unfinished = board.items.filter((item) => item.status !== "accepted" && item.status !== "canceled");
      if (unfinished.length) throw new Error(`WORKBOARD_INCOMPLETE: ${unfinished.map((item) => item.key).join(", ")}`);
      const now = new Date().toISOString(); board.status = "completed"; board.lifecycle = { ...board.lifecycle, stateChangedAt: now, completedAt: now, ...(reason ? { reason: clip(reason, 2_000) } : { reason: undefined }) };
      this.save(board, revision); return board;
    });
  }

  async cancel(id: string, reason: string): Promise<Workboard> {
    return this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision; reclaimAllExpired(board); requireBoardState(board, ["active", "paused"], "cancel"); requireNoLiveLeases(board);
      const now = new Date().toISOString(), why = requiredReason(reason);
      for (const item of board.items) if (item.status !== "accepted" && item.status !== "canceled") { item.status = "canceled"; item.cancellation = { at: now, reason: why }; item.owner = undefined; item.reviewOwner = undefined; }
      board.status = "canceled"; board.lifecycle = { ...board.lifecycle, stateChangedAt: now, canceledAt: now, reason: why };
      this.save(board, revision); return board;
    });
  }

  async archive(id: string, reason?: string): Promise<Workboard> {
    return this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision; reclaimAllExpired(board); requireBoardState(board, ["completed", "canceled"], "archive"); requireNoLiveLeases(board);
      const now = new Date().toISOString(); board.status = "archived"; board.lifecycle = { ...board.lifecycle, stateChangedAt: now, archivedAt: now, ...(reason ? { reason: clip(reason, 2_000) } : { reason: undefined }) };
      this.save(board, revision); return board;
    });
  }

  async cancelItem(id: string, key: string, reason: string): Promise<Workboard> {
    return this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision, item = find(board, key); reclaimAllExpired(board); requireBoardState(board, ["active", "paused"], "cancel item");
      if (item.owner || item.reviewOwner) throw new Error(`WORK_ITEM_BUSY: ${key} has a live lease`);
      if (item.status === "accepted" || item.status === "canceled") throw new Error(`WORK_ITEM_INVALID_TRANSITION: cannot cancel ${key} from ${item.status}`);
      item.status = "canceled"; item.cancellation = { at: new Date().toISOString(), reason: requiredReason(reason) };
      this.save(board, revision); return board;
    });
  }

  /** Budget-safe reset for retry. Attempts and usage are deliberately never replenished. */
  async retry(id: string, key: string): Promise<Workboard> {
    return this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision, item = find(board, key); reclaimAllExpired(board); requireBoardState(board, ["active", "paused"], "retry item");
      if (item.owner || item.reviewOwner) throw new Error(`WORK_ITEM_BUSY: ${key} has a live lease`);
      if (!["failed", "blocked", "rejected"].includes(item.status)) throw new Error(`WORK_ITEM_INVALID_TRANSITION: cannot retry ${key} from ${item.status}`);
      if (item.attempts >= item.budget.maxAttempts) throw new Error(`WORK_ITEM_BUDGET_EXHAUSTED: ${key}`);
      if (item.reviewAttempts >= item.budget.maxReviewAttempts) throw new Error(`WORK_ITEM_REVIEW_BUDGET_EXHAUSTED: ${key}`);
      clearPriorOutcome(item); item.cancellation = undefined; item.status = "ready";
      this.save(board, revision); return board;
    });
  }

  async decideApproval(id: string, key: string, decidedBy: string, decision: "approved" | "rejected", rationale: string): Promise<Workboard> {
    return this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision, item = find(board, key); requireBoardState(board, ["active", "paused"], "decide approval");
      if (item.owner || item.reviewOwner) throw new Error(`WORK_ITEM_BUSY: ${key} has a live lease`);
      if (item.approval.state !== "pending") throw new Error(`WORK_ITEM_APPROVAL_NOT_PENDING: ${key} is ${item.approval.state}`);
      if (!decidedBy.trim()) throw new Error("approval decidedBy is required");
      item.approval = { ...item.approval, state: decision, decidedAt: new Date().toISOString(), decidedBy: clip(decidedBy, 200), rationale: requiredReason(rationale) };
      this.save(board, revision); return board;
    });
  }

  async run(id: string, key: string, agentId: string, executor: WorkExecutor, options: { retryFailed?: boolean; leaseSec?: number } = {}): Promise<Workboard> {
    const claim = await this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision, item = find(board, key);
      reclaimAllExpired(board); requireBoardState(board, ["active"], "run item");
      if (item.status === "failed" && options.retryFailed && item.attempts < item.budget.maxAttempts) item.status = "ready";
      if (item.status === "running") throw new Error(`WORK_ITEM_BUSY: ${key} has a live owner lease`);
      if (item.status !== "ready") throw new Error(`WORK_ITEM_NOT_READY: ${key} is ${item.status}`);
      if (item.approval.state === "pending" || item.approval.state === "rejected") throw new Error(`WORK_ITEM_APPROVAL_REQUIRED: ${key} is ${item.approval.state}`);
      if (!item.dependsOn.every((dep) => find(board, dep).status === "accepted")) throw new Error(`WORK_ITEM_BLOCKED: ${key} has unaccepted dependencies`);
      if (board.items.filter((i) => i.status === "running" || i.reviewOwner).length >= board.maxParallel) throw new Error(`WORKBOARD_AT_CAPACITY: ${board.maxParallel}`);
      if (item.attempts >= item.budget.maxAttempts) throw new Error(`WORK_ITEM_BUDGET_EXHAUSTED: ${key}`);
      const leaseSec = options.leaseSec ?? item.budget.maxWallSec + 60;
      if (!Number.isInteger(leaseSec) || leaseSec < 1 || leaseSec > 86_400) throw new Error("leaseSec must be an integer from 1 to 86400");
      clearPriorOutcome(item);
      item.attempts++; item.status = "running"; item.owner = { agentId, leaseId: randomUUID(), claimedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + leaseSec * 1000).toISOString() };
      this.save(board, revision); return { board, item: structuredClone(item), revision: board.revision };
    });
    const started = Date.now();
    try {
      const output = await executor({ workboard: claim.board, item: claim.item, agentId, timeoutSec: claim.item.budget.maxWallSec, sandbox: "read-only" });
      return this.withLock(id, async () => {
        const board = this.get(id), item = find(board, key), revision = board.revision; requireOwner(item, claim.item.owner!.leaseId);
        const artifacts = [...item.artifacts, ...structuredClone(output.artifacts ?? [])], evidence = [...item.evidence, ...structuredClone(output.evidenceRefs ?? [])];
        validateReferences(artifacts, board.id, `item ${key}.artifacts`); validateReferences(evidence, board.id, `item ${key}.evidence`);
        item.artifacts = artifacts; item.evidence = evidence; item.status = "submitted"; item.owner = undefined; item.sessionId = output.sessionId; item.spent.wallMs += Date.now() - started; item.spent.turns++;
        item.submission = { summary: clip(output.summary, 20_000), evidence: clip(output.evidence ?? "", 20_000), risks: clip(output.risks ?? "", 20_000), submittedAt: new Date().toISOString(), submittedByAgentId: agentId };
        this.save(board, revision); return board;
      });
    } catch (error) {
      return this.withLock(id, async () => { const board = this.get(id), item = find(board, key), revision = board.revision; requireOwner(item, claim.item.owner!.leaseId); item.status = "failed"; item.owner = undefined; item.spent.wallMs += Date.now() - started; item.failure = { code: "EXECUTION_FAILED", message: error instanceof Error ? error.message : String(error), at: new Date().toISOString() }; this.save(board, revision); return board; });
    }
  }
  async review(id: string, key: string, reviewerAgentId: string, verdict: "accepted" | "rejected", rationale: string, sessionId?: string): Promise<Workboard> {
    return this.withLock(id, async () => { const board = this.get(id), item = find(board, key), revision = board.revision; reclaimExpiredReview(item); requireBoardState(board, ["active"], "review item"); if (item.status !== "submitted" || !item.submission) throw new Error(`WORK_ITEM_NOT_SUBMITTED: ${key}`); if (item.submission.submittedByAgentId === reviewerAgentId) throw new Error("REVIEWER_IS_SUBMITTER"); if (item.reviewOwner) throw new Error(`WORK_ITEM_REVIEW_BUSY: ${key} has a live reviewer lease`); item.status = verdict === "accepted" ? "accepted" : rejectionStatus(item); item.review = { reviewerAgentId, verdict, rationale: clip(rationale, 20_000), reviewedAt: new Date().toISOString(), ...(sessionId ? { sessionId } : {}) }; this.save(board, revision); return board; });
  }
  /** Claims an atomic review lease before calling an external reviewer. tokenBudgetHint remains advisory: adapters do not expose comparable token counts. */
  async runReview(id: string, key: string, reviewerAgentId: string, executor: ReviewExecutor, options: { leaseSec?: number } = {}): Promise<Workboard> {
    const claim = await this.withLock(id, async () => {
      const board = this.get(id), revision = board.revision, item = find(board, key);
      reclaimAllExpired(board); requireBoardState(board, ["active"], "run review");
      if (item.status !== "submitted" || !item.submission) throw new Error(`WORK_ITEM_NOT_SUBMITTED: ${key}`);
      if (item.submission.submittedByAgentId === reviewerAgentId) throw new Error("REVIEWER_IS_SUBMITTER");
      if (item.reviewOwner) throw new Error(`WORK_ITEM_REVIEW_BUSY: ${key} has a live reviewer lease`);
      if (board.items.filter((candidate) => candidate.status === "running" || candidate.reviewOwner).length >= board.maxParallel) throw new Error(`WORKBOARD_AT_CAPACITY: ${board.maxParallel}`);
      if (item.reviewAttempts >= item.budget.maxReviewAttempts) throw new Error(`WORK_ITEM_REVIEW_BUDGET_EXHAUSTED: ${key}`);
      const leaseSec = options.leaseSec ?? item.budget.maxWallSec + 60;
      if (!Number.isInteger(leaseSec) || leaseSec < 1 || leaseSec > 86_400) throw new Error("leaseSec must be an integer from 1 to 86400");
      item.reviewAttempts++;
      if (item.failure?.code === "REVIEW_FAILED") item.failure = undefined;
      item.reviewOwner = { agentId: reviewerAgentId, leaseId: randomUUID(), claimedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + leaseSec * 1000).toISOString() };
      this.save(board, revision); return { board, item: structuredClone(item) };
    });
    const started = Date.now();
    try {
      const output = await executor({ workboard: claim.board, item: claim.item, reviewerAgentId, timeoutSec: claim.item.budget.maxWallSec, sandbox: "read-only" });
      return this.completeReview(id, key, reviewerAgentId, claim.item.reviewOwner!.leaseId, output, Date.now() - started);
    } catch (error) {
      return this.withLock(id, async () => { const board = this.get(id), item = find(board, key), revision = board.revision; if (item.reviewOwner?.leaseId !== claim.item.reviewOwner!.leaseId) throw new Error("WORK_ITEM_REVIEW_LEASE_LOST"); item.reviewOwner = undefined; item.reviewSpent.wallMs += Date.now() - started; item.reviewSpent.turns++; item.failure = { code: "REVIEW_FAILED", message: error instanceof Error ? error.message : String(error), at: new Date().toISOString() }; if (item.reviewAttempts >= item.budget.maxReviewAttempts) item.status = "blocked"; this.save(board, revision); return board; });
    }
  }
  private async completeReview(id: string, key: string, reviewerAgentId: string, leaseId: string, output: { verdict: "accepted" | "rejected"; rationale: string; sessionId?: string }, wallMs: number): Promise<Workboard> {
    return this.withLock(id, async () => { const board = this.get(id), item = find(board, key), revision = board.revision; if (item.reviewOwner?.leaseId !== leaseId) throw new Error("WORK_ITEM_REVIEW_LEASE_LOST"); item.reviewOwner = undefined; item.reviewSpent.wallMs += wallMs; item.reviewSpent.turns++; item.status = output.verdict === "accepted" ? "accepted" : rejectionStatus(item); item.review = { reviewerAgentId, verdict: output.verdict, rationale: clip(output.rationale, 20_000), reviewedAt: new Date().toISOString(), ...(output.sessionId ? { sessionId: output.sessionId } : {}) }; this.save(board, revision); return board; });
  }
}

export function projectWorkboard(board: Workboard, maxChars = 4_000): Workboard {
  const cap = Math.max(1, Math.min(maxChars, 100_000)); const clean = structuredClone(board);
  clean.title = clip(clean.title, cap); clean.objective = clip(clean.objective, cap); clean.cwd = clip(clean.cwd, cap);
  clean.lifecycle.reason = clean.lifecycle.reason ? clip(clean.lifecycle.reason, cap) : undefined;
  for (const item of clean.items) {
    item.key = clip(item.key, cap); item.title = clip(item.title, cap); item.instructions = clip(item.instructions, cap); item.dependsOn = item.dependsOn.map((value) => clip(value, cap)); item.acceptanceCriteria = item.acceptanceCriteria.map((value) => clip(value, cap)); item.requirements.capabilities = item.requirements.capabilities.map((value) => clip(value, cap));
    for (const reference of [...item.artifacts, ...item.evidence]) { reference.id = clip(reference.id, cap); reference.uri = reference.uri ? clip(reference.uri, cap) : undefined; reference.path = reference.path ? clip(reference.path, cap) : undefined; reference.hash = reference.hash ? clip(reference.hash, cap) : undefined; reference.mediaType = reference.mediaType ? clip(reference.mediaType, cap) : undefined; }
    item.approval.reason = item.approval.reason ? clip(item.approval.reason, cap) : undefined; item.approval.decidedBy = item.approval.decidedBy ? clip(item.approval.decidedBy, cap) : undefined; item.approval.rationale = item.approval.rationale ? clip(item.approval.rationale, cap) : undefined;
    if (item.cancellation) item.cancellation.reason = clip(item.cancellation.reason, cap);
    if (item.owner) { item.owner.agentId = clip(item.owner.agentId, cap); item.owner.leaseId = "[redacted]"; }
    if (item.reviewOwner) { item.reviewOwner.agentId = clip(item.reviewOwner.agentId, cap); item.reviewOwner.leaseId = "[redacted]"; }
    if (item.submission) { item.submission.summary = clip(item.submission.summary, cap); item.submission.evidence = clip(item.submission.evidence, cap); item.submission.risks = clip(item.submission.risks, cap); item.submission.submittedByAgentId = clip(item.submission.submittedByAgentId, cap); }
    if (item.review) { item.review.reviewerAgentId = clip(item.review.reviewerAgentId, cap); item.review.rationale = clip(item.review.rationale, cap); item.review.sessionId = undefined; }
    if (item.failure) { item.failure.code = clip(item.failure.code, cap); item.failure.message = clip(item.failure.message, cap); }
  }
  return clean;
}
export function integratorBrief(board: Workboard, maxChars = 24_000): string {
  const accepted = board.items.filter((item) => item.status === "accepted"); let text = `## Cooperative workboard\n\nStatus: ${board.status}\nObjective: ${board.objective}\nWorking directory: ${board.cwd}\n\n`;
  for (const item of accepted) text += `### ${item.key} — ${item.title}\nKind: ${item.kind}\nAcceptance criteria: ${item.acceptanceCriteria.join("; ") || "not specified"}\n${item.submission?.summary ?? ""}\n\nEvidence:\n${item.submission?.evidence ?? ""}\n\nRisks:\n${item.submission?.risks ?? ""}\n\nReview: ${item.review?.rationale ?? ""}\n\n`;
  const pending = board.items.filter((item) => item.status !== "accepted").map((item) => `${item.key} (${item.status})`).join(", ");
  text += `Unaccepted work: ${pending || "none"}\n`; return clip(text, maxChars);
}

function migratePersistedWorkboard(raw: unknown, expectedId: string): { board: Workboard; changed: boolean } {
  if (!isRecord(raw)) throw corrupt(expectedId, "root must be an object");
  if (raw.schemaVersion === 2) return { board: raw as unknown as Workboard, changed: false };
  if (raw.schemaVersion !== undefined && raw.schemaVersion !== 1) {
    const label = typeof raw.schemaVersion === "number" ? String(raw.schemaVersion) : JSON.stringify(raw.schemaVersion);
    throw new Error(`WORKBOARD_UNSUPPORTED_VERSION: workboard ${expectedId} has schemaVersion ${label}`);
  }
  // v0.3-dev first persisted without a version, then as schema v1. Normalize both before the v2 lifecycle migration.
  const migrated = structuredClone(raw) as Record<string, unknown>;
  const wasUnversioned = migrated.schemaVersion === undefined;
  if (wasUnversioned && Array.isArray(migrated.items)) for (const candidate of migrated.items) if (isRecord(candidate) && candidate.reviewSpent === undefined) candidate.reviewSpent = { wallMs: 0, turns: 0 };
  validateLegacyV1Shape(migrated, expectedId, wasUnversioned);
  if (wasUnversioned) migrated.schemaVersion = 1;
  const migrationAt = typeof migrated.createdAt === "string" ? migrated.createdAt : new Date(0).toISOString();
  migrated.schemaVersion = 2;
  migrated.status = "active";
  migrated.lifecycle = { stateChangedAt: migrationAt, reason: "Migrated from workboard schema v1." };
  if (Array.isArray(migrated.items)) {
    for (const candidate of migrated.items) if (isRecord(candidate)) {
      candidate.kind = "other";
      candidate.acceptanceCriteria = [];
      candidate.requirements = normalizeRequirements();
      candidate.artifacts = [];
      candidate.evidence = [];
      candidate.approval = { state: "not-required" };
      if (candidate.status === "canceled") candidate.cancellation = { at: migrationAt, reason: "Migrated canceled work item." };
    }
  }
  return { board: migrated as unknown as Workboard, changed: true };
}

function validateLegacyV1Shape(board: Record<string, unknown>, id: string, unversioned: boolean): void {
  const rootKeys = ["id", "title", "objective", "cwd", "createdAt", "updatedAt", "revision", "maxParallel", "items"];
  exactKeys(board, unversioned ? rootKeys : ["schemaVersion", ...rootKeys], id, "legacy root");
  if (!unversioned && board.schemaVersion !== 1) throw new Error(`WORKBOARD_UNSUPPORTED_VERSION: workboard ${id} has schemaVersion ${String(board.schemaVersion)}`);
  if (!Array.isArray(board.items) || board.items.length === 0) throw corrupt(id, "legacy items must be a non-empty array");
  const itemKeys = ["key", "title", "instructions", "dependsOn", "status", "owner", "sessionId", "attempts", "reviewAttempts", "budget", "spent", "reviewSpent", "submission", "review", "reviewOwner", "failure"];
  for (let index = 0; index < board.items.length; index++) {
    const item = board.items[index];
    if (!isRecord(item)) throw corrupt(id, `legacy items[${index}] must be an object`);
    exactKeys(item, itemKeys, id, `legacy items[${index}]`);
  }
}

function validatePersistedWorkboard(board: unknown, expectedId: string): asserts board is Workboard {
  if (!isRecord(board)) throw corrupt(expectedId, "root must be an object");
  exactKeys(board, ["schemaVersion", "id", "title", "objective", "cwd", "createdAt", "updatedAt", "revision", "maxParallel", "status", "lifecycle", "items"], expectedId, "root");
  if (board.schemaVersion !== 2) throw new Error(`WORKBOARD_UNSUPPORTED_VERSION: workboard ${expectedId} has schemaVersion ${String(board.schemaVersion)}`);
  stringField(board.id, expectedId, "id");
  if (board.id !== expectedId || !/^[A-Za-z0-9_-]+$/.test(board.id)) throw corrupt(expectedId, "id does not match its file name or is unsafe");
  for (const field of ["title", "objective", "cwd"] as const) stringField(board[field], expectedId, field);
  isoField(board.createdAt, expectedId, "createdAt"); isoField(board.updatedAt, expectedId, "updatedAt");
  integerField(board.revision, expectedId, "revision", 0);
  integerField(board.maxParallel, expectedId, "maxParallel", 1, 32);
  if (!["active", "paused", "completed", "canceled", "archived"].includes(String(board.status))) throw corrupt(expectedId, "status is invalid");
  validateLifecycle(board.lifecycle, expectedId);
  if (!Array.isArray(board.items) || board.items.length === 0) throw corrupt(expectedId, "items must be a non-empty array");
  const keys = new Set<string>();
  for (let index = 0; index < board.items.length; index++) {
    const item = board.items[index]; const at = `items[${index}]`;
    if (!isRecord(item)) throw corrupt(expectedId, `${at} must be an object`);
    exactKeys(item, ["key", "title", "instructions", "dependsOn", "kind", "acceptanceCriteria", "requirements", "artifacts", "evidence", "approval", "status", "owner", "sessionId", "attempts", "reviewAttempts", "budget", "spent", "reviewSpent", "submission", "review", "reviewOwner", "failure", "cancellation"], expectedId, at);
    stringField(item.key, expectedId, `${at}.key`); stringField(item.title, expectedId, `${at}.title`); stringField(item.instructions, expectedId, `${at}.instructions`);
    if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(item.key) || keys.has(item.key)) throw corrupt(expectedId, `${at}.key is invalid or duplicated`); keys.add(item.key);
    if (!Array.isArray(item.dependsOn) || item.dependsOn.some((value) => typeof value !== "string")) throw corrupt(expectedId, `${at}.dependsOn must be a string array`);
    if (new Set(item.dependsOn).size !== item.dependsOn.length) throw corrupt(expectedId, `${at}.dependsOn contains duplicates`);
    if (!["research", "implementation", "review", "design", "content", "validation", "other"].includes(String(item.kind))) throw corrupt(expectedId, `${at}.kind is invalid`);
    stringArray(item.acceptanceCriteria, expectedId, `${at}.acceptanceCriteria`); validateRequirements(item.requirements, expectedId, `${at}.requirements`); validateReferences(item.artifacts, expectedId, `${at}.artifacts`); validateReferences(item.evidence, expectedId, `${at}.evidence`); validateApproval(item.approval, expectedId, `${at}.approval`);
    if (!["ready", "running", "submitted", "accepted", "rejected", "blocked", "failed", "canceled"].includes(String(item.status))) throw corrupt(expectedId, `${at}.status is invalid`);
    integerField(item.attempts, expectedId, `${at}.attempts`, 0); integerField(item.reviewAttempts, expectedId, `${at}.reviewAttempts`, 0);
    validateBudget(item.budget, expectedId, `${at}.budget`); validateUsage(item.spent, expectedId, `${at}.spent`); validateUsage(item.reviewSpent, expectedId, `${at}.reviewSpent`);
    const budget = item.budget as Record<string, unknown>;
    if ((item.attempts as number) > (budget.maxAttempts as number) || (item.reviewAttempts as number) > (budget.maxReviewAttempts as number)) throw corrupt(expectedId, `${at} attempts exceed budget`);
    optionalString(item.sessionId, expectedId, `${at}.sessionId`);
    optionalOwner(item.owner, expectedId, `${at}.owner`); optionalOwner(item.reviewOwner, expectedId, `${at}.reviewOwner`);
    if (item.status === "running" && item.owner === undefined) throw corrupt(expectedId, `${at} is running without an owner`);
    if (item.status !== "running" && item.owner !== undefined) throw corrupt(expectedId, `${at} has an owner while not running`);
    if (item.reviewOwner !== undefined && item.status !== "submitted") throw corrupt(expectedId, `${at} has a review owner while not submitted`);
    optionalSubmission(item.submission, expectedId, `${at}.submission`); optionalReview(item.review, expectedId, `${at}.review`); optionalFailure(item.failure, expectedId, `${at}.failure`); optionalCancellation(item.cancellation, expectedId, `${at}.cancellation`);
    if (item.status === "canceled" && item.cancellation === undefined) throw corrupt(expectedId, `${at} is canceled without cancellation metadata`);
    if (item.status !== "canceled" && item.cancellation !== undefined) throw corrupt(expectedId, `${at} has cancellation metadata while status is ${String(item.status)}`);
    if (["submitted", "accepted"].includes(String(item.status)) && item.submission === undefined) throw corrupt(expectedId, `${at} is ${String(item.status)} without a submission`);
    if (item.review !== undefined && item.submission === undefined) throw corrupt(expectedId, `${at} has a review without a submission`);
    if (item.status === "accepted" && (!isRecord(item.review) || item.review.verdict !== "accepted")) throw corrupt(expectedId, `${at} is accepted without an accepted review`);
    if (isRecord(item.review) && item.review.verdict === "accepted" && item.status !== "accepted") throw corrupt(expectedId, `${at} has an accepted review while status is ${String(item.status)}`);
    if (isRecord(item.review) && item.review.verdict === "rejected") {
      const retryExhausted = (item.attempts as number) >= (budget.maxAttempts as number) || (item.reviewAttempts as number) >= (budget.maxReviewAttempts as number);
      const expectedStatus = retryExhausted ? "blocked" : "ready";
      if (item.status !== expectedStatus && item.status !== "canceled") throw corrupt(expectedId, `${at} has a rejected review while status is ${String(item.status)}; expected ${expectedStatus}`);
    }
    if (isRecord(item.failure) && item.failure.code === "EXECUTION_FAILED" && item.status !== "failed" && item.status !== "canceled") throw corrupt(expectedId, `${at} has an execution failure while status is ${String(item.status)}`);
    if (isRecord(item.failure) && item.failure.code === "REVIEW_FAILED" && item.status !== "submitted" && item.status !== "blocked" && item.status !== "canceled") throw corrupt(expectedId, `${at} has a review failure while status is ${String(item.status)}`);
  }
  const itemMap = new Map((board.items as unknown as WorkItem[]).map((item) => [item.key, item]));
  const visit = (key: string, trail: Set<string>): void => {
    const current = itemMap.get(key); if (!current) throw corrupt(expectedId, `unknown dependency: ${key}`);
    if (trail.has(key)) throw corrupt(expectedId, `dependency cycle includes ${key}`);
    const next = new Set(trail); next.add(key); for (const dependency of current.dependsOn) visit(dependency, next);
  };
  for (const key of itemMap.keys()) visit(key, new Set());
  validateBoardLifecycleState(board as unknown as Workboard, expectedId);
}

function validateBudget(value: unknown, id: string, at: string): void {
  if (!isRecord(value)) throw corrupt(id, `${at} must be an object`);
  exactKeys(value, ["maxAttempts", "maxReviewAttempts", "maxWallSec", "tokenBudgetHint"], id, at);
  integerField(value.maxAttempts, id, `${at}.maxAttempts`, 1, 10); integerField(value.maxReviewAttempts, id, `${at}.maxReviewAttempts`, 1, 10); integerField(value.maxWallSec, id, `${at}.maxWallSec`, 1, 7_200);
  if (value.tokenBudgetHint !== undefined) integerField(value.tokenBudgetHint, id, `${at}.tokenBudgetHint`, 1);
}
function validateLifecycle(value: unknown, id: string): void {
  if (!isRecord(value)) throw corrupt(id, "lifecycle must be an object");
  exactKeys(value, ["stateChangedAt", "reason", "pausedAt", "resumedAt", "completedAt", "canceledAt", "archivedAt"], id, "lifecycle");
  isoField(value.stateChangedAt, id, "lifecycle.stateChangedAt"); optionalString(value.reason, id, "lifecycle.reason");
  for (const field of ["pausedAt", "resumedAt", "completedAt", "canceledAt", "archivedAt"] as const) if (value[field] !== undefined) isoField(value[field], id, `lifecycle.${field}`);
}
function validateBoardLifecycleState(board: Workboard, id: string): void {
  const lifecycle = board.lifecycle;
  if (lifecycle.completedAt && lifecycle.canceledAt) throw corrupt(id, "lifecycle cannot be both completed and canceled");
  if (board.status !== "archived" && lifecycle.archivedAt) throw corrupt(id, `status ${board.status} has archivedAt`);
  if (board.status === "active") {
    if (lifecycle.completedAt || lifecycle.canceledAt) throw corrupt(id, "active board has a terminal timestamp");
    if (lifecycle.resumedAt && lifecycle.stateChangedAt !== lifecycle.resumedAt) throw corrupt(id, "active board stateChangedAt must match resumedAt");
    if (!lifecycle.resumedAt && lifecycle.stateChangedAt !== board.createdAt) throw corrupt(id, "initial active board stateChangedAt must match createdAt");
  }
  if (board.status === "paused" && (!lifecycle.pausedAt || lifecycle.stateChangedAt !== lifecycle.pausedAt)) throw corrupt(id, "paused board is missing its current pausedAt");
  if (board.status === "completed" && (!lifecycle.completedAt || lifecycle.stateChangedAt !== lifecycle.completedAt || lifecycle.canceledAt)) throw corrupt(id, "completed board has inconsistent lifecycle metadata");
  if (board.status === "canceled" && (!lifecycle.canceledAt || lifecycle.stateChangedAt !== lifecycle.canceledAt || lifecycle.completedAt)) throw corrupt(id, "canceled board has inconsistent lifecycle metadata");
  if (board.status === "archived" && (!lifecycle.archivedAt || lifecycle.stateChangedAt !== lifecycle.archivedAt || (!lifecycle.completedAt && !lifecycle.canceledAt))) throw corrupt(id, "archived board has no terminal history");
  if (["completed", "canceled", "archived"].includes(board.status)) {
    const nonterminal = board.items.filter((item) => item.status !== "accepted" && item.status !== "canceled");
    if (nonterminal.length) throw corrupt(id, `${board.status} board has nonterminal item(s): ${nonterminal.map((item) => item.key).join(", ")}`);
  }
}
function validateRequirements(value: unknown, id: string, at: string): void {
  if (!isRecord(value)) throw corrupt(id, `${at} must be an object`);
  exactKeys(value, ["dataClass", "filesystem", "network", "capabilities"], id, at);
  if (!["public", "internal", "confidential", "restricted"].includes(String(value.dataClass))) throw corrupt(id, `${at}.dataClass is invalid`);
  if (!["none", "metadata-only", "read-only"].includes(String(value.filesystem))) throw corrupt(id, `${at}.filesystem is invalid`);
  if (!["none", "restricted", "required"].includes(String(value.network))) throw corrupt(id, `${at}.network is invalid`);
  stringArray(value.capabilities, id, `${at}.capabilities`);
}
function validateReferences(value: unknown, id: string, at: string): asserts value is ArtifactReference[] {
  if (!Array.isArray(value)) throw corrupt(id, `${at} must be an array`);
  if (value.length > 1_000) throw corrupt(id, `${at} exceeds 1000 metadata references`);
  const ids = new Set<string>();
  for (let index = 0; index < value.length; index++) {
    const reference = value[index], refAt = `${at}[${index}]`;
    if (!isRecord(reference)) throw corrupt(id, `${refAt} must be an object`);
    exactKeys(reference, ["id", "kind", "uri", "path", "hash", "mediaType", "dataClass", "accessibility"], id, refAt);
    stringField(reference.id, id, `${refAt}.id`);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(reference.id) || ids.has(reference.id)) throw corrupt(id, `${refAt}.id is invalid or duplicated`);
    ids.add(reference.id);
    if (!["source", "report", "image", "video", "audio", "document", "dataset", "build", "link", "other"].includes(String(reference.kind))) throw corrupt(id, `${refAt}.kind is invalid`);
    if (!["public", "internal", "confidential", "restricted"].includes(String(reference.dataClass))) throw corrupt(id, `${refAt}.dataClass is invalid`);
    if (!["local", "remote", "inline", "unavailable"].includes(String(reference.accessibility))) throw corrupt(id, `${refAt}.accessibility is invalid`);
    for (const field of ["uri", "path", "hash", "mediaType"] as const) optionalString(reference[field], id, `${refAt}.${field}`);
    if (reference.accessibility !== "unavailable" && reference.uri === undefined && reference.path === undefined) throw corrupt(id, `${refAt} needs uri or path unless unavailable`);
  }
}
function validateApproval(value: unknown, id: string, at: string): void {
  if (!isRecord(value)) throw corrupt(id, `${at} must be an object`);
  exactKeys(value, ["state", "reason", "requestedAt", "decidedAt", "decidedBy", "rationale"], id, at);
  if (!["not-required", "pending", "approved", "rejected"].includes(String(value.state))) throw corrupt(id, `${at}.state is invalid`);
  for (const field of ["reason", "decidedBy", "rationale"] as const) optionalString(value[field], id, `${at}.${field}`);
  for (const field of ["requestedAt", "decidedAt"] as const) if (value[field] !== undefined) isoField(value[field], id, `${at}.${field}`);
  if (value.state === "not-required" && (value.requestedAt !== undefined || value.decidedAt !== undefined || value.decidedBy !== undefined || value.rationale !== undefined)) throw corrupt(id, `${at} not-required state has decision metadata`);
  if (value.state === "pending" && (value.requestedAt === undefined || value.decidedAt !== undefined || value.decidedBy !== undefined || value.rationale !== undefined)) throw corrupt(id, `${at} pending state has inconsistent metadata`);
  if ((value.state === "approved" || value.state === "rejected") && (value.requestedAt === undefined || value.decidedAt === undefined || value.decidedBy === undefined || value.rationale === undefined)) throw corrupt(id, `${at} decision state is incomplete`);
}
function validateUsage(value: unknown, id: string, at: string): void { if (!isRecord(value)) throw corrupt(id, `${at} must be an object`); exactKeys(value, ["wallMs", "turns"], id, at); integerField(value.wallMs, id, `${at}.wallMs`, 0); integerField(value.turns, id, `${at}.turns`, 0); }
function optionalOwner(value: unknown, id: string, at: string): void { if (value === undefined) return; if (!isRecord(value)) throw corrupt(id, `${at} must be an object`); exactKeys(value, ["agentId", "leaseId", "claimedAt", "expiresAt"], id, at); stringField(value.agentId, id, `${at}.agentId`); stringField(value.leaseId, id, `${at}.leaseId`); isoField(value.claimedAt, id, `${at}.claimedAt`); isoField(value.expiresAt, id, `${at}.expiresAt`); }
function optionalSubmission(value: unknown, id: string, at: string): void { if (value === undefined) return; if (!isRecord(value)) throw corrupt(id, `${at} must be an object`); exactKeys(value, ["summary", "evidence", "risks", "submittedAt", "submittedByAgentId"], id, at); for (const field of ["summary", "evidence", "risks", "submittedByAgentId"] as const) stringField(value[field], id, `${at}.${field}`); isoField(value.submittedAt, id, `${at}.submittedAt`); }
function optionalReview(value: unknown, id: string, at: string): void { if (value === undefined) return; if (!isRecord(value)) throw corrupt(id, `${at} must be an object`); exactKeys(value, ["reviewerAgentId", "verdict", "rationale", "reviewedAt", "sessionId"], id, at); stringField(value.reviewerAgentId, id, `${at}.reviewerAgentId`); if (value.verdict !== "accepted" && value.verdict !== "rejected") throw corrupt(id, `${at}.verdict is invalid`); stringField(value.rationale, id, `${at}.rationale`); isoField(value.reviewedAt, id, `${at}.reviewedAt`); optionalString(value.sessionId, id, `${at}.sessionId`); }
function optionalFailure(value: unknown, id: string, at: string): void { if (value === undefined) return; if (!isRecord(value)) throw corrupt(id, `${at} must be an object`); exactKeys(value, ["code", "message", "at"], id, at); stringField(value.code, id, `${at}.code`); stringField(value.message, id, `${at}.message`); isoField(value.at, id, `${at}.at`); }
function optionalCancellation(value: unknown, id: string, at: string): void { if (value === undefined) return; if (!isRecord(value)) throw corrupt(id, `${at} must be an object`); exactKeys(value, ["at", "reason"], id, at); isoField(value.at, id, `${at}.at`); stringField(value.reason, id, `${at}.reason`); if (!value.reason.trim()) throw corrupt(id, `${at}.reason cannot be empty`); }
function exactKeys(value: Record<string, unknown>, allowed: string[], id: string, at: string): void { const permitted = new Set(allowed); const extra = Object.keys(value).filter((key) => !permitted.has(key)); if (extra.length) throw corrupt(id, `${at} has unknown field(s): ${extra.join(", ")}`); }
function stringField(value: unknown, id: string, at: string): asserts value is string { if (typeof value !== "string") throw corrupt(id, `${at} must be a string`); }
function optionalString(value: unknown, id: string, at: string): void { if (value !== undefined) stringField(value, id, at); }
function integerField(value: unknown, id: string, at: string, min: number, max = Number.MAX_SAFE_INTEGER): asserts value is number { if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) throw corrupt(id, `${at} must be an integer from ${min} to ${max}`); }
function stringArray(value: unknown, id: string, at: string): asserts value is string[] { if (!Array.isArray(value) || value.length > 256 || value.some((entry) => typeof entry !== "string" || !entry.trim())) throw corrupt(id, `${at} must be an array of at most 256 non-empty strings`); if (new Set(value).size !== value.length) throw corrupt(id, `${at} contains duplicates`); }
function isoField(value: unknown, id: string, at: string): void { stringField(value, id, at); if (Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw corrupt(id, `${at} must be an ISO timestamp`); }
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function corrupt(id: string, detail: string): Error { return new Error(`WORKBOARD_CORRUPT: workboard ${id}: ${detail}`); }
function writeAtomic(path: string, board: Workboard): void { const temp = `${path}.${process.pid}.${randomUUID()}.tmp`; writeFileSync(temp, JSON.stringify(board, null, 2), { encoding: "utf8", mode: 0o600 }); renameSync(temp, path); }

function validateInputs(items: WorkItemInput[]): void {
  if (!Array.isArray(items) || !items.length) throw new Error("workboard requires at least one item");
  const keys = new Set<string>();
  for (const item of items) {
    if (!isRecord(item)) throw new Error("each work item must be an object");
    exactKeys(item, ["key", "title", "instructions", "dependsOn", "kind", "acceptanceCriteria", "requirements", "artifacts", "evidence", "approval", "budget"], "new", "input item");
    if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(item.key) || keys.has(item.key)) throw new Error(`invalid or duplicate work item key: ${item.key}`);
    keys.add(item.key);
    if (!item.title || !item.instructions) throw new Error(`work item ${item.key} needs title and instructions`);
    if (item.kind !== undefined && !["research", "implementation", "review", "design", "content", "validation", "other"].includes(item.kind)) throw new Error(`invalid kind for ${item.key}`);
    if (item.acceptanceCriteria !== undefined) stringArray(item.acceptanceCriteria, "new", `${item.key}.acceptanceCriteria`);
    validateRequirementsInput(item.requirements, item.key); validateRequirements(normalizeRequirements(item.requirements), "new", `${item.key}.requirements`);
    validateReferences(item.artifacts ?? [], "new", `${item.key}.artifacts`); validateReferences(item.evidence ?? [], "new", `${item.key}.evidence`);
    if (item.approval !== undefined) {
      if (!isRecord(item.approval)) throw new Error(`invalid approval for ${item.key}`);
      exactKeys(item.approval, ["required", "reason"], "new", `${item.key}.approval`);
      if (typeof item.approval.required !== "boolean" || (item.approval.reason !== undefined && (typeof item.approval.reason !== "string" || !item.approval.reason.trim()))) throw new Error(`invalid approval for ${item.key}`);
    }
    if (item.budget !== undefined) { if (!isRecord(item.budget)) throw new Error(`invalid budget for ${item.key}`); exactKeys(item.budget, ["maxAttempts", "maxWallSec", "tokenBudgetHint"], "new", `${item.key}.budget`); }
    const maxAttempts = item.budget?.maxAttempts ?? 2, maxWallSec = item.budget?.maxWallSec ?? 600, tokenHint = item.budget?.tokenBudgetHint;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10 || !Number.isInteger(maxWallSec) || maxWallSec < 1 || maxWallSec > 7_200 || (tokenHint !== undefined && (!Number.isInteger(tokenHint) || tokenHint < 1))) throw new Error(`invalid budget for ${item.key}`);
  }
  const map = new Map(items.map((item) => [item.key, item]));
  const visit = (key: string, trail: Set<string>) => { const item = map.get(key); if (!item) throw new Error(`unknown dependency: ${key}`); if (trail.has(key)) throw new Error(`dependency cycle includes ${key}`); const next = new Set(trail); next.add(key); for (const dep of item.dependsOn ?? []) visit(dep, next); };
  for (const item of items) visit(item.key, new Set());
}
function find(board: Workboard, key: string): WorkItem { const item = board.items.find((candidate) => candidate.key === key); if (!item) throw new Error(`no such work item: ${key}`); return item; }
function validateRequirementsInput(value: unknown, key: string): void {
  if (value === undefined) return;
  if (!isRecord(value)) throw new Error(`invalid requirements for ${key}`);
  exactKeys(value, ["dataClass", "filesystem", "network", "capabilities"], "new", `${key}.requirements`);
  if (value.dataClass !== undefined && !["public", "internal", "confidential", "restricted"].includes(String(value.dataClass))) throw new Error(`invalid requirements dataClass for ${key}`);
  if (value.filesystem !== undefined && !["none", "metadata-only", "read-only"].includes(String(value.filesystem))) throw new Error(`invalid requirements filesystem for ${key}`);
  if (value.network !== undefined && !["none", "restricted", "required"].includes(String(value.network))) throw new Error(`invalid requirements network for ${key}`);
  if (value.capabilities !== undefined) stringArray(value.capabilities, "new", `${key}.requirements.capabilities`);
}
function normalizeRequirements(value: Partial<WorkItemRequirements> = {}): WorkItemRequirements {
  // Cooperative CLI providers may use their own service egress. "restricted"
  // permits that provider path; it does not promise arbitrary network access.
  return { dataClass: value.dataClass ?? "internal", filesystem: value.filesystem ?? "read-only", network: value.network ?? "restricted", capabilities: [...(value.capabilities ?? [])] };
}
function reclaimExpired(item: WorkItem): void { if (item.status === "running" && item.owner && Date.parse(item.owner.expiresAt) <= Date.now()) { item.status = "ready"; item.owner = undefined; } }
function reclaimExpiredReview(item: WorkItem): void { if (item.reviewOwner && Date.parse(item.reviewOwner.expiresAt) <= Date.now()) item.reviewOwner = undefined; }
function reclaimAllExpired(board: Workboard): void { for (const item of board.items) { reclaimExpired(item); reclaimExpiredReview(item); } }
function clearPriorOutcome(item: WorkItem): void { item.sessionId = undefined; item.submission = undefined; item.review = undefined; item.failure = undefined; item.reviewOwner = undefined; }
function rejectionStatus(item: WorkItem): "ready" | "blocked" { return item.attempts >= item.budget.maxAttempts || item.reviewAttempts >= item.budget.maxReviewAttempts ? "blocked" : "ready"; }
function requireOwner(item: WorkItem, leaseId: string): void { if (item.status !== "running" || item.owner?.leaseId !== leaseId) throw new Error("WORK_ITEM_LEASE_LOST"); }
function requireBoardState(board: Workboard, allowed: WorkboardStatus[], operation: string): void { if (!allowed.includes(board.status)) throw new Error(`WORKBOARD_INVALID_TRANSITION: cannot ${operation} while ${board.status}`); }
function requireNoLiveLeases(board: Workboard): void { const busy = board.items.filter((item) => item.owner || item.reviewOwner).map((item) => item.key); if (busy.length) throw new Error(`WORKBOARD_BUSY: live lease(s) on ${busy.join(", ")}`); }
function requiredReason(value: string): string { if (typeof value !== "string" || !value.trim()) throw new Error("reason is required"); return clip(value.trim(), 2_000); }
function safeId(id: string): string { if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error(`invalid workboard id: ${id}`); return id; }
function stale(path: string, ms: number): boolean { try { return Date.now() - statSync(path).mtimeMs > ms; } catch { return false; } }
function sleep(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)); }
function clip(value: string, max: number): string { return value.length > max ? `${value.slice(0, max)}\n…[truncated]` : value; }
