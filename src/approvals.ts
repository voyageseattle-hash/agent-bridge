import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";

export const APPROVAL_CATEGORIES = [
  "remote_egress",
  "paid_or_unknown_cost",
  "secrets",
  "browser_or_connectors",
  "authority_escalation",
  "apply_or_merge",
  "deploy_or_publish",
] as const;
export type ApprovalCategory = typeof APPROVAL_CATEGORIES[number];

const FRESH_PER_CALL_CATEGORIES = new Set<ApprovalCategory>([
  "remote_egress",
  "paid_or_unknown_cost",
]);

export const APPROVAL_STATES = ["pending", "approved", "denied", "consumed", "expired", "canceled"] as const;
export type ApprovalState = typeof APPROVAL_STATES[number];

export const APPROVAL_DATA_CLASSES = ["public", "internal", "confidential", "restricted"] as const;
export type ApprovalDataClass = typeof APPROVAL_DATA_CLASSES[number];

export interface ApprovalScope {
  subject: string;
  action: string;
  dataClass: ApprovalDataClass;
  root: string;
  agent: string;
  /** Lowercase SHA-256 of the exact UTF-8 payload bytes being authorized. */
  payloadSha256: string;
}

export type ApprovalEventType = "requested" | "approved" | "denied" | "used" | "consumed" | "expired" | "canceled";

export interface ApprovalEvent {
  sequence: number;
  type: ApprovalEventType;
  at: string;
  actor: string;
  reason: string;
}

export interface ApprovalRecord {
  schemaVersion: 2;
  id: string;
  category: ApprovalCategory;
  state: ApprovalState;
  scope: ApprovalScope;
  requestedBy: string;
  reason: string;
  requestedAt: string;
  updatedAt: string;
  expiresAt: string;
  estimatedCost: number | null;
  currency: string | null;
  consumeOnce: boolean;
  maxUses: number;
  useCount: number;
  revision: number;
  events: ApprovalEvent[];
}

export interface ApprovalRequestInput {
  category: ApprovalCategory;
  scope: ApprovalScope;
  requestedBy: string;
  reason: string;
  expiresAt: string;
  estimatedCost?: number;
  currency?: string;
  /** Defaults to true. Reusable approvals are still capped by maxUses. */
  consumeOnce?: boolean;
  /** Defaults to 1 for one-time approvals and 100 otherwise; maximum 1000. */
  maxUses?: number;
}

export interface ApprovalListFilter {
  state?: ApprovalState;
  category?: ApprovalCategory;
  subject?: string;
  agent?: string;
  limit?: number;
}

export class ApprovalStore {
  readonly dir: string;
  readonly lockDir: string;

  constructor(
    stateDir: string,
    private readonly lockWaitMs = 30_000,
    private readonly lockStaleMs = 7_500_000,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.dir = join(stateDir, "approvals");
    this.lockDir = join(stateDir, "approval-locks");
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    mkdirSync(this.lockDir, { recursive: true, mode: 0o700 });
  }

  create(input: ApprovalRequestInput): ApprovalRecord {
    validateRequestInput(input);
    const now = this.now();
    if (Date.parse(input.expiresAt) <= Date.parse(now)) {
      throw new Error("APPROVAL_INVALID_EXPIRY: expiresAt must be later than requestedAt");
    }
    const consumeOnce = input.consumeOnce ?? true;
    const maxUses = input.maxUses ?? (consumeOnce ? 1 : 100);
    if (consumeOnce && maxUses !== 1) throw new Error("APPROVAL_INVALID_USES: one-time approvals must have maxUses=1");
    if (!consumeOnce && maxUses === 1) throw new Error("APPROVAL_INVALID_USES: reusable approvals must have maxUses of at least 2");
    if (!Number.isSafeInteger(maxUses) || maxUses < 1 || maxUses > 1_000) {
      throw new Error("APPROVAL_INVALID_USES: maxUses must be an integer from 1 to 1000");
    }
    requireFreshPerCallAuthority(input.category, consumeOnce, maxUses);
    const id = randomUUID();
    const record: ApprovalRecord = {
      schemaVersion: 2,
      id,
      category: input.category,
      state: "pending",
      scope: structuredClone(input.scope),
      requestedBy: input.requestedBy,
      reason: input.reason,
      requestedAt: now,
      updatedAt: now,
      expiresAt: input.expiresAt,
      estimatedCost: input.estimatedCost ?? null,
      currency: input.currency?.toUpperCase() ?? null,
      consumeOnce,
      maxUses,
      useCount: 0,
      revision: 0,
      events: [{ sequence: 1, type: "requested", at: now, actor: input.requestedBy, reason: input.reason }],
    };
    validatePersistedApproval(record, id);
    writeAtomic(this.path(id), record);
    return structuredClone(record);
  }

  path(id: string): string {
    return join(this.dir, `${safeId(id)}.json`);
  }

  get(id: string): ApprovalRecord {
    const path = this.path(id);
    if (!existsSync(path)) throw new Error(`APPROVAL_NOT_FOUND: ${id}`);
    let raw: unknown;
    try { raw = JSON.parse(readFileSync(path, "utf8")); }
    catch (error) { throw corrupt(id, `invalid JSON: ${error instanceof Error ? error.message : String(error)}`); }
    if (isRecord(raw) && raw.schemaVersion === 1) {
      const migrated = migrateLegacyApproval(raw, id, this.now());
      writeAtomic(path, migrated);
      return structuredClone(migrated);
    }
    if (isRecord(raw) && raw.schemaVersion !== 2) {
      const label = typeof raw.schemaVersion === "number" ? String(raw.schemaVersion) : JSON.stringify(raw.schemaVersion);
      throw new Error(`APPROVAL_UNSUPPORTED_VERSION: approval ${id} has schemaVersion ${label}`);
    }
    validatePersistedApproval(raw, id);
    return structuredClone(raw);
  }

  list(filter: ApprovalListFilter = {}): ApprovalRecord[] {
    validateListFilter(filter);
    const records = readdirSync(this.dir)
      .filter((file) => file.endsWith(".json"))
      .map((file) => this.get(file.slice(0, -5)))
      .filter((record) => filter.state === undefined || record.state === filter.state)
      .filter((record) => filter.category === undefined || record.category === filter.category)
      .filter((record) => filter.subject === undefined || record.scope.subject === filter.subject)
      .filter((record) => filter.agent === undefined || record.scope.agent === filter.agent)
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt) || right.id.localeCompare(left.id));
    return records.slice(0, filter.limit ?? 50);
  }

  async approve(id: string, input: { approvedBy: string; reason: string }): Promise<ApprovalRecord> {
    exactInputKeys(input, ["approvedBy", "reason"], "APPROVAL_INVALID_DECISION: approval");
    validateActorAndReason(input.approvedBy, input.reason, "approval");
    return this.mutate(id, input.approvedBy, (record, at) => {
      requireState(record, "pending", "approve");
      requireFreshPerCallAuthority(record.category, record.consumeOnce, record.maxUses);
      appendEvent(record, "approved", at, input.approvedBy, input.reason);
      record.state = "approved";
    });
  }

  async deny(id: string, input: { deniedBy: string; reason: string }): Promise<ApprovalRecord> {
    exactInputKeys(input, ["deniedBy", "reason"], "APPROVAL_INVALID_DECISION: denial");
    validateActorAndReason(input.deniedBy, input.reason, "denial");
    return this.mutate(id, input.deniedBy, (record, at) => {
      requireState(record, "pending", "deny");
      appendEvent(record, "denied", at, input.deniedBy, input.reason);
      record.state = "denied";
    });
  }

  async cancel(id: string, input: { canceledBy: string; reason: string }): Promise<ApprovalRecord> {
    exactInputKeys(input, ["canceledBy", "reason"], "APPROVAL_INVALID_DECISION: cancellation");
    validateActorAndReason(input.canceledBy, input.reason, "cancellation");
    return this.mutate(id, input.canceledBy, (record, at) => {
      if (record.state !== "pending" && record.state !== "approved") {
        throw new Error(`APPROVAL_INVALID_TRANSITION: cannot cancel ${record.state} approval ${record.id}`);
      }
      appendEvent(record, "canceled", at, input.canceledBy, input.reason);
      record.state = "canceled";
    });
  }

  async consume(id: string, input: { consumedBy: string; scope: ApprovalScope; reason: string }): Promise<ApprovalRecord> {
    exactInputKeys(input, ["consumedBy", "scope", "reason"], "APPROVAL_INVALID_CONSUMPTION");
    validateScope(input.scope, "consume.scope");
    validateActorAndReason(input.consumedBy, input.reason, "consumption");
    return this.mutate(id, input.consumedBy, (record, at) => {
      requireState(record, "approved", "consume");
      requireFreshPerCallAuthority(record.category, record.consumeOnce, record.maxUses);
      if (!sameScope(record.scope, input.scope)) {
        throw new Error(`APPROVAL_SCOPE_MISMATCH: approval ${record.id} does not authorize the supplied scope`);
      }
      const nextUseCount = record.useCount + 1;
      if (nextUseCount > record.maxUses) throw new Error(`APPROVAL_USE_LIMIT: approval ${record.id} has no uses remaining`);
      record.useCount = nextUseCount;
      const terminal = record.consumeOnce || record.useCount === record.maxUses;
      appendEvent(record, terminal ? "consumed" : "used", at, input.consumedBy, input.reason);
      if (terminal) record.state = "consumed";
    });
  }

  /** Persist an expiry transition if the approval is due; otherwise return it unchanged. */
  async expireDue(id: string, actor = "agent-bridge"): Promise<ApprovalRecord> {
    validateBoundedString(actor, "expiry actor", 200);
    return this.withLock(id, async () => {
      const record = this.get(id);
      const now = this.now();
      if (!isLive(record.state) || Date.parse(record.expiresAt) > Date.parse(now)) return record;
      const revision = record.revision;
      appendEvent(record, "expired", now, actor, "approval validity window ended");
      record.state = "expired";
      this.save(record, revision);
      return structuredClone(record);
    });
  }

  async withLock<T>(id: string, operation: () => Promise<T>): Promise<T> {
    const lock = join(this.lockDir, `${safeId(id)}.lock`);
    const started = Date.now();
    let heartbeat: NodeJS.Timeout | undefined;
    while (true) {
      try {
        mkdirSync(lock);
        writeFileSync(join(lock, "owner.json"), JSON.stringify({ pid: process.pid, acquiredAt: new Date().toISOString() }), { mode: 0o600 });
        heartbeat = setInterval(() => {
          try { utimesSync(lock, new Date(), new Date()); } catch { /* released */ }
        }, Math.min(30_000, Math.max(1_000, Math.floor(this.lockStaleMs / 4))));
        heartbeat.unref();
        break;
      } catch (error: any) {
        if (error?.code !== "EEXIST") throw error;
        if (isStale(lock, this.lockStaleMs)) {
          try { rmSync(lock, { recursive: true, force: true }); } catch { /* another waiter won */ }
          continue;
        }
        if (Date.now() - started >= this.lockWaitMs) throw new Error(`APPROVAL_BUSY: approval ${id} is being changed`);
        await delay(50 + Math.floor(Math.random() * 50));
      }
    }
    try { return await operation(); }
    finally {
      if (heartbeat) clearInterval(heartbeat);
      rmSync(lock, { recursive: true, force: true });
    }
  }

  private now(): string {
    const value = this.clock();
    if (!(value instanceof Date) || Number.isNaN(value.valueOf())) throw new Error("APPROVAL_CLOCK_INVALID");
    return value.toISOString();
  }

  private async mutate(id: string, expiryActor: string, change: (record: ApprovalRecord, at: string) => void): Promise<ApprovalRecord> {
    return this.withLock(id, async () => {
      const record = this.get(id);
      const revision = record.revision;
      const now = this.now();
      if (isLive(record.state) && Date.parse(record.expiresAt) <= Date.parse(now)) {
        appendEvent(record, "expired", now, expiryActor, "approval validity window ended");
        record.state = "expired";
        this.save(record, revision);
        throw new Error(`APPROVAL_EXPIRED: approval ${id} expired before the requested transition`);
      }
      change(record, now);
      this.save(record, revision);
      return structuredClone(record);
    });
  }

  private save(record: ApprovalRecord, expectedRevision: number): void {
    const current = this.get(record.id);
    if (current.revision !== expectedRevision) {
      throw new Error(`APPROVAL_CONFLICT: approval ${record.id} changed from revision ${expectedRevision} to ${current.revision}`);
    }
    record.revision = expectedRevision + 1;
    const last = record.events.at(-1);
    if (!last) throw corrupt(record.id, "events must not be empty");
    record.updatedAt = last.at;
    validatePersistedApproval(record, record.id);
    writeAtomic(this.path(record.id), record);
  }
}

/** All stored fields are intentionally visible; projection only applies output bounds. */
export function projectApproval(record: ApprovalRecord, maxChars = 4_000): ApprovalRecord {
  const cap = Math.max(1, Math.min(maxChars, 100_000));
  const projected = structuredClone(record);
  for (const key of ["subject", "action", "root", "agent"] as const) projected.scope[key] = clip(projected.scope[key], cap);
  projected.requestedBy = clip(projected.requestedBy, cap);
  projected.reason = clip(projected.reason, cap);
  for (const event of projected.events) {
    event.actor = clip(event.actor, cap);
    event.reason = clip(event.reason, cap);
  }
  return projected;
}

function validateRequestInput(input: ApprovalRequestInput): void {
  exactInputKeys(input as unknown as Record<string, unknown>, ["category", "scope", "requestedBy", "reason", "expiresAt", "estimatedCost", "currency", "consumeOnce", "maxUses"], "APPROVAL_INVALID_REQUEST");
  if (!APPROVAL_CATEGORIES.includes(input.category)) throw new Error("APPROVAL_INVALID_CATEGORY");
  validateScope(input.scope, "scope");
  validateBoundedString(input.requestedBy, "requestedBy", 200);
  validateBoundedString(input.reason, "reason", 4_000);
  validateIso(input.expiresAt, "expiresAt");
  if (input.estimatedCost !== undefined && (!Number.isFinite(input.estimatedCost) || input.estimatedCost < 0 || input.estimatedCost > 1_000_000_000)) {
    throw new Error("APPROVAL_INVALID_COST: estimatedCost must be between 0 and 1000000000");
  }
  if (input.currency !== undefined && !/^[A-Za-z]{3}$/.test(input.currency)) throw new Error("APPROVAL_INVALID_CURRENCY: use a three-letter currency code");
  if (input.estimatedCost !== undefined && input.currency === undefined) throw new Error("APPROVAL_INVALID_CURRENCY: estimated cost requires currency");
  if (input.category === "paid_or_unknown_cost" && input.currency === undefined) throw new Error("APPROVAL_INVALID_CURRENCY: paid or unknown cost approvals require currency");
}

function validateScope(scope: unknown, at: string): asserts scope is ApprovalScope {
  if (!isRecord(scope)) throw new Error(`APPROVAL_INVALID_SCOPE: ${at} must be an object`);
  exactInputKeys(scope, ["subject", "action", "dataClass", "root", "agent", "payloadSha256"], `APPROVAL_INVALID_SCOPE: ${at}`);
  validateBoundedString(scope.subject, `${at}.subject`, 500);
  validateBoundedString(scope.action, `${at}.action`, 500);
  if (!APPROVAL_DATA_CLASSES.includes(scope.dataClass as ApprovalDataClass)) throw new Error(`APPROVAL_INVALID_SCOPE: ${at}.dataClass is invalid`);
  validateBoundedString(scope.root, `${at}.root`, 4_096);
  validateBoundedString(scope.agent, `${at}.agent`, 200);
  validatePayloadSha256(scope.payloadSha256, `${at}.payloadSha256`);
}

function validateActorAndReason(actor: string, reason: string, label: string): void {
  validateBoundedString(actor, `${label} actor`, 200);
  validateBoundedString(reason, `${label} reason`, 4_000);
}

function validateListFilter(filter: ApprovalListFilter): void {
  exactInputKeys(filter as unknown as Record<string, unknown>, ["state", "category", "subject", "agent", "limit"], "APPROVAL_INVALID_LIST_FILTER");
  if (filter.state !== undefined && !APPROVAL_STATES.includes(filter.state)) throw new Error("APPROVAL_INVALID_LIST_FILTER: state");
  if (filter.category !== undefined && !APPROVAL_CATEGORIES.includes(filter.category)) throw new Error("APPROVAL_INVALID_LIST_FILTER: category");
  if (filter.subject !== undefined) validateBoundedString(filter.subject, "subject filter", 500);
  if (filter.agent !== undefined) validateBoundedString(filter.agent, "agent filter", 200);
  if (filter.limit !== undefined && (!Number.isSafeInteger(filter.limit) || filter.limit < 1 || filter.limit > 1_000)) throw new Error("APPROVAL_INVALID_LIST_FILTER: limit");
}

function validatePersistedApproval(value: unknown, expectedId: string): asserts value is ApprovalRecord {
  if (!isRecord(value)) throw corrupt(expectedId, "root must be an object");
  exactKeys(value, ["schemaVersion", "id", "category", "state", "scope", "requestedBy", "reason", "requestedAt", "updatedAt", "expiresAt", "estimatedCost", "currency", "consumeOnce", "maxUses", "useCount", "revision", "events"], expectedId, "root");
  if (value.schemaVersion !== 2) throw new Error(`APPROVAL_UNSUPPORTED_VERSION: approval ${expectedId} has schemaVersion ${String(value.schemaVersion)}`);
  requiredString(value.id, expectedId, "id", 200);
  if (value.id !== expectedId || !/^[A-Za-z0-9_-]+$/.test(value.id)) throw corrupt(expectedId, "id does not match its file name or is unsafe");
  if (!APPROVAL_CATEGORIES.includes(value.category as ApprovalCategory)) throw corrupt(expectedId, "category is invalid");
  if (!APPROVAL_STATES.includes(value.state as ApprovalState)) throw corrupt(expectedId, "state is invalid");
  validatePersistedScope(value.scope, expectedId);
  requiredString(value.requestedBy, expectedId, "requestedBy", 200);
  requiredString(value.reason, expectedId, "reason", 4_000);
  isoField(value.requestedAt, expectedId, "requestedAt");
  isoField(value.updatedAt, expectedId, "updatedAt");
  isoField(value.expiresAt, expectedId, "expiresAt");
  if (Date.parse(value.expiresAt as string) <= Date.parse(value.requestedAt as string)) throw corrupt(expectedId, "expiresAt must be later than requestedAt");
  if (Date.parse(value.updatedAt as string) < Date.parse(value.requestedAt as string)) throw corrupt(expectedId, "updatedAt precedes requestedAt");
  if (value.estimatedCost !== null && (typeof value.estimatedCost !== "number" || !Number.isFinite(value.estimatedCost) || value.estimatedCost < 0 || value.estimatedCost > 1_000_000_000)) throw corrupt(expectedId, "estimatedCost is invalid");
  if (value.currency !== null && (typeof value.currency !== "string" || !/^[A-Z]{3}$/.test(value.currency))) throw corrupt(expectedId, "currency is invalid");
  if (value.estimatedCost !== null && value.currency === null) throw corrupt(expectedId, "estimatedCost requires currency");
  if (value.category === "paid_or_unknown_cost" && value.currency === null) throw corrupt(expectedId, "paid or unknown cost approval requires currency");
  if (typeof value.consumeOnce !== "boolean") throw corrupt(expectedId, "consumeOnce must be boolean");
  integerField(value.maxUses, expectedId, "maxUses", 1, 1_000);
  integerField(value.useCount, expectedId, "useCount", 0, value.maxUses as number);
  integerField(value.revision, expectedId, "revision", 0);
  if (value.consumeOnce && value.maxUses !== 1) throw corrupt(expectedId, "one-time approval must have maxUses=1");
  if (!value.consumeOnce && value.maxUses === 1) throw corrupt(expectedId, "reusable approval must have maxUses of at least 2");
  validateEvents(value, expectedId);
  if (value.revision !== (value.events as unknown[]).length - 1) throw corrupt(expectedId, "revision must match the append-only event count");
}

function validatePersistedScope(value: unknown, id: string): asserts value is ApprovalScope {
  if (!isRecord(value)) throw corrupt(id, "scope must be an object");
  exactKeys(value, ["subject", "action", "dataClass", "root", "agent", "payloadSha256"], id, "scope");
  requiredString(value.subject, id, "scope.subject", 500);
  requiredString(value.action, id, "scope.action", 500);
  if (!APPROVAL_DATA_CLASSES.includes(value.dataClass as ApprovalDataClass)) throw corrupt(id, "scope.dataClass is invalid");
  requiredString(value.root, id, "scope.root", 4_096);
  requiredString(value.agent, id, "scope.agent", 200);
  if (typeof value.payloadSha256 !== "string" || !/^[a-f0-9]{64}$/.test(value.payloadSha256)) throw corrupt(id, "scope.payloadSha256 must be a lowercase SHA-256 digest");
}

function validateEvents(record: Record<string, unknown>, id: string): void {
  const events = record.events;
  const maxUses = record.maxUses as number;
  if (!Array.isArray(events) || events.length < 1 || events.length > maxUses + 3) throw corrupt(id, `events must contain 1 to ${maxUses + 3} entries`);
  let derivedState: ApprovalState = "pending";
  let derivedUseCount = 0;
  let priorAt = "";
  for (let index = 0; index < events.length; index++) {
    const event = events[index];
    const at = `events[${index}]`;
    if (!isRecord(event)) throw corrupt(id, `${at} must be an object`);
    exactKeys(event, ["sequence", "type", "at", "actor", "reason"], id, at);
    integerField(event.sequence, id, `${at}.sequence`, 1);
    if (event.sequence !== index + 1) throw corrupt(id, `${at}.sequence is not contiguous`);
    if (!["requested", "approved", "denied", "used", "consumed", "expired", "canceled"].includes(String(event.type))) throw corrupt(id, `${at}.type is invalid`);
    isoField(event.at, id, `${at}.at`);
    requiredString(event.actor, id, `${at}.actor`, 200);
    requiredString(event.reason, id, `${at}.reason`, 4_000);
    if (priorAt && (event.at as string) < priorAt) throw corrupt(id, `${at}.at precedes the previous event`);
    priorAt = event.at as string;
    if (index === 0) {
      if (event.type !== "requested" || event.at !== record.requestedAt || event.actor !== record.requestedBy || event.reason !== record.reason) throw corrupt(id, "first event must exactly record the request");
      continue;
    }
    if (event.type === "approved") {
      if (derivedState !== "pending") throw corrupt(id, `${at} cannot approve ${derivedState}`);
      derivedState = "approved";
    } else if (event.type === "denied") {
      if (derivedState !== "pending") throw corrupt(id, `${at} cannot deny ${derivedState}`);
      derivedState = "denied";
    } else if (event.type === "canceled") {
      if (derivedState !== "pending" && derivedState !== "approved") throw corrupt(id, `${at} cannot cancel ${derivedState}`);
      derivedState = "canceled";
    } else if (event.type === "expired") {
      if (derivedState !== "pending" && derivedState !== "approved") throw corrupt(id, `${at} cannot expire ${derivedState}`);
      if (Date.parse(event.at as string) < Date.parse(record.expiresAt as string)) throw corrupt(id, `${at} occurs before expiresAt`);
      derivedState = "expired";
    } else if (event.type === "used" || event.type === "consumed") {
      if (derivedState !== "approved") throw corrupt(id, `${at} cannot consume ${derivedState}`);
      derivedUseCount++;
      if (derivedUseCount > maxUses) throw corrupt(id, `${at} exceeds maxUses`);
      const terminal = (record.consumeOnce as boolean) || derivedUseCount === maxUses;
      if ((event.type === "consumed") !== terminal) throw corrupt(id, `${at}.type does not match the use limit`);
      if (terminal) derivedState = "consumed";
    } else {
      throw corrupt(id, `${at} has a duplicate request event`);
    }
  }
  if (record.state !== derivedState) throw corrupt(id, `state ${String(record.state)} does not match event history state ${derivedState}`);
  if (record.useCount !== derivedUseCount) throw corrupt(id, `useCount ${String(record.useCount)} does not match event history count ${derivedUseCount}`);
  const last = events.at(-1) as Record<string, unknown>;
  if (last.at !== record.updatedAt) throw corrupt(id, "updatedAt must match the last event");
}

function appendEvent(record: ApprovalRecord, type: ApprovalEventType, at: string, actor: string, reason: string): void {
  record.events.push({ sequence: record.events.length + 1, type, at, actor, reason });
}

function requireState(record: ApprovalRecord, required: ApprovalState, action: string): void {
  if (record.state !== required) throw new Error(`APPROVAL_INVALID_TRANSITION: cannot ${action} ${record.state} approval ${record.id}`);
}

function isLive(state: ApprovalState): boolean { return state === "pending" || state === "approved"; }

function requireFreshPerCallAuthority(category: ApprovalCategory, consumeOnce: boolean, maxUses: number): void {
  if (FRESH_PER_CALL_CATEGORIES.has(category) && (!consumeOnce || maxUses !== 1)) {
    throw new Error(`APPROVAL_REUSABLE_FORBIDDEN: ${category} approvals must be one-time with maxUses=1`);
  }
}

function sameScope(left: ApprovalScope, right: ApprovalScope): boolean {
  return left.subject === right.subject && left.action === right.action && left.dataClass === right.dataClass && left.root === right.root
    && left.agent === right.agent && left.payloadSha256 === right.payloadSha256;
}

function validatePayloadSha256(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`APPROVAL_INVALID_SCOPE: ${label} must be a lowercase SHA-256 digest`);
  }
}

/**
 * V1 approvals did not bind the authorized outbound bytes. They are migrated
 * for audit readability, but every still-live record is canceled so it can
 * never authorize a v2 payload. The sentinel is only provenance, never a
 * digest produced by the normal payload helper.
 */
function migrateLegacyApproval(raw: Record<string, unknown>, id: string, migratedAt: string): ApprovalRecord {
  exactKeys(raw, ["schemaVersion", "id", "category", "state", "scope", "requestedBy", "reason", "requestedAt", "updatedAt", "expiresAt", "estimatedCost", "currency", "consumeOnce", "maxUses", "useCount", "revision", "events"], id, "root");
  if (!isRecord(raw.scope)) throw corrupt(id, "scope must be an object");
  exactKeys(raw.scope, ["subject", "action", "dataClass", "root", "agent"], id, "scope");
  const migrated = structuredClone(raw) as Record<string, unknown>;
  migrated.schemaVersion = 2;
  (migrated.scope as Record<string, unknown>).payloadSha256 = createHash("sha256")
    .update("agent-bridge:legacy-unbound-approval:v1", "utf8")
    .digest("hex");
  validatePersistedApproval(migrated, id);
  const record = migrated as unknown as ApprovalRecord;
  if (record.state === "pending" || record.state === "approved") {
    const at = new Date(Math.max(Date.parse(migratedAt), Date.parse(record.updatedAt))).toISOString();
    appendEvent(record, "canceled", at, "agent-bridge", "legacy unbound approval invalidated during schema v2 migration");
    record.state = "canceled";
    record.updatedAt = at;
    record.revision += 1;
    validatePersistedApproval(record, id);
  }
  return record;
}

function validateBoundedString(value: unknown, label: string, max: number): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > max) throw new Error(`APPROVAL_INVALID_TEXT: ${label} must contain 1 to ${max} characters`);
  assertNoSecretMaterial(value, label);
}

function requiredString(value: unknown, id: string, at: string, max: number): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > max) throw corrupt(id, `${at} must contain 1 to ${max} characters`);
  try { assertNoSecretMaterial(value, at); } catch { throw corrupt(id, `${at} appears to contain secret material`); }
}

function assertNoSecretMaterial(value: string, label: string): void {
  const patterns = [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
    /\b(?:sk|key)-[A-Za-z0-9_-]{20,}\b/i,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
    /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/i,
    /\b(?:api[_-]?key|access[_-]?token|secret)\s*[=:]\s*[^\s,;]{12,}/i,
  ];
  if (patterns.some((pattern) => pattern.test(value))) throw new Error(`APPROVAL_SECRET_MATERIAL_REJECTED: ${label} must reference a credential by name, never contain its value`);
}

function validateIso(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error(`APPROVAL_INVALID_TIMESTAMP: ${label}`);
}

function isoField(value: unknown, id: string, at: string): asserts value is string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw corrupt(id, `${at} must be an ISO timestamp`);
}

function integerField(value: unknown, id: string, at: string, min: number, max = Number.MAX_SAFE_INTEGER): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) throw corrupt(id, `${at} must be an integer from ${min} to ${max}`);
}

function exactInputKeys(value: Record<string, unknown>, allowed: string[], prefix: string): void {
  const permitted = new Set(allowed);
  const extra = Object.keys(value).filter((key) => !permitted.has(key));
  if (extra.length) throw new Error(`${prefix} has unknown field(s): ${extra.join(", ")}`);
}

function exactKeys(value: Record<string, unknown>, allowed: string[], id: string, at: string): void {
  const permitted = new Set(allowed);
  const extra = Object.keys(value).filter((key) => !permitted.has(key));
  if (extra.length) throw corrupt(id, `${at} has unknown field(s): ${extra.join(", ")}`);
}

function isRecord(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function safeId(id: string): string { if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error(`APPROVAL_INVALID_ID: ${id}`); return id; }
function isStale(path: string, ms: number): boolean { try { return Date.now() - statSync(path).mtimeMs > ms; } catch { return false; } }
function delay(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)); }
function corrupt(id: string, detail: string): Error { return new Error(`APPROVAL_CORRUPT: approval ${id}: ${detail}`); }
function clip(value: string, max: number): string { return value.length > max ? `${value.slice(0, max)}\n…[truncated]` : value; }

function writeAtomic(path: string, record: ApprovalRecord): void {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, JSON.stringify(record, null, 2), { encoding: "utf8", mode: 0o600 });
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}
