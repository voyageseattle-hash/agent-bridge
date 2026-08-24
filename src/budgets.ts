import { randomUUID } from "node:crypto";
import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync,
  rmSync, writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

const LEDGER_SCHEMA_VERSION = 1;
const MAX_RECENT_RESERVATIONS = 4_096;

export interface RemoteCostBudgetPolicy {
  currency: "USD";
  maxReservedCents: number;
}

export interface RemoteCostBudgetSnapshot {
  enabled: true;
  currency: "USD";
  maxReservedCents: number;
  committedCents: number;
  remainingCents: number;
  reservationCount: number;
}

interface BudgetReservation {
  approvalId: string;
  agentId: string;
  sessionId: string;
  turnIndex: number;
  cents: number;
  at: string;
}

interface BudgetLedger {
  schemaVersion: 1;
  currency: "USD";
  committedCents: number;
  reservationCount: number;
  recentReservations: BudgetReservation[];
}

/**
 * A conservative pre-launch reservation ledger for direct remote APIs.
 * Reservations are never released because the bridge cannot prove that a
 * provider did not bill an accepted request after an error, abort, or crash.
 */
export class RemoteCostBudgetStore {
  readonly dir: string;
  readonly lockDir: string;
  readonly path: string;
  readonly initializedPath: string;

  constructor(
    stateDir: string,
    readonly policy: RemoteCostBudgetPolicy,
    private readonly lockWaitMs = 30_000,
    _lockStaleMs = 7_500_000,
    private readonly clock: () => Date = () => new Date(),
  ) {
    validatePolicy(policy);
    this.dir = join(stateDir, "budgets");
    this.lockDir = join(stateDir, "budget-locks");
    this.path = join(this.dir, "cumulative-remote-cost.json");
    this.initializedPath = join(this.dir, "cumulative-remote-cost.initialized.json");
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    mkdirSync(this.lockDir, { recursive: true, mode: 0o700 });
  }

  status(): RemoteCostBudgetSnapshot {
    const ledger = this.load();
    return {
      enabled: true,
      currency: this.policy.currency,
      maxReservedCents: this.policy.maxReservedCents,
      committedCents: ledger.committedCents,
      remainingCents: Math.max(0, this.policy.maxReservedCents - ledger.committedCents),
      reservationCount: ledger.reservationCount,
    };
  }

  async reserve(input: Omit<BudgetReservation, "at">): Promise<RemoteCostBudgetSnapshot> {
    validateReservationInput(input);
    return this.withLock(async () => {
      const ledger = this.load();
      if (ledger.recentReservations.some((entry) => entry.approvalId === input.approvalId)) {
        throw new Error(`CUMULATIVE_BUDGET_APPROVAL_ALREADY_RESERVED: approval ${input.approvalId} already reserved remote cost`);
      }
      if (ledger.committedCents > this.policy.maxReservedCents - input.cents) {
        throw new Error(
          `CUMULATIVE_BUDGET_EXHAUSTED: reserving ${input.cents} ${this.policy.currency} cent(s) would exceed `
          + `${this.policy.maxReservedCents}; ${Math.max(0, this.policy.maxReservedCents - ledger.committedCents)} remain`,
        );
      }
      const at = this.now();
      ledger.committedCents += input.cents;
      ledger.reservationCount++;
      ledger.recentReservations.push({ ...input, at });
      if (ledger.recentReservations.length > MAX_RECENT_RESERVATIONS) {
        ledger.recentReservations.splice(0, ledger.recentReservations.length - MAX_RECENT_RESERVATIONS);
      }
      validateLedger(ledger);
      if (!existsSync(this.initializedPath)) {
        writeAtomic(this.initializedPath, { schemaVersion: LEDGER_SCHEMA_VERSION, currency: this.policy.currency });
      }
      writeAtomic(this.path, ledger);
      return this.statusFromLedger(ledger);
    });
  }

  private statusFromLedger(ledger: BudgetLedger): RemoteCostBudgetSnapshot {
    return {
      enabled: true,
      currency: this.policy.currency,
      maxReservedCents: this.policy.maxReservedCents,
      committedCents: ledger.committedCents,
      remainingCents: Math.max(0, this.policy.maxReservedCents - ledger.committedCents),
      reservationCount: ledger.reservationCount,
    };
  }

  private load(): BudgetLedger {
    if (existsSync(this.initializedPath)) validateInitializationMarker(this.initializedPath);
    if (!existsSync(this.path)) {
      if (existsSync(this.initializedPath)) {
        throw new Error("CUMULATIVE_BUDGET_LEDGER_MISSING: an initialized remote-cost ledger is absent; restore it or perform the documented offline operator reset");
      }
      return { schemaVersion: LEDGER_SCHEMA_VERSION, currency: "USD", committedCents: 0, reservationCount: 0, recentReservations: [] };
    }
    let raw: unknown;
    try { raw = JSON.parse(readFileSync(this.path, "utf8")); }
    catch (error) { throw corrupt(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`); }
    if (isRecord(raw) && raw.schemaVersion !== LEDGER_SCHEMA_VERSION) {
      throw new Error(`CUMULATIVE_BUDGET_UNSUPPORTED_VERSION: ledger has schemaVersion ${String(raw.schemaVersion)}`);
    }
    validateLedger(raw);
    return structuredClone(raw);
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    const lock = join(this.lockDir, "cumulative-remote-cost.lock");
    const started = Date.now();
    const ownerToken = randomUUID();
    let ownsLock = false;
    while (true) {
      try {
        mkdirSync(lock);
        try {
          writeFileSync(join(lock, "owner.json"), JSON.stringify({ token: ownerToken, pid: process.pid, acquiredAt: this.now() }), { mode: 0o600 });
        } catch (error) {
          rmSync(lock, { recursive: true, force: true });
          throw error;
        }
        ownsLock = true;
        break;
      } catch (error: any) {
        if (error?.code !== "EEXIST") throw error;
        // This security boundary deliberately never reclaims a lock. A paused
        // prior owner could otherwise resume after reclamation and overwrite a
        // newer reservation. Recovery is an explicit all-hosts-stopped action.
        if (Date.now() - started >= this.lockWaitMs) {
          throw new Error("CUMULATIVE_BUDGET_BUSY: the remote-cost ledger lock exists; if its owner crashed, stop every bridge host before removing that exact lock directory");
        }
        await delay(50 + Math.floor(Math.random() * 50));
      }
    }
    try {
      const result = await operation();
      if (readOwnerToken(lock) !== ownerToken) {
        throw new Error("CUMULATIVE_BUDGET_LOCK_LOST: remote-cost reservation lock ownership changed before commit completed");
      }
      return result;
    }
    finally {
      if (ownsLock && readOwnerToken(lock) === ownerToken) rmSync(lock, { recursive: true, force: true });
    }
  }

  private now(): string {
    const value = this.clock();
    if (!(value instanceof Date) || Number.isNaN(value.valueOf())) throw new Error("CUMULATIVE_BUDGET_CLOCK_INVALID");
    return value.toISOString();
  }
}

export function approvedCostToCents(value: number | null, currency: string | null): number {
  if (currency !== "USD") throw new Error("CUMULATIVE_BUDGET_CURRENCY_REQUIRED: the configured breaker requires a USD approval");
  if (value === null || !Number.isFinite(value) || value <= 0) {
    throw new Error("CUMULATIVE_BUDGET_BOUNDED_COST_REQUIRED: the configured breaker requires a positive approved maximum cost");
  }
  const normalized = Number(value.toFixed(2));
  const rounded = Math.round(normalized * 100);
  if (normalized !== value || !Number.isSafeInteger(rounded)) {
    throw new Error("CUMULATIVE_BUDGET_WHOLE_CENTS_REQUIRED: the approved maximum cost must resolve to whole USD cents");
  }
  return rounded;
}

function validatePolicy(value: RemoteCostBudgetPolicy): void {
  if (value.currency !== "USD") throw new Error("CUMULATIVE_BUDGET_INVALID_POLICY: currency must be USD");
  if (!Number.isSafeInteger(value.maxReservedCents) || value.maxReservedCents < 1 || value.maxReservedCents > 100_000_000_000) {
    throw new Error("CUMULATIVE_BUDGET_INVALID_POLICY: maxReservedCents must be an integer from 1 to 100000000000");
  }
}

function validateReservationInput(value: Omit<BudgetReservation, "at">): void {
  exactKeys(value as unknown as Record<string, unknown>, ["approvalId", "agentId", "sessionId", "turnIndex", "cents"], "reservation");
  boundedId(value.approvalId, "approvalId");
  boundedId(value.agentId, "agentId");
  boundedId(value.sessionId, "sessionId");
  if (!Number.isSafeInteger(value.turnIndex) || value.turnIndex < 0) throw new Error("CUMULATIVE_BUDGET_INVALID_RESERVATION: turnIndex must be a non-negative integer");
  if (!Number.isSafeInteger(value.cents) || value.cents < 1) throw new Error("CUMULATIVE_BUDGET_INVALID_RESERVATION: cents must be a positive integer");
}

function validateLedger(value: unknown): asserts value is BudgetLedger {
  if (!isRecord(value)) throw corrupt("root must be an object");
  exactKeys(value, ["schemaVersion", "currency", "committedCents", "reservationCount", "recentReservations"], "root");
  if (value.schemaVersion !== LEDGER_SCHEMA_VERSION) throw new Error(`CUMULATIVE_BUDGET_UNSUPPORTED_VERSION: ledger has schemaVersion ${String(value.schemaVersion)}`);
  if (value.currency !== "USD") throw corrupt("currency must be USD");
  if (!Number.isSafeInteger(value.committedCents) || (value.committedCents as number) < 0) throw corrupt("committedCents must be a non-negative integer");
  if (!Number.isSafeInteger(value.reservationCount) || (value.reservationCount as number) < 0) throw corrupt("reservationCount must be a non-negative integer");
  if (!Array.isArray(value.recentReservations) || value.recentReservations.length > MAX_RECENT_RESERVATIONS) throw corrupt("recentReservations is invalid");
  if ((value.reservationCount as number) < value.recentReservations.length) throw corrupt("reservationCount is smaller than retained reservations");
  let retainedCents = 0;
  const approvalIds = new Set<string>();
  for (const [index, candidate] of value.recentReservations.entries()) {
    if (!isRecord(candidate)) throw corrupt(`recentReservations[${index}] must be an object`);
    exactKeys(candidate, ["approvalId", "agentId", "sessionId", "turnIndex", "cents", "at"], `recentReservations[${index}]`);
    boundedId(candidate.approvalId, `recentReservations[${index}].approvalId`);
    boundedId(candidate.agentId, `recentReservations[${index}].agentId`);
    boundedId(candidate.sessionId, `recentReservations[${index}].sessionId`);
    if (approvalIds.has(candidate.approvalId)) throw corrupt("recentReservations contains a duplicate approvalId");
    approvalIds.add(candidate.approvalId);
    if (!Number.isSafeInteger(candidate.turnIndex) || (candidate.turnIndex as number) < 0) throw corrupt(`recentReservations[${index}].turnIndex is invalid`);
    if (!Number.isSafeInteger(candidate.cents) || (candidate.cents as number) < 1) throw corrupt(`recentReservations[${index}].cents is invalid`);
    retainedCents += candidate.cents as number;
    if (!Number.isSafeInteger(retainedCents)) throw corrupt("retained reservation cents overflow");
    if (typeof candidate.at !== "string" || Number.isNaN(Date.parse(candidate.at)) || new Date(candidate.at).toISOString() !== candidate.at) throw corrupt(`recentReservations[${index}].at is invalid`);
  }
  if (retainedCents > (value.committedCents as number)) throw corrupt("retained reservations exceed committedCents");
}

function exactKeys(value: Record<string, unknown>, allowed: string[], at: string): void {
  const permitted = new Set(allowed);
  const extra = Object.keys(value).filter((key) => !permitted.has(key));
  if (extra.length) throw corrupt(`${at} has unknown field(s): ${extra.join(", ")}`);
}

function boundedId(value: unknown, at: string): asserts value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(value)) throw corrupt(`${at} is invalid`);
}

function writeAtomic(path: string, value: unknown): void {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, JSON.stringify(value, null, 2), { encoding: "utf8" });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    syncDirectoryBestEffort(dirname(path));
  } finally {
    if (descriptor !== undefined) try { closeSync(descriptor); } catch { /* already closed */ }
    rmSync(temporary, { force: true });
  }
}

function validateInitializationMarker(path: string): void {
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(path, "utf8")); }
  catch (error) { throw corrupt(`invalid initialization marker: ${error instanceof Error ? error.message : String(error)}`); }
  if (!isRecord(raw)) throw corrupt("initialization marker must be an object");
  exactKeys(raw, ["schemaVersion", "currency"], "initialization marker");
  if (raw.schemaVersion !== LEDGER_SCHEMA_VERSION) throw new Error(`CUMULATIVE_BUDGET_UNSUPPORTED_VERSION: initialization marker has schemaVersion ${String(raw.schemaVersion)}`);
  if (raw.currency !== "USD") throw corrupt("initialization marker currency must be USD");
}

function readOwnerToken(lock: string): string | undefined {
  try {
    const parsed = JSON.parse(readFileSync(join(lock, "owner.json"), "utf8"));
    return isRecord(parsed) && typeof parsed.token === "string" ? parsed.token : undefined;
  } catch { return undefined; }
}

function syncDirectoryBestEffort(path: string): void {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, "r");
    fsyncSync(descriptor);
  } catch (error: any) {
    if (!["EACCES", "EPERM", "EINVAL", "EISDIR", "ENOTSUP"].includes(error?.code)) throw error;
  } finally { if (descriptor !== undefined) try { closeSync(descriptor); } catch { /* already closed */ } }
}

function isRecord(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function delay(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)); }
function corrupt(detail: string): Error { return new Error(`CUMULATIVE_BUDGET_CORRUPT: ${detail}`); }
