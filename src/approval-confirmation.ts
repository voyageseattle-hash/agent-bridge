import type { ApprovalRecord } from "./approvals.js";

const DISPLAY_LIMITS = {
  id: 200,
  category: 100,
  subject: 500,
  action: 500,
  dataClass: 50,
  root: 4_096,
  agent: 200,
  payloadSha256: 64,
  timestamp: 40,
  currency: 3,
  message: 8_192,
} as const;

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
  /\b(?:sk|key)-[A-Za-z0-9_-]{20,}\b/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/i,
  /\b(?:api[_-]?key|access[_-]?token|secret)\s*[=:]\s*[^\s,;]{12,}/i,
  /https?:\/\/[^\s/:@]+:[^\s/@]+@/i,
] as const;

const DANGEROUS_DISPLAY_CHARACTERS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/u;

export interface ApprovalElicitationRequest {
  mode: "form";
  message: string;
  requestedSchema: {
    type: "object";
    properties: {
      approvalId: {
        type: "string";
        title: string;
        description: string;
        minLength: number;
        maxLength: number;
      };
      approve: {
        type: "boolean";
        title: string;
        description: string;
        default: false;
      };
    };
    required: ["approvalId", "approve"];
  };
}

export type ApprovalConfirmationResult =
  | { accepted: true }
  | { accepted: false; reason: "declined" | "canceled" | "mismatch" };

/**
 * Build a non-sensitive MCP form elicitation. The approval reason, requester,
 * event history, and any execution transcript are deliberately not rendered.
 */
export function buildApprovalElicitationRequest(record: ApprovalRecord): ApprovalElicitationRequest {
  const details = approvalDisplay(record);
  const message = [
    "Human approval required. Verify every field before accepting.",
    details,
    "To approve, set Approve to true and type the Approval ID exactly. Decline or cancel otherwise.",
  ].join("\n\n");
  if (message.length > DISPLAY_LIMITS.message) throw new Error("APPROVAL_CONFIRMATION_DISPLAY_TOO_LONG");

  return {
    mode: "form",
    message,
    requestedSchema: {
      type: "object",
      properties: {
        approvalId: {
          type: "string",
          title: "Approval ID",
          description: "Type the displayed approval ID exactly; do not paste credentials.",
          minLength: record.id.length,
          maxLength: record.id.length,
        },
        approve: {
          type: "boolean",
          title: "Approve this exact scope",
          description: "Must be explicitly enabled. Leaving it false does not approve anything.",
          default: false,
        },
      },
      required: ["approvalId", "approve"],
    },
  };
}

/** Verify an MCP elicitation result without trusting client-side form validation. */
export function verifyApprovalElicitationResult(record: ApprovalRecord, result: unknown): ApprovalConfirmationResult {
  if (!isRecord(result)) return { accepted: false, reason: "mismatch" };
  if (result.action === "decline") return { accepted: false, reason: "declined" };
  if (result.action === "cancel") return { accepted: false, reason: "canceled" };
  if (result.action !== "accept" || !isRecord(result.content)) return { accepted: false, reason: "mismatch" };
  if (!hasExactKeys(result.content, ["approvalId", "approve"])) return { accepted: false, reason: "mismatch" };
  return result.content.approve === true && result.content.approvalId === record.id
    ? { accepted: true }
    : { accepted: false, reason: "mismatch" };
}

/**
 * Build a deterministic challenge for a parent-owned interactive CLI. The
 * parent must require an actual TTY and must not supply input programmatically.
 */
export function buildCliApprovalChallenge(record: ApprovalRecord): string {
  const details = approvalDisplay(record);
  const challenge = cliApprovalResponse(record);
  const prompt = [
    "HUMAN APPROVAL REQUIRED",
    details,
    `Type exactly: ${challenge}`,
    `Or type exactly: DECLINE ${safeDisplay(record.id, "id", DISPLAY_LIMITS.id)}`,
  ].join("\n\n");
  if (prompt.length > DISPLAY_LIMITS.message) throw new Error("APPROVAL_CONFIRMATION_DISPLAY_TOO_LONG");
  return prompt;
}

/** Verify one line read from an interactive CLI. Nullish input means cancellation. */
export function verifyCliApprovalResult(record: ApprovalRecord, response: unknown): ApprovalConfirmationResult {
  if (response === null || response === undefined) return { accepted: false, reason: "canceled" };
  if (typeof response !== "string") return { accepted: false, reason: "mismatch" };
  if (response === `DECLINE ${record.id}`) return { accepted: false, reason: "declined" };
  return response === cliApprovalResponse(record)
    ? { accepted: true }
    : { accepted: false, reason: "mismatch" };
}

function cliApprovalResponse(record: ApprovalRecord): string {
  return `APPROVE ${safeDisplay(record.id, "id", DISPLAY_LIMITS.id)}`;
}

function approvalDisplay(record: ApprovalRecord): string {
  const id = safeDisplay(record.id, "id", DISPLAY_LIMITS.id);
  const category = safeDisplay(record.category, "category", DISPLAY_LIMITS.category);
  const subject = safeDisplay(record.scope?.subject, "scope.subject", DISPLAY_LIMITS.subject);
  const action = safeDisplay(record.scope?.action, "scope.action", DISPLAY_LIMITS.action);
  const dataClass = safeDisplay(record.scope?.dataClass, "scope.dataClass", DISPLAY_LIMITS.dataClass);
  const root = safeDisplay(record.scope?.root, "scope.root", DISPLAY_LIMITS.root);
  const agent = safeDisplay(record.scope?.agent, "scope.agent", DISPLAY_LIMITS.agent);
  const payload = safeDisplay(record.scope?.payloadSha256, "scope.payloadSha256", DISPLAY_LIMITS.payloadSha256);
  if (!/^[a-f0-9]{64}$/.test(payload)) throw new Error("APPROVAL_CONFIRMATION_INVALID_PAYLOAD_DIGEST");
  const expiresAt = safeDisplay(record.expiresAt, "expiresAt", DISPLAY_LIMITS.timestamp);
  if (Number.isNaN(Date.parse(expiresAt)) || new Date(expiresAt).toISOString() !== expiresAt) {
    throw new Error("APPROVAL_CONFIRMATION_INVALID_TIMESTAMP: expiresAt");
  }
  const currency = record.currency === null
    ? null
    : safeDisplay(record.currency, "currency", DISPLAY_LIMITS.currency);
  if (currency !== null && !/^[A-Z]{3}$/.test(currency)) throw new Error("APPROVAL_CONFIRMATION_INVALID_CURRENCY");
  if (record.estimatedCost !== null && (!Number.isFinite(record.estimatedCost) || record.estimatedCost < 0)) {
    throw new Error("APPROVAL_CONFIRMATION_INVALID_COST");
  }
  if (!Number.isSafeInteger(record.useCount) || !Number.isSafeInteger(record.maxUses) || record.useCount < 0 || record.maxUses < 1 || record.useCount > record.maxUses) {
    throw new Error("APPROVAL_CONFIRMATION_INVALID_USE_COUNT");
  }

  const cost = record.estimatedCost === null
    ? (currency === null ? "not specified" : `unknown ${currency}`)
    : `${record.estimatedCost} ${currency ?? "[currency missing]"}`;
  const useMode = record.consumeOnce ? "one-time" : "reusable";
  return [
    `Approval ID: ${JSON.stringify(id)}`,
    `Category: ${JSON.stringify(category)}`,
    "Scope:",
    `  subject: ${JSON.stringify(subject)}`,
    `  action: ${JSON.stringify(action)}`,
    `  dataClass: ${JSON.stringify(dataClass)}`,
    `  root: ${JSON.stringify(root)}`,
    `  agent: ${JSON.stringify(agent)}`,
    `  payloadSha256: ${JSON.stringify(payload)}`,
    `Expires: ${JSON.stringify(expiresAt)}`,
    `Cost: ${cost}`,
    `Use count: ${record.useCount}/${record.maxUses} (${useMode})`,
  ].join("\n");
}

function safeDisplay(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) {
    throw new Error(`APPROVAL_CONFIRMATION_INVALID_DISPLAY: ${field}`);
  }
  if (DANGEROUS_DISPLAY_CHARACTERS.test(value)) {
    throw new Error(`APPROVAL_CONFIRMATION_UNSAFE_DISPLAY: ${field}`);
  }
  if (SECRET_PATTERNS.some((pattern) => pattern.test(value))) {
    throw new Error(`APPROVAL_CONFIRMATION_SECRET_REJECTED: ${field}`);
  }
  return value;
}

function hasExactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...allowed].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
