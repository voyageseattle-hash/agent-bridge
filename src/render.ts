import type { RunTurnOutcome } from "./bridge.js";
import type { BridgeSession } from "./types.js";

export const TURN_OUTPUT_PREVIEW_CHARS = 24_000;
export const TURN_STDERR_PREVIEW_CHARS = 8_000;

export interface TextPage {
  text: string;
  offset: number;
  nextOffset: number | null;
  totalChars: number;
  complete: boolean;
}

export function renderTurn(outcome: RunTurnOutcome, note?: string) {
  const turn = outcome.session.turns.length - 1;
  const lines = [
    `agent: ${outcome.agent.displayName} (${outcome.agent.id})`,
    `bridge_session_id: ${outcome.session.id}`,
    `turn: ${turn}`,
    `continuity: ${outcome.continuity}`,
    `cross_agent_context_applied: ${outcome.contextDeltaApplied}`,
    `duration: ${(outcome.result.durationMs / 1_000).toFixed(1)}s`,
    outcome.result.isError ? "status: ERROR" : "status: ok",
  ];
  if (note) lines.push(note);
  const output = clipPreview(outcome.result.text, TURN_OUTPUT_PREVIEW_CHARS);
  const outputBody = output.text.trim() || "(the agent returned no text)";
  const stderr = clipPreview(outcome.result.stderr, TURN_STDERR_PREVIEW_CHARS);
  const stderrBody = outcome.result.isError && stderr.text ? `\n\n--- stderr (preview) ---\n${stderr.text}` : "";
  const retrieval = output.truncated || (outcome.result.isError && stderr.truncated)
    ? `\n\nFull stored text: call get_turn_output with bridge_session_id=${outcome.session.id} and turn=${turn}.`
    : "";
  return {
    content: [{ type: "text" as const, text: `${lines.join("\n")}\n\n--- output (preview) ---\n${outputBody}${stderrBody}${retrieval}` }],
    structuredContent: {
      bridge_session_id: outcome.session.id,
      turn,
      agent: outcome.agent.id,
      continuity: outcome.continuity,
      cross_agent_context_applied: outcome.contextDeltaApplied,
      is_error: outcome.result.isError,
      exit_code: outcome.result.exitCode,
      duration_ms: outcome.result.durationMs,
      output: output.text,
      output_chars: output.totalChars,
      output_truncated: output.truncated,
      stderr: stderr.text,
      stderr_chars: stderr.totalChars,
      stderr_truncated: stderr.truncated,
      output_ref: { bridge_session_id: outcome.session.id, turn, tool: "get_turn_output" },
      timed_out: outcome.result.timedOut,
      meta: projectResultMeta(outcome.agent.id, outcome.result.meta),
    },
    isError: outcome.result.isError,
  };
}

function projectResultMeta(agentId: string, meta: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!meta) return {};
  if (agentId !== "manus") return meta;
  const projected: Record<string, unknown> = {};
  for (const key of [
    "taskStatus", "resumable", "timedOut", "stopRequested", "eventId", "eventType",
  ] as const) {
    const value = meta[key];
    if (typeof value === "string" || typeof value === "boolean") projected[key] = value;
  }
  for (const key of ["payloadSha256", "providerRequestSha256", "providerErrorRequestSha256"] as const) {
    const value = meta[key];
    if (typeof value === "string" && /^[a-f0-9]{64}$/.test(value)) projected[key] = value;
  }
  const waiting = meta.waitingAction;
  if (waiting && typeof waiting === "object" && !Array.isArray(waiting)) {
    const value = waiting as Record<string, unknown>;
    if (typeof value.eventId === "string" && typeof value.eventType === "string") {
      projected.waitingAction = { eventId: value.eventId, eventType: value.eventType };
    }
  }
  return projected;
}

/** Read a stable page from the full text persisted in a bridge session. */
export function pageTurnText(
  session: BridgeSession,
  turnIndex: number,
  field: "output" | "stderr",
  offset: number,
  maxChars: number,
): TextPage {
  if (!Number.isSafeInteger(turnIndex) || turnIndex < 0 || turnIndex >= session.turns.length) {
    throw new Error(`turn ${turnIndex} does not exist in bridge session ${session.id}`);
  }
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("offset must be a non-negative integer");
  if (!Number.isSafeInteger(maxChars) || maxChars < 1 || maxChars > 100_000) {
    throw new Error("max_chars must be an integer from 1 to 100000");
  }
  const turn = session.turns[turnIndex]!;
  const source = field === "stderr" ? turn.stderr : turn.response;
  const start = Math.min(offset, source.length);
  const end = Math.min(source.length, start + maxChars);
  return {
    text: source.slice(start, end),
    offset: start,
    nextOffset: end < source.length ? end : null,
    totalChars: source.length,
    complete: end === source.length,
  };
}

function clipPreview(value: string, maxChars: number): { text: string; totalChars: number; truncated: boolean } {
  if (value.length <= maxChars) return { text: value, totalChars: value.length, truncated: false };
  const marker = "\n…[preview clipped; use get_turn_output for full stored text]…\n";
  const available = Math.max(0, maxChars - marker.length);
  const head = Math.ceil(available * 0.6);
  const tail = available - head;
  return {
    text: `${value.slice(0, head)}${marker}${tail > 0 ? value.slice(-tail) : ""}`,
    totalChars: value.length,
    truncated: true,
  };
}
