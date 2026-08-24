import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Internal daemon/proxy protocol. This is deliberately separate from MCP. */
export const RPC_PROTOCOL_VERSION = 2;
export const DEFAULT_MAX_FRAME_BYTES = 1_048_576;

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export interface RpcRequest<TParams extends JsonValue = JsonValue> {
  type: "request";
  protocolVersion: typeof RPC_PROTOCOL_VERSION;
  id: string;
  method: string;
  params: TParams;
  /** Absolute Unix epoch deadline enforced by both proxy and daemon. */
  deadlineUnixMs?: number;
}

export interface RpcCancel {
  type: "cancel";
  protocolVersion: typeof RPC_PROTOCOL_VERSION;
  id: string;
}

export interface RpcSuccess<TResult extends JsonValue = JsonValue> {
  type: "response";
  protocolVersion: typeof RPC_PROTOCOL_VERSION;
  id: string;
  ok: true;
  result: TResult;
}

export interface RpcFailure {
  type: "response";
  protocolVersion: typeof RPC_PROTOCOL_VERSION;
  id: string;
  ok: false;
  error: { code: string; message: string };
}

export type RpcEnvelope = RpcRequest | RpcSuccess | RpcFailure;

export interface HandshakeHello {
  type: "hello";
  protocolVersion: typeof RPC_PROTOCOL_VERSION;
  configFingerprint: string;
  clientNonce: string;
}

export interface HandshakeChallenge {
  type: "challenge";
  protocolVersion: typeof RPC_PROTOCOL_VERSION;
  configFingerprint: string;
  clientNonce: string;
  daemonNonce: string;
  /** HMAC proof that the responding daemon holds the local capability token. */
  daemonProof: string;
}

export interface HandshakeResponse {
  type: "authenticate";
  protocolVersion: typeof RPC_PROTOCOL_VERSION;
  proof: string;
}

/** Every message permitted on the daemon/proxy framed transport. */
export type RpcWireMessage = RpcEnvelope | RpcCancel | HandshakeHello | HandshakeChallenge | HandshakeResponse;

export class RpcProtocolError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "RpcProtocolError";
  }
}

export function createRequest<TParams extends JsonValue>(
  id: string,
  method: string,
  params: TParams,
  options: { deadlineUnixMs?: number } = {},
): RpcRequest<TParams> {
  const value: RpcRequest<TParams> = {
    type: "request", protocolVersion: RPC_PROTOCOL_VERSION, id, method, params,
    ...(options.deadlineUnixMs !== undefined ? { deadlineUnixMs: options.deadlineUnixMs } : {}),
  };
  assertRpcEnvelope(value);
  return value;
}

export function createCancel(id: string): RpcCancel {
  const value: RpcCancel = { type: "cancel", protocolVersion: RPC_PROTOCOL_VERSION, id };
  assertRpcWireMessage(value);
  return value;
}

export function createSuccess<TResult extends JsonValue>(id: string, result: TResult): RpcSuccess<TResult> {
  const value: RpcSuccess<TResult> = { type: "response", protocolVersion: RPC_PROTOCOL_VERSION, id, ok: true, result };
  assertRpcEnvelope(value);
  return value;
}

export function createFailure(id: string, code: string, message: string): RpcFailure {
  const value: RpcFailure = { type: "response", protocolVersion: RPC_PROTOCOL_VERSION, id, ok: false, error: { code, message } };
  assertRpcEnvelope(value);
  return value;
}

/** Encodes exactly one size-prefixed internal RPC frame. */
export function encodeRpcFrame(message: RpcWireMessage): Buffer {
  assertRpcWireMessage(message);
  const body = Buffer.from(JSON.stringify(message), "utf8");
  if (body.length === 0 || body.length > DEFAULT_MAX_FRAME_BYTES) throw new RpcProtocolError("RPC_FRAME_TOO_LARGE");
  const frame = Buffer.allocUnsafe(4 + body.length);
  frame.writeUInt32BE(body.length, 0);
  body.copy(frame, 4);
  return frame;
}

/**
 * Incremental decoder for a 4-byte big-endian length followed by strict JSON.
 * It is fail-closed after any malformed or oversized frame.
 */
export class RpcFrameDecoder {
  private buffered = Buffer.alloc(0);
  private failed = false;
  private readonly maxBufferedBytes: number;

  constructor(readonly maxFrameBytes = DEFAULT_MAX_FRAME_BYTES, maxBufferedBytes?: number) {
    if (!Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 2) throw new RpcProtocolError("RPC_FRAME_LIMIT_INVALID");
    this.maxBufferedBytes = maxBufferedBytes ?? (maxFrameBytes * 2 + 8);
    if (!Number.isSafeInteger(this.maxBufferedBytes) || this.maxBufferedBytes < maxFrameBytes + 4) {
      throw new RpcProtocolError("RPC_BUFFER_LIMIT_INVALID");
    }
  }

  push(chunk: Uint8Array): RpcWireMessage[] {
    if (this.failed) throw new RpcProtocolError("RPC_DECODER_CLOSED");
    if (chunk.byteLength === 0) return [];
    if (this.buffered.length + chunk.byteLength > this.maxBufferedBytes) return this.fail("RPC_BUFFER_TOO_LARGE");
    this.buffered = Buffer.concat([this.buffered, Buffer.from(chunk)]);
    const values: RpcWireMessage[] = [];
    try {
      while (this.buffered.length >= 4) {
        const length = this.buffered.readUInt32BE(0);
        if (length < 2 || length > this.maxFrameBytes) return this.fail("RPC_FRAME_TOO_LARGE");
        if (this.buffered.length < length + 4) break;
        const payload = this.buffered.subarray(4, length + 4);
        this.buffered = this.buffered.subarray(length + 4);
        let parsed: unknown;
        try {
          parsed = JSON.parse(decodeUtf8(payload));
        } catch {
          return this.fail("RPC_FRAME_MALFORMED");
        }
        values.push(assertRpcWireMessage(parsed));
      }
      return values;
    } catch (error) {
      if (error instanceof RpcProtocolError) return this.fail(error.code);
      return this.fail("RPC_FRAME_MALFORMED");
    }
  }

  private fail(code: string): never {
    this.failed = true;
    this.buffered = Buffer.alloc(0);
    throw new RpcProtocolError(code);
  }
}

export function assertRpcEnvelope(value: unknown): RpcEnvelope {
  if (!isRecord(value) || !hasOnlyKeys(value, ["type", "protocolVersion", "id", "method", "params", "deadlineUnixMs", "ok", "result", "error"])) {
    throw new RpcProtocolError("RPC_ENVELOPE_INVALID");
  }
  if (value.protocolVersion !== RPC_PROTOCOL_VERSION || !validId(value.id)) throw new RpcProtocolError("RPC_ENVELOPE_INVALID");
  if (value.type === "request") {
    const keys = value.deadlineUnixMs === undefined
      ? ["type", "protocolVersion", "id", "method", "params"]
      : ["type", "protocolVersion", "id", "method", "params", "deadlineUnixMs"];
    if (!hasExactKeys(value, keys) || !validMethod(value.method) || !isJsonValue(value.params)
      || (value.deadlineUnixMs !== undefined && !validDeadline(value.deadlineUnixMs))) {
      throw new RpcProtocolError("RPC_ENVELOPE_INVALID");
    }
    return value as unknown as RpcRequest;
  }
  if (value.type === "response" && value.ok === true) {
    if (!hasExactKeys(value, ["type", "protocolVersion", "id", "ok", "result"]) || !isJsonValue(value.result)) {
      throw new RpcProtocolError("RPC_ENVELOPE_INVALID");
    }
    return value as unknown as RpcSuccess;
  }
  if (value.type === "response" && value.ok === false) {
    if (!hasExactKeys(value, ["type", "protocolVersion", "id", "ok", "error"]) || !validSafeError(value.error)) {
      throw new RpcProtocolError("RPC_ENVELOPE_INVALID");
    }
    return value as unknown as RpcFailure;
  }
  throw new RpcProtocolError("RPC_ENVELOPE_INVALID");
}

/** Strictly validates an internal wire message without reflecting input data. */
export function assertRpcWireMessage(value: unknown): RpcWireMessage {
  if (!isRecord(value)) throw new RpcProtocolError("RPC_WIRE_MESSAGE_INVALID");
  if (value.type === "hello") {
    assertHandshakeHello(value);
    return value;
  }
  if (value.type === "challenge") {
    assertHandshakeChallenge(value);
    return value;
  }
  if (value.type === "authenticate") {
    assertHandshakeResponse(value);
    return value;
  }
  if (value.type === "cancel") {
    if (!hasExactKeys(value, ["type", "protocolVersion", "id"])
      || value.protocolVersion !== RPC_PROTOCOL_VERSION || !validId(value.id)) {
      throw new RpcProtocolError("RPC_CANCEL_INVALID");
    }
    return value as unknown as RpcCancel;
  }
  return assertRpcEnvelope(value);
}

/** SHA-256 fingerprint of the exact canonical config bytes used by both peers. */
export function configFingerprint(config: string | Uint8Array): string {
  const bytes = typeof config === "string" ? Buffer.from(config, "utf8") : Buffer.from(config);
  return sha256(bytes);
}

export function createHandshakeHello(config: string | Uint8Array, clientNonce = newNonce()): HandshakeHello {
  const hello: HandshakeHello = { type: "hello", protocolVersion: RPC_PROTOCOL_VERSION, configFingerprint: configFingerprint(config), clientNonce };
  assertHandshakeHello(hello);
  return hello;
}

export function createHandshakeChallenge(
  hello: HandshakeHello,
  expectedConfigFingerprint: string,
  secret: string | Uint8Array,
  daemonNonce = newNonce(),
): HandshakeChallenge {
  assertHandshakeHello(hello);
  if (!validFingerprint(expectedConfigFingerprint) || hello.configFingerprint !== expectedConfigFingerprint) {
    throw new RpcProtocolError("RPC_CONFIG_FINGERPRINT_MISMATCH");
  }
  const unsigned: Pick<HandshakeChallenge, "type" | "protocolVersion" | "configFingerprint" | "clientNonce" | "daemonNonce"> = {
    type: "challenge", protocolVersion: RPC_PROTOCOL_VERSION, configFingerprint: expectedConfigFingerprint,
    clientNonce: hello.clientNonce, daemonNonce,
  };
  const challenge: HandshakeChallenge = {
    ...unsigned,
    daemonProof: createDaemonProof(secretBytes(secret), hello, unsigned),
  };
  assertHandshakeChallenge(challenge);
  return challenge;
}

export function createHandshakeResponse(
  hello: HandshakeHello,
  challenge: HandshakeChallenge,
  secret: string | Uint8Array,
): HandshakeResponse {
  assertHandshakeHello(hello);
  assertHandshakeChallenge(challenge);
  if (!verifyHandshakeChallenge(hello, challenge, secret)) throw new RpcProtocolError("RPC_DAEMON_AUTH_FAILED");
  const response: HandshakeResponse = {
    type: "authenticate", protocolVersion: RPC_PROTOCOL_VERSION,
    proof: createClientProof(secretBytes(secret), hello, challenge),
  };
  assertHandshakeResponse(response);
  return response;
}

/**
 * Verifies the daemon's domain-separated proof before a proxy sends its own
 * credential proof. A false result deliberately exposes no token detail.
 */
export function verifyHandshakeChallenge(
  hello: HandshakeHello,
  challenge: HandshakeChallenge,
  secret: string | Uint8Array,
): boolean {
  try {
    assertHandshakeHello(hello);
    assertHandshakeChallenge(challenge);
    if (challenge.configFingerprint !== hello.configFingerprint || challenge.clientNonce !== hello.clientNonce) return false;
    return constantTimeProofEquals(
      createDaemonProof(secretBytes(secret), hello, challenge),
      challenge.daemonProof,
    );
  } catch {
    return false;
  }
}

/** Constant-time verification. It intentionally never includes credential material in an error. */
export function verifyHandshakeResponse(
  hello: HandshakeHello,
  challenge: HandshakeChallenge,
  response: HandshakeResponse,
  secret: string | Uint8Array,
): boolean {
  try {
    assertHandshakeHello(hello);
    assertHandshakeChallenge(challenge);
    assertHandshakeResponse(response);
    if (!verifyHandshakeChallenge(hello, challenge, secret)) return false;
    return constantTimeProofEquals(createClientProof(secretBytes(secret), hello, challenge), response.proof);
  } catch {
    return false;
  }
}

function assertHandshakeHello(value: unknown): asserts value is HandshakeHello {
  if (!isRecord(value) || !hasExactKeys(value, ["type", "protocolVersion", "configFingerprint", "clientNonce"])
    || value.type !== "hello" || value.protocolVersion !== RPC_PROTOCOL_VERSION
    || !validFingerprint(value.configFingerprint) || !validNonce(value.clientNonce)) throw new RpcProtocolError("RPC_HANDSHAKE_INVALID");
}

function assertHandshakeChallenge(value: unknown): asserts value is HandshakeChallenge {
  if (!isRecord(value) || !hasExactKeys(value, ["type", "protocolVersion", "configFingerprint", "clientNonce", "daemonNonce", "daemonProof"])
    || value.type !== "challenge" || value.protocolVersion !== RPC_PROTOCOL_VERSION
    || !validFingerprint(value.configFingerprint) || !validNonce(value.clientNonce) || !validNonce(value.daemonNonce) || !validProof(value.daemonProof)) {
    throw new RpcProtocolError("RPC_HANDSHAKE_INVALID");
  }
}

function assertHandshakeResponse(value: unknown): asserts value is HandshakeResponse {
  if (!isRecord(value) || !hasExactKeys(value, ["type", "protocolVersion", "proof"])
    || value.type !== "authenticate" || value.protocolVersion !== RPC_PROTOCOL_VERSION || !validProof(value.proof)) {
    throw new RpcProtocolError("RPC_HANDSHAKE_INVALID");
  }
}

function createDaemonProof(
  secret: Buffer,
  hello: HandshakeHello,
  challenge: Pick<HandshakeChallenge, "configFingerprint" | "clientNonce" | "daemonNonce">,
): string {
  return createHmac("sha256", secret)
    .update(`agent-bridge-daemon-challenge-v1\n${RPC_PROTOCOL_VERSION}\n${hello.configFingerprint}\n${hello.clientNonce}\n${challenge.daemonNonce}`, "utf8")
    .digest("hex");
}

function createClientProof(secret: Buffer, hello: HandshakeHello, challenge: HandshakeChallenge): string {
  return createHmac("sha256", secret)
    .update(`agent-bridge-client-response-v1\n${RPC_PROTOCOL_VERSION}\n${hello.configFingerprint}\n${hello.clientNonce}\n${challenge.daemonNonce}`, "utf8")
    .digest("hex");
}

function constantTimeProofEquals(expectedProof: string, suppliedProof: string): boolean {
  const expected = Buffer.from(expectedProof, "hex");
  const supplied = validProof(suppliedProof) ? Buffer.from(suppliedProof, "hex") : Buffer.alloc(expected.length);
  return supplied.length === expected.length && timingSafeEqual(expected, supplied);
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function newNonce(): string { return randomBytes(24).toString("base64url"); }

function secretBytes(value: string | Uint8Array): Buffer {
  const result = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
  if (result.length < 32 || result.length > 4096) throw new RpcProtocolError("RPC_SECRET_INVALID");
  return result;
}

function decodeUtf8(value: Buffer): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(value); }
  catch { throw new RpcProtocolError("RPC_FRAME_MALFORMED"); }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (!isRecord(value)) return false;
  return Object.values(value).every(isJsonValue);
}

function validId(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value); }
function validMethod(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/.test(value); }
function validNonce(value: unknown): value is string { return typeof value === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(value); }
function validFingerprint(value: unknown): value is string { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value); }
function validProof(value: unknown): value is string { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value); }
function validDeadline(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}
function validSafeError(value: unknown): value is { code: string; message: string } {
  return isRecord(value) && hasExactKeys(value, ["code", "message"])
    && typeof value.code === "string" && /^[A-Z0-9_]{1,64}$/.test(value.code)
    && typeof value.message === "string" && value.message.length <= 512;
}
