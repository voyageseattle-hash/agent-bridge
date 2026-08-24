import { randomBytes } from "node:crypto";
import { createConnection, type Socket } from "node:net";
import {
  createCancel,
  createHandshakeHello,
  createHandshakeResponse,
  createRequest,
  encodeRpcFrame,
  type JsonValue,
  RpcFrameDecoder,
  type RpcFailure,
  type RpcSuccess,
  type RpcWireMessage,
} from "./rpc.js";

export interface RpcProxyOptions {
  ipcPath: string;
  config: string | Uint8Array;
  secret: string | Uint8Array;
  maxInFlight?: number;
  maxFrameBytes?: number;
  connectTimeoutMs?: number;
}

export interface RpcRequestOptions {
  signal?: AbortSignal;
  /** Relative deadline. When combined with deadlineUnixMs, the earlier value wins. */
  timeoutMs?: number;
  /** Absolute Unix epoch deadline forwarded to and enforced by the daemon. */
  deadlineUnixMs?: number;
}
export type RpcProxyState = "disconnected" | "connecting" | "ready" | "closing" | "closed";

interface PendingRequest {
  resolve(value: JsonValue): void;
  reject(error: Error): void;
  removeAbort?: () => void;
  deadlineTimer?: NodeJS.Timeout;
}

export class RpcProxy {
  private stateValue: RpcProxyState = "disconnected";
  private socket: Socket | undefined;
  private decoder: RpcFrameDecoder | undefined;
  private readonly pending = new Map<string, PendingRequest>();
  private readonly canceledResponseIds = new Set<string>();
  private sequence = 0;

  constructor(private readonly options: RpcProxyOptions) {
    if (!Number.isSafeInteger(options.maxInFlight ?? 64) || (options.maxInFlight ?? 64) < 1) throw new RpcProxyError("RPC_IN_FLIGHT_LIMIT_INVALID");
    if (!Number.isSafeInteger(options.connectTimeoutMs ?? 5_000) || (options.connectTimeoutMs ?? 5_000) < 1) throw new RpcProxyError("RPC_CONNECT_TIMEOUT_INVALID");
    try { new RpcFrameDecoder(options.maxFrameBytes); }
    catch { throw new RpcProxyError("RPC_FRAME_LIMIT_INVALID"); }
  }

  get state(): RpcProxyState { return this.stateValue; }
  get inFlight(): number { return this.pending.size; }

  async connect(): Promise<void> {
    if (this.stateValue !== "disconnected") throw new RpcProxyError("RPC_PROXY_ALREADY_USED");
    this.stateValue = "connecting";
    this.decoder = new RpcFrameDecoder(this.options.maxFrameBytes);
    const hello = createHandshakeHello(this.options.config);
    const socket = createConnection(this.options.ipcPath);
    this.socket = socket;

    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const timeout = setTimeout(() => fail(new RpcProxyError("RPC_CONNECT_TIMEOUT")), this.options.connectTimeoutMs ?? 5_000);
      timeout.unref();
      const cleanupHandshake = () => { clearTimeout(timeout); };
      const fail = (error: Error) => {
        if (settled) return;
        settled = true;
        cleanupHandshake();
        this.failConnection(error);
        reject(error);
      };
      socket.once("error", fail);
      socket.once("close", () => {
        if (!settled) fail(new RpcProxyError("RPC_CONNECTION_CLOSED"));
        else this.failConnection(new RpcProxyError("RPC_CONNECTION_CLOSED"));
      });
      socket.on("data", (chunk) => {
        let messages: RpcWireMessage[];
        try { messages = this.decoder!.push(chunk); }
        catch { fail(new RpcProxyError("RPC_PROTOCOL_INVALID")); return; }
        for (const message of messages) {
          if (!settled) {
            if (message.type !== "challenge") { fail(new RpcProxyError("RPC_PROTOCOL_STATE_INVALID")); return; }
            try {
              const response = createHandshakeResponse(hello, message, this.options.secret);
              socket.write(encodeRpcFrame(response), (error) => {
                if (error) { fail(error); return; }
                if (settled) return;
                settled = true;
                cleanupHandshake();
                this.stateValue = "ready";
                resolve();
              });
            } catch { fail(new RpcProxyError("RPC_DAEMON_AUTH_FAILED")); }
          } else {
            try { this.processResponse(message); }
            catch { this.failConnection(new RpcProxyError("RPC_PROTOCOL_STATE_INVALID")); }
          }
        }
      });
      socket.once("connect", () => socket.write(encodeRpcFrame(hello)));
    });
  }

  request(method: string, params: JsonValue, options: RpcRequestOptions = {}): Promise<JsonValue> {
    if (this.stateValue !== "ready" || !this.socket || this.socket.destroyed) return Promise.reject(new RpcProxyError("RPC_PROXY_NOT_READY"));
    if (options.signal?.aborted) return Promise.reject(abortError());
    if (this.pending.size >= (this.options.maxInFlight ?? 64)) return Promise.reject(new RpcProxyError("RPC_IN_FLIGHT_LIMIT"));
    let deadlineUnixMs: number | undefined;
    try { deadlineUnixMs = resolveDeadline(options); }
    catch (error) { return Promise.reject(error); }
    if (deadlineUnixMs !== undefined && deadlineUnixMs <= Date.now()) {
      return Promise.reject(new RpcProxyError("RPC_REQUEST_DEADLINE_EXCEEDED"));
    }
    const id = `r_${process.pid}_${++this.sequence}_${randomBytes(6).toString("hex")}`;
    let frame: Buffer;
    try { frame = encodeRpcFrame(createRequest(id, method, params, { deadlineUnixMs })); }
    catch (error) { return Promise.reject(error); }
    return new Promise<JsonValue>((resolve, reject) => {
      const pending: PendingRequest = { resolve, reject };
      const cancel = (error: Error) => this.cancelPending(id, error);
      if (options.signal) {
        const onAbort = () => cancel(abortError());
        options.signal.addEventListener("abort", onAbort, { once: true });
        pending.removeAbort = () => options.signal!.removeEventListener("abort", onAbort);
      }
      if (deadlineUnixMs !== undefined) {
        pending.deadlineTimer = setTimeout(
          () => cancel(new RpcProxyError("RPC_REQUEST_DEADLINE_EXCEEDED")),
          deadlineUnixMs - Date.now(),
        );
        pending.deadlineTimer.unref();
      }
      this.pending.set(id, pending);
      this.socket!.write(frame, (error) => {
        if (error) this.failConnection(error);
      });
    });
  }

  async close(): Promise<void> {
    if (this.stateValue === "closed") return;
    this.stateValue = "closing";
    const socket = this.socket;
    if (!socket || socket.destroyed) {
      this.failConnection(new RpcProxyError("RPC_PROXY_CLOSED"));
      this.stateValue = "closed";
      return;
    }
    const closed = new Promise<void>((resolve) => socket.once("close", resolve));
    socket.destroy();
    await closed;
    this.stateValue = "closed";
  }

  private processResponse(message: RpcWireMessage): void {
    if (message.type !== "response") throw new RpcProxyError("RPC_PROTOCOL_STATE_INVALID");
    const response = message as RpcSuccess | RpcFailure;
    const pending = this.pending.get(response.id);
    if (!pending) {
      // A response can cross an explicit cancel frame on the wire. It is safe
      // to ignore exactly one correlated late response, but never an unknown id.
      if (this.canceledResponseIds.delete(response.id)) return;
      throw new RpcProxyError("RPC_RESPONSE_NOT_CORRELATED");
    }
    this.pending.delete(response.id);
    cleanupPending(pending);
    if (response.ok) pending.resolve(response.result);
    else pending.reject(new RpcRemoteError(response.error.code, response.error.message));
  }

  private failConnection(error: Error): void {
    if (this.stateValue !== "closed") this.stateValue = "closed";
    const socket = this.socket;
    this.socket = undefined;
    if (socket && !socket.destroyed) socket.destroy();
    for (const pending of this.pending.values()) {
      cleanupPending(pending);
      pending.reject(error);
    }
    this.pending.clear();
    this.canceledResponseIds.clear();
  }

  private cancelPending(id: string, error: Error): void {
    const pending = this.pending.get(id);
    if (!pending) return;
    this.pending.delete(id);
    cleanupPending(pending);
    rememberCanceledId(this.canceledResponseIds, id);
    const socket = this.socket;
    if (this.stateValue === "ready" && socket && !socket.destroyed) {
      socket.write(encodeRpcFrame(createCancel(id)), (writeError) => {
        if (writeError) this.failConnection(writeError);
      });
    }
    pending.reject(error);
  }
}

export class RpcProxyError extends Error {
  constructor(readonly code: string) { super(code); this.name = "RpcProxyError"; }
}

export class RpcRemoteError extends Error {
  constructor(readonly code: string, message: string) { super(message); this.name = "RpcRemoteError"; }
}

export function createRpcProxy(options: RpcProxyOptions): RpcProxy { return new RpcProxy(options); }

function abortError(): Error {
  const error = new Error("The RPC request was aborted");
  error.name = "AbortError";
  return error;
}

function resolveDeadline(options: RpcRequestOptions): number | undefined {
  let deadline = options.deadlineUnixMs;
  if (deadline !== undefined && (!Number.isSafeInteger(deadline) || deadline <= 0)) {
    throw new RpcProxyError("RPC_REQUEST_DEADLINE_INVALID");
  }
  if (options.timeoutMs !== undefined) {
    if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 7_200_000) {
      throw new RpcProxyError("RPC_REQUEST_TIMEOUT_INVALID");
    }
    const relative = Date.now() + options.timeoutMs;
    deadline = deadline === undefined ? relative : Math.min(deadline, relative);
  }
  if (deadline !== undefined && deadline - Date.now() > 2_147_483_647) {
    throw new RpcProxyError("RPC_REQUEST_DEADLINE_INVALID");
  }
  return deadline;
}

function cleanupPending(pending: PendingRequest): void {
  pending.removeAbort?.();
  if (pending.deadlineTimer) clearTimeout(pending.deadlineTimer);
}

function rememberCanceledId(ids: Set<string>, id: string): void {
  ids.add(id);
  // Bound race tombstones on a long-lived proxy even if a canceled handler
  // correctly suppresses its response forever.
  if (ids.size > 1_024) ids.delete(ids.values().next().value!);
}
