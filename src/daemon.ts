import { chmod } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import {
  configFingerprint,
  createFailure,
  createHandshakeChallenge,
  createSuccess,
  encodeRpcFrame,
  type HandshakeChallenge,
  type HandshakeHello,
  type JsonValue,
  RpcFrameDecoder,
  type RpcRequest,
  type RpcCancel,
  type RpcWireMessage,
  verifyHandshakeResponse,
} from "./rpc.js";

export interface DaemonRequestContext {
  readonly connectionId: string;
  readonly signal: AbortSignal;
}

export type DaemonRpcHandler = (request: RpcRequest, context: DaemonRequestContext) => JsonValue | Promise<JsonValue>;

export interface IpcSecurityEvidence {
  readonly ipcPath: string;
  readonly transport: "windows-named-pipe" | "unix-domain-socket";
  readonly exclusiveEndpointBinding: true;
  readonly capabilityAuthentication: "mutual-hmac-sha256";
  readonly peerIdentity: "unavailable-to-node-net";
  readonly endpointAccessControl: "windows-acl-not-configured-by-node" | "unix-mode-0600";
  readonly endpointAccessControlVerified: boolean;
}

export interface RpcDaemonOptions {
  ipcPath: string;
  config: string | Uint8Array;
  secret: string | Uint8Array;
  handler: DaemonRpcHandler;
  maxConnections?: number;
  maxInFlightPerConnection?: number;
  maxFrameBytes?: number;
  handshakeTimeoutMs?: number;
  /**
   * Optional fail-closed policy. Node's net API does not expose Windows named
   * pipe peer credentials or an explicit pipe ACL API, so callers that require
   * stronger evidence can reject here or provision the endpoint externally.
   */
  authorizeConnection?: (evidence: IpcSecurityEvidence) => boolean | Promise<boolean>;
}

export type RpcDaemonState = "stopped" | "starting" | "running" | "stopping";

interface ActiveRequest {
  readonly controller: AbortController;
  deadlineTimer?: NodeJS.Timeout;
}

export class RpcDaemon {
  private stateValue: RpcDaemonState = "stopped";
  private server: Server | undefined;
  private readonly sockets = new Set<Socket>();
  private nextConnectionId = 0;
  readonly securityEvidence: IpcSecurityEvidence;

  constructor(private readonly options: RpcDaemonOptions) {
    validateIpcPath(options.ipcPath);
    validateLimit(options.maxConnections ?? 32, "RPC_CONNECTION_LIMIT_INVALID");
    validateLimit(options.maxInFlightPerConnection ?? 64, "RPC_IN_FLIGHT_LIMIT_INVALID");
    validateDuration(options.handshakeTimeoutMs ?? 5_000, "RPC_HANDSHAKE_TIMEOUT_INVALID");
    try { new RpcFrameDecoder(options.maxFrameBytes); }
    catch { throw new DaemonStateError("RPC_FRAME_LIMIT_INVALID"); }
    if (typeof options.handler !== "function") throw new DaemonStateError("RPC_HANDLER_INVALID");
    this.securityEvidence = Object.freeze(buildSecurityEvidence(options.ipcPath));
  }

  get state(): RpcDaemonState { return this.stateValue; }
  get activeConnections(): number { return this.sockets.size; }

  /** Starts only when called; importing or constructing the daemon has no side effects. */
  async start(): Promise<void> {
    if (this.stateValue !== "stopped") throw new DaemonStateError("RPC_DAEMON_ALREADY_STARTED");
    this.stateValue = "starting";
    const server = createServer({ allowHalfOpen: false });
    this.server = server;
    server.on("connection", (socket) => this.accept(socket));

    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error) => { cleanup(); reject(error); };
        const onListening = () => { cleanup(); resolve(); };
        const cleanup = () => {
          server.off("error", onError);
          server.off("listening", onListening);
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(this.options.ipcPath);
      });
      if (process.platform !== "win32") await chmod(this.options.ipcPath, 0o600);
      // Prevent an asynchronous server error from becoming an uncaught process error.
      // Existing sockets are still closed explicitly by stop().
      server.on("error", () => undefined);
      this.stateValue = "running";
    } catch (error) {
      await closeServer(server);
      if (this.server === server) this.server = undefined;
      this.stateValue = "stopped";
      throw error;
    }
  }

  async stop(): Promise<void> {
    if (this.stateValue === "stopped") return;
    if (this.stateValue !== "running") throw new DaemonStateError("RPC_DAEMON_TRANSITION_IN_PROGRESS");
    this.stateValue = "stopping";
    const server = this.server;
    this.server = undefined;
    for (const socket of [...this.sockets]) socket.destroy();
    if (server) await closeServer(server);
    this.stateValue = "stopped";
  }

  private accept(socket: Socket): void {
    const maxConnections = this.options.maxConnections ?? 32;
    if (this.stateValue !== "running" || this.sockets.size >= maxConnections) {
      socket.destroy();
      return;
    }

    this.sockets.add(socket);
    const connectionId = `connection_${++this.nextConnectionId}`;
    const decoder = new RpcFrameDecoder(this.options.maxFrameBytes);
    const activeRequests = new Map<string, ActiveRequest>();
    let protocolState: "awaitingHello" | "awaitingAuth" | "authenticated" | "closed" = "awaitingHello";
    let hello: HandshakeHello | undefined;
    let challenge: HandshakeChallenge | undefined;
    const authorization = this.authorize();
    let chain = Promise.resolve();
    const handshakeTimer = setTimeout(() => socket.destroy(), this.options.handshakeTimeoutMs ?? 5_000);
    handshakeTimer.unref();

    const processMessage = (message: RpcWireMessage): void => {
      if (protocolState === "awaitingHello" && message.type === "hello") {
        challenge = createHandshakeChallenge(
          message,
          configFingerprint(this.options.config),
          this.options.secret,
        );
        hello = message;
        protocolState = "awaitingAuth";
        socket.write(encodeRpcFrame(challenge));
        return;
      }
      if (protocolState === "awaitingAuth" && message.type === "authenticate") {
        if (!hello || !challenge || !verifyHandshakeResponse(hello, challenge, message, this.options.secret)) {
          throw new DaemonStateError("RPC_CLIENT_AUTH_FAILED");
        }
        protocolState = "authenticated";
        clearTimeout(handshakeTimer);
        return;
      }
      if (protocolState === "authenticated" && message.type === "request") {
        this.startRequest(socket, connectionId, activeRequests, message);
        return;
      }
      if (protocolState === "authenticated" && message.type === "cancel") {
        this.cancelRequest(activeRequests, message);
        return;
      }
      throw new DaemonStateError("RPC_PROTOCOL_STATE_INVALID");
    };

    const close = () => {
      if (protocolState === "closed") return;
      protocolState = "closed";
      clearTimeout(handshakeTimer);
      for (const active of activeRequests.values()) {
        if (active.deadlineTimer) clearTimeout(active.deadlineTimer);
        active.controller.abort();
      }
      activeRequests.clear();
      this.sockets.delete(socket);
    };
    socket.once("close", close);
    socket.once("error", () => socket.destroy());
    socket.on("data", (chunk) => {
      let messages: RpcWireMessage[];
      try { messages = decoder.push(chunk); }
      catch { socket.destroy(); return; }
      chain = chain.then(async () => {
        if (!await authorization) throw new DaemonStateError("RPC_CONNECTION_NOT_AUTHORIZED");
        for (const message of messages) processMessage(message);
      }).catch(() => { socket.destroy(); });
    });
  }

  private startRequest(
    socket: Socket,
    connectionId: string,
    activeRequests: Map<string, ActiveRequest>,
    request: RpcRequest,
  ): void {
    if (activeRequests.has(request.id)) throw new DaemonStateError("RPC_REQUEST_ID_IN_USE");
    const limit = this.options.maxInFlightPerConnection ?? 64;
    if (activeRequests.size >= limit) {
      socket.write(encodeRpcFrame(createFailure(request.id, "RPC_IN_FLIGHT_LIMIT", "Too many in-flight requests")));
      return;
    }
    if (request.deadlineUnixMs !== undefined && request.deadlineUnixMs <= Date.now()) {
      socket.write(encodeRpcFrame(createFailure(request.id, "RPC_REQUEST_DEADLINE_EXCEEDED", "RPC request deadline exceeded")));
      return;
    }
    const controller = new AbortController();
    const active: ActiveRequest = { controller };
    activeRequests.set(request.id, active);
    if (request.deadlineUnixMs !== undefined) {
      active.deadlineTimer = setTimeout(() => {
        if (activeRequests.get(request.id) !== active) return;
        activeRequests.delete(request.id);
        controller.abort();
        if (!socket.destroyed) {
          socket.write(encodeRpcFrame(createFailure(request.id, "RPC_REQUEST_DEADLINE_EXCEEDED", "RPC request deadline exceeded")));
        }
      }, request.deadlineUnixMs - Date.now());
      active.deadlineTimer.unref();
    }
    void Promise.resolve()
      .then(() => this.options.handler(request, { connectionId, signal: controller.signal }))
      .then((result) => {
        if (!controller.signal.aborted && !socket.destroyed) socket.write(encodeRpcFrame(createSuccess(request.id, result)));
      })
      .catch(() => {
        if (!controller.signal.aborted && !socket.destroyed) {
          socket.write(encodeRpcFrame(createFailure(request.id, "RPC_HANDLER_ERROR", "RPC handler failed")));
        }
      })
      .finally(() => {
        if (active.deadlineTimer) clearTimeout(active.deadlineTimer);
        if (activeRequests.get(request.id) === active) activeRequests.delete(request.id);
      });
  }

  private cancelRequest(activeRequests: Map<string, ActiveRequest>, message: RpcCancel): void {
    const active = activeRequests.get(message.id);
    if (!active) return; // cancellation is idempotent and may race completion
    activeRequests.delete(message.id);
    if (active.deadlineTimer) clearTimeout(active.deadlineTimer);
    active.controller.abort();
  }

  private async authorize(): Promise<boolean> {
    try { return this.options.authorizeConnection ? await this.options.authorizeConnection(this.securityEvidence) : true; }
    catch { return false; }
  }
}

export class DaemonStateError extends Error {
  constructor(readonly code: string) { super(code); this.name = "DaemonStateError"; }
}

export function createRpcDaemon(options: RpcDaemonOptions): RpcDaemon { return new RpcDaemon(options); }

function validateIpcPath(ipcPath: string): void {
  if (typeof ipcPath !== "string" || ipcPath.length === 0 || ipcPath.includes("\0")) throw new DaemonStateError("RPC_IPC_PATH_INVALID");
  if (process.platform === "win32") {
    if (!/^\\\\\.\\pipe\\[A-Za-z0-9._-]{1,180}$/.test(ipcPath)) throw new DaemonStateError("RPC_IPC_PATH_INVALID");
    return;
  }
  if (!ipcPath.startsWith("/") || Buffer.byteLength(ipcPath) > 100) throw new DaemonStateError("RPC_IPC_PATH_INVALID");
}

function validateLimit(value: number, code: string): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 10_000) throw new DaemonStateError(code);
}

function validateDuration(value: number, code: string): void {
  if (!Number.isSafeInteger(value) || value < 10 || value > 300_000) throw new DaemonStateError(code);
}

function buildSecurityEvidence(ipcPath: string): IpcSecurityEvidence {
  const windows = process.platform === "win32";
  return {
    ipcPath,
    transport: windows ? "windows-named-pipe" : "unix-domain-socket",
    exclusiveEndpointBinding: true,
    capabilityAuthentication: "mutual-hmac-sha256",
    peerIdentity: "unavailable-to-node-net",
    endpointAccessControl: windows ? "windows-acl-not-configured-by-node" : "unix-mode-0600",
    endpointAccessControlVerified: !windows,
  };
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve) => server.close(() => resolve()));
}
