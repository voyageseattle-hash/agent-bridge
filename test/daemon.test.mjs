import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { rm } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const buildDir = join(tmpdir(), `agent-bridge-daemon-build-${process.pid}-${randomBytes(5).toString("hex")}`);
await build({
  entryPoints: { daemon: "src/daemon.ts", proxy: "src/proxy.ts", rpc: "src/rpc.ts" },
  outdir: buildDir,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
});
const daemonApi = await import(`${pathToFileURL(join(buildDir, "daemon.js")).href}?${Date.now()}`);
const proxyApi = await import(`${pathToFileURL(join(buildDir, "proxy.js")).href}?${Date.now()}`);
const rpc = await import(`${pathToFileURL(join(buildDir, "rpc.js")).href}?${Date.now()}`);

const secret = "agent-bridge-test-capability-token-000000000000000000000000";
const config = JSON.stringify({ allowedRoots: ["temporary-test-only"] });
const cleanupPaths = new Set();
test.after(async () => {
  for (const path of cleanupPaths) await rm(path, { force: true });
  await rm(buildDir, { recursive: true, force: true });
});

function ipcPath(label) {
  const suffix = `${process.pid}-${randomBytes(5).toString("hex")}`;
  if (process.platform === "win32") return `\\\\.\\pipe\\agent-bridge-${label}-${suffix}`;
  const path = join(tmpdir(), `ab-${label}-${suffix}.sock`);
  cleanupPaths.add(path);
  return path;
}

function daemonAt(path, handler, options = {}) {
  return daemonApi.createRpcDaemon({ ipcPath: path, config, secret, handler, ...options });
}

function proxyAt(path, options = {}) {
  return proxyApi.createRpcProxy({ ipcPath: path, config, secret, connectTimeoutMs: 1_000, ...options });
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("daemon import and construction have no side effects; start/stop are explicit", { timeout: 5_000 }, async () => {
  const path = ipcPath("lifecycle");
  const daemon = daemonAt(path, () => ({ ok: true }));
  assert.equal(daemon.state, "stopped");
  assert.equal(daemon.activeConnections, 0);
  assert.equal(daemon.securityEvidence.transport, process.platform === "win32" ? "windows-named-pipe" : "unix-domain-socket");
  assert.equal(daemon.securityEvidence.endpointAccessControlVerified, process.platform !== "win32");

  await daemon.start();
  assert.equal(daemon.state, "running");
  await daemon.stop();
  assert.equal(daemon.state, "stopped");
  await daemon.stop();
});

test("mutually authenticated proxy correlates concurrent request/response pairs", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("roundtrip");
  const releaseFirst = deferred();
  const daemon = daemonAt(path, async (request, context) => {
    assert.match(context.connectionId, /^connection_\d+$/);
    if (request.params.order === 1) await releaseFirst.promise;
    return { echoed: request.params, method: request.method };
  });
  await daemon.start();
  t.after(() => daemon.stop());
  const proxy = proxyAt(path);
  await proxy.connect();
  t.after(() => proxy.close());

  const first = proxy.request("test.echo", { order: 1 });
  const second = proxy.request("test.echo", { order: 2 });
  assert.deepEqual(await second, { echoed: { order: 2 }, method: "test.echo" });
  releaseFirst.resolve();
  assert.deepEqual(await first, { echoed: { order: 1 }, method: "test.echo" });
  assert.equal(proxy.inFlight, 0);
});

test("handshake rejects wrong capability, config, and fail-closed policy", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("auth");
  let handlerCalls = 0;
  const daemon = daemonAt(path, () => { handlerCalls++; return null; });
  await daemon.start();
  t.after(() => daemon.stop());

  const wrongSecret = proxyAt(path, { secret: "wrong-agent-bridge-capability-token-000000000000000000000" });
  await assert.rejects(wrongSecret.connect(), (error) => error.code === "RPC_DAEMON_AUTH_FAILED");
  const wrongConfig = proxyAt(path, { config: "different-config" });
  await assert.rejects(wrongConfig.connect(), (error) => error.code === "RPC_CONNECTION_CLOSED");
  assert.equal(handlerCalls, 0);

  const deniedPath = ipcPath("policy");
  let evidence;
  const denied = daemonAt(deniedPath, () => null, { authorizeConnection: (value) => { evidence = value; return false; } });
  await denied.start();
  t.after(() => denied.stop());
  await assert.rejects(proxyAt(deniedPath).connect(), (error) => error.code === "RPC_CONNECTION_CLOSED");
  assert.equal(evidence.peerIdentity, "unavailable-to-node-net");
});

test("strict state machine closes a request sent before handshake", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("state");
  let handlerCalls = 0;
  const daemon = daemonAt(path, () => { handlerCalls++; return null; });
  await daemon.start();
  t.after(() => daemon.stop());

  const socket = createConnection(path);
  socket.on("error", () => undefined);
  const closed = new Promise((resolve) => socket.once("close", resolve));
  await new Promise((resolve) => socket.once("connect", resolve));
  socket.write(rpc.encodeRpcFrame(rpc.createRequest("premature", "test.invalid", null)));
  await closed;
  assert.equal(handlerCalls, 0);
});

test("handshake deadline releases an unauthenticated connection slot", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("handshake-timeout");
  // Leave enough observation time for a loaded Windows event loop while still
  // keeping this test's deliberately short deadline well below its own timeout.
  const daemon = daemonAt(path, () => null, { maxConnections: 1, handshakeTimeoutMs: 250 });
  await daemon.start();
  t.after(() => daemon.stop());
  const idle = createConnection(path);
  idle.on("error", () => undefined);
  await new Promise((resolve) => idle.once("connect", resolve));
  await eventually(() => daemon.activeConnections === 1);
  assert.equal(daemon.activeConnections, 1);
  await new Promise((resolve) => idle.once("close", resolve));
  await eventually(() => daemon.activeConnections === 0);
  assert.equal(daemon.activeConnections, 0);
  const proxy = proxyAt(path);
  await proxy.connect();
  await proxy.close();
});

async function eventually(predicate, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition was not observed before the test deadline");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

test("daemon and proxy enforce bounded in-flight work", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("limits");
  const started = deferred();
  const release = deferred();
  const daemon = daemonAt(path, async (request) => {
    if (request.params.slot === 1) { started.resolve(); await release.promise; }
    return request.params;
  }, { maxInFlightPerConnection: 1 });
  await daemon.start();
  t.after(() => daemon.stop());
  const proxy = proxyAt(path, { maxInFlight: 2 });
  await proxy.connect();
  t.after(() => proxy.close());

  const first = proxy.request("test.limit", { slot: 1 });
  await started.promise;
  await assert.rejects(proxy.request("test.limit", { slot: 2 }), (error) => error.code === "RPC_IN_FLIGHT_LIMIT");
  release.resolve();
  assert.deepEqual(await first, { slot: 1 });

  const localPath = ipcPath("proxy-limit");
  const localRelease = deferred();
  const localDaemon = daemonAt(localPath, async () => { await localRelease.promise; return null; });
  await localDaemon.start();
  t.after(() => localDaemon.stop());
  const localProxy = proxyAt(localPath, { maxInFlight: 1 });
  await localProxy.connect();
  t.after(() => localProxy.close());
  const pending = localProxy.request("test.localLimit", null);
  await assert.rejects(localProxy.request("test.localLimit", null), (error) => error.code === "RPC_IN_FLIGHT_LIMIT");
  localRelease.resolve();
  await pending;
});

test("oversized request encoding does not reserve a proxy in-flight slot", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("oversized-request");
  const daemon = daemonAt(path, (request) => request.params);
  await daemon.start();
  t.after(() => daemon.stop());
  const proxy = proxyAt(path, { maxInFlight: 1 });
  await proxy.connect();
  t.after(() => proxy.close());
  await assert.rejects(proxy.request("test.oversized", { value: "x".repeat(rpc.DEFAULT_MAX_FRAME_BYTES) }), (error) => error.code === "RPC_FRAME_TOO_LARGE");
  assert.equal(proxy.inFlight, 0);
  assert.deepEqual(await proxy.request("test.small", { ok: true }), { ok: true });
});

test("invalid frame limits fail at daemon/proxy construction", () => {
  const path = ipcPath("bad-frame-limit");
  assert.throws(() => daemonAt(path, () => null, { maxFrameBytes: 1 }), (error) => error.code === "RPC_FRAME_LIMIT_INVALID");
  assert.throws(() => proxyAt(path, { maxFrameBytes: 1 }), (error) => error.code === "RPC_FRAME_LIMIT_INVALID");
});

test("connection limit refuses additional authenticated clients", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("connections");
  const daemon = daemonAt(path, () => null, { maxConnections: 1 });
  await daemon.start();
  t.after(() => daemon.stop());
  const first = proxyAt(path);
  await first.connect();
  t.after(() => first.close());
  assert.equal(daemon.activeConnections, 1);
  await assert.rejects(proxyAt(path).connect(), (error) => error.code === "RPC_CONNECTION_CLOSED");
});

test("proxy disconnect aborts every active daemon handler and rejects callers", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("cancel");
  const started = deferred();
  const aborted = deferred();
  const daemon = daemonAt(path, async (_request, context) => {
    started.resolve();
    await new Promise((resolve) => {
      context.signal.addEventListener("abort", () => { aborted.resolve(); resolve(); }, { once: true });
    });
    return null;
  });
  await daemon.start();
  t.after(() => daemon.stop());
  const proxy = proxyAt(path);
  await proxy.connect();
  const request = proxy.request("test.cancel", null);
  await started.promise;
  await proxy.close();
  await aborted.promise;
  await assert.rejects(request, (error) => error.code === "RPC_CONNECTION_CLOSED");
});

test("caller abort sends a cancel frame and aborts only the correlated daemon handler", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("request-cancel");
  const started = deferred();
  const aborted = deferred();
  const daemon = daemonAt(path, async (request, context) => {
    if (request.method === "test.quick") return { ok: true };
    started.resolve();
    await new Promise((resolve) => {
      context.signal.addEventListener("abort", () => { aborted.resolve(); resolve(); }, { once: true });
    });
    return null;
  });
  await daemon.start();
  t.after(() => daemon.stop());
  const proxy = proxyAt(path);
  await proxy.connect();
  t.after(() => proxy.close());

  const controller = new AbortController();
  const request = proxy.request("test.cancel-one", null, { signal: controller.signal });
  await started.promise;
  controller.abort();
  await assert.rejects(request, (error) => error.name === "AbortError");
  await aborted.promise;
  assert.equal(proxy.inFlight, 0);
  assert.deepEqual(await proxy.request("test.quick", null), { ok: true });
});

test("proxy and daemon enforce a shared request deadline", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("request-deadline");
  const started = deferred();
  const aborted = deferred();
  let forwardedDeadline;
  const daemon = daemonAt(path, async (request, context) => {
    forwardedDeadline = request.deadlineUnixMs;
    started.resolve();
    await new Promise((resolve) => {
      context.signal.addEventListener("abort", () => { aborted.resolve(); resolve(); }, { once: true });
    });
    return null;
  });
  await daemon.start();
  t.after(() => daemon.stop());
  const proxy = proxyAt(path);
  await proxy.connect();
  t.after(() => proxy.close());

  const request = proxy.request("test.deadline", null, { timeoutMs: 40 });
  await started.promise;
  await assert.rejects(request, (error) => error.code === "RPC_REQUEST_DEADLINE_EXCEEDED");
  await aborted.promise;
  assert.equal(typeof forwardedDeadline, "number");
  assert.equal(proxy.inFlight, 0);
});

test("exclusive IPC binding refuses a second daemon instance", { timeout: 5_000 }, async (t) => {
  const path = ipcPath("singleton");
  const first = daemonAt(path, () => null);
  const second = daemonAt(path, () => null);
  await first.start();
  t.after(() => first.stop());
  await assert.rejects(second.start(), (error) => error.code === "EADDRINUSE");
  assert.equal(second.state, "stopped");
  assert.equal(first.state, "running");
});
