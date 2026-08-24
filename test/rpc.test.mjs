import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const outputDir = await mkdtemp(join(tmpdir(), "agent-bridge-rpc-"));
const outfile = join(outputDir, "rpc.mjs");
await build({ entryPoints: ["src/rpc.ts"], outfile, bundle: true, platform: "node", format: "esm", target: "node20" });
const rpc = await import(`${pathToFileURL(outfile).href}?${Date.now()}`);
test.after(async () => { await rm(outputDir, { recursive: true, force: true }); });

function rawFrame(body) {
  const bytes = Buffer.from(body, "utf8");
  const frame = Buffer.alloc(4 + bytes.length);
  frame.writeUInt32BE(bytes.length, 0);
  bytes.copy(frame, 4);
  return frame;
}

test("length-prefixed RPC decoder accepts fragmented and coalesced envelopes", () => {
  const first = rpc.encodeRpcFrame(rpc.createRequest("request_1", "bridge.run", { cwd: "C:\\safe" }));
  const second = rpc.encodeRpcFrame(rpc.createSuccess("request_1", { accepted: true }));
  const decoder = new rpc.RpcFrameDecoder(1024);
  assert.deepEqual(decoder.push(first.subarray(0, 2)), []);
  assert.deepEqual(decoder.push(first.subarray(2, 9)), []);
  const values = decoder.push(Buffer.concat([first.subarray(9), second]));
  assert.equal(values.length, 2);
  assert.equal(values[0].type, "request");
  assert.equal(values[0].id, "request_1");
  assert.equal(values[1].type, "response");
  assert.equal(values[1].ok, true);
});

test("RPC decoder rejects oversize, malformed, and invalid-envelope frames without payload disclosure", () => {
  const oversized = Buffer.alloc(4);
  oversized.writeUInt32BE(1025, 0);
  assert.throws(() => new rpc.RpcFrameDecoder(1024).push(oversized), { code: "RPC_FRAME_TOO_LARGE" });
  assert.throws(() => new rpc.RpcFrameDecoder().push(rawFrame("{not-json-secret=do-not-leak")), (error) => {
    assert.equal(error.code, "RPC_FRAME_MALFORMED");
    assert.doesNotMatch(error.message, /do-not-leak/);
    return true;
  });
  assert.throws(() => new rpc.RpcFrameDecoder().push(rawFrame(JSON.stringify({ type: "request", protocolVersion: 1, id: "x", method: "ok", params: {}, extra: "no" }))), { code: "RPC_ENVELOPE_INVALID" });
});

test("RPC correlation requires typed request and response envelopes", () => {
  const request = rpc.createRequest("correlation_7", "session.get", { id: "abc" });
  const response = rpc.createSuccess(request.id, { found: true });
  const failure = rpc.createFailure(request.id, "SESSION_BUSY", "session is already running a turn");
  assert.equal(response.id, request.id);
  assert.equal(response.ok, true);
  assert.equal(failure.id, request.id);
  assert.equal(failure.ok, false);
  assert.throws(() => rpc.createRequest("bad id with spaces", "session.get", {}), { code: "RPC_ENVELOPE_INVALID" });
});

test("RPC request deadlines and cancellation frames are strict protocol messages", () => {
  const deadlineUnixMs = Date.now() + 10_000;
  const request = rpc.createRequest("deadline_1", "bridge.run", { value: true }, { deadlineUnixMs });
  assert.equal(request.deadlineUnixMs, deadlineUnixMs);
  const cancel = rpc.createCancel(request.id);
  const decoded = new rpc.RpcFrameDecoder().push(rpc.encodeRpcFrame(cancel));
  assert.deepEqual(decoded, [cancel]);
  assert.throws(
    () => rpc.createRequest("deadline_2", "bridge.run", null, { deadlineUnixMs: -1 }),
    { code: "RPC_ENVELOPE_INVALID" },
  );
  assert.throws(
    () => new rpc.RpcFrameDecoder().push(rawFrame(JSON.stringify({
      type: "cancel", protocolVersion: rpc.RPC_PROTOCOL_VERSION, id: "deadline_1", reason: "leak",
    }))),
    { code: "RPC_CANCEL_INVALID" },
  );
});

test("handshake proves the shared secret and binds the exact config fingerprint", () => {
  const config = '{"allowedRoots":["C:\\\\safe"]}';
  const secret = Buffer.alloc(32, 7);
  const hello = rpc.createHandshakeHello(config, "client_nonce_123456");
  const challenge = rpc.createHandshakeChallenge(hello, rpc.configFingerprint(config), secret, "daemon_nonce_123456");
  assert.equal(rpc.verifyHandshakeChallenge(hello, challenge, secret), true);
  assert.equal(rpc.verifyHandshakeChallenge(hello, challenge, Buffer.alloc(32, 8)), false);
  const response = rpc.createHandshakeResponse(hello, challenge, secret);
  assert.equal(rpc.verifyHandshakeResponse(hello, challenge, response, secret), true);
  assert.equal(rpc.verifyHandshakeResponse(hello, challenge, response, Buffer.alloc(32, 8)), false);
  assert.equal(rpc.verifyHandshakeResponse(hello, { ...challenge, daemonNonce: "other_daemon_nonce_123456" }, response, secret), false);
});

test("hello, challenge, and authentication proof traverse the framed transport", () => {
  const config = '{"allowedRoots":["C:\\\\safe"]}';
  const secret = Buffer.alloc(32, 9);
  const client = new rpc.RpcFrameDecoder();
  const daemon = new rpc.RpcFrameDecoder();

  const hello = rpc.createHandshakeHello(config, "client_nonce_123456");
  const receivedHello = daemon.push(rpc.encodeRpcFrame(hello));
  assert.equal(receivedHello.length, 1);
  assert.equal(receivedHello[0].type, "hello");

  const challenge = rpc.createHandshakeChallenge(receivedHello[0], rpc.configFingerprint(config), secret, "daemon_nonce_123456");
  const receivedChallenge = client.push(rpc.encodeRpcFrame(challenge));
  assert.equal(receivedChallenge[0].type, "challenge");

  const proof = rpc.createHandshakeResponse(hello, receivedChallenge[0], secret);
  const receivedProof = daemon.push(rpc.encodeRpcFrame(proof));
  assert.equal(receivedProof[0].type, "authenticate");
  assert.equal(rpc.verifyHandshakeResponse(hello, challenge, receivedProof[0], secret), true);
});

test("proxy rejects a forged or tampered daemon challenge before it emits its proof", () => {
  const config = '{"allowedRoots":["C:\\\\safe"]}';
  const proxySecret = Buffer.alloc(32, 3);
  const fakeDaemonSecret = Buffer.alloc(32, 4);
  const hello = rpc.createHandshakeHello(config, "client_nonce_123456");
  const forged = rpc.createHandshakeChallenge(hello, rpc.configFingerprint(config), fakeDaemonSecret, "daemon_nonce_123456");
  assert.equal(rpc.verifyHandshakeChallenge(hello, forged, proxySecret), false);
  assert.throws(() => rpc.createHandshakeResponse(hello, forged, proxySecret), { code: "RPC_DAEMON_AUTH_FAILED" });

  const valid = rpc.createHandshakeChallenge(hello, rpc.configFingerprint(config), proxySecret, "daemon_nonce_123456");
  const tampered = { ...valid, daemonProof: `${valid.daemonProof.slice(0, -1)}${valid.daemonProof.endsWith("0") ? "1" : "0"}` };
  assert.equal(rpc.verifyHandshakeChallenge(hello, tampered, proxySecret), false);
  assert.throws(() => rpc.createHandshakeResponse(hello, tampered, proxySecret), { code: "RPC_DAEMON_AUTH_FAILED" });
});

test("handshake rejects a different config before authentication", () => {
  const hello = rpc.createHandshakeHello('{"allowedRoots":["C:\\\\safe"]}', "client_nonce_123456");
  assert.throws(
    () => rpc.createHandshakeChallenge(hello, rpc.configFingerprint('{"allowedRoots":["C:\\\\other"]}'), Buffer.alloc(32, 1), "daemon_nonce_123456"),
    { code: "RPC_CONFIG_FINGERPRINT_MISMATCH" },
  );
});
