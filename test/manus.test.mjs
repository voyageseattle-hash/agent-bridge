import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const outputDir = await mkdtemp(join(tmpdir(), "agent-bridge-manus-"));
const outputFile = join(outputDir, "manus.mjs");
await build({ entryPoints: ["src/adapters/manus.ts"], outfile: outputFile, bundle: true, platform: "node", format: "esm", target: "node20" });
const { ManusAdapter, ManusApiError, isValidManusEventId, isValidManusTaskId } = await import(pathToFileURL(outputFile).href);

function acknowledgedManus(options = {}) {
  return new ManusAdapter({ acknowledgeAccountDefaultCapabilities: true, accountCapabilityProfile: "test-reviewed-profile", ...options });
}

const TASK_CREATED = "A".repeat(22);
const TASK_EXISTING = "B".repeat(22);
const TASK_TIMEOUT = "C".repeat(22);
const TASK_WAITING = "D".repeat(22);
const TASK_API_FAILURE = "E".repeat(22);
const TASK_PHANTOM = "F".repeat(22);
const TASK_VISIBLE = "G".repeat(22);
const TASK_CORRELATION = "H".repeat(22);
const TASK_ABORTED = "I".repeat(22);
const TASK_SAFE = "J".repeat(22);
const TASK_OTHER = "K".repeat(22);

test.after(async () => { await rm(outputDir, { recursive: true, force: true }); });

function request(prompt, overrides = {}) {
  return { prompt, cwd: process.cwd(), sandbox: "workspace-write", timeoutMs: 2_000, ...overrides };
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

test("Manus creates a task, polls it, and returns the assistant message", async () => {
  const calls = [];
  const responses = [
    { code: 0, data: { task_id: TASK_CREATED } },
    { code: 0, data: [
      { message_type: "status_update", content: { agent_status: "running" } },
    ] },
    { code: 0, data: [
      { message_type: "status_update", content: { agent_status: "stopped" } },
      { message_type: "assistant_message", content: "finished answer" },
    ] },
  ];
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, fetch: async (url, init) => {
    calls.push({ url: String(url), init });
    return json(responses.shift());
  } });

  const result = await adapter.execute(request("do the thing", { model: "manus-1.6" }));

  assert.equal(result.text, "finished answer");
  assert.equal(result.nativeSessionId, TASK_CREATED);
  assert.equal(calls.length, 3);
  assert.equal(calls[0].url, "https://api.manus.ai/v2/task.create");
  assert.equal(calls[0].init.headers["x-manus-api-key"], "test-key");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    message: { content: "do the thing", connectors: [], force_skills: [], task_references: [] }, interactive_mode: false, hide_in_task_list: false,
    share_visibility: "private", agent_profile: "manus-1.6",
  });
  assert.match(calls[1].url, new RegExp(`task_id=${TASK_CREATED}.*order=desc.*limit=200`));
});

test("Manus resumes using task.sendMessage", async () => {
  const calls = [];
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, fetch: async (url, init) => {
    calls.push({ url: String(url), init });
    if (calls.length === 1) return json({ ok: true, task_id: TASK_EXISTING, messages: [
      { id: "old-stop", type: "status_update", timestamp: 10, status_update: { agent_status: "stopped" } },
    ] });
    if (calls.length === 2) return json({ ok: true, task_id: TASK_EXISTING, request_id: "send-request" });
    return json({ ok: true, task_id: TASK_EXISTING, messages: [
      { id: "new-stop", type: "status_update", timestamp: 40, status_update: { agent_status: "stopped" } },
      { id: "new-answer", type: "assistant_message", timestamp: 30, assistant_message: { content: "continued" } },
      { id: "new-user", type: "user_message", timestamp: 20, user_message: { content: "continue" } },
      { id: "old-stop", type: "status_update", timestamp: 10, status_update: { agent_status: "stopped" } },
    ] });
  } });

  const result = await adapter.execute(request("continue", { resumeSessionId: TASK_EXISTING, model: "manus-1.6-lite" }));
  assert.equal(result.nativeSessionId, TASK_EXISTING);
  assert.match(calls[0].url, /task\.listMessages/);
  assert.equal(calls[1].url, "https://api.manus.ai/v2/task.sendMessage");
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    task_id: TASK_EXISTING,
    message: { content: "continue", force_skills: [], task_references: [] },
    clear_connectors: true,
    agent_profile: "manus-1.6-lite",
  });
  assert.equal(result.text, "continued");
});

test("Manus surfaces authentication failures without exposing the API key", async () => {
  const adapter = acknowledgedManus({ apiKey: "test-fixture-secret-that-must-not-appear", fetch: async () => json({ code: 401, message: "invalid key" }, 401) });
  await assert.rejects(adapter.execute(request("hello")), (error) => {
    assert.ok(error instanceof ManusApiError);
    assert.equal(error.status, 401);
    assert.doesNotMatch(error.message, /secret-that-must-not-appear/);
    return true;
  });
});

test("Manus request preflight rejects missing authority, unsupported models, and oversized prompts before network access", async () => {
  let calls = 0;
  const fetch = async () => { calls++; return json({ ok: true }); };
  const missingCredential = acknowledgedManus({ apiKey: "", fetch });
  await assert.rejects(missingCredential.execute(request("hello")), /credential is not configured/i);
  const unsupportedModel = acknowledgedManus({ apiKey: "test-key", fetch });
  await assert.rejects(unsupportedModel.execute(request("hello", { model: "manus-other" })), /Unsupported Manus model/);
  await assert.rejects(unsupportedModel.execute(request("x".repeat(4_501))), /prompt is too large/i);
  await assert.rejects(unsupportedModel.execute(request("🙂".repeat(1_126))), /prompt is too large/i);
  const unacknowledged = new ManusAdapter({ apiKey: "test-key", accountCapabilityProfile: "test-reviewed-profile", fetch });
  await assert.rejects(unacknowledged.execute(request("hello")), /not acknowledged/i);
  assert.equal(calls, 0);
});

test("Manus ordinary continuation requires the provider's latest state to be stopped", async () => {
  let calls = 0;
  const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async () => {
    calls++;
    return json({ ok: true, task_id: TASK_EXISTING, messages: [
      { id: "waiting", type: "status_update", timestamp: 20, status_update: { agent_status: "waiting" } },
      { id: "old-stop", type: "status_update", timestamp: 10, status_update: { agent_status: "stopped" } },
    ] });
  } });
  await assert.rejects(adapter.execute(request("must not send", { resumeSessionId: TASK_EXISTING })), /ordinary continuation is denied/i);
  assert.equal(calls, 1);
});

test("Manus explicit credential file and official endpoint override ambient authority", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-manus-credential-"));
  const credential = join(root, "key");
  const oldKey = process.env.MANUS_API_KEY;
  const oldBase = process.env.MANUS_API_BASE_URL;
  try {
    await writeFile(credential, "file-key\n");
    process.env.MANUS_API_KEY = "ambient-key";
    process.env.MANUS_API_BASE_URL = "http://127.0.0.1:9";
    let request;
    const adapter = acknowledgedManus({
      apiKeyFile: credential,
      acknowledgeAccountDefaultCapabilities: true,
      fetch: async (url, init) => { request = { url: String(url), init }; return json({ ok: true, tasks: [] }); },
    });
    const health = await adapter.health();
    assert.equal(health.usable, true);
    assert.match(request.url, /^https:\/\/api\.manus\.ai\//);
    assert.equal(request.init.headers["x-manus-api-key"], "file-key");
  } finally {
    if (oldKey === undefined) delete process.env.MANUS_API_KEY; else process.env.MANUS_API_KEY = oldKey;
    if (oldBase === undefined) delete process.env.MANUS_API_BASE_URL; else process.env.MANUS_API_BASE_URL = oldBase;
    await rm(root, { recursive: true, force: true });
  }
});

test("Manus credential-file installs fail closed until account defaults are acknowledged", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-manus-capabilities-"));
  const credential = join(root, "key");
  try {
    await writeFile(credential, "file-key\n");
    let calls = 0;
    const adapter = acknowledgedManus({ apiKeyFile: credential, acknowledgeAccountDefaultCapabilities: false, fetch: async () => { calls++; return json({ ok: true }); } });
    const health = await adapter.health();
    assert.equal(health.usable, false);
    assert.match(health.auth.detail, /account-default skills/i);
    await assert.rejects(adapter.execute(request("blocked")), /account-default capabilities are not acknowledged/i);
    assert.equal(calls, 0);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("Manus persists a known task id on deadline and requests stop", async () => {
  const calls = [];
  const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url, init) => {
    calls.push(String(url));
    if (String(url).endsWith("task.create")) return json({ code: 0, data: { task_id: TASK_TIMEOUT } });
    if (String(url).endsWith("task.stop")) return json({ code: 0 });
    return await new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    });
  } });
  const result = await adapter.execute(request("slow", { timeoutMs: 5 }));
  assert.equal(result.nativeSessionId, TASK_TIMEOUT);
  assert.equal(result.timedOut, true);
  assert.equal(result.meta.taskStatus, "timed_out");
  assert.equal(result.meta.stopRequested, true);
  assert.ok(calls.some((url) => url.endsWith("task.stop")));
});

test("Manus returns a safe resumable result when a task is waiting", async () => {
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, fetch: async (url) => {
    return String(url).endsWith("task.create")
      ? json({ code: 0, data: { task_id: TASK_WAITING } })
      : json({ code: 0, data: [{ message_type: "status_update", content: {
        agent_status: "waiting", status_detail: {
          waiting_for_event_id: "evt_waiting", waiting_for_event_type: "apiHighCreditNotice",
          waiting_description: "Credit notice\napi_key: sk_secret_that_must_not_appear",
          confirm_input_schema: { raw: "must not persist" },
        },
      } }] });
  } });
  const result = await adapter.execute(request("needs you"));
  assert.equal(result.nativeSessionId, TASK_WAITING);
  assert.equal(result.isError, true);
  assert.equal(result.meta.taskStatus, "waiting");
  assert.equal(result.meta.resumable, true);
  assert.deepEqual(result.meta.waitingAction, {
    taskId: TASK_WAITING, eventId: "evt_waiting", eventType: "apiHighCreditNotice",
  });
  assert.doesNotMatch(JSON.stringify(result.meta.waitingAction), /secret|schema|raw/i);
  assert.doesNotMatch(result.text, new RegExp(TASK_WAITING));
});

test("Manus result polling fails closed on conflicting statuses at one provider timestamp", async () => {
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, fetch: async (url) => {
    return String(url).endsWith("task.create")
      ? json({ ok: true, data: { task_id: TASK_WAITING } })
      : json({ ok: true, task_id: TASK_WAITING, messages: [
        { id: "poll-stopped", type: "status_update", timestamp: 20, status_update: { agent_status: "stopped" } },
        { id: "poll-waiting", type: "status_update", timestamp: 20, status_update: { agent_status: "waiting" } },
        { id: "poll-answer", type: "assistant_message", timestamp: 19, assistant_message: { content: "must not return" } },
      ] });
  } });
  const result = await adapter.execute(request("conflicting result"));
  assert.equal(result.isError, true);
  assert.equal(result.meta.taskStatus, "unknown");
  assert.doesNotMatch(result.text, /must not return/);
});

test("Manus retains a task id after a polling API failure without copying response text", async () => {
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, fetch: async (url) => {
    return String(url).endsWith("task.create")
      ? json({ code: 0, data: { task_id: TASK_API_FAILURE } })
      : json({ code: 500, message: "provider diagnostic that must not be returned" }, 500);
  } });
  const result = await adapter.execute(request("do work"));
  assert.equal(result.nativeSessionId, TASK_API_FAILURE);
  assert.equal(result.meta.taskStatus, "unknown");
  assert.equal(result.meta.resumable, true);
  assert.doesNotMatch(result.text, new RegExp(`provider diagnostic|${TASK_API_FAILURE}`));
});

test("Manus classifies a created-but-unretrievable task as non-resumable", async () => {
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, creationVisibilityGraceMs: 0, fetch: async (url) => {
    return String(url).endsWith("task.create")
      ? json({ ok: true, task_id: TASK_PHANTOM })
      : json({ ok: false, error: { code: "not_found", message: "task not found" } }, 404);
  } });
  const result = await adapter.execute(request("do work"));
  assert.equal(result.nativeSessionId, TASK_PHANTOM);
  assert.equal(result.isError, true);
  assert.equal(result.meta.taskStatus, "not_found");
  assert.equal(result.meta.resumable, false);
  assert.match(result.text, /account provisioning and credits/i);
  assert.doesNotMatch(result.text, new RegExp(TASK_PHANTOM));
});

test("Manus retries an initially invisible asynchronous task before polling succeeds", async () => {
  const calls = [];
  const responses = [
    json({ ok: true, request_id: "req_create_visible", task_id: TASK_VISIBLE }),
    json({ ok: false, request_id: "req_visibility_race", error: { code: "not_found", message: "not visible yet" } }, 404),
    json({ ok: true, request_id: "req_detail_visible", task: { id: TASK_VISIBLE, status: "running" } }),
    json({ ok: true, messages: [
      { type: "status_update", status_update: { agent_status: "stopped" } },
      { type: "assistant_message", assistant_message: { content: "visible answer" } },
    ] }),
  ];
  const adapter = acknowledgedManus({
    apiKey: "test-key",
    pollIntervalMs: 1,
    creationVisibilityGraceMs: 100,
    fetch: async (url) => { calls.push(String(url)); return responses.shift(); },
  });

  const result = await adapter.execute(request("wait for visibility"));
  assert.equal(result.text, "visible answer");
  assert.equal(calls.filter((url) => url.includes("task.listMessages")).length, 2);
  assert.equal(calls.filter((url) => url.includes("task.detail")).length, 1);
  assert.equal(calls.filter((url) => url.endsWith("task.create")).length, 1);
  assert.match(result.meta.providerRequestSha256, /^[a-f0-9]{64}$/);
});

test("Manus preserves private request correlation but exposes only hashes", async () => {
  const adapter = acknowledgedManus({
    apiKey: "test-key",
    creationVisibilityGraceMs: 0,
    fetch: async (url) => String(url).endsWith("task.create")
      ? json({ ok: true, request_id: "req_private_create", task_id: TASK_CORRELATION })
      : json({ ok: false, request_id: String(url).includes("task.detail") ? "req_private_detail" : "req_private_poll", error: { code: "not_found", message: "missing" } }, 404),
  });

  const result = await adapter.execute(request("correlate"));
  assert.equal(result.meta.providerRequestId, undefined);
  assert.equal(result.meta.providerErrorRequestId, undefined);
  assert.match(result.meta.providerRequestSha256, /^[a-f0-9]{64}$/);
  assert.match(result.meta.providerErrorRequestSha256, /^[a-f0-9]{64}$/);
});

test("Manus retains a known id and requests stop when externally aborted", async () => {
  const calls = [];
  const controller = new AbortController();
  const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url, init) => {
    calls.push(String(url));
    if (String(url).endsWith("task.create")) return json({ code: 0, data: { task_id: TASK_ABORTED } });
    if (String(url).endsWith("task.stop")) return json({ code: 0 });
    return await new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
      controller.abort();
    });
  } });
  const result = await adapter.execute(request("stop"), { signal: controller.signal });
  assert.equal(result.nativeSessionId, TASK_ABORTED);
  assert.equal(result.meta.taskStatus, "aborted");
  assert.equal(result.meta.stopRequested, true);
  assert.ok(calls.some((url) => url.endsWith("task.stop")));
});

test("Manus inspects a bounded waiting action and revalidates it before confirming", async () => {
  const calls = [];
  const waiting = { ok: true, messages: [{
    type: "status_update",
    status_update: {
      agent_status: "waiting",
      status_detail: {
        waiting_for_event_id: "evt_123", waiting_for_event_type: "gmailSendAction",
        waiting_description: "Send a draft\nAuthorization: secret-that-must-not-appear",
        confirm_input_schema: { arbitrary: "provider schema must not be reflected" },
      },
    },
  }] };
  const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url, init) => {
    calls.push({ url: String(url), init });
    return String(url).includes("task.confirmAction")
      ? json({ ok: true, task_id: TASK_SAFE, confirmed: true })
      : json(waiting);
  } });

  const action = await adapter.getWaitingAction(TASK_SAFE);
  assert.deepEqual(action, { taskId: TASK_SAFE, eventId: "evt_123", eventType: "gmailSendAction" });
  assert.doesNotMatch(JSON.stringify(action), /secret|schema/i);
  await adapter.confirmAction(TASK_SAFE, "evt_123", { accept: true, save_draft: true });
  assert.equal(calls.length, 3, "inspection plus confirmation revalidation plus POST");
  assert.match(calls[2].url, /\/v2\/task\.confirmAction$/);
  assert.deepEqual(JSON.parse(calls[2].init.body), {
    task_id: TASK_SAFE, event_id: "evt_123", input: { accept: true, save_draft: true },
  });
});

test("Manus refuses an older waiting event when the newest task status is not waiting", async () => {
  let posts = 0;
  const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url) => {
    if (String(url).includes("confirmAction")) posts++;
    return json({ ok: true, messages: [
      { type: "status_update", status_update: { agent_status: "stopped" } },
      { type: "status_update", status_update: { agent_status: "waiting", status_detail: {
        waiting_for_event_id: "evt_old", waiting_for_event_type: "needConnectMyBrowser",
      } } },
    ] });
  } });
  await assert.rejects(adapter.getWaitingAction(TASK_SAFE), (error) => error?.code === "waiting_action_missing");
  assert.equal(posts, 0);
});

test("Manus confirmation rejects stale, secret, message, unknown, and widening inputs before POST", async () => {
  const cases = [
    { eventType: "messageAskUser", code: /waiting_message_required/ },
    { eventType: "webdevRequestSecrets", code: /waiting_secrets_denied/ },
    { eventType: "deployAction", code: /waiting_action_unsupported/ },
  ];
  for (const { eventType, code } of cases) {
    let posts = 0;
    const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url) => {
      if (String(url).includes("confirmAction")) posts++;
      return json({ ok: true, messages: [{ type: "status_update", status_update: { agent_status: "waiting", status_detail: {
        waiting_for_event_id: "evt_safe", waiting_for_event_type: eventType, waiting_description: "safe",
      } } }] });
    } });
    await assert.rejects(adapter.getWaitingAction(TASK_SAFE), (error) => error?.code && code.test(error.code));
    assert.equal(posts, 0);
  }

  let posts = 0;
  const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url) => {
    if (String(url).includes("confirmAction")) posts++;
    return json({ ok: true, messages: [{ type: "status_update", status_update: { agent_status: "waiting", status_detail: {
      waiting_for_event_id: "evt_current", waiting_for_event_type: "needConnectMyBrowser",
    } } }] });
  } });
  await assert.rejects(adapter.confirmAction(TASK_SAFE, "evt_stale", { action: "skip" }), (error) => error?.code === "waiting_action_stale");
  await assert.rejects(adapter.confirmAction(TASK_SAFE, "evt_current", { action: "select", client_id: "browser" }), (error) => error?.code === "confirmation_input_denied");
  assert.equal(posts, 0);
});

test("Manus confirmation requires a fully accepted matching provider response", async () => {
  for (const response of [
    { ok: true, task_id: TASK_OTHER, confirmed: true },
    { ok: true, task_id: TASK_SAFE, confirmed: false },
    { ok: false, error: { code: "denied", message: "raw provider detail" } },
  ]) {
    const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url) => String(url).includes("confirmAction")
      ? json(response)
      : json({ ok: true, messages: [{ type: "status_update", status_update: { agent_status: "waiting", status_detail: {
        waiting_for_event_id: "evt_current", waiting_for_event_type: "apiHighCreditNotice",
      } } }] }),
    });
    await assert.rejects(adapter.confirmAction(TASK_SAFE, "evt_current", { action: "reject" }), (error) => {
      assert.doesNotMatch(error?.message ?? "", /raw provider detail/i);
      return error?.code === "confirmation_unaccepted" || error?.code === "denied";
    });
  }
});

test("Manus keeps task and event identifiers on separate provider contracts", async () => {
  assert.equal(isValidManusTaskId(TASK_CREATED), true);
  for (const value of ["A".repeat(21), "A".repeat(23), "A".repeat(21) + "_", "A".repeat(21) + "-", "https://example.invalid", "A".repeat(21) + "\n"]) {
    assert.equal(isValidManusTaskId(value), false, value);
  }
  assert.equal(isValidManusEventId("evt_with_underscores"), true);

  let calls = 0;
  const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async () => { calls++; return json({ ok: true }); } });
  await assert.rejects(adapter.getWaitingAction("invalid_task"), (error) => error?.code === "invalid_task_id");
  await assert.rejects(adapter.execute(request("invalid resume", { resumeSessionId: "invalid_task" })), (error) => error?.code === "invalid_task_id");
  assert.equal(calls, 0, "invalid task ids must fail before HTTP");
});

test("Manus retries when both message and detail visibility are initially delayed", async () => {
  const calls = [];
  let messageCalls = 0;
  const adapter = acknowledgedManus({
    apiKey: "test-key",
    pollIntervalMs: 1,
    creationVisibilityGraceMs: 100,
    fetch: async (url) => {
      const target = String(url);
      calls.push(target);
      if (target.endsWith("task.create")) return json({ ok: true, task_id: TASK_VISIBLE });
      if (target.includes("task.detail")) return json({ ok: false, error: { code: "not_found", message: "not visible" } }, 404);
      messageCalls++;
      return messageCalls === 1
        ? json({ ok: false, error: { code: "not_found", message: "not visible" } }, 404)
        : json({ ok: true, task_id: TASK_VISIBLE, messages: [
          { type: "status_update", status_update: { agent_status: "stopped" } },
          { type: "assistant_message", assistant_message: { content: "eventually visible" } },
        ] });
    },
  });

  const result = await adapter.execute(request("wait safely"));
  assert.equal(result.text, "eventually visible");
  assert.equal(calls.filter((url) => url.endsWith("task.create")).length, 1);
  assert.equal(calls.filter((url) => url.includes("task.detail")).length, 1);
});

test("Manus keeps a detail-confirmed task resumable when messages remain invisible", async () => {
  const calls = [];
  const adapter = acknowledgedManus({
    apiKey: "test-key",
    creationVisibilityGraceMs: 0,
    fetch: async (url) => {
      const target = String(url);
      calls.push(target);
      if (target.endsWith("task.create")) return json({ ok: true, task_id: TASK_VISIBLE });
      if (target.includes("task.detail")) return json({ ok: true, request_id: "req_detail", task: { id: TASK_VISIBLE, status: "running" } });
      return json({ ok: false, request_id: "req_messages", error: { code: "not_found", message: "messages unavailable" } }, 404);
    },
  });

  const result = await adapter.execute(request("do not duplicate"));
  assert.equal(result.meta.taskStatus, "unknown");
  assert.equal(result.meta.resumable, true);
  assert.equal(result.meta.providerErrorRequestId, undefined);
  assert.match(result.meta.providerErrorRequestSha256, /^[a-f0-9]{64}$/);
  assert.equal(calls.filter((url) => url.endsWith("task.create")).length, 1);
  assert.equal(calls.filter((url) => url.includes("task.detail")).length, 1);
});

test("Manus rejects mismatched task identities from messages and detail", async () => {
  const messageMismatch = acknowledgedManus({ apiKey: "test-key", fetch: async (url) => String(url).endsWith("task.create")
    ? json({ ok: true, task_id: TASK_CREATED })
    : json({ ok: true, task_id: TASK_OTHER, messages: [] }) });
  const messageResult = await messageMismatch.execute(request("check messages"));
  assert.equal(messageResult.meta.taskStatus, "unknown");
  assert.equal(messageResult.meta.resumable, true);

  const detailMismatch = acknowledgedManus({ apiKey: "test-key", creationVisibilityGraceMs: 100, fetch: async (url) => {
    const target = String(url);
    if (target.endsWith("task.create")) return json({ ok: true, task_id: TASK_CREATED });
    if (target.includes("task.detail")) return json({ ok: true, task: { id: TASK_OTHER, status: "running" } });
    return json({ ok: false, error: { code: "not_found", message: "not visible" } }, 404);
  } });
  const detailResult = await detailMismatch.execute(request("check detail"));
  assert.equal(detailResult.meta.taskStatus, "unknown");
  assert.equal(detailResult.meta.resumable, true);
});

test("Manus resume probes detail after an acknowledged send when messages become invisible", async () => {
  const calls = [];
  const adapter = acknowledgedManus({ apiKey: "test-key", creationVisibilityGraceMs: 0, fetch: async (url) => {
    const target = String(url);
    calls.push(target);
    if (calls.length === 1) return json({ ok: true, task_id: TASK_EXISTING, messages: [
      { id: "resume-baseline", type: "status_update", timestamp: 1, status_update: { agent_status: "stopped" } },
    ] });
    if (target.endsWith("task.sendMessage")) return json({ ok: true, task_id: TASK_EXISTING });
    if (target.includes("task.detail")) return json({ ok: true, task: { id: TASK_EXISTING, status: "running" } });
    return json({ ok: false, request_id: "resume_messages_missing", error: { code: "not_found", message: "missing" } }, 404);
  } });
  const result = await adapter.execute(request("continue", { resumeSessionId: TASK_EXISTING }));
  assert.equal(result.meta.taskStatus, "unknown");
  assert.equal(result.meta.resumable, true);
  assert.equal(calls.some((url) => url.includes("task.detail")), true);
});

test("Manus resume baseline failure sends nothing, stops nothing, and is not recorded as an acknowledged turn", async () => {
  const calls = [];
  const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url) => {
    calls.push(String(url));
    return json({ ok: false, request_id: "baseline_missing", error: { code: "not_found", message: "missing" } }, 404);
  } });
  await assert.rejects(adapter.execute(request("must not send", { resumeSessionId: TASK_EXISTING })), (error) => {
    assert.ok(error instanceof ManusApiError);
    assert.equal(error.status, 404);
    return true;
  });
  assert.equal(calls.length, 1);
  assert.match(calls[0], /task\.listMessages/);
  assert.equal(calls.some((url) => url.endsWith("task.sendMessage") || url.endsWith("task.stop")), false);
});

test("Manus resume never returns stale stopped output before the new user-message anchor", async () => {
  let listCount = 0;
  const baseline = { id: "old-stop", type: "status_update", timestamp: 10, status_update: { agent_status: "stopped" } };
  const oldAnswer = { id: "old-answer", type: "assistant_message", timestamp: 9, assistant_message: { content: "stale answer" } };
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, fetch: async (url) => {
    const target = String(url);
    if (target.endsWith("task.sendMessage")) return json({ ok: true, task_id: TASK_EXISTING });
    listCount++;
    if (listCount <= 2) return json({ ok: true, task_id: TASK_EXISTING, messages: [baseline, oldAnswer] });
    return json({ ok: true, task_id: TASK_EXISTING, messages: [
      { id: "new-stop", type: "status_update", timestamp: 40, status_update: { agent_status: "stopped" } },
      { id: "new-answer", type: "assistant_message", timestamp: 30, assistant_message: { content: "fresh answer" } },
      { id: "new-user", type: "user_message", timestamp: 20, user_message: { content: "continue" } },
      baseline,
      oldAnswer,
    ] });
  } });
  const result = await adapter.execute(request("continue", { resumeSessionId: TASK_EXISTING }));
  assert.equal(result.text, "fresh answer");
  assert.equal(listCount, 3);
});

test("Manus resume follows pagination until it finds the exact opaque baseline id", async () => {
  let postSendPage = 0;
  const baseline = { id: "opaque-baseline", type: "status_update", timestamp: 10, status_update: { agent_status: "stopped" } };
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, fetch: async (url) => {
    const target = String(url);
    if (target.endsWith("task.sendMessage")) return json({ ok: true, task_id: TASK_EXISTING });
    if (!target.includes("cursor=")) {
      postSendPage++;
      if (postSendPage === 1) return json({ ok: true, task_id: TASK_EXISTING, messages: [baseline] });
      return json({ ok: true, task_id: TASK_EXISTING, has_more: true, next_cursor: "older-page", messages: [
        { id: "page-new-stop", type: "status_update", timestamp: 40, status_update: { agent_status: "stopped" } },
        { id: "page-new-answer", type: "assistant_message", timestamp: 30, assistant_message: { content: "paged fresh answer" } },
        { id: "page-new-user", type: "user_message", timestamp: 20, user_message: { content: "continue paged" } },
      ] });
    }
    assert.match(target, /cursor=older-page/);
    return json({ ok: true, task_id: TASK_EXISTING, has_more: false, messages: [baseline] });
  } });
  const result = await adapter.execute(request("continue paged", { resumeSessionId: TASK_EXISTING }));
  assert.equal(result.text, "paged fresh answer");
});

test("Manus resume snapshots the complete equal-timestamp frontier", async () => {
  let listCount = 0;
  const oldStop = { id: "same-old-stop", type: "status_update", timestamp: 10, status_update: { agent_status: "stopped" } };
  const oldAnswer = { id: "same-old-answer", type: "assistant_message", timestamp: 10, assistant_message: { content: "old" } };
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, fetch: async (url) => {
    if (String(url).endsWith("task.sendMessage")) return json({ ok: true, task_id: TASK_EXISTING });
    listCount++;
    if (listCount === 1) return json({ ok: true, task_id: TASK_EXISTING, messages: [oldStop, oldAnswer] });
    return json({ ok: true, task_id: TASK_EXISTING, messages: [
      oldAnswer,
      { id: "same-new-answer", type: "assistant_message", timestamp: 10, assistant_message: { content: "new at same timestamp" } },
      oldStop,
      { id: "same-new-user", type: "user_message", timestamp: 10, user_message: { content: "same frontier" } },
      { id: "same-new-stop", type: "status_update", timestamp: 10, status_update: { agent_status: "stopped" } },
    ] });
  } });
  const result = await adapter.execute(request("same frontier", { resumeSessionId: TASK_EXISTING }));
  assert.equal(result.text, "new at same timestamp");
});

test("Manus resume rejects conflicting statuses at one provider timestamp", async () => {
  let calls = 0;
  const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async () => {
    calls++;
    return json({ ok: true, task_id: TASK_EXISTING, messages: [
      { id: "tied-stopped", type: "status_update", timestamp: 10, status_update: { agent_status: "stopped" } },
      { id: "tied-waiting", type: "status_update", timestamp: 10, status_update: { agent_status: "waiting" } },
    ] });
  } });
  await assert.rejects(adapter.execute(request("must not send", { resumeSessionId: TASK_EXISTING })), /status is missing or ambiguous/i);
  assert.equal(calls, 1);
});

test("Manus resume fails closed on a concurrent user message after the baseline", async () => {
  let listCount = 0;
  const baseline = { id: "concurrent-baseline", type: "status_update", timestamp: 10, status_update: { agent_status: "stopped" } };
  const adapter = acknowledgedManus({ apiKey: "test-key", pollIntervalMs: 0, fetch: async (url) => {
    if (String(url).endsWith("task.sendMessage")) return json({ ok: true, task_id: TASK_EXISTING });
    listCount++;
    if (listCount === 1) return json({ ok: true, task_id: TASK_EXISTING, messages: [baseline] });
    return json({ ok: true, task_id: TASK_EXISTING, messages: [
      { id: "concurrent-stop", type: "status_update", timestamp: 40, status_update: { agent_status: "stopped" } },
      { id: "concurrent-answer", type: "assistant_message", timestamp: 35, assistant_message: { content: "must not return" } },
      { id: "concurrent-other-user", type: "user_message", timestamp: 30, user_message: { content: "out-of-band message" } },
      { id: "concurrent-our-user", type: "user_message", timestamp: 20, user_message: { content: "our prompt" } },
      baseline,
    ] });
  } });
  const result = await adapter.execute(request("our prompt", { resumeSessionId: TASK_EXISTING }));
  assert.equal(result.isError, true);
  assert.equal(result.meta.taskStatus, "unknown");
  assert.equal(result.meta.resumable, true);
  assert.doesNotMatch(result.text, /must not return/);
});

test("Manus omits malicious or overlong provider request ids", async () => {
  for (const requestId of ["request id with spaces", "R".repeat(201), "request\r\ninjected"]) {
    const adapter = acknowledgedManus({ apiKey: "test-key", fetch: async (url) => String(url).endsWith("task.create")
      ? json({ ok: true, request_id: requestId, task_id: TASK_CREATED })
      : json({ ok: true, messages: [
        { type: "status_update", status_update: { agent_status: "stopped" } },
        { type: "assistant_message", assistant_message: { content: "safe" } },
      ] }) });
    const result = await adapter.execute(request("correlate safely"));
    assert.equal(result.meta.providerRequestId, undefined);
    assert.equal(result.meta.providerRequestSha256, undefined);
  }
});
