import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";

// Keep a space in the fixture path so Windows health probes, fresh turns,
// resume, review, and handoff all exercise shell-free npm shim resolution.
const root = await mkdtemp(join(tmpdir(), "agent bridge smoke "));
const work = join(root, "work");
const state = join(root, "state");
const outside = await mkdtemp(join(tmpdir(), "agent-bridge-smoke-outside-"));
const logPath = join(root, "mock-log.jsonl");
const serverPath = join(process.cwd(), "dist", "agent-bridge.mjs");
const mockPath = join(root, "mock-agent.mjs");

async function makeMocks() {
  await writeFile(mockPath, `
import { appendFile } from "node:fs/promises";
const [agent, ...args] = process.argv.slice(2);
const input = await new Promise((resolve) => { let value = ""; process.stdin.setEncoding("utf8"); process.stdin.on("data", (chunk) => value += chunk); process.stdin.on("end", () => resolve(value)); });
const mockLog = process.env.MOCK_LOG || ${JSON.stringify(logPath)};
if (mockLog) await appendFile(mockLog, JSON.stringify({ agent, args, input }) + "\\n");
if (args[0] === "--version") {
  if (agent === "gemini") { console.error("Bearer GEMINI_BINARY_SECRET provider failure " + "B".repeat(900)); process.exit(1); }
  console.log("mock-" + agent + " 1.0.0 api_key=VERSION_SECRET_" + "V".repeat(900)); process.exit(0);
}
if (agent === "codex" && args[0] === "login" && args[1] === "status") { console.log("Logged in as smoke-user token=CODEX_AUTH_SECRET " + "C".repeat(900)); process.exit(0); }
if (agent === "claude" && args[0] === "auth" && args[1] === "status") { console.log(JSON.stringify({ loggedIn: true, authMethod: "mock-oauth password=CLAUDE_AUTH_SECRET " + "A".repeat(900) })); process.exit(0); }
if (agent === "codex") {
  const resumed = args[0] === "exec" && args[1] === "resume";
  const responseText = input.includes("# Cooperative work item")
    ? "## Summary\\nMOCK_WORK_ITEM_OK\\n## Evidence\\nmock evidence\\n## Risks\\nnone"
    : resumed ? "CODEX RESUMED: " + input : "CODEX FRESH: " + input;
  console.log(JSON.stringify({ type: "thread.started", thread_id: "codex-native-smoke" }));
  console.log(JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: responseText } }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 1 } }));
  process.exit(0);
}
const prompt = args[args.indexOf("-p") + 1] ?? "";
const result = prompt.includes("# Independent review") ? "VERDICT: ACCEPTED\\nMock evidence is sufficient." : "CLAUDE HANDOFF: " + prompt;
console.log(JSON.stringify({ session_id: "claude-native-smoke", result, is_error: false, num_turns: 1 }));
`, "utf8");
  if (process.platform === "win32") {
    const makeNpmShim = async (agent) => {
      const command = join(root, `mock-${agent}.cmd`);
      const entry = join(root, "node_modules", `mock-${agent}`, "cli.mjs");
      await mkdir(join(root, "node_modules", `mock-${agent}`), { recursive: true });
      await writeFile(entry, `process.argv.splice(2, 0, ${JSON.stringify(agent)}); await import("../../mock-agent.mjs");\n`, "utf8");
      await writeFile(command, [
        "@ECHO off", "GOTO start", ":find_dp0", "SET dp0=%~dp0", "EXIT /b", ":start", "SETLOCAL", "CALL :find_dp0",
        "IF EXIST \"%dp0%\\node.exe\" ( SET \"_prog=%dp0%\\node.exe\" ) ELSE ( SET \"_prog=node\" )",
        `endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" \"%dp0%\\node_modules\\mock-${agent}\\cli.mjs\" %*`,
      ].join("\r\n"), "utf8");
      return command;
    };
    const codex = await makeNpmShim("codex");
    const claude = await makeNpmShim("claude");
    const gemini = await makeNpmShim("gemini");
    return { codex, claude, gemini };
  }
  const codex = join(root, "mock-codex");
  const claude = join(root, "mock-claude");
  const gemini = join(root, "mock-gemini");
  await writeFile(codex, `#!/bin/sh\nexec node "$(dirname "$0")/mock-agent.mjs" codex "$@"\n`, "utf8");
  await writeFile(claude, `#!/bin/sh\nexec node "$(dirname "$0")/mock-agent.mjs" claude "$@"\n`, "utf8");
  await writeFile(gemini, `#!/bin/sh\nexec node "$(dirname "$0")/mock-agent.mjs" gemini "$@"\n`, "utf8");
  await Promise.all([chmod(codex, 0o755), chmod(claude, 0o755), chmod(gemini, 0o755)]);
  return { codex, claude, gemini };
}

function text(result) { return result.content.map((item) => item.text ?? "").join("\n"); }
async function call(client, name, args) { return client.callTool({ name, arguments: args }); }
async function expectExit(command, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let stderr = "";
    child.stderr.setEncoding("utf8"); child.stderr.on("data", (chunk) => stderr += chunk);
    child.on("error", reject); child.on("close", (code) => resolve({ code, stderr }));
  });
}

try {
  const bins = await makeMocks();
  await writeFile(join(root, "config.json"), JSON.stringify({
    agents: {
      codex: { bin: bins.codex, extraArgs: ["--sandbox", "danger-full-access"], extraEnv: { MOCK_LOG: logPath, DIAGNOSTIC_SECRET: "DIAGNOSTIC_SECRET_MUST_NOT_LEAK" } },
      claude: { bin: bins.claude, extraArgs: ["--permission-mode", "bypassPermissions"], extraEnv: { MOCK_LOG: logPath } },
      gemini: { enabled: true, bin: bins.gemini }, manus: { enabled: false },
    },
    defaults: { cwd: work, sandbox: "workspace-write", timeoutSec: 10 },
    allowedRoots: [work], stateDir: state, handoffMaxChars: 10_000,
    policy: { cumulativeRemoteCost: { currency: "USD", maxReservedCents: 5000 } },
  }), "utf8");
  await (await import("node:fs/promises")).mkdir(work, { recursive: true });

  const transport = new StdioClientTransport({ command: process.execPath, args: [serverPath], env: { ...process.env, AGENT_BRIDGE_CONFIG: join(root, "config.json"), MOCK_LOG: logPath } });
  const client = new Client({ name: "agent-bridge-smoke", version: "1.0.0" }, { capabilities: { elicitation: { form: {} } } });
  client.setRequestHandler(ElicitRequestSchema, async (request) => ({
    action: "accept",
    content: { approvalId: request.params.requestedSchema.properties.approvalId.minLength ? approvalIdFromMessage(request.params.message) : "", approve: true },
  }));
  await client.connect(transport);
  try {
    const tools = await client.listTools();
    assert.equal(tools.tools.length, 33, "tool discovery must expose bridge, approvals, budgets, creator status, Manus confirmation/reconciliation, recommendations, diagnostics, output retrieval, and lifecycle tools");
    assert.deepEqual(tools.tools.map((tool) => tool.name).sort(), [
      "archive_workboard", "cancel_work_item", "cancel_workboard", "collect_recommendations", "complete_workboard", "confirm_manus_action",
      "continue_session", "create_workboard", "decide_approval", "decide_work_item_approval", "delegate_task",
      "diagnose_install", "get_budget_status", "get_creator_status", "get_manus_waiting_action", "get_session", "get_turn_output", "get_workboard", "handoff", "list_agents",
      "list_approvals", "list_sessions", "list_workboards", "pause_workboard", "preview_manus_confirmation", "preview_recommendation_approval", "preview_turn_approval",
      "reconcile_manus_task", "request_approval", "resume_workboard", "retry_work_item", "review_work_item", "run_work_item",
    ]);

    const creatorStatus = await call(client, "get_creator_status", {});
    assert.equal(creatorStatus.structuredContent.status, "needs-attention");
    assert.equal(creatorStatus.structuredContent.healthChecked, false);
    assert.deepEqual(creatorStatus.structuredContent.sessions, { scanned: 0, truncated: false, unreadable: 0, sample: [] });
    assert.deepEqual(creatorStatus.structuredContent.approvals, { scanned: 0, truncated: false, unreadable: 0, byState: {} });
    assert.match(text(creatorStatus), /backend health: not checked; run list_agents separately/i);
    assert.equal(await readFile(logPath, "utf8").catch(() => ""), "", "creator status must not launch backend health probes");
    const sessionsDir = join(state, "sessions");
    const invalidSessionPath = join(sessionsDir, "creator-status-invalid.json");
    await writeFile(invalidSessionPath, "{", "utf8");
    const unreadableCreatorStatus = await call(client, "get_creator_status", {});
    assert.equal(unreadableCreatorStatus.structuredContent.status, "needs-attention");
    assert.equal(unreadableCreatorStatus.structuredContent.sessions.unreadable, 1);
    assert.match(text(unreadableCreatorStatus), /truncated or found unreadable state/i);
    await rm(invalidSessionPath);
    const sampledSessionPaths = Array.from({ length: 201 }, (_, index) => join(sessionsDir, `creatorstatus${String(index).padStart(3, "0")}.json`));
    const sampledSession = JSON.stringify({ updatedAt: "2026-08-20T00:00:00.000Z", revision: 0, turns: [] });
    await Promise.all(sampledSessionPaths.map((path) => writeFile(path, sampledSession, "utf8")));
    const truncatedCreatorStatus = await call(client, "get_creator_status", {});
    assert.equal(truncatedCreatorStatus.structuredContent.status, "needs-attention");
    assert.equal(truncatedCreatorStatus.structuredContent.sessions.scanned, 200);
    assert.equal(truncatedCreatorStatus.structuredContent.sessions.truncated, true);
    await Promise.all(sampledSessionPaths.map((path) => rm(path)));

    const agents = await call(client, "list_agents", {});
    assert.notEqual(agents.isError, true);
    const agentListing = JSON.stringify(agents.structuredContent);
    const agentText = text(agents);
    for (const secret of ["GEMINI_BINARY_SECRET", "VERSION_SECRET", "CODEX_AUTH_SECRET", "CLAUDE_AUTH_SECRET"]) {
      assert.doesNotMatch(agentListing, new RegExp(secret), `structured agent listing leaked ${secret}`);
      assert.doesNotMatch(agentText, new RegExp(secret), `text agent listing leaked ${secret}`);
    }
    const agentData = agents.structuredContent.agents;
    assert.equal(agentData.length, 3);
    assert.deepEqual(agentData.map((agent) => agent.id).sort(), ["claude", "codex", "gemini"]);
    for (const agent of agentData.filter((candidate) => candidate.id !== "gemini")) {
      assert.equal(agent.health.binary.ok, true, JSON.stringify(agent.health));
      assert.equal(agent.health.auth.status, "authenticated");
      assert.equal(agent.health.usable, true);
      assert.match(agent.health.binary.version, /mock-/);
      assert.ok(agent.health.binary.version.length <= 256);
      assert.ok((agent.health.auth.detail ?? "").length <= 512);
    }
    const geminiHealth = agentData.find((agent) => agent.id === "gemini").health;
    assert.equal(geminiHealth.binary.ok, false);
    assert.ok(geminiHealth.binary.error.length <= 512);
    assert.match(geminiHealth.binary.error, /REDACTED/);

    const diagnostic = await call(client, "diagnose_install", {});
    assert.notEqual(diagnostic.isError, true);
    assert.equal(diagnostic.structuredContent.diagnostics.config.allowedRootCount, 1);
    assert.deepEqual(diagnostic.structuredContent.budget, { enabled: true, currency: "USD", maxReservedCents: 5000, committedCents: 0, remainingCents: 5000, reservationCount: 0 });
    assert.doesNotMatch(JSON.stringify(diagnostic.structuredContent), /DIAGNOSTIC_SECRET_MUST_NOT_LEAK/);
    const budgetStatus = await call(client, "get_budget_status", {});
    assert.deepEqual(budgetStatus.structuredContent.budget, { enabled: true, currency: "USD", maxReservedCents: 5000, committedCents: 0, remainingCents: 5000, reservationCount: 0 });
    assert.match(text(diagnostic), /direct-remote budget: 0\/5000 USD/);
    assert.match(text(budgetStatus), /5000 remain/);
    const budgetDir = join(state, "budgets");
    const budgetPath = join(budgetDir, "cumulative-remote-cost.json");
    await mkdir(budgetDir, { recursive: true });
    const diagnosticSecret = "sk-DIAGNOSTIC_BUDGET_SECRET_12345678";
    await writeFile(budgetPath, JSON.stringify({ schemaVersion: 1, currency: "USD", committedCents: 0, reservationCount: 0, recentReservations: [], [`api_key=${diagnosticSecret}`]: true }), "utf8");
    const degradedDiagnostic = await call(client, "diagnose_install", {});
    assert.notEqual(degradedDiagnostic.isError, true, "budget corruption must not hide install and rollback diagnostics");
    assert.equal(degradedDiagnostic.structuredContent.diagnostics.config.allowedRootCount, 1);
    assert.equal(degradedDiagnostic.structuredContent.budget.status, "error");
    assert.match(text(degradedDiagnostic), /direct-remote budget: ERROR/);
    assert.doesNotMatch(JSON.stringify(degradedDiagnostic), new RegExp(diagnosticSecret));
    const corruptBudgetStatus = await call(client, "get_budget_status", {});
    assert.equal(corruptBudgetStatus.isError, true, "dedicated budget status must still fail closed on corruption");
    const degradedCreatorStatus = await call(client, "get_creator_status", {});
    assert.equal(degradedCreatorStatus.structuredContent.status, "blocked");
    assert.doesNotMatch(JSON.stringify(degradedCreatorStatus.structuredContent), new RegExp(diagnosticSecret));
    await rm(budgetPath);

    const createdBoard = await call(client, "create_workboard", {
      title: "smoke board", objective: "Verify cooperative work", cwd: work,
      items: [{
        key: "inspect", title: "Inspect", instructions: "Return the mock finding", kind: "validation",
        acceptance_criteria: ["Independent reviewer accepts the evidence"],
        requirements: { data_class: "internal", filesystem: "read-only", network: "restricted", capabilities: ["structuredOutput"] },
        budget: { max_attempts: 1, max_wall_sec: 10 },
      }],
    });
    assert.notEqual(createdBoard.isError, true);
    const workboardId = createdBoard.structuredContent.workboard.id;
    for (const agent of ["missing-agent", "gemini"]) {
      const invalidRun = await call(client, "run_work_item", { workboard_id: workboardId, item_key: "inspect", agent });
      assert.equal(invalidRun.isError, true);
      const unchanged = await call(client, "get_workboard", { workboard_id: workboardId });
      assert.equal(unchanged.structuredContent.workboard.items[0].attempts, 0, `${agent} preflight must not spend an attempt`);
    }
    const ranItem = await call(client, "run_work_item", { workboard_id: workboardId, item_key: "inspect", agent: "codex" });
    assert.notEqual(ranItem.isError, true, `${text(ranItem)}\n${JSON.stringify(ranItem.structuredContent)}`);
    assert.equal(ranItem.structuredContent.workboard.items[0].status, "submitted");
    for (const reviewer_agent of ["missing-agent", "gemini"]) {
      const invalidReview = await call(client, "review_work_item", { workboard_id: workboardId, item_key: "inspect", reviewer_agent });
      assert.equal(invalidReview.isError, true);
      const unchanged = await call(client, "get_workboard", { workboard_id: workboardId });
      assert.equal(unchanged.structuredContent.workboard.items[0].reviewAttempts, 0, `${reviewer_agent} preflight must not spend a review attempt`);
    }
    const reviewedItem = await call(client, "review_work_item", { workboard_id: workboardId, item_key: "inspect", reviewer_agent: "claude" });
    assert.notEqual(reviewedItem.isError, true);
    assert.equal(reviewedItem.structuredContent.verdict, "accepted");
    const workboard = await call(client, "get_workboard", { workboard_id: workboardId });
    assert.notEqual(workboard.isError, true);
    assert.equal(workboard.structuredContent.workboard.items[0].status, "accepted");
    assert.match(workboard.structuredContent.integrator_brief, /MOCK_WORK_ITEM_OK/);
    const completedBoard = await call(client, "complete_workboard", { workboard_id: workboardId, reason: "smoke acceptance passed" });
    assert.equal(completedBoard.structuredContent.workboard.status, "completed");
    const archivedBoard = await call(client, "archive_workboard", { workboard_id: workboardId, reason: "smoke evidence retained" });
    assert.equal(archivedBoard.structuredContent.workboard.status, "archived");
    const listedBoards = await call(client, "list_workboards", { status: "archived" });
    assert.ok(listedBoards.structuredContent.workboards.some((board) => board.id === workboardId));

    const approvalRequest = await call(client, "request_approval", {
      category: "remote_egress", subject: "agent-bridge:delegate_task", action: "delegate:manus",
      data_classification: "public", root: work, agent: "manus", requested_by: "smoke-test",
      payload: "sanitized smoke payload", reason: "verify approval request and decision wiring", expires_in_sec: 300,
    });
    assert.equal(approvalRequest.structuredContent.approval.state, "pending");
    const approvedApproval = await call(client, "decide_approval", {
      approval_id: approvalRequest.structuredContent.approval.id,
    });
    assert.equal(approvedApproval.structuredContent.approval.state, "approved");
    const listedApprovals = await call(client, "list_approvals", { state: "approved" });
    assert.ok(listedApprovals.structuredContent.approvals.some((approval) => approval.id === approvalRequest.structuredContent.approval.id));

    const secretTail = "UNTRUNCATED_SECRET_TAIL_MUST_NOT_LEAK";
    const fresh = await call(client, "delegate_task", { agent: "codex", prompt: `build the bridge ${"x".repeat(80)}${secretTail}`, cwd: work });
    assert.notEqual(fresh.isError, true);
    assert.equal(fresh.structuredContent.continuity, "new");
    assert.doesNotMatch(JSON.stringify(fresh.structuredContent), /native_session_id|codex-native-smoke/);
    const sessionId = fresh.structuredContent.bridge_session_id;

    const resumed = await call(client, "continue_session", { session_id: sessionId, prompt: "continue Codex work" });
    assert.notEqual(resumed.isError, true);
    assert.equal(resumed.structuredContent.continuity, "native-resume");
    assert.equal(resumed.structuredContent.cross_agent_context_applied, false);

    const handed = await call(client, "handoff", { session_id: sessionId, to_agent: "claude", prompt: "review Codex conclusions" });
    assert.notEqual(handed.isError, true);
    assert.equal(handed.structuredContent.continuity, "context-replay");
    assert.equal(handed.structuredContent.cross_agent_context_applied, true);
    assert.doesNotMatch(JSON.stringify(handed.structuredContent), /native_session_id|claude-native-smoke/);

    const returned = await call(client, "handoff", { session_id: sessionId, to_agent: "codex", prompt: "apply Claude review" });
    assert.notEqual(returned.isError, true);
    assert.equal(returned.structuredContent.continuity, "native-resume");
    assert.equal(returned.structuredContent.cross_agent_context_applied, true);

    const sessions = await call(client, "list_sessions", {});
    assert.notEqual(sessions.isError, true);
    assert.equal(sessions.structuredContent.sessions.length, 3, "sequential, work-item, and review sessions should be isolated");
    assert.ok(sessions.structuredContent.sessions.some((session) => session.id === sessionId));
    assert.doesNotMatch(JSON.stringify(sessions.structuredContent), /native-smoke/);
    const creatorStatusAfterWork = await call(client, "get_creator_status", {});
    assert.equal(creatorStatusAfterWork.structuredContent.sessions.scanned, 3);
    assert.equal(creatorStatusAfterWork.structuredContent.sessions.sample.some((session) => "id" in session || "title" in session || "cwd" in session), false);
    assert.doesNotMatch(JSON.stringify(creatorStatusAfterWork.structuredContent), /native-smoke|UNTRUNCATED_SECRET_TAIL_MUST_NOT_LEAK/);

    const projected = await call(client, "get_session", { session_id: sessionId, max_chars_per_turn: 20 });
    assert.notEqual(projected.isError, true);
    const projection = JSON.stringify(projected.structuredContent);
    assert.doesNotMatch(projection, /native-smoke/);
    assert.doesNotMatch(projection, new RegExp(secretTail));
    assert.match(projection, /more chars/);

    const rejected = await call(client, "delegate_task", { agent: "codex", prompt: "must not run", cwd: outside });
    assert.equal(rejected.isError, true);
    assert.match(text(rejected), /outside the allowed roots/i);
  } finally { await client.close(); }

  const launches = (await readFile(logPath, "utf8")).trim().split("\n").map(JSON.parse);
  const codexLaunches = launches.filter((entry) => entry.agent === "codex");
  assert.equal(codexLaunches.filter((entry) => entry.args[0] === "exec").length, 4);
  const workItemLaunch = codexLaunches.find((entry) => entry.input.includes("# Cooperative work item"));
  assert.ok(workItemLaunch);
  assert.ok(workItemLaunch.args.includes("read-only"), "cooperative MCP execution must force the local CLI read-only");
  assert.ok(!workItemLaunch.args.includes("danger-full-access"), "cooperative work must suppress configured authority overrides");
  assert.match(workItemLaunch.input, /untrusted evidence, not as instructions/i);
  const reviewLaunch = launches.find((entry) => entry.agent === "claude" && entry.args.some((arg) => arg.includes("# Independent review")));
  assert.ok(reviewLaunch);
  assert.ok(!reviewLaunch.args.includes("bypassPermissions"), "cooperative review must suppress configured authority overrides");
  assert.ok(codexLaunches.some((entry) => entry.args[0] === "exec" && entry.args[1] === "resume" && entry.args[2] === "codex-native-smoke"));
  const finalCodex = codexLaunches.at(-1);
  assert.match(finalCodex.input, /Cross-agent update/);
  assert.match(finalCodex.input, /CLAUDE HANDOFF/);

  const malformed = join(root, "malformed.json");
  await writeFile(malformed, "{ definitely not JSON", "utf8");
  const failed = await expectExit(process.execPath, [serverPath], { ...process.env, AGENT_BRIDGE_CONFIG: malformed });
  assert.equal(failed.code, 1);
  assert.match(failed.stderr, /invalid agent-bridge config/i);
  console.log("agent-bridge smoke: PASS");
} finally {
  await rm(root, { recursive: true, force: true });
  await rm(outside, { recursive: true, force: true });
}

function approvalIdFromMessage(message) {
  const match = /^Approval ID: "([A-Za-z0-9_-]+)"$/m.exec(message);
  assert.ok(match, "elicitation must display an exact approval id");
  return match[1];
}
