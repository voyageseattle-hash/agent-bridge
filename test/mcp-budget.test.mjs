import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

test("MCP remote-turn preview reports budget without session, ledger, or provider execution", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-mcp-budget-"));
  const work = join(root, "work");
  const state = join(root, "state");
  const credential = join(root, "manus-key");
  await mkdir(work, { recursive: true });
  await writeFile(credential, "test-only-key\n", "utf8");
  const config = join(root, "config.json");
  await writeFile(config, JSON.stringify({
    agents: {
      codex: { enabled: false }, claude: { enabled: false }, gemini: { enabled: false },
      manus: {
        enabled: true, baseUrl: "http://127.0.0.1:9", allowDevelopmentBaseUrl: true, credentialFile: credential,
        acknowledgeAccountDefaultCapabilities: true, accountCapabilityProfile: "test-reviewed-profile",
      },
    },
    defaults: { cwd: work, sandbox: "read-only", timeoutSec: 5 },
    allowedRoots: [work], stateDir: state,
    policy: {
      sandboxCeiling: "read-only",
      remoteEgress: { enabled: true, allowedAgents: ["manus"], allowedRoots: [work], allowedDataClasses: ["internal"] },
      cumulativeRemoteCost: { currency: "USD", maxReservedCents: 5000 },
    },
  }, null, 2), "utf8");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(process.cwd(), "dist", "agent-bridge.mjs"), "--config", config],
    env: { PATH: process.env.PATH ?? "", SystemRoot: process.env.SystemRoot ?? "", TEMP: process.env.TEMP ?? "", TMP: process.env.TMP ?? "" },
  });
  const client = new Client({ name: "agent-bridge-budget-preview-test", version: "1.0.0" });
  try {
    await client.connect(transport);
    const preview = await client.callTool({ name: "preview_turn_approval", arguments: {
      agent: "manus", prompt: "review only this inert brief", cwd: work,
      allow_remote_egress: true, data_classification: "internal",
    } });
    assert.notEqual(preview.isError, true, JSON.stringify(preview));
    assert.deepEqual(preview.structuredContent.budget, { enabled: true, currency: "USD", maxReservedCents: 5000, committedCents: 0, remainingCents: 5000, reservationCount: 0 });
    assert.match(preview.content.map((item) => item.text ?? "").join("\n"), /direct-remote budget: 0\/5000 USD/);
    const sessions = await client.callTool({ name: "list_sessions", arguments: {} });
    assert.deepEqual(sessions.structuredContent.sessions, []);
    assert.equal(existsSync(join(state, "budgets", "cumulative-remote-cost.json")), false);
  } finally {
    await client.close().catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});
