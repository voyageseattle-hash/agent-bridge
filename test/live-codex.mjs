import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { assertRuntimeIdentity, emitLiveResult, failLive, resolveLiveServer } from "./live-support.mjs";

async function main() {
const identity = await resolveLiveServer();
const root = await mkdtemp(join(tmpdir(), "agent-bridge-live-codex-"));
const work = join(root, "work");
const state = join(root, "state");
await mkdir(work, { recursive: true });
await writeFile(join(work, ".gitkeep"), "", "utf8");

const codex = process.env.AGENT_BRIDGE_CODEX_BIN ?? "codex";
const configPath = join(root, "config.json");
await writeFile(configPath, JSON.stringify({
  agents: { codex: { enabled: true, bin: codex }, claude: { enabled: false }, manus: { enabled: false }, gemini: { enabled: false } },
  defaults: { cwd: work, sandbox: "read-only", timeoutSec: 120 },
  allowedRoots: [work], stateDir: state,
}), "utf8");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [identity.path],
  env: { ...process.env, AGENT_BRIDGE_CONFIG: configPath },
});
const client = new Client({ name: "agent-bridge-live-codex", version: "1.0.0" });
try {
  await client.connect(transport);
  const diagnostics = await assertRuntimeIdentity(client, identity);
  const health = await client.callTool({ name: "list_agents", arguments: {} });
  const agent = health.structuredContent.agents[0];
  assert.equal(agent.id, "codex");
  assert.equal(agent.health.auth.status, "authenticated", JSON.stringify(agent.health));

  const fresh = await client.callTool({ name: "delegate_task", arguments: {
    agent: "codex", cwd: work, sandbox: "read-only",
    prompt: "Connection test only. Do not call tools or modify files. Reply exactly: LIVE_CODEX_FRESH_OK",
  } });
  assert.notEqual(fresh.isError, true, JSON.stringify(fresh));
  assert.match(fresh.structuredContent.output, /LIVE_CODEX_FRESH_OK/);
  assert.equal(fresh.structuredContent.continuity, "new");

  const resumed = await client.callTool({ name: "continue_session", arguments: {
    session_id: fresh.structuredContent.bridge_session_id, sandbox: "read-only",
    prompt: "Connection test continuation. Do not call tools or modify files. Reply exactly: LIVE_CODEX_RESUME_OK",
  } });
  assert.notEqual(resumed.isError, true, JSON.stringify(resumed));
  assert.match(resumed.structuredContent.output, /LIVE_CODEX_RESUME_OK/);
  assert.equal(resumed.structuredContent.continuity, "native-resume");
  emitLiveResult("codex", "pass", { version: diagnostics.runtime.version, runtimeSha256: diagnostics.runtime.sha256, runtimePath: identity.path, releaseId: identity.releaseId, releaseMode: identity.releaseMode });
} finally {
  await client.close().catch(() => {});
  await rm(root, { recursive: true, force: true });
}
}

main().catch((error) => failLive("codex", error));
