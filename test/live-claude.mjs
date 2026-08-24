import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { assertRuntimeIdentity, emitLiveResult, failLive, resolveLiveServer, skipLive } from "./live-support.mjs";

async function main() {
const identity = await resolveLiveServer();
const claude = process.env.AGENT_BRIDGE_CLAUDE_BIN ?? "claude";
const auth = spawnSync(claude, ["auth", "status"], { encoding: "utf8", windowsHide: true });
if (auth.status !== 0) {
  skipLive("claude", "configured Claude CLI is not authenticated");
  return;
}

const root = await mkdtemp(join(tmpdir(), "agent-bridge-live-claude-"));
const work = join(root, "work");
const state = join(root, "state");
await mkdir(work, { recursive: true });
const configPath = join(root, "config.json");
await writeFile(configPath, JSON.stringify({
  agents: { codex: { enabled: false }, claude: { enabled: true, bin: claude }, manus: { enabled: false }, gemini: { enabled: false } },
  defaults: { cwd: work, sandbox: "read-only", timeoutSec: 120 },
  allowedRoots: [work], stateDir: state,
}), "utf8");
const transport = new StdioClientTransport({ command: process.execPath, args: [identity.path], env: { ...process.env, AGENT_BRIDGE_CONFIG: configPath } });
const client = new Client({ name: "agent-bridge-live-claude", version: "1.0.0" });
try {
  await client.connect(transport);
  const diagnostics = await assertRuntimeIdentity(client, identity);
  const result = await client.callTool({ name: "delegate_task", arguments: {
    agent: "claude", cwd: work, sandbox: "read-only",
    prompt: "Connection test only. Do not call tools or modify files. Reply exactly: LIVE_CLAUDE_FRESH_OK",
  } });
  if (result.isError === true && /session limit|usage limit|rate limit/i.test(result.structuredContent?.output ?? "")) {
    skipLive("claude", "provider session, usage, or rate limit prevented the canary");
    return;
  } else {
    assert.notEqual(result.isError, true, JSON.stringify(result));
    assert.match(result.structuredContent.output, /LIVE_CLAUDE_FRESH_OK/);
    emitLiveResult("claude", "pass", { version: diagnostics.runtime.version, runtimeSha256: diagnostics.runtime.sha256, runtimePath: identity.path, releaseId: identity.releaseId, releaseMode: identity.releaseMode });
  }
} finally {
  await client.close().catch(() => {});
  await rm(root, { recursive: true, force: true });
}
}

main().catch((error) => failLive("claude", error));
