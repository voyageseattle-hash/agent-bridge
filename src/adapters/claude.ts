import type { AgentAdapter, AgentHealth, AgentResult, RawProcessResult, RunRequest, SandboxMode, SpawnSpec } from "../types.js";

export class ClaudeAdapter implements AgentAdapter {
  readonly id = "claude";
  readonly displayName = "Claude Code CLI";
  readonly versionArgs = ["--version"];
  readonly capabilities = {
    resume: true, model: true, sandbox: true, structuredOutput: true,
    directRemoteApi: false, offMachineEgress: true, remote: false,
    localFilesystem: true, independentLocalCodeReview: true,
  };

  constructor(readonly bin = "claude") {}

  buildSpawn(req: RunRequest): SpawnSpec {
    const args = [
      "-p", req.prompt,
      "--output-format", "json",
      // Keep normal OAuth/keychain authentication, but block inherited MCP
      // configuration so delegating to Claude cannot recursively call bridge.
      "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
    ];
    if (req.model) args.push("--model", req.model);
    if (req.resumeSessionId) args.push("--resume", req.resumeSessionId);
    args.push("--add-dir", req.cwd, ...permissionArgs(req.sandbox));
    if (req.extraArgs?.length) args.push(...req.extraArgs);
    return { command: this.bin, args, env: req.extraEnv };
  }

  authSpec(): SpawnSpec {
    return { command: this.bin, args: ["auth", "status"] };
  }

  parseAuth(raw: RawProcessResult): AgentHealth["auth"] {
    const text = `${raw.stdout}\n${raw.stderr}`.trim();
    try {
      const parsed = JSON.parse(text) as { loggedIn?: boolean; authMethod?: string };
      if (parsed.loggedIn === true) return { status: "authenticated", detail: parsed.authMethod ?? "logged in" };
      if (parsed.loggedIn === false) return { status: "unauthenticated", detail: parsed.authMethod ?? "not logged in" };
    } catch { /* fall through */ }
    if (/not logged in|run \/login/i.test(text)) return { status: "unauthenticated", detail: firstLine(text) };
    return { status: "unknown", detail: firstLine(text) || `exit ${raw.exitCode}` };
  }

  parse(raw: RawProcessResult): AgentResult {
    const object = extractJsonObject(raw.stdout);
    if (!object) {
      return {
        text: raw.stdout.trim() || "[bridge] Claude Code produced no parseable output.",
        exitCode: raw.exitCode,
        isError: true,
        stderr: tail(raw.stderr),
        timedOut: raw.timedOut,
      };
    }
    const text = String(object.result ?? object.structured_output ?? "");
    const isError = raw.timedOut || raw.aborted || object.is_error === true || raw.exitCode !== 0;
    return {
      text: raw.timedOut ? `${text}\n\n[bridge] Claude Code timed out and was killed.`.trim() : text,
      nativeSessionId: typeof object.session_id === "string" ? object.session_id : undefined,
      exitCode: raw.exitCode,
      isError,
      stderr: tail(raw.stderr),
      timedOut: raw.timedOut,
      meta: {
        numTurns: object.num_turns,
        totalCostUsd: object.total_cost_usd,
        usage: object.usage,
        subtype: object.subtype,
        ...(raw.aborted ? { aborted: true } : {}),
      },
    };
  }
}

function permissionArgs(mode: SandboxMode): string[] {
  if (mode === "read-only") return ["--permission-mode", "plan", "--allowedTools", "Read,Grep,Glob,WebSearch"];
  if (mode === "full-access") return ["--permission-mode", "bypassPermissions"];
  return ["--permission-mode", "acceptEdits"];
}

function extractJsonObject(stdout: string): Record<string, any> | null {
  const whole = stdout.trim();
  try {
    const parsed = JSON.parse(whole);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
  } catch { /* continue */ }
  for (const line of whole.split("\n").reverse()) {
    const value = line.trim();
    if (!value.startsWith("{")) continue;
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === "object" && ("result" in parsed || "session_id" in parsed)) return parsed;
    } catch { /* continue */ }
  }
  return null;
}

function firstLine(value: string): string { return value.split("\n")[0]?.trim() ?? ""; }
function tail(value: string, count = 40): string { return value.trim().split("\n").slice(-count).join("\n"); }
