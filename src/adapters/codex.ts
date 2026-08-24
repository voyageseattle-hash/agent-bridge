import type { AgentAdapter, AgentHealth, AgentResult, RawProcessResult, RunRequest, SandboxMode, SpawnSpec } from "../types.js";

export class CodexAdapter implements AgentAdapter {
  readonly id = "codex";
  readonly displayName = "OpenAI Codex CLI";
  readonly versionArgs = ["--version"];
  readonly capabilities = {
    resume: true, model: true, sandbox: true, structuredOutput: true,
    directRemoteApi: false, offMachineEgress: true, remote: false,
    localFilesystem: true, independentLocalCodeReview: true,
  };

  constructor(readonly bin = "codex") {}

  buildSpawn(req: RunRequest): SpawnSpec {
    const common = ["--json", "--skip-git-repo-check", "--ignore-user-config"];
    let args: string[];
    if (req.resumeSessionId) {
      // `codex exec resume` has its own option grammar. In particular it does
      // not accept --cd or --sandbox in current Codex releases.
      args = ["exec", "resume", req.resumeSessionId, ...common];
      if (req.model) args.push("--model", req.model);
    } else {
      args = ["exec", ...common, "--cd", req.cwd, "--sandbox", mapSandbox(req.sandbox)];
      if (req.model) args.push("--model", req.model);
    }
    if (req.extraArgs?.length) args.push(...req.extraArgs);
    args.push("-");
    return { command: this.bin, args, stdin: req.prompt, env: req.extraEnv };
  }

  authSpec(): SpawnSpec {
    return { command: this.bin, args: ["login", "status"] };
  }

  parseAuth(raw: RawProcessResult): AgentHealth["auth"] {
    const detail = `${raw.stdout}\n${raw.stderr}`.trim().split("\n")[0] ?? "";
    if (raw.exitCode === 0 && /logged in/i.test(detail)) return { status: "authenticated", detail };
    if (/not logged in|login required/i.test(detail)) return { status: "unauthenticated", detail };
    return { status: "unknown", detail: detail || `exit ${raw.exitCode}` };
  }

  parse(raw: RawProcessResult): AgentResult {
    const messages: string[] = [];
    let nativeSessionId: string | undefined;
    let failure: string | undefined;
    let usage: unknown;
    for (const line of raw.stdout.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("{")) continue;
      let event: Record<string, any>;
      try { event = JSON.parse(trimmed); } catch { continue; }
      if (event.type === "thread.started") nativeSessionId = event.thread_id ?? event.threadId ?? nativeSessionId;
      if (event.type === "item.completed") {
        const item = event.item ?? {};
        if (item.type === "agent_message" || item.item_type === "agent_message") {
          const text = item.text ?? item.content ?? "";
          if (text) messages.push(String(text));
        }
      }
      if (event.type === "turn.completed" && event.usage) usage = event.usage;
      if (event.type === "turn.failed") failure = event.error?.message ?? "turn failed";
      if (event.type === "error") failure = event.message ?? event.error?.message ?? "codex reported an error";
    }
    const fallback = raw.stdout.split("\n").filter((line) => !line.trim().startsWith("{")).join("\n").trim();
    const text = messages.length ? messages.join("\n\n") : fallback;
    const isError = raw.timedOut || raw.aborted || failure !== undefined || raw.exitCode !== 0;
    return {
      text: raw.timedOut ? `${text}\n\n[bridge] Codex timed out and was killed.`.trim() : text,
      nativeSessionId,
      exitCode: raw.exitCode,
      isError,
      stderr: tail(raw.stderr),
      timedOut: raw.timedOut,
      meta: { ...(usage ? { usage } : {}), ...(failure ? { failure } : {}), ...(raw.aborted ? { aborted: true } : {}) },
    };
  }
}

function mapSandbox(mode: SandboxMode): string {
  if (mode === "read-only") return "read-only";
  if (mode === "full-access") return "danger-full-access";
  return "workspace-write";
}

function tail(value: string, count = 40): string {
  return value.trim().split("\n").slice(-count).join("\n");
}
