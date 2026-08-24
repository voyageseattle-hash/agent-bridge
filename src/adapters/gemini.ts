import type { AgentAdapter, AgentResult, RawProcessResult, RunRequest, SpawnSpec } from "../types.js";

export class GeminiAdapter implements AgentAdapter {
  readonly id = "gemini";
  readonly displayName = "Gemini CLI";
  readonly versionArgs = ["--version"];
  readonly capabilities = {
    resume: false, model: true, sandbox: false, structuredOutput: true,
    directRemoteApi: false, offMachineEgress: true, remote: false,
    localFilesystem: true, independentLocalCodeReview: true,
  };

  constructor(readonly bin = "gemini") {}

  buildSpawn(req: RunRequest): SpawnSpec {
    if (req.sandbox === "read-only") throw new Error("the Gemini adapter cannot enforce read-only mode");
    const args = ["-p", req.prompt, "--output-format", "json"];
    if (req.model) args.push("--model", req.model);
    args.push("--yolo");
    if (req.extraArgs?.length) args.push(...req.extraArgs);
    return { command: this.bin, args, env: req.extraEnv };
  }

  parse(raw: RawProcessResult): AgentResult {
    let text = raw.stdout.trim();
    let meta: Record<string, unknown> | undefined;
    try {
      const object = JSON.parse(text);
      text = String(object.response ?? object.result ?? object.text ?? text);
      meta = { stats: object.stats };
    } catch { /* plain text fallback */ }
    return {
      text: raw.timedOut ? `${text}\n\n[bridge] Gemini timed out and was killed.`.trim() : text,
      exitCode: raw.exitCode,
      isError: raw.timedOut || raw.aborted || raw.exitCode !== 0,
      stderr: raw.stderr.trim().split("\n").slice(-40).join("\n"),
      timedOut: raw.timedOut,
      meta: { ...meta, ...(raw.aborted ? { aborted: true } : {}) },
    };
  }
}
