import { spawn } from "node:child_process";
import { sanitizedEnvironment } from "./env.js";
import type { RawProcessResult, SpawnSpec } from "./types.js";
import { buildLaunch } from "./win.js";

const MAX_CAPTURE = 4 * 1024 * 1024;

function appendBounded(chunks: string[], size: { value: number }, chunk: string): void {
  if (size.value >= MAX_CAPTURE) return;
  const room = MAX_CAPTURE - size.value;
  const value = chunk.length > room ? `${chunk.slice(0, room)}\n…[truncated]` : chunk;
  chunks.push(value);
  size.value += value.length;
}

export async function runProcess(spec: SpawnSpec, options: {
  cwd: string;
  timeoutMs: number;
  agentId: string;
  signal?: AbortSignal;
}): Promise<RawProcessResult> {
  if (options.signal?.aborted) {
    return {
      stdout: "",
      stderr: "[bridge] process launch was canceled before spawn.",
      exitCode: null,
      timedOut: false,
      aborted: true,
    };
  }
  return new Promise((resolve) => {
    const env = sanitizedEnvironment(options.agentId, spec.env);
    const launch = buildLaunch(spec.command, spec.args, env);
    const child = spawn(launch.command, launch.args, {
      cwd: options.cwd,
      env,
      stdio: ["pipe", "pipe", "pipe"],
      detached: process.platform !== "win32",
      windowsHide: true,
      windowsVerbatimArguments: launch.windowsVerbatimArguments,
    });
    const stdout: string[] = [];
    const stderr: string[] = [];
    const stdoutSize = { value: 0 };
    const stderrSize = { value: 0 };
    let timedOut = false;
    let aborted = false;
    let settled = false;
    let forceKillTimer: NodeJS.Timeout | undefined;

    const killTree = (signal: NodeJS.Signals): void => {
      try {
        if (process.platform === "win32" && child.pid) {
          const killer = spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], {
            stdio: "ignore", windowsHide: true,
          });
          killer.on("error", () => child.kill(signal));
          killer.on("close", (code) => { if (code !== 0) child.kill(signal); });
        } else if (child.pid) {
          try { process.kill(-child.pid, signal); }
          catch { child.kill(signal); }
        } else {
          child.kill(signal);
        }
      } catch { /* process already exited */ }
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killTree("SIGTERM");
      forceKillTimer = setTimeout(() => killTree("SIGKILL"), 5_000);
      forceKillTimer.unref();
    }, options.timeoutMs);

    const onAbort = (): void => {
      if (settled || aborted) return;
      aborted = true;
      clearTimeout(timer);
      appendBounded(stderr, stderrSize, "\n[bridge] process execution was canceled; terminating its process tree.");
      killTree("SIGTERM");
      forceKillTimer = setTimeout(() => killTree("SIGKILL"), 5_000);
      forceKillTimer.unref();
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => appendBounded(stdout, stdoutSize, chunk));
    child.stderr.on("data", (chunk: string) => appendBounded(stderr, stderrSize, chunk));

    const finish = (exitCode: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (forceKillTimer) clearTimeout(forceKillTimer);
      options.signal?.removeEventListener("abort", onAbort);
      resolve({ stdout: stdout.join(""), stderr: stderr.join(""), exitCode, timedOut, aborted });
    };
    child.on("error", (error) => {
      appendBounded(stderr, stderrSize, `\n[bridge] failed to spawn ${launch.command}: ${error.message}`);
      finish(null);
    });
    child.on("close", finish);
    child.stdin.on("error", () => undefined);
    child.stdin.end(spec.stdin);
  });
}

export async function probe(command: string, args: string[], agentId: string, signal?: AbortSignal): Promise<RawProcessResult> {
  return runProcess({ command, args }, { cwd: process.cwd(), timeoutMs: 10_000, agentId, signal });
}
