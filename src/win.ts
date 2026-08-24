import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";

const cache = new Map<string, string>();

export function resolveCommand(command: string, env: NodeJS.ProcessEnv = process.env): string {
  if (process.platform !== "win32") return command;
  if (isAbsolute(command) || command.includes("/") || command.includes("\\")) return command;
  const cacheKey = [command.toLowerCase(), env.PATH ?? "", env.PATHEXT ?? ""].join("\u0000");
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  const extensions = (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").map((item) => item.trim()).filter(Boolean);
  const directories = (env.PATH ?? "").split(";").filter(Boolean);
  for (const directory of directories) {
    for (const extension of extensions) {
      const candidate = join(directory, command + extension);
      if (existsSync(candidate)) {
        cache.set(cacheKey, candidate);
        return candidate;
      }
    }
    const candidate = join(directory, command);
    if (existsSync(candidate)) {
      cache.set(cacheKey, candidate);
      return candidate;
    }
  }
  return command;
}

export function buildLaunch(command: string, args: string[], env: NodeJS.ProcessEnv): {
  command: string;
  args: string[];
  windowsVerbatimArguments: boolean;
} {
  const resolved = resolveCommand(command, env);
  if (process.platform !== "win32") return { command: resolved, args, windowsVerbatimArguments: false };
  const lower = resolved.toLowerCase();
  if (lower.endsWith(".bat")) {
    throw new Error(
      `UNSAFE_WINDOWS_BATCH_SHIM: refusing to pass Agent Bridge arguments through cmd.exe for ${resolved}; `
      + "configure a direct .exe or a canonical static npm .cmd shim",
    );
  }
  if (lower.endsWith(".cmd")) {
    return resolveSafeNodeShim(resolved, args, env);
  }
  return { command: resolved, args, windowsVerbatimArguments: false };
}

/**
 * Windows cannot execute a batch file without cmd.exe, and cmd.exe reparses
 * arguments after expansion. Quoting arbitrary model names, prompts, roots, or
 * adapter extensions into `cmd /c` is therefore both lossy and injectable.
 *
 * Canonical static npm-generated shims contain one Node entry point followed by
 * `%*`. Resolve that entry point and launch Node directly so every adapter
 * argument stays an argv element and never enters a command shell. Arbitrary
 * or dynamic batch launchers fail closed; configure their underlying
 * executable instead.
 */
function resolveSafeNodeShim(command: string, args: string[], env: NodeJS.ProcessEnv): {
  command: string;
  args: string[];
  windowsVerbatimArguments: boolean;
} {
  let source: string;
  try { source = readFileSync(command, "utf8"); }
  catch (error) { throw new Error(`unable to read Windows batch shim ${command}: ${safeError(error)}`); }

  const lines = source.split(/\r?\n/);
  const candidates = lines.flatMap((line) => {
    const match = line.match(/^endLocal\s+&\s+goto\s+#_undefined_#\s+2>NUL\s+\|\|\s+title\s+%COMSPEC%\s+&\s+"%_prog%"\s+"%(?:~dp0|dp0%)\\([^"\r\n]+)"\s+%\*\s*$/i);
    return match?.[1] ? [match[1]] : [];
  });
  const hasNpmPrelude = lines.some((line) => /^GOTO\s+start\s*$/i.test(line.trim()))
    && lines.some((line) => /^:find_dp0\s*$/i.test(line.trim()))
    && lines.some((line) => /^SET\s+dp0=%~dp0\s*$/i.test(line.trim()))
    && lines.some((line) => /^CALL\s+:find_dp0\s*$/i.test(line.trim()));
  if (!hasNpmPrelude || candidates.length !== 1 || !candidates[0]) {
    throw new Error(
      `UNSAFE_WINDOWS_BATCH_SHIM: refusing to pass Agent Bridge arguments through cmd.exe for ${command}; `
      + "configure a direct .exe or a canonical static npm .cmd shim",
    );
  }

  const base = dirname(command);
  const entry = resolve(base, candidates[0]);
  if (!existsSync(entry) || !statSync(entry).isFile()) throw new Error(`Windows npm shim entry point is not a file: ${entry}`);
  const canonicalEntry = realpathSync(entry);
  const packageRoot = basename(base).toLowerCase() === ".bin" ? dirname(base) : base;
  const canonicalPackageRoot = realpathSync(packageRoot);
  if (!isInsideOrEqual(canonicalPackageRoot, canonicalEntry)) {
    throw new Error(`UNSAFE_WINDOWS_BATCH_SHIM: npm shim entry point escaped its package root: ${command}`);
  }
  const normalizedRelative = relative(canonicalPackageRoot, canonicalEntry).replaceAll("\\", "/").toLowerCase();
  if (!normalizedRelative.startsWith("node_modules/") && basename(base).toLowerCase() !== ".bin") {
    throw new Error(`UNSAFE_WINDOWS_BATCH_SHIM: npm shim entry point is not below node_modules: ${command}`);
  }

  const node = realpathSync(process.execPath);
  if (!isAbsolute(node) || !/\.exe$/i.test(node) || !existsSync(node) || !statSync(node).isFile()) {
    throw new Error(`UNSAFE_WINDOWS_BATCH_SHIM: no direct Node executable is available for ${command}`);
  }
  return { command: node, args: [canonicalEntry, ...args], windowsVerbatimArguments: false };
}

function isInsideOrEqual(parent: string, child: string): boolean {
  const value = relative(parent, child);
  return value === "" || (!value.startsWith("..") && !isAbsolute(value));
}

function safeError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").slice(0, 300);
}
