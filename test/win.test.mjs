import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const outputDir = await mkdtemp(join(tmpdir(), "agent-bridge-win-build-"));
await build({ entryPoints: { win: "src/win.ts", runner: "src/runner.ts" }, outdir: outputDir, bundle: true, platform: "node", format: "esm", target: "node20" });
const win = await import(`${pathToFileURL(join(outputDir, "win.js")).href}?${Date.now()}`);
const runner = await import(`${pathToFileURL(join(outputDir, "runner.js")).href}?${Date.now()}`);
test.after(async () => { await rm(outputDir, { recursive: true, force: true }); });

test("direct executables bypass the Windows command shell", () => {
  const launch = win.buildLaunch(process.execPath, ["-e", "process.exit(0)"], process.env);
  assert.equal(launch.command, process.execPath);
  assert.deepEqual(launch.args, ["-e", "process.exit(0)"]);
  assert.equal(launch.windowsVerbatimArguments, false);
});

test("command resolution cache is isolated by PATH and PATHEXT", { skip: process.platform !== "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent bridge resolver cache "));
  const first = join(root, "first");
  const second = join(root, "second");
  try {
    await Promise.all([mkdir(first), mkdir(second)]);
    await Promise.all([writeFile(join(first, "bridge-tool.CMD"), "@echo first\r\n"), writeFile(join(second, "bridge-tool.CMD"), "@echo second\r\n")]);
    assert.equal(win.resolveCommand("bridge-tool", { PATH: first, PATHEXT: ".CMD" }), join(first, "bridge-tool.CMD"));
    assert.equal(win.resolveCommand("bridge-tool", { PATH: second, PATHEXT: ".CMD" }), join(second, "bridge-tool.CMD"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("standard npm batch shims launch through Node without shell argument injection", { skip: process.platform !== "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent bridge npm shim "));
  const prefix = join(root, "Creator Tools");
  const entry = join(prefix, "node_modules", "safe-cli", "cli.js");
  const shim = join(prefix, "safe-cli.cmd");
  const sentinel = join(tmpdir(), `agent-bridge-win-injection-${randomUUID()}.sentinel`);
  const hostile = [
    "", "two words", "tab\tvalue", "trailing\\", 'embedded"quote', "caret^value",
    "%PATH%", "!PATH!", "amp&ersand", "pipe|value", "less<value", "more>value",
    "paren(value)", "unicode-雪", '{"mcpServers":{}}', `x&echo injected>${sentinel}`,
  ];
  try {
    await mkdir(dirname(entry), { recursive: true });
    await writeFile(entry, "process.stdout.write(JSON.stringify(process.argv.slice(2)));\n", "utf8");
    await writeFile(shim, [
      "@ECHO off", "GOTO start", ":find_dp0", "SET dp0=%~dp0", "EXIT /b", ":start", "SETLOCAL", "CALL :find_dp0",
      "IF EXIST \"%dp0%\\node.exe\" ( SET \"_prog=%dp0%\\node.exe\" ) ELSE ( SET \"_prog=node\" )",
      "endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" \"%dp0%\\node_modules\\safe-cli\\cli.js\" %*",
    ].join("\r\n"), "utf8");
    const launch = win.buildLaunch(shim, hostile, process.env);
    assert.equal(launch.windowsVerbatimArguments, false);
    assert.equal(launch.args[0].toLowerCase(), entry.toLowerCase());
    assert.deepEqual(launch.args.slice(1), hostile);
    assert.doesNotMatch(launch.command, /\.(?:cmd|bat)$/i);

    const result = await runner.runProcess({ command: shim, args: hostile }, { cwd: root, timeoutMs: 10_000, agentId: "codex" });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), hostile);
    assert.equal(existsSync(sentinel), false, "a batch metacharacter argument executed a second command");
  } finally {
    await rm(sentinel, { force: true });
    await rm(root, { recursive: true, force: true });
  }
});

test("PATH-resolved node_modules bin shims support uppercase CMD and parent-relative entry points", { skip: process.platform !== "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent bridge local npm bin "));
  const bin = join(root, "node_modules", ".bin");
  const entry = join(root, "node_modules", "local-safe-cli", "cli.js");
  const shim = join(bin, "agent-bridge-local-safe.CMD");
  const args = ["local path", "x&echo must-not-run", "%PATH%", "!PATH!"];
  try {
    await Promise.all([mkdir(bin, { recursive: true }), mkdir(dirname(entry), { recursive: true })]);
    await writeFile(entry, "process.stdout.write(JSON.stringify(process.argv.slice(2)));\n", "utf8");
    await writeFile(shim, [
      "@ECHO off", "GOTO start", ":find_dp0", "SET dp0=%~dp0", "EXIT /b", ":start", "SETLOCAL", "CALL :find_dp0",
      "IF EXIST \"%dp0%\\node.exe\" ( SET \"_prog=%dp0%\\node.exe\" ) ELSE ( SET \"_prog=node\" )",
      "endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" \"%dp0%\\..\\local-safe-cli\\cli.js\" %*",
    ].join("\r\n"), "utf8");
    const env = { ...process.env, PATH: `${bin};${process.env.PATH ?? ""}`, PATHEXT: ".EXE;.CMD;.BAT" };
    const launch = win.buildLaunch("agent-bridge-local-safe", args, env);
    assert.equal(launch.command.toLowerCase(), process.execPath.toLowerCase());
    assert.equal(launch.args[0].toLowerCase(), entry.toLowerCase());
    assert.deepEqual(launch.args.slice(1), args);
    const result = await runner.runProcess({ command: "agent-bridge-local-safe", args, env }, { cwd: root, timeoutMs: 10_000, agentId: "codex" });
    assert.equal(result.exitCode, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), args);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("npm shim containment rejects textual and linked escapes", { skip: process.platform !== "win32" }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "agent bridge shim containment "));
  const bin = join(root, "node_modules", ".bin");
  const outside = join(root, "outside.js");
  const outsidePackage = join(root, "outside-package");
  const escapedShim = join(bin, "escaped.cmd");
  const linkedEntry = join(root, "node_modules", "linked", "cli.js");
  const linkedShim = join(bin, "linked.cmd");
  try {
    await Promise.all([mkdir(bin, { recursive: true }), mkdir(outsidePackage, { recursive: true })]);
    await writeFile(outside, "process.exit(99);\n", "utf8");
    await writeFile(join(outsidePackage, "cli.js"), "process.exit(98);\n", "utf8");
    const template = (entryPath) => [
      "@ECHO off", "GOTO start", ":find_dp0", "SET dp0=%~dp0", "EXIT /b", ":start", "SETLOCAL", "CALL :find_dp0",
      "IF EXIST \"%dp0%\\node.exe\" ( SET \"_prog=%dp0%\\node.exe\" ) ELSE ( SET \"_prog=node\" )",
      `endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" \"%dp0%\\${entryPath}\" %*`,
    ].join("\r\n");
    await writeFile(escapedShim, template("..\\..\\outside.js"), "utf8");
    assert.throws(() => win.buildLaunch(escapedShim, [], process.env), /UNSAFE_WINDOWS_BATCH_SHIM.*escaped/i);
    try {
      await (await import("node:fs/promises")).symlink(outsidePackage, dirname(linkedEntry), "junction");
    } catch (error) {
      if (!["EPERM", "EACCES", "ENOTSUP"].includes(error?.code)) throw error;
      return t.diagnostic(`symlink case unavailable: ${error.code}`);
    }
    await writeFile(linkedShim, template("..\\linked\\cli.js"), "utf8");
    assert.throws(() => win.buildLaunch(linkedShim, [], process.env), /UNSAFE_WINDOWS_BATCH_SHIM.*escaped/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("dynamic, commented, ambiguous, and BAT launchers fail closed", { skip: process.platform !== "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent bridge rejected shims "));
  const entry = join(root, "node_modules", "pkg", "cli.js");
  const canonicalLine = 'endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%" "%dp0%\\node_modules\\pkg\\cli.js" %*';
  const prelude = ["@ECHO off", "GOTO start", ":find_dp0", "SET dp0=%~dp0", "EXIT /b", ":start", "SETLOCAL", "CALL :find_dp0"];
  try {
    await mkdir(dirname(entry), { recursive: true });
    await writeFile(entry, "process.exit(0);\n", "utf8");
    const cases = [
      ["dynamic.cmd", [...prelude, '"%NODE_EXE%" "%NPM_CLI_JS%" %*']],
      ["commented.cmd", [...prelude, `REM ${canonicalLine}`, "echo unrelated %*"]],
      ["ambiguous.cmd", [...prelude, canonicalLine, canonicalLine]],
      ["static.BAT", [...prelude, canonicalLine]],
    ];
    for (const [name, lines] of cases) {
      const shim = join(root, name);
      await writeFile(shim, lines.join("\r\n"), "utf8");
      assert.throws(() => win.buildLaunch(shim, ["x&echo injected"], process.env), /UNSAFE_WINDOWS_BATCH_SHIM/i, name);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("arbitrary Windows batch files fail closed instead of receiving bridge arguments", { skip: process.platform !== "win32" }, async () => {
  const root = await mkdtemp(join(tmpdir(), "agent bridge unsafe batch "));
  const shim = join(root, "custom launcher.cmd");
  try {
    await writeFile(shim, "@echo off\r\necho %*\r\n", "utf8");
    assert.throws(
      () => win.buildLaunch(shim, ["x&echo injected"], process.env),
      /UNSAFE_WINDOWS_BATCH_SHIM.*direct \.exe or a canonical static npm \.cmd shim/i,
    );
    await assert.rejects(
      runner.runProcess({ command: shim, args: ["x&echo injected"] }, { cwd: root, timeoutMs: 10_000, agentId: "codex" }),
      /UNSAFE_WINDOWS_BATCH_SHIM/i,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
