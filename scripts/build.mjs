import { execFileSync } from "node:child_process";
import { chmod, mkdir, readFile } from "node:fs/promises";
import { build } from "esbuild";

const pkg = JSON.parse(await readFile("package.json", "utf8"));
let gitSha = "unknown";
try { gitSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || "unknown"; }
catch { /* source archives may not include Git metadata */ }

await mkdir("dist", { recursive: true });
await build({
  entryPoints: ["src/index.ts"],
  outfile: "dist/agent-bridge.mjs",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  sourcemap: true,
  banner: { js: "#!/usr/bin/env node" },
  define: {
    __AGENT_BRIDGE_VERSION__: JSON.stringify(pkg.version),
    __AGENT_BRIDGE_GIT_SHA__: JSON.stringify(gitSha),
  },
});
if (process.platform !== "win32") await chmod("dist/agent-bridge.mjs", 0o755);
