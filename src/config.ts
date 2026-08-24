import { existsSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { BridgeConfig, SandboxMode } from "./types.js";
import { assertSandboxAllowed, DATA_CLASSIFICATIONS, normalizeManusBaseUrl, type BridgePolicy } from "./policy.js";

const agentSchema = z.object({
  enabled: z.boolean().optional(),
  bin: z.string().min(1).optional(),
  defaultModel: z.string().min(1).optional(),
  extraArgs: z.array(z.string()).optional(),
  extraEnv: z.record(z.string()).optional(),
  credentialFile: z.string().min(1).optional(),
  baseUrl: z.string().url().optional(),
  allowDevelopmentBaseUrl: z.boolean().optional(),
  acknowledgeAccountDefaultCapabilities: z.boolean().optional(),
  accountCapabilityProfile: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/).optional(),
  sandboxCeiling: z.enum(["read-only", "workspace-write", "full-access"]).optional(),
}).strict();

const configSchema = z.object({
  agents: z.record(agentSchema).optional(),
  defaults: z.object({
    timeoutSec: z.number().int().positive().max(7200).optional(),
    sandbox: z.enum(["read-only", "workspace-write", "full-access"]).optional(),
    cwd: z.string().min(1).optional(),
  }).strict().optional(),
  allowedRoots: z.array(z.string().min(1)).min(1),
  policy: z.object({
    sandboxCeiling: z.enum(["read-only", "workspace-write", "full-access"]).optional(),
    remoteEgress: z.object({
      enabled: z.boolean().optional(),
      allowedAgents: z.array(z.string().min(1)).max(32).optional(),
      allowedRoots: z.array(z.string().min(1)).max(64).optional(),
      allowedDataClasses: z.array(z.enum(DATA_CLASSIFICATIONS)).max(DATA_CLASSIFICATIONS.length).optional(),
    }).strict().optional(),
    cumulativeRemoteCost: z.object({
      currency: z.literal("USD"),
      maxReservedCents: z.number().int().min(1).max(100_000_000_000),
    }).strict().optional(),
  }).strict().optional(),
  handoffMaxChars: z.number().int().min(1000).max(1_000_000).optional(),
  stateDir: z.string().min(1).optional(),
  sessionLockWaitMs: z.number().int().min(0).max(300_000).optional(),
  sessionLockStaleMs: z.number().int().min(60_000).max(86_400_000).optional(),
  _notes: z.unknown().optional(),
}).strict();

const DEFAULTS = {
  agents: {
    codex: { enabled: true },
    claude: { enabled: true },
    gemini: { enabled: false },
    // Manus is opt-in because it requires MANUS_API_KEY.
    manus: { enabled: false },
  },
  defaults: { timeoutSec: 600, sandbox: "read-only" as SandboxMode },
  handoffMaxChars: 24_000,
  stateDir: join(homedir(), ".agent-bridge"),
  sessionLockWaitMs: 30_000,
  sessionLockStaleMs: 7_500_000,
};

export function resolveConfigPath(): { path: string; source: string } {
  const flag = process.argv.indexOf("--config");
  const flagValue = flag >= 0 ? process.argv[flag + 1] : undefined;
  if (flagValue) {
    return { path: resolve(expandHome(flagValue)), source: "--config flag" };
  }
  if (process.env.AGENT_BRIDGE_CONFIG) {
    return { path: resolve(expandHome(process.env.AGENT_BRIDGE_CONFIG)), source: "AGENT_BRIDGE_CONFIG env var" };
  }
  const beside = join(dirname(fileURLToPath(import.meta.url)), "config.json");
  if (existsSync(beside)) return { path: beside, source: "found next to the server file" };
  return { path: join(homedir(), ".agent-bridge", "config.json"), source: "default location" };
}

export function loadConfig(pathOverride?: string): BridgeConfig {
  const selected = pathOverride
    ? { path: resolve(expandHome(pathOverride)), source: "explicit path" }
    : resolveConfigPath();
  const explicitSelector = !!pathOverride || selected.source === "--config flag" || selected.source === "AGENT_BRIDGE_CONFIG env var";
  const bundleMode = process.env.AGENT_BRIDGE_BUNDLE_MODE === "1" && !explicitSelector;
  const resolved = bundleMode
    ? { path: "MCPB:user_config", source: "MCPB user_config environment" }
    : selected;
  let raw: unknown;
  if (bundleMode) {
    raw = bundleConfigFromEnvironment();
  } else {
    if (!existsSync(resolved.path)) {
      throw new Error(`agent-bridge config not found at ${resolved.path}; refusing unrestricted fallback`);
    }
    try {
      raw = JSON.parse(readFileSync(resolved.path, "utf8"));
    } catch (error) {
      throw new Error(`invalid agent-bridge config at ${resolved.path}: ${(error as Error).message}`);
    }
  }

  const parsed = configSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`invalid agent-bridge config at ${resolved.path}: ${parsed.error.issues.map((issue) => `${issue.path.join(".") || "root"}: ${issue.message}`).join("; ")}`);
  }
  const file = parsed.data;
  const allowedRoots = file.allowedRoots.map((root) => canonicalDirectory(root, "allowed root"));
  const cwd = file.defaults?.cwd ? canonicalDirectory(file.defaults.cwd, "default cwd") : undefined;
  if (cwd) assertCanonicalPathAllowed(cwd, allowedRoots);

  const agents = { ...DEFAULTS.agents, ...(file.agents ?? {}) } as BridgeConfig["agents"];
  for (const [id, rawAgent] of Object.entries(file.agents ?? {})) {
    if (rawAgent.allowDevelopmentBaseUrl && id !== "manus") {
      throw new Error(`invalid agent-bridge config at ${resolved.path}: agents.${id}.allowDevelopmentBaseUrl is only valid for Manus`);
    }
    if (rawAgent.acknowledgeAccountDefaultCapabilities !== undefined && id !== "manus") {
      throw new Error(`invalid agent-bridge config at ${resolved.path}: agents.${id}.acknowledgeAccountDefaultCapabilities is only valid for Manus`);
    }
    if (rawAgent.accountCapabilityProfile !== undefined && id !== "manus") {
      throw new Error(`invalid agent-bridge config at ${resolved.path}: agents.${id}.accountCapabilityProfile is only valid for Manus`);
    }
    if (id === "manus" && rawAgent.acknowledgeAccountDefaultCapabilities === true && !rawAgent.accountCapabilityProfile) {
      throw new Error(`invalid agent-bridge config at ${resolved.path}: agents.manus.accountCapabilityProfile is required when account-default capabilities are acknowledged`);
    }
    const agent = agents[id] as typeof rawAgent;
    if (rawAgent.credentialFile) agent.credentialFile = resolve(expandHome(rawAgent.credentialFile));
    if (id === "manus" && rawAgent.baseUrl) {
      try { agent.baseUrl = normalizeManusBaseUrl(rawAgent.baseUrl, rawAgent.allowDevelopmentBaseUrl); }
      catch (error) { throw new Error(`invalid agent-bridge config at ${resolved.path}: agents.manus.baseUrl: ${(error as Error).message}`); }
    }
  }

  const remoteFile = file.policy?.remoteEgress;
  const remoteRoots = (remoteFile?.allowedRoots ?? []).map((root) => canonicalDirectory(root, "remote-egress allowed root"));
  for (const root of remoteRoots) assertCanonicalPathAllowed(root, allowedRoots);
  if (remoteFile?.enabled) {
    if (!remoteFile.allowedAgents?.length) throw new Error(`invalid agent-bridge config at ${resolved.path}: policy.remoteEgress.allowedAgents is required when remote egress is enabled`);
    if (!remoteRoots.length) throw new Error(`invalid agent-bridge config at ${resolved.path}: policy.remoteEgress.allowedRoots is required when remote egress is enabled`);
    if (!remoteFile.allowedDataClasses?.length) throw new Error(`invalid agent-bridge config at ${resolved.path}: policy.remoteEgress.allowedDataClasses is required when remote egress is enabled`);
  }
  const policy: BridgePolicy = {
    sandboxCeiling: file.policy?.sandboxCeiling ?? "workspace-write",
    remoteEgress: {
      enabled: remoteFile?.enabled ?? false,
      allowedAgents: [...new Set(remoteFile?.allowedAgents ?? [])],
      allowedRoots: remoteRoots,
      allowedDataClasses: [...new Set(remoteFile?.allowedDataClasses ?? [])],
    },
    ...(file.policy?.cumulativeRemoteCost ? { cumulativeRemoteCost: file.policy.cumulativeRemoteCost } : {}),
  };
  const defaultSandbox = file.defaults?.sandbox ?? DEFAULTS.defaults.sandbox;
  try { assertSandboxAllowed(defaultSandbox, { agents, allowedRoots, policy }, "defaults"); }
  catch (error) { throw new Error(`invalid agent-bridge config at ${resolved.path}: defaults.sandbox: ${(error as Error).message}`); }

  const loaded = {
    agents,
    defaults: { ...DEFAULTS.defaults, ...(file.defaults ?? {}), cwd },
    allowedRoots,
    policy,
    handoffMaxChars: file.handoffMaxChars ?? DEFAULTS.handoffMaxChars,
    stateDir: resolve(expandHome(file.stateDir ?? DEFAULTS.stateDir)),
    sessionLockWaitMs: file.sessionLockWaitMs ?? DEFAULTS.sessionLockWaitMs,
    sessionLockStaleMs: file.sessionLockStaleMs ?? DEFAULTS.sessionLockStaleMs,
    configPath: resolved.path,
    configSource: resolved.source,
  };
  return loaded;
}

/**
 * Minimal fail-closed interface for MCPB manifest user_config. Normal installs
 * never consult these values unless AGENT_BRIDGE_BUNDLE_MODE is exactly "1".
 */
function bundleConfigFromEnvironment(): unknown {
  const allowedRoot = requiredBundleValue("AGENT_BRIDGE_ALLOWED_ROOT");
  const defaultSandbox = bundleSandbox("AGENT_BRIDGE_DEFAULT_SANDBOX", "read-only");
  const sandboxCeiling = bundleSandbox("AGENT_BRIDGE_SANDBOX_CEILING", "read-only");
  const manusEnabled = bundleBoolean("AGENT_BRIDGE_ENABLE_MANUS", false);
  const remoteEnabled = bundleBoolean("AGENT_BRIDGE_REMOTE_EGRESS", false);
  const remoteDataClass = process.env.AGENT_BRIDGE_REMOTE_DATA_CLASS;
  if (remoteEnabled && !manusEnabled) throw new Error("invalid MCPB user_config: remote egress requires Manus to be enabled");
  if (remoteEnabled && !DATA_CLASSIFICATIONS.includes(remoteDataClass as any)) {
    throw new Error(`invalid MCPB user_config: AGENT_BRIDGE_REMOTE_DATA_CLASS must be one of ${DATA_CLASSIFICATIONS.join(", ")}`);
  }
  return {
    agents: {
      codex: { enabled: bundleBoolean("AGENT_BRIDGE_ENABLE_CODEX", true) },
      claude: { enabled: bundleBoolean("AGENT_BRIDGE_ENABLE_CLAUDE", true) },
      gemini: { enabled: bundleBoolean("AGENT_BRIDGE_ENABLE_GEMINI", false) },
      manus: {
        enabled: manusEnabled,
        acknowledgeAccountDefaultCapabilities: bundleBoolean("AGENT_BRIDGE_MANUS_ACKNOWLEDGE_ACCOUNT_DEFAULT_CAPABILITIES", false),
        ...(process.env.AGENT_BRIDGE_MANUS_ACCOUNT_CAPABILITY_PROFILE
          ? { accountCapabilityProfile: process.env.AGENT_BRIDGE_MANUS_ACCOUNT_CAPABILITY_PROFILE }
          : {}),
        ...(process.env.AGENT_BRIDGE_MANUS_CREDENTIAL_FILE
          ? { credentialFile: process.env.AGENT_BRIDGE_MANUS_CREDENTIAL_FILE }
          : {}),
      },
    },
    defaults: { cwd: allowedRoot, sandbox: defaultSandbox },
    allowedRoots: [allowedRoot],
    ...(process.env.AGENT_BRIDGE_STATE_DIR ? { stateDir: process.env.AGENT_BRIDGE_STATE_DIR } : {}),
    policy: {
      sandboxCeiling,
      remoteEgress: {
        enabled: remoteEnabled,
        allowedAgents: remoteEnabled ? ["manus"] : [],
        allowedRoots: remoteEnabled ? [allowedRoot] : [],
        allowedDataClasses: remoteEnabled ? [remoteDataClass] : [],
      },
    },
  };
}

function requiredBundleValue(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`invalid MCPB user_config: ${name} is required`);
  return value;
}

function bundleBoolean(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (value === undefined || value === "") return fallback;
  if (value === "true" || value === "1") return true;
  if (value === "false" || value === "0") return false;
  throw new Error(`invalid MCPB user_config: ${name} must be true or false`);
}

function bundleSandbox(name: string, fallback: SandboxMode): SandboxMode {
  const value = process.env[name] ?? fallback;
  if (value === "read-only" || value === "workspace-write" || value === "full-access") return value;
  throw new Error(`invalid MCPB user_config: ${name} must be read-only, workspace-write, or full-access`);
}

export function expandHome(value: string): string {
  if (value === "~") return homedir();
  if (value.startsWith(`~${sep}`) || value.startsWith("~/") || value.startsWith("~\\")) {
    return join(homedir(), value.slice(2));
  }
  return value;
}

export function canonicalDirectory(value: string, label = "directory"): string {
  const absolute = resolve(expandHome(value));
  if (!existsSync(absolute)) throw new Error(`${label} "${absolute}" does not exist`);
  try {
    return realpathSync.native(absolute);
  } catch (error) {
    throw new Error(`cannot resolve ${label} "${absolute}": ${(error as Error).message}`);
  }
}

function normalize(value: string): string {
  return process.platform === "win32" ? value.toLowerCase() : value;
}

export function assertCanonicalPathAllowed(canonicalPath: string, canonicalRoots: string[]): string {
  const candidate = normalize(canonicalPath);
  const ok = canonicalRoots.some((root) => {
    const normalizedRoot = normalize(root);
    return candidate === normalizedRoot || candidate.startsWith(`${normalizedRoot}${sep}`);
  });
  if (!ok) {
    throw new Error(`cwd "${canonicalPath}" is outside the allowed roots (${canonicalRoots.join(", ")})`);
  }
  return canonicalPath;
}

export function assertAllowedCwd(value: string, cfg: Pick<BridgeConfig, "allowedRoots">): string {
  const canonical = canonicalDirectory(value, "cwd");
  return assertCanonicalPathAllowed(canonical, cfg.allowedRoots);
}
