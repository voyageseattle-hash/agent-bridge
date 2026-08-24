import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { build } from "esbuild";

const outputDir = await mkdtemp(join(tmpdir(), "agent-bridge-policy-build-"));
await build({
  entryPoints: {
    policy: "src/policy.ts", config: "src/config.ts", manus: "src/adapters/manus.ts",
    codex: "src/adapters/codex.ts", claude: "src/adapters/claude.ts", gemini: "src/adapters/gemini.ts",
  },
  outdir: outputDir, bundle: true, platform: "node", format: "esm", target: "node20",
});
const policy = await import(pathToFileURL(join(outputDir, "policy.js")).href);
const config = await import(pathToFileURL(join(outputDir, "config.js")).href);
const { ManusAdapter } = await import(pathToFileURL(join(outputDir, "manus.js")).href);
const { CodexAdapter } = await import(pathToFileURL(join(outputDir, "codex.js")).href);
const { ClaudeAdapter } = await import(pathToFileURL(join(outputDir, "claude.js")).href);
const { GeminiAdapter } = await import(pathToFileURL(join(outputDir, "gemini.js")).href);

test.after(async () => { await rm(outputDir, { recursive: true, force: true }); });

test("sandbox requests cannot exceed global or per-agent ceilings", () => {
  const base = {
    agents: { codex: {}, claude: { sandboxCeiling: "read-only" } },
    allowedRoots: [process.cwd()],
    policy: { sandboxCeiling: "workspace-write", remoteEgress: { enabled: false, allowedAgents: [], allowedRoots: [], allowedDataClasses: [] } },
  };
  assert.equal(policy.assertSandboxAllowed("workspace-write", base, "codex"), "workspace-write");
  assert.throws(() => policy.assertSandboxAllowed("full-access", base, "codex"), /SANDBOX_AUTHORITY_DENIED.*workspace-write/i);
  assert.throws(() => policy.assertSandboxAllowed("workspace-write", base, "claude"), /SANDBOX_AUTHORITY_DENIED.*read-only/i);
});

test("legacy configuration permits at most workspace-write and full-access requires an explicit ceiling", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-policy-config-"));
  try {
    const legacy = join(root, "legacy.json");
    await writeFile(legacy, JSON.stringify({ allowedRoots: [root], defaults: { sandbox: "read-only" } }));
    assert.equal(config.loadConfig(legacy).policy.sandboxCeiling, "workspace-write");

    const implicitFull = join(root, "implicit-full.json");
    await writeFile(implicitFull, JSON.stringify({ allowedRoots: [root], defaults: { sandbox: "full-access" } }));
    assert.throws(() => config.loadConfig(implicitFull), /defaults\.sandbox.*SANDBOX_AUTHORITY_DENIED/i);

    const explicitFull = join(root, "explicit-full.json");
    await writeFile(explicitFull, JSON.stringify({
      allowedRoots: [root], defaults: { sandbox: "full-access" }, policy: { sandboxCeiling: "full-access" },
    }));
    assert.equal(config.loadConfig(explicitFull).defaults.sandbox, "full-access");
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("remote egress requires configured agent/root/classification and fresh per-call consent", () => {
  const root = process.cwd();
  const cfg = {
    agents: { manus: {} }, allowedRoots: [root],
    policy: {
      sandboxCeiling: "workspace-write",
      remoteEgress: { enabled: true, allowedAgents: ["manus"], allowedRoots: [root], allowedDataClasses: ["public", "internal"] },
    },
  };
  const approved = { config: cfg, agentId: "manus", cwd: root, allowRemoteEgress: true, dataClassification: "internal" };
  assert.equal(policy.assertRemoteEgressAllowed(approved), "internal");
  assert.throws(() => policy.assertRemoteEgressAllowed({ ...approved, allowRemoteEgress: false }), /CONSENT_REQUIRED/i);
  assert.throws(() => policy.assertRemoteEgressAllowed({ ...approved, dataClassification: undefined }), /CLASSIFICATION_REQUIRED/i);
  assert.throws(() => policy.assertRemoteEgressAllowed({ ...approved, dataClassification: "confidential" }), /DATA_DENIED/i);
  assert.throws(() => policy.assertRemoteEgressAllowed({ ...approved, agentId: "other" }), /AGENT_DENIED/i);
  assert.throws(() => policy.assertRemoteEgressAllowed({ ...approved, cwd: tmpdir() }), /ROOT_DENIED/i);
});

test("enabled remote-egress config fails closed unless all allowlists are populated", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-egress-config-"));
  try {
    const path = join(root, "config.json");
    await writeFile(path, JSON.stringify({ allowedRoots: [root], policy: { remoteEgress: { enabled: true } } }));
    assert.throws(() => config.loadConfig(path), /allowedAgents is required/i);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("cumulative direct-remote budget config is optional and strictly bounded", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-budget-config-"));
  try {
    const path = join(root, "config.json");
    await writeFile(path, JSON.stringify({ allowedRoots: [root] }));
    assert.equal(config.loadConfig(path).policy.cumulativeRemoteCost, undefined);
    await writeFile(path, JSON.stringify({ allowedRoots: [root], policy: { cumulativeRemoteCost: { currency: "USD", maxReservedCents: 5000 } } }));
    assert.deepEqual(config.loadConfig(path).policy.cumulativeRemoteCost, { currency: "USD", maxReservedCents: 5000 });
    for (const cumulativeRemoteCost of [
      { currency: "EUR", maxReservedCents: 5000 },
      { currency: "USD", maxReservedCents: 0 },
      { currency: "USD", maxReservedCents: 1.5 },
      { currency: "USD", maxReservedCents: 5000, resetOnFailure: true },
    ]) {
      await writeFile(path, JSON.stringify({ allowedRoots: [root], policy: { cumulativeRemoteCost } }));
      assert.throws(() => config.loadConfig(path), /cumulativeRemoteCost/);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("explicit MCPB bundle mode builds a narrow config only from validated user_config environment", async () => {
  const root = await mkdtemp(join(tmpdir(), "agent-bridge-bundle-root-"));
  const names = [
    "AGENT_BRIDGE_BUNDLE_MODE", "AGENT_BRIDGE_ALLOWED_ROOT", "AGENT_BRIDGE_STATE_DIR",
    "AGENT_BRIDGE_ENABLE_CODEX", "AGENT_BRIDGE_ENABLE_CLAUDE", "AGENT_BRIDGE_ENABLE_GEMINI",
    "AGENT_BRIDGE_ENABLE_MANUS", "AGENT_BRIDGE_REMOTE_EGRESS", "AGENT_BRIDGE_REMOTE_DATA_CLASS",
    "AGENT_BRIDGE_MANUS_ACKNOWLEDGE_ACCOUNT_DEFAULT_CAPABILITIES", "AGENT_BRIDGE_MANUS_ACCOUNT_CAPABILITY_PROFILE",
    "AGENT_BRIDGE_DEFAULT_SANDBOX", "AGENT_BRIDGE_SANDBOX_CEILING",
  ];
  const before = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  try {
    process.env.AGENT_BRIDGE_BUNDLE_MODE = "1";
    process.env.AGENT_BRIDGE_ALLOWED_ROOT = root;
    process.env.AGENT_BRIDGE_ENABLE_CODEX = "true";
    process.env.AGENT_BRIDGE_ENABLE_CLAUDE = "false";
    process.env.AGENT_BRIDGE_ENABLE_MANUS = "false";
    const loaded = config.loadConfig();
    assert.deepEqual(loaded.allowedRoots, [config.canonicalDirectory(root)]);
    assert.equal(loaded.defaults.cwd, config.canonicalDirectory(root));
    assert.equal(loaded.defaults.sandbox, "read-only");
    assert.equal(loaded.policy.sandboxCeiling, "read-only");
    assert.equal(loaded.agents.codex.enabled, true);
    assert.equal(loaded.agents.claude.enabled, false);
    assert.equal(loaded.agents.manus.enabled, false);
    assert.equal(loaded.policy.remoteEgress.enabled, false);
    assert.equal(loaded.configSource, "MCPB user_config environment");

    delete process.env.AGENT_BRIDGE_ALLOWED_ROOT;
    assert.throws(() => config.loadConfig(), /AGENT_BRIDGE_ALLOWED_ROOT is required/i);
  } finally {
    for (const name of names) {
      if (before[name] === undefined) delete process.env[name];
      else process.env[name] = before[name];
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("Manus credentials can only be sent to the official HTTPS API or explicit loopback development endpoint", () => {
  assert.doesNotThrow(() => new ManusAdapter({ apiKey: "test", baseUrl: "https://api.manus.ai" }));
  assert.doesNotThrow(() => new ManusAdapter({ apiKey: "test", baseUrl: "https://preview.api.manus.ai" }));
  assert.throws(() => new ManusAdapter({ apiKey: "test", baseUrl: "http://api.manus.ai" }), /HTTPS api\.manus\.ai/i);
  assert.throws(() => new ManusAdapter({ apiKey: "test", baseUrl: "https://api.manus.ai.evil.example" }), /HTTPS api\.manus\.ai/i);
  assert.throws(() => new ManusAdapter({ apiKey: "test", baseUrl: "https://evil.example" }), /HTTPS api\.manus\.ai/i);
  assert.throws(() => new ManusAdapter({ apiKey: "test", baseUrl: "http://evil.example", allowDevelopmentBaseUrl: true }), /loopback/i);
  assert.doesNotThrow(() => new ManusAdapter({ apiKey: "test", baseUrl: "http://127.0.0.1:8787", allowDevelopmentBaseUrl: true }));
});

test("remote Manus cannot be used as an independent local-workspace reviewer", () => {
  const manus = new ManusAdapter({ apiKey: "test" });
  assert.equal(manus.capabilities.directRemoteApi, true);
  assert.equal(manus.capabilities.offMachineEgress, true);
  assert.throws(() => policy.assertCooperativeAgentCompatible(manus), /cannot independently inspect local workspace evidence/i);
  const local = { id: "local", bin: "local", capabilities: { sandbox: true } };
  assert.equal(policy.assertCooperativeAgentCompatible(local), local);
});

test("CLI capability declarations distinguish provider egress from a direct remote API", () => {
  for (const adapter of [new CodexAdapter(), new ClaudeAdapter(), new GeminiAdapter()]) {
    assert.equal(adapter.capabilities.directRemoteApi, false, adapter.id);
    assert.equal(adapter.capabilities.offMachineEgress, true, adapter.id);
  }
  assert.equal(policy.assertCooperativeAgentCompatible(new CodexAdapter()).id, "codex");
  assert.equal(policy.assertCooperativeAgentCompatible(new ClaudeAdapter()).id, "claude");
  assert.throws(() => policy.assertCooperativeAgentCompatible(new GeminiAdapter()), /cannot enforce read-only local execution/i);
});

test("work-item compatibility fails closed before a lease for filesystem, egress, and capability mismatches", () => {
  const codex = new CodexAdapter();
  const item = {
    key: "inspect",
    requirements: { dataClass: "internal", filesystem: "read-only", network: "restricted", capabilities: ["structuredOutput"] },
  };
  assert.equal(policy.assertWorkItemAgentCompatible(item, codex), codex);
  assert.throws(
    () => policy.assertWorkItemAgentCompatible({ ...item, requirements: { ...item.requirements, filesystem: "metadata-only" } }, codex),
    /requires filesystem=read-only/i,
  );
  assert.throws(
    () => policy.assertWorkItemAgentCompatible({ ...item, requirements: { ...item.requirements, network: "none" } }, codex),
    /off-machine.*network=none/i,
  );
  assert.throws(
    () => policy.assertWorkItemAgentCompatible({ ...item, requirements: { ...item.requirements, capabilities: ["source-review"] } }, codex),
    /does not advertise required capability source-review/i,
  );
  assert.throws(
    () => policy.assertWorkItemAgentCompatible({ ...item, requirements: { ...item.requirements, capabilities: ["directRemoteApi"] } }, codex),
    /does not advertise required capability directRemoteApi/i,
  );
});

test("distributed configuration template disables Manus and fails closed until roots are selected", async () => {
  const example = JSON.parse(await readFile("config.example.json", "utf8"));
  assert.equal(example.agents.manus.enabled, false);
  assert.deepEqual(example.allowedRoots, []);
});
