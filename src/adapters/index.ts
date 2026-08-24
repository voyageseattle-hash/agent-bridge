import type { AgentAdapter, BridgeConfig } from "../types.js";
import { ClaudeAdapter } from "./claude.js";
import { CodexAdapter } from "./codex.js";
import { GeminiAdapter } from "./gemini.js";
import { ManusAdapter } from "./manus.js";

const factories: Record<string, (bin?: string) => AgentAdapter> = {
  codex: (bin) => new CodexAdapter(bin),
  claude: (bin) => new ClaudeAdapter(bin),
  gemini: (bin) => new GeminiAdapter(bin),
  manus: () => new ManusAdapter(),
};

export function buildRegistry(config: BridgeConfig): Map<string, AgentAdapter> {
  const registry = new Map<string, AgentAdapter>();
  for (const [id, factory] of Object.entries(factories)) {
    const agentConfig = config.agents[id];
    // HTTP-backed adapters are opt-in: their credentials are supplied only
    // through the process environment, never configuration files.
    if (id === "manus" && !agentConfig) continue;
    if (agentConfig?.enabled === false) continue;
    if (id === "manus") {
      registry.set(id, new ManusAdapter({
        apiKeyFile: agentConfig?.credentialFile,
        baseUrl: agentConfig?.baseUrl,
        allowDevelopmentBaseUrl: agentConfig?.allowDevelopmentBaseUrl,
        acknowledgeAccountDefaultCapabilities: agentConfig?.acknowledgeAccountDefaultCapabilities,
        accountCapabilityProfile: agentConfig?.accountCapabilityProfile,
      }));
    } else {
      registry.set(id, factory(agentConfig?.bin));
    }
  }
  return registry;
}

export { ClaudeAdapter, CodexAdapter, GeminiAdapter, ManusAdapter };
