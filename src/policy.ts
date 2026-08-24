import { sep } from "node:path";
import type { AgentAdapter, AgentConfig, BridgeConfig, SandboxMode } from "./types.js";
import type { WorkItem } from "./workboards.js";

export const DATA_CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"] as const;
export type DataClassification = typeof DATA_CLASSIFICATIONS[number];

export interface BridgePolicy {
  sandboxCeiling: SandboxMode;
  remoteEgress: {
    enabled: boolean;
    allowedAgents: string[];
    allowedRoots: string[];
    allowedDataClasses: DataClassification[];
  };
  cumulativeRemoteCost?: {
    currency: "USD";
    maxReservedCents: number;
  };
}

type PolicyAwareConfig = Pick<BridgeConfig, "agents" | "allowedRoots"> & { policy?: BridgePolicy };
type AgentPolicyConfig = AgentConfig & { sandboxCeiling?: SandboxMode };

const SANDBOX_RANK: Record<SandboxMode, number> = {
  "read-only": 0,
  "workspace-write": 1,
  "full-access": 2,
};

/** Reject authority escalation above either the global or per-agent ceiling. */
export function assertSandboxAllowed(requested: SandboxMode, config: PolicyAwareConfig, agentId: string): SandboxMode {
  const globalCeiling = config.policy?.sandboxCeiling ?? "workspace-write";
  const agentCeiling = (config.agents[agentId] as AgentPolicyConfig | undefined)?.sandboxCeiling ?? globalCeiling;
  const effectiveCeiling = SANDBOX_RANK[agentCeiling] < SANDBOX_RANK[globalCeiling] ? agentCeiling : globalCeiling;
  if (SANDBOX_RANK[requested] > SANDBOX_RANK[effectiveCeiling]) {
    throw new Error(`SANDBOX_AUTHORITY_DENIED: ${agentId} requested ${requested}, above the configured ${effectiveCeiling} ceiling`);
  }
  return requested;
}

/**
 * Require both administrator policy and fresh caller consent before sending a
 * prompt to a remote backend. The classification is deliberately mandatory:
 * an omitted label is not treated as harmless data.
 */
export function assertRemoteEgressAllowed(input: {
  config: PolicyAwareConfig;
  agentId: string;
  cwd: string;
  allowRemoteEgress?: boolean;
  dataClassification?: DataClassification;
}): DataClassification {
  const policy = input.config.policy?.remoteEgress;
  if (!policy?.enabled) throw new Error("REMOTE_EGRESS_DISABLED: remote delegation is disabled by bridge policy");
  if (input.allowRemoteEgress !== true) {
    throw new Error("REMOTE_EGRESS_CONSENT_REQUIRED: set allow_remote_egress=true for this call after reviewing the outbound prompt");
  }
  if (!input.dataClassification) {
    throw new Error(`REMOTE_EGRESS_CLASSIFICATION_REQUIRED: data_classification must be one of ${DATA_CLASSIFICATIONS.join(", ")}`);
  }
  if (!policy.allowedAgents.includes(input.agentId)) {
    throw new Error(`REMOTE_EGRESS_AGENT_DENIED: ${input.agentId} is not allowlisted for remote egress`);
  }
  if (!policy.allowedDataClasses.includes(input.dataClassification)) {
    throw new Error(`REMOTE_EGRESS_DATA_DENIED: ${input.dataClassification} data is not approved for remote egress`);
  }
  if (!isWithinAnyRoot(input.cwd, policy.allowedRoots)) {
    throw new Error(`REMOTE_EGRESS_ROOT_DENIED: cwd is outside the remote-egress root allowlist`);
  }
  return input.dataClassification;
}

/** Workboards currently provide only a local cwd, not an accessible artifact bundle. */
export function assertCooperativeAgentCompatible(adapter: AgentAdapter): AgentAdapter {
  if (adapter.bin && !adapter.capabilities.sandbox) {
    throw new Error(`COOPERATIVE_AGENT_INCOMPATIBLE: ${adapter.id} cannot enforce read-only local execution`);
  }
  const capabilities = adapter.capabilities as AgentAdapter["capabilities"] & {
    directRemoteApi?: boolean;
    remote?: boolean;
    localFilesystem?: boolean;
    independentLocalCodeReview?: boolean;
  };
  // `remote` is retained as a compatibility alias for older adapters. An
  // off-machine CLI backend is still cooperative when it can inspect the
  // canonical cwd under a read-only sandbox; a direct API without that local
  // evidence boundary is not.
  if ((capabilities.directRemoteApi ?? capabilities.remote ?? false) || capabilities.localFilesystem === false || capabilities.independentLocalCodeReview === false) {
    throw new Error(`COOPERATIVE_AGENT_INCOMPATIBLE: ${adapter.id} cannot independently inspect local workspace evidence; provide an approved accessible artifact workflow first`);
  }
  return adapter;
}

/** Fail before leasing work that the selected cooperative adapter cannot satisfy. */
export function assertWorkItemAgentCompatible(item: WorkItem, adapter: AgentAdapter): AgentAdapter {
  assertCooperativeAgentCompatible(adapter);
  if (item.requirements.filesystem !== "read-only") {
    throw new Error(`WORK_ITEM_AGENT_INCOMPATIBLE: ${adapter.id} cooperative execution requires filesystem=read-only; ${item.requirements.filesystem} cannot establish the local evidence boundary`);
  }
  if (item.requirements.network === "none" && adapter.capabilities.offMachineEgress) {
    throw new Error(`WORK_ITEM_AGENT_INCOMPATIBLE: ${adapter.id} can send prompt or workspace-derived content off-machine but item ${item.key} requires network=none`);
  }
  for (const name of item.requirements.capabilities) {
    if (!Object.prototype.hasOwnProperty.call(adapter.capabilities, name) || adapter.capabilities[name as keyof typeof adapter.capabilities] !== true) {
      throw new Error(`WORK_ITEM_AGENT_INCOMPATIBLE: ${adapter.id} does not advertise required capability ${name}`);
    }
  }
  return adapter;
}

export function normalizeManusBaseUrl(value: string, allowDevelopmentBaseUrl = false): string {
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error("invalid Manus baseUrl"); }
  if (url.username || url.password) throw new Error("Manus baseUrl must not contain credentials");
  if (url.search || url.hash) throw new Error("Manus baseUrl must not contain a query or fragment");
  if (allowDevelopmentBaseUrl) {
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    const loopback = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
    if (!loopback || (url.protocol !== "http:" && url.protocol !== "https:")) {
      throw new Error("development Manus baseUrl override is restricted to an HTTP(S) loopback endpoint");
    }
  }
  if (!allowDevelopmentBaseUrl) {
    const hostname = url.hostname.toLowerCase();
    const officialHost = hostname === "api.manus.ai" || hostname.endsWith(".api.manus.ai");
    if (url.protocol !== "https:" || !officialHost || url.port || (url.pathname !== "/" && url.pathname !== "")) {
      throw new Error("Manus baseUrl must be the HTTPS api.manus.ai endpoint (or its subdomain); set allowDevelopmentBaseUrl only for an isolated development endpoint");
    }
  }
  return url.toString().replace(/\/$/, "");
}

function isWithinAnyRoot(candidate: string, roots: string[]): boolean {
  const normalizedCandidate = normalizePath(candidate);
  return roots.some((root) => {
    const normalizedRoot = normalizePath(root);
    return normalizedCandidate === normalizedRoot || normalizedCandidate.startsWith(`${normalizedRoot}${sep}`);
  });
}

function normalizePath(value: string): string {
  return process.platform === "win32" ? value.toLowerCase() : value;
}
