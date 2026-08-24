export type SandboxMode = "read-only" | "workspace-write" | "full-access";

export interface AgentConfig {
  enabled?: boolean;
  bin?: string;
  defaultModel?: string;
  extraArgs?: string[];
  extraEnv?: Record<string, string>;
  credentialFile?: string;
  baseUrl?: string;
  allowDevelopmentBaseUrl?: boolean;
  /**
   * Manus v2 cannot disable account-default skills in task payloads. Enabling
   * this is an explicit operator acknowledgement of that provider-side scope.
   */
  acknowledgeAccountDefaultCapabilities?: boolean;
  /** Stable operator label for the reviewed Manus account/default-skill set. */
  accountCapabilityProfile?: string;
  sandboxCeiling?: SandboxMode;
}

export interface BridgeConfig {
  agents: Record<string, AgentConfig>;
  defaults: {
    timeoutSec: number;
    sandbox: SandboxMode;
    cwd?: string;
  };
  allowedRoots: string[];
  policy?: {
    sandboxCeiling: SandboxMode;
    remoteEgress: {
      enabled: boolean;
      allowedAgents: string[];
      allowedRoots: string[];
      allowedDataClasses: Array<"public" | "internal" | "confidential" | "restricted">;
    };
    cumulativeRemoteCost?: {
      currency: "USD";
      maxReservedCents: number;
    };
  };
  handoffMaxChars: number;
  stateDir: string;
  sessionLockWaitMs: number;
  sessionLockStaleMs: number;
  configPath: string;
  configSource: string;
}

export interface RunRequest {
  prompt: string;
  cwd: string;
  model?: string;
  sandbox: SandboxMode;
  timeoutMs: number;
  resumeSessionId?: string;
  extraArgs?: string[];
  extraEnv?: Record<string, string>;
}

export interface SpawnSpec {
  command: string;
  args: string[];
  stdin?: string;
  env?: Record<string, string>;
}

export interface RawProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  aborted: boolean;
}

export interface AgentResult {
  text: string;
  nativeSessionId?: string;
  exitCode: number | null;
  isError: boolean;
  stderr: string;
  timedOut: boolean;
  durationMs?: number;
  meta?: Record<string, unknown>;
}

export interface AgentHealth {
  binary: { ok: boolean; version?: string; error?: string };
  auth: { status: "authenticated" | "unauthenticated" | "unknown" | "not-applicable"; detail?: string };
  usable: boolean;
}

export interface AdapterCapabilities {
  resume: boolean;
  model: boolean;
  sandbox: boolean;
  structuredOutput: boolean;
  /** Bridge calls the provider over an API instead of launching a local process. */
  directRemoteApi: boolean;
  /** Prompt or workspace-derived content can leave the local machine. */
  offMachineEgress: boolean;
  /** @deprecated Compatibility alias for directRemoteApi. */
  remote?: boolean;
  /** Backend can independently inspect the canonical local cwd. */
  localFilesystem?: boolean;
  /** Backend can verify local-code evidence in the current cooperative workflow. */
  independentLocalCodeReview?: boolean;
}

export interface AgentAdapter {
  readonly id: string;
  readonly displayName: string;
  /** Present for adapters backed by a local subprocess. */
  readonly bin?: string;
  readonly versionArgs?: string[];
  readonly capabilities: AdapterCapabilities;
  buildSpawn?(req: RunRequest): SpawnSpec;
  parse?(raw: RawProcessResult): AgentResult;
  /** Execute directly when the backend is an HTTP API rather than a CLI. */
  execute?(req: RunRequest, options?: { signal?: AbortSignal }): Promise<AgentResult>;
  /** Check a non-subprocess backend without exposing credentials. */
  health?(options?: { signal?: AbortSignal }): Promise<AgentHealth>;
  parseAuth?(raw: RawProcessResult): AgentHealth["auth"];
  authSpec?(): SpawnSpec;
}

export interface BridgeTurn {
  index: number;
  agentId: string;
  prompt: string;
  response: string;
  isError: boolean;
  nativeSessionId?: string;
  startedAt: string;
  durationMs: number;
  exitCode: number | null;
  stderr: string;
  timedOut: boolean;
  meta?: Record<string, unknown>;
}

export interface NativeSessionPolicy {
  cwd: string;
  sandbox: SandboxMode;
  model?: string;
}

export interface BridgeSession {
  schemaVersion: 1;
  id: string;
  title: string;
  cwd: string;
  createdAt: string;
  updatedAt: string;
  revision: number;
  nativeSessions: Record<string, string>;
  nativeSessionPolicies: Record<string, NativeSessionPolicy>;
  lastSeenTurnByAgent: Record<string, number>;
  turns: BridgeTurn[];
}
