const COMMON_ENV = [
  "PATH", "PATHEXT", "SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP",
  "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
  "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "USERNAME", "USERDOMAIN",
  "LANG", "LC_ALL", "TERM", "COLORTERM", "NO_COLOR", "CI",
  "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
] as const;

const BACKEND_ENV: Record<string, readonly string[]> = {
  codex: ["OPENAI_API_KEY", "CODEX_HOME"],
  claude: ["ANTHROPIC_API_KEY", "CLAUDE_CONFIG_DIR"],
  gemini: ["GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"],
  manus: ["MANUS_API_KEY"],
};

export function sanitizedEnvironment(agentId: string, explicit: Record<string, string> = {}): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {};
  for (const key of [...COMMON_ENV, ...(BACKEND_ENV[agentId] ?? [])]) {
    if (process.env[key] !== undefined) result[key] = process.env[key];
  }
  for (const [key, value] of Object.entries(explicit)) result[key] = value;
  return result;
}
