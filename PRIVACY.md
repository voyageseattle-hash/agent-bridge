# Privacy

Agent Bridge is a local stdio MCP server. It does not implement its own analytics or telemetry service. It does, however, coordinate tools that may send data to hosted model providers, and it stores operational records locally. Review these boundaries before enabling a backend or delegating workspace-derived content.

## Provider egress

- Codex, Claude Code, and Gemini are local command-line programs whose own provider and account policies control off-machine processing. Agent Bridge can pass prompts and bounded workspace context to those programs; it does not make their inference local.
- Manus is an optional direct HTTPS backend and is disabled by default. When enabled, Agent Bridge sends explicitly approved prompt text to the Manus API. Manus receives no Agent Bridge local-filesystem access. The bridge requests empty connectors and skills, but the provider API does not prove that account-default capabilities are disabled.
- Remote Manus calls require configured agent, root, and data-class allowlists plus fresh, exact-scope remote-egress and paid-or-unknown-cost approvals.

Do not delegate confidential, restricted, credential-bearing, or otherwise sensitive content unless the selected provider, account, and approval scope are appropriate for that data.

## Local records

Agent Bridge stores sessions, transcripts, approvals, workboards, leases, and optional approved-cost reservations under the configured `stateDir`. These records are plaintext and are not encrypted by Agent Bridge. Keep the state directory outside shared or source-controlled storage and protect it with operating-system access controls.

The bridge sanitizes public diagnostics and release-evidence exports, but sanitization is a bounded safeguard rather than permission to publish private state. Inspect every exported artifact before sharing it.

## Credentials

Credential values must not be committed to source control, embedded in MCP manifests, placed in prompts, or pasted into public evidence. Manus credentials should be stored in a user-only file. Child-process environments are allowlisted and scrubbed, but the selected backend still operates inside its own account and provider trust boundary.

## Operator control

Allowed roots, sandbox ceilings, enabled backends, remote data classes, approvals, and retention of local state are controlled by the operator. Disabling a backend stops new bridge delegations to it; it does not delete provider-side data or local records that already exist.

Security issues should be reported through [SECURITY.md](SECURITY.md), without attaching credentials, raw private transcripts, or unreviewed state archives.
