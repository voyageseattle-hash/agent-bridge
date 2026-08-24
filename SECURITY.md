# Security policy and operating model

## Security boundary

Agent Bridge is a local MCP server that launches configured local CLIs or calls the Manus API. It does not make remote agents local. The server is safe only to the extent that its MCP host, configuration, allowed roots, enabled agents, and selected sandbox are trusted.

- A configuration file is required and must contain at least one existing `allowedRoots` entry. Invalid or absent config fails closed.
- Roots and task working directories are resolved to canonical paths; a pre-launch check rejects paths outside those roots, including a junction/symlink that resolves outside.
- Default sandbox is `read-only`. Codex and Claude receive mode-specific flags. Caller requests are rejected above the global or per-agent sandbox ceiling. Legacy configs default to a `workspace-write` ceiling; `full-access` requires an explicit full-access ceiling in configuration.
- Gemini cannot provide the read-only guarantee and rejects a read-only request. Keep it disabled unless its CLI and authorization scope are acceptable.
- Codex, Claude, and Gemini are locally launched CLIs whose prompts and workspace-derived content can leave the machine for their hosted providers. This off-machine egress is governed by each CLI/account/provider policy and is outside the bridge-managed direct-API approval gate. Capability output distinguishes `offMachineEgress` from `directRemoteApi`; do not interpret a local subprocess as local-only inference.
- Manus is remote HTTP API execution, has no local filesystem access, and cannot receive a bridge sandbox. Its credential is sent only to HTTPS `api.manus.ai` or its subdomains; an explicit development override is restricted to loopback HTTP(S). Do not delegate tasks that require local inspection or edits to Manus without providing safe, remote-accessible input.
- Direct remote API execution has four gates: configuration must enable and allowlist the backend, canonical root, and data class; each call must explicitly consent to egress and label the data; an exact-scope `remote_egress` approval must be approved and consumed; and every call requires a separate currency-bound `paid_or_unknown_cost` approval because a tool caller cannot prove provider cost is zero. Both remote categories must be fresh, one-time records with `maxUses=1`; creation, approval, bridge preflight, and consumption reject reusable authority. The approval scope binds subject `agent-bridge:delegate_task`, action `delegate:<agent-id>`, canonical root, agent, data class, and the SHA-256 of the exact finalized outbound prompt. `preview_turn_approval` derives that scope for context-injected continuations/handoffs without provider execution or state mutation; its session revision guard makes a changed transcript require another preview. Omitted, expired, reused, payload-mismatched, stale-revision, or insufficient approvals fail closed. Never classify credentials or other restricted data as a lower class to bypass policy.
- When `policy.cumulativeRemoteCost` is configured, a dedicated state-wide ledger reserves the approved maximum in positive whole USD cents before approval consumption and provider launch. The token-owned lock spans sessions, reservations are monotonic, and failures never release them. This prevents declared-cost oversubscription but does not prove or reconcile actual billing and does not cover Codex/Claude/Gemini CLI account usage. A malformed, unknown-version, or initialized-but-missing ledger blocks covered launches. Reservation before approval consumption is deliberately fail-safe for spend and can reduce availability by burning a reservation when a subsequent local approval mutation fails.
- The budget lock is deliberately never auto-reclaimed. Automatic recovery cannot fence a paused prior process from resuming and overwriting a newer reservation. If its owner crashes, stop every bridge host before removing only `stateDir\budget-locks\cumulative-remote-cost.lock`; deleting it while any host is live invalidates the spend guarantee.
- Cooperative workboard execution and review are always forced to `read-only`. Separate session locks do not prevent concurrent edits to the same files, so cooperative writes remain unsupported. Remote Manus is not cooperative-ready for local-code workboards because the current workflow has no accessible, hash-verified artifact bundle.
- Public `list_agents` provider/CLI details are control-character stripped, credential-pattern redacted, and length bounded before text or structured output is returned. This reduces accidental disclosure; it is not a general secret scanner.

## Credentials and subprocesses

The bridge invokes the Codex, Claude Code, and Gemini CLIs from `PATH`. Claude authentication is the **Claude Code CLI's** own login/OAuth/keychain state; Claude Desktop or Cowork authentication does not authenticate the `claude` executable. The child environment is sanitized rather than inheriting arbitrary environment variables.

For Manus, use `scripts/setup-manus.ps1` to create a per-user credential file with restricted ACLs, or set `MANUS_API_KEY` only in the bridge process environment. The key is read into memory for HTTPS requests and is not intentionally written to session files, health output, or packages. Do not add keys to `config.json`, prompts, or `manifest.json`.

If a key is pasted into chat, logs, source, or another disclosure surface, treat it as compromised: revoke/rotate it in Manus before enabling the backend. Do not validate a disclosed key by creating paid tasks. The MCPB file picker accepts a credential-file path, never the credential value itself.

## Transcript retention

Session files are plaintext JSON. They retain prompts, agent responses, stderr tails, paths, native IDs, and timing/usage metadata. File mode is requested as owner-only where supported, but OS/account policy remains the real protection. Set `stateDir` to a protected per-user directory, apply your retention policy outside the bridge, and never assume transcript output is secret-safe.

On Windows, `scripts/inspect-install.ps1` reports whether the state directory has protected inheritance and lists unexpected allow identities. `scripts/protect-state.ps1` can recursively replace inherited rules with explicit full control for the current user, SYSTEM, and Administrators. This is a material ACL change: inspect the exact state path and run it only during an approved maintenance window.

Client-registration apply/restore and release switching share an install-scoped exclusive mutation lock. The release switch additionally replaces the stable shim with a temporary refusing barrier before its final zero-host scan, so a host racing the old shim is detected and forces exact restoration. Promotion backups include shim, config, and marker bytes or marker absence; do not restore only a shim/config while retaining a newer marker.

The refusing shim cannot fence a host that cached a previously registered direct immutable-runtime command. Cutover therefore also requires repeated absence of Agent Bridge processes and known Codex/Claude host families and descendants in an operator-declared maintenance window. This is an operational quiescence control, not an OS execution policy. Watchers may notify but must never promote automatically, and the bridge never terminates a host to manufacture readiness.

Windows batch files are also a shell boundary: `.cmd`/`.bat` arguments can be reparsed as commands. Agent Bridge never sends backend prompts, models, roots, or configured extension arguments through `cmd.exe`. It resolves only a canonical static npm `.cmd` shim's single contained `node_modules` entry point and launches that entry with the bridge's own Node executable; dynamic/custom `.cmd` files and all `.bat` launchers are rejected. Configure the underlying executable when a CLI uses another batch wrapper.

Workboards, approval ledgers, and the cumulative direct-remote budget ledger are also plaintext JSON under `stateDir/workboards`, `stateDir/approvals`, and `stateDir/budgets`. They can contain objectives, instructions, submissions, evidence, risks, review rationale, bridge session IDs, approval scope, actors, reasons, and cost/reservation metadata and inherit the same disclosure and retention boundary. The initialization marker detects ledger-only deletion, but a local principal able to remove both files can deliberately reset the accounting domain; ACL protection and offline backup remain part of this control.

`get_session` projects out native IDs and metadata and clips returned fields. This limits MCP exposure only; it does not redact the underlying session file or remove sensitive data from previous backend services.

## Session integrity and availability

Session writes use a temporary file and atomic rename plus revisions. Per-session locks prevent concurrent turns. A heartbeat updates locks; stale locks are reclaimed only after the configured threshold. A process crash can leave a lock until it becomes stale. Do not manually delete a lock for an actively running process.

## Experimental daemon transport status

The daemon/proxy source implements local IPC only, mutual HMAC/config-fingerprint binding, strict handshake state, exclusive endpoint binding, bounded connections/in-flight requests, correlation, disconnect cancellation, and explicit lifecycle. It is not connected to MCP or included as a release entrypoint, and importing it has no startup side effect.

Unix sockets are changed to mode `0600`. Node's `net` API cannot configure or verify a user-only Windows named-pipe ACL or expose peer identity; the runtime reports this as unverified and offers a fail-closed authorization hook. Do not deploy it on Windows until external ACL provisioning and verification are implemented. Never expose the internal RPC transport on TCP or treat the HMAC capability token as a substitute for endpoint ACL enforcement. Capability tokens must be generated randomly, stored outside source/config/transcripts, and rotated after suspected exposure.

## Reporting a vulnerability

Do not open a public issue containing a credential, private transcript, or reproduction that grants access to a system. Report the affected version, platform, minimal safe reproduction, and impact to the maintainer through the private channel established for this project.
