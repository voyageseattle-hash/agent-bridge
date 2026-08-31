# Live acceptance checklist

Copy this checklist into the release evidence packet. Use `pass`, `fail`, `blocked`, or `not-run`; do not turn an automated pass into a live or visual pass. For schema v2, the exporter-derived profile—not an operator-selected checklist—determines the required gates.

- [ ] **Durable evidence root:** a new private directory outside the Agent Bridge install root is recorded together with its intended packet ID.

## 1. Candidate identity and automation

- [ ] **Source identity:** clean commit SHA recorded.
- [ ] **Locked install:** `npm ci` completed from the lockfile.
- [ ] **Repository gate:** `npm run verify` passed; command, exit code, timestamp, and log reference recorded.
- [ ] **Production dependency audit:** `npm audit --omit=dev --audit-level=high` result recorded.
- [ ] **MCPB schema:** official validator passed against the candidate manifest.
- [ ] **Artifact identity:** bundle filename, byte count, SHA-256, runtime SHA-256, and release metadata agree.
- [ ] **Immutable operations integrity:** the exact readiness, cutover, rollback, inspection, registration, lock, and quiescence files are present; their installed hashes and byte counts match release metadata and their bundle bytes.
- [ ] **Immutable install:** candidate installed to a new `releases\<version+sha7>` directory without changing the live shim.
- [ ] **Installed MCP canary:** `scripts\canary-release.mjs --evidence-dir <durable-private-directory>` passed against the absolute immutable runtime; its `canary-evidence.json` hash/reference is recorded and source `dist` results are not substituted.
- [ ] **Capability profile:** a schema-v2 export derives `windows-local-core` or `windows-local-manus` from the exact hash-verified shared config; the descriptor's `expectedProfile` matches but does not select it. RC9 accepts only core.
- [ ] **Profile binding:** release ID, runtime SHA-256, config SHA-256, a sanitized capability projection (booleans plus remote-allowlist count), and `profileInputSha256` are recorded. Unknown agents, enabled Gemini, disabled Codex/Claude, or ambiguous Manus/remote-egress state are rejected.

## 2. Passive preflight

- [ ] `<candidate-release>\operations\inspect-install.ps1` output exported.
- [ ] Installed shared config exists and its canonical path/SHA-256 are recorded without exporting its contents; it is not confused with the source checkout's `config.example.json` or a config beside source `dist`.
- [ ] Every detected explicit or fallback config path, including registrations parsed from single-quoted TOML, resolves to the installed shared config with the same SHA-256. Any divergent fallback is a cutover blocker.
- [ ] State ACL audit is compliant. If repair was necessary, a new hash-pinned backup path outside state/install was supplied with `-ApplyStateAcl`; the receipt records its path/hash, `rollbackPolicy: forward-only-security-hardening`, and whether protection was invoked. Later cutover failure does not roll back a successful hardening.
- [ ] Codex, Claude Code, and every detected Claude Desktop registration target the stable shim.
- [ ] No registration pins a path below `releases\`.
- [ ] Candidate `--doctor --json` reports the intended runtime, config source/hash, sandbox, roots, and promotion status.
- [ ] Enabled-agent health contains no credential, prompt, transcript, or raw provider error leakage.

## 3. Immutable canary before promotion

- [ ] Provider-disabled artifact canary reports the expected version/runtime hash, all required tools, zero enabled providers, and `drift` or `marker-missing` promotion state.
- [ ] Fixed inert Manus and Gemini delegations both fail at the disabled adapter registry; the post-attempt record shows zero sessions, zero approvals, zero enabled providers, and no credential/provider/authentication path.
- [ ] **Installed Windows npm-shim canary:** the absolute immutable runtime, not source `dist`, launches a canonical static npm `.cmd` shim under a path containing spaces; hostile metacharacter arguments are preserved exactly and no injection sentinel is created.
- [ ] Shim, shared-config, and promotion-marker hashes are identical before and after the artifact canary.
- [ ] Canary uses a disposable allowed root and state directory.
- [ ] `list_agents` distinguishes installed, authenticated/reachable, and cooperative-ready capabilities.
- [ ] Codex completes one bounded read-only task and returns inspectable evidence.
- [ ] Claude Code completes one bounded read-only task and returns inspectable evidence.
- [ ] Resume and cross-agent handoff work with bounded, untrusted context.
- [ ] Cancellation stops a controlled long-running local task without a surviving child process.
- [ ] Output clipping returns an `output_ref`; paged retrieval reconstructs the expected output.
- [ ] A root escape and an over-ceiling sandbox request both fail closed.

For an accepted disposition, record the installed Windows canary as required `windows-npm-shim-installed-runtime` automated evidence. A source-only `test/win.test.mjs` result does not substitute for this installed-runtime check.

## 4. Manus capability profile

This section applies to `windows-local-manus`. RC9 recognizes that profile but refuses an accepted export because the current live harness is runtime-bound but not bound to the shared-config profile input. These checks are diagnostic until that contract exists; `blocked`, `not-run`, a service-maintenance note, or an accepted residual risk is not a substitute. Keep Manus disabled for an accepted RC9 release and do not manufacture paid or consequential work. A `windows-local-core` packet must state **“Manus disabled; not live-certified.”**

- [ ] Previously exposed Manus keys are revoked and only the replacement credential-file reference is present, **or** the operator's explicit refusal to rotate is recorded as an accepted residual risk. The refusal does not make credential hygiene pass.
- [ ] Manus remains disabled until remote-egress policy names the intended root, agent, and data class.
- [ ] The account's default Manus skills were reviewed, `agents.manus.acknowledgeAccountDefaultCapabilities` is explicitly `true`, and a stable non-secret `accountCapabilityProfile` names that review. Evidence states that the Manus API does not let Agent Bridge disable account defaults.
- [ ] New-task requests contain empty `connectors`, `force_skills`, and `task_references`; continuation requests set `clear_connectors: true` and empty `force_skills`/`task_references`. Evidence does not claim that these request fields override account-default capabilities.
- [ ] Before preview or authority consumption, local-only preflight rejects a missing/empty credential, missing capability acknowledgement/profile, unsupported model, or finalized prompt above the conservative 4,500 UTF-8 byte ceiling without contacting Manus or changing approval/budget state.
- [ ] Canary brief contains only reviewed `public` or sanitized `internal` data.
- [ ] The live harness preview used a new absolute durable evidence directory, created a 15-minute one-use ticket, and recorded `providerContacted: false`; no provider request, approval consumption, or state mutation occurred during preview.
- [ ] The execution command used the exact previewed ticket SHA-256; the ticket moved from pending to consumed before provider launch, replay was rejected, and the sanitized result remains in the same durable directory.
- [ ] `preview_turn_approval` is used for a context-injected Manus continuation/handoff; execution supplies the returned session revision and full approval-envelope digest.
- [ ] Evidence distinguishes `prompt_sha256` for the finalized outbound prompt from `payload_sha256` for the complete approval envelope. The envelope exposes and binds the provider endpoint, request-capability policy version, and non-secret account-capability profile; approval requests bind to the envelope hash, not merely the prompt hash.
- [ ] Fresh one-time exact-scope `remote_egress` approval is approved and consumed.
- [ ] Fresh one-time currency-bound `paid_or_unknown_cost` approval is approved and consumed for every call, including caller-estimated zero cost.
- [ ] `get_budget_status` reports the deliberate direct-remote ceiling and the expected pre-canary remaining amount.
- [ ] The canary reserves the approval's positive whole-cent maximum; an over-cap parallel request fails before provider launch and approval consumption.
- [ ] Evidence labels the reservation total as conservative approved-cost accounting, not actual provider billing or coverage of local CLI accounts.
- [ ] The private provider response used an exact 22-character alphanumeric Manus task ID. Public evidence records bridge session/lifecycle plus sanitized request/response correlation SHA-256 values, not the native task ID.
- [ ] A create-time 404 within the 15-second visibility grace is treated as pending. After that grace, message-list 404 plus successful task detail is `unknown`/resumable; only absence from both endpoints is `not_found`/non-resumable.
- [ ] Ordinary continuation sends only when the persisted provider state is `stopped`; `waiting` remains on the specialized confirmation path.
- [ ] A persisted `timed_out`, `aborted`, `error`, or `unknown` session is tested through `reconcile_manus_task` with explicit remote-egress consent, data classification, and the current session revision. Evidence shows GET-only polling, no `task.sendMessage`, and no provider stop request when the bounded local reconciliation window expires.
- [ ] Manus output makes no claim of inspecting local files.
- [ ] Provider error details and task output are sanitized before evidence export.
- [ ] A naturally occurring safe `waiting` event is inspected with `get_manus_waiting_action`, previewed without provider/state/approval effects, and resolved only through the matching fixed decision plus both exact approvals.
- [ ] The confirmation preview exposes and binds the provider endpoint, connector/default-skill capability-policy version, and non-secret account profile. Confirmation revalidates the live provider action before approval consumption or budget reservation; a stale action consumes neither.
- [ ] After successful live revalidation, the attempted-confirmation record is persisted immediately before the non-idempotent confirmation POST; a lost response therefore requires provider reconciliation rather than replay.
- [ ] Public tool output omits the Manus task ID, provider description, and dynamic confirmation schema; a stale revision/event and unsupported decision fail before confirmation POST.
- [ ] No paid or externally consequential waiting event is manufactured solely for acceptance testing.

For a future release that accepts `windows-local-manus`, record this as required `manus-waiting-action-canary` remote-service evidence. RC9 refuses accepted export for that profile. If no safe naturally occurring event occurs, record it `blocked`; do not manufacture a paid or externally consequential event.

## 5. Cooperative creator workflow

- [ ] The accepted creator workflow records two to four independent recommendation runs separately, including failures/invalid output. A single-agent Manus `brief` collection is valid advisory evidence but is not by itself multi-agent acceptance.
- [ ] Local Codex/Claude recommendations use `workspace` scope. Manus uses only `brief` scope; the brief is isolated from local-filesystem access, sanitized, and its `briefSha256` is retained independently of the full approval-envelope hash. Evidence does not describe `brief` as provider-side read-only or no-side-effect execution.
- [ ] P0/P1 findings have explicit accept, reject, or defer decisions with reasons.
- [ ] Accepted recommendations map to workboard items with dependencies, acceptance criteria, data class, capabilities, budgets, and evidence targets.
- [ ] Workboard execution remains read-only.
- [ ] Every accepted item has an independent reviewer different from its submitter.
- [ ] Rejected/failed items preserve attempt and review budgets across retries.
- [ ] Applied changes are made by one authorized integrator and revalidated on the resulting tree.
- [ ] Board reaches `completed` only when every item is accepted or deliberately canceled, then is archived with a reason.

## 6. Promotion and restarted clients

- [ ] Codex, Claude Code, Claude Desktop, and other MCP hosts are fully quit.
- [ ] `<candidate-release>\operations\inspect-install.ps1` reports `activeProcessCount: 0` immediately before switching.
- [ ] `<candidate-release>\operations\check-cutover-readiness.ps1` records repeated empty samples for Agent Bridge nodes and known Codex/Claude host families and descendants.
- [ ] The cutover is operator-run in a declared maintenance window; no watcher or unattended task invokes a mutation command.
- [ ] Prior release ID, runtime hash, and rollback location are recorded.
- [ ] `<candidate-release>\operations\configure-clients.ps1` dry-run reports only expected changes and no ambiguity.
- [ ] `<candidate-release>\operations\cutover-release.ps1` reports both the registration backup and promotion backup after successful one-lock normalization and switch.
- [ ] Release switching used the refusing maintenance-shim barrier, rechecked zero active processes while the barrier was active, and recorded no recovery event.
- [ ] Cutover rechecked full host-family quiescence before registration writes, before switching, and behind the maintenance barrier; any nonempty or failed process query refused or restored the transaction.
- [ ] Promotion backup records exact prior shim, config, and marker bytes or explicit marker absence.
- [ ] Before any client restart, `scripts\canary-live-pointer.mjs` passed through the current stable shim with exact release, version, reviewed source-Git, metadata, manifest, runtime, shim, and shared-config hashes plus a new external evidence directory. Those reviewed identity values came from the reviewed install/package record. `strict` is limited to RC9; `rollback-minimum` is limited to historical `0.2.1+4785d63`.
- [ ] The pointer-only evidence validates every metadata-pinned immutable payload and the manifest/runtime identity, exact marker/shim/config binding, and a sanitized `windows-local-core` projection: Codex/Claude enabled; Gemini/Manus/direct remote egress disabled; direct-remote allowlist empty.
- [ ] The pointer-only gate performed only MCP initialization and tool discovery, forwarded no ambient Agent Bridge selector or provider/credential override, attempted zero delegations, observed no session-record drift, and recorded identical shim/config/marker hashes before and after. Its evidence contains no raw config, credentials, roots, provider details, or session contents.
- [ ] Codex is restarted and passes `diagnose_install`, `list_agents`, and one read-only task.
- [ ] Claude Code is restarted and passes the same checks.
- [ ] Claude Desktop is restarted and passes the same checks.
- [ ] All three report the same runtime identity and shared config hash.
- [ ] A fresh post-cutover schema-v2 profile has the same config SHA-256, profile ID, sanitized capability projection, and `profileInputSha256` as the pre-promotion record. Any mismatch invalidates the packet and requires re-acceptance.
- [ ] Ignored RC5/RC6/RC7/RC8 bundles and their `.release-staging` directories were treated as historical artifacts and were not selected as RC9 promotion inputs.

## 7. Human creator acceptance

- [ ] A creator can describe an objective, receive multi-agent recommendations, and understand why they agree or differ.
- [ ] Approval prompts expose agent, root, action, data class, expiry, cost, one-time/reusable scope, finalized-prompt SHA-256, and complete approval-envelope SHA-256 before decision.
- [ ] Failed and blocked states explain the next safe action without hiding evidence.
- [ ] The creator can pause, resume, cancel, retry within remaining budget, complete, and archive a workboard.
- [ ] `npm run evidence:release` generated a self-contained sanitized JSON and Markdown evidence packet from the recorded inputs; both display the derived profile and disabled/not-certified integrations.
- [ ] The creator can identify the live release and execute the documented rollback without deleting either release.

## 8. Final disposition

- [ ] Run `npm run evidence:release -- --descriptor <absolute-descriptor.json> --output-dir <evidence-root>\<packet-id> --require-accepted`, then `npm run evidence:verify -- --packet-dir <absolute-packet-directory>`; record the JSON, Markdown, and manifest hashes. Do not assign an accepted disposition without this generated and verified packet.

Record exactly one outcome:

- [ ] **Accepted for the derived capability profile:** every profile-selected gate passed.
- [ ] **Accepted for the derived capability profile with explicit residual risks:** deviations are named, bounded, owned, do not waive a selected gate, and do not include a stop condition from [THREAT_MATRIX.md](THREAT_MATRIX.md).
- [ ] **Rejected:** candidate remains unpromoted or is rolled back.
