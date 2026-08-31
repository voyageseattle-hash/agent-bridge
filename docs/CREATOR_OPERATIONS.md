# Agent Bridge creator operations

This guide is the operating path for a creator using Agent Bridge. Codex and Claude are the local adapter paths required by RC9's supported profiles; Manus is an optional remote integration and is not assumed active. It assumes an immutable Agent Bridge v0.3 release has already been installed. Do not use a source checkout or a development bundle as the live server.

## Choose the agent by evidence boundary

| Agent | Best role | What it can inspect | What it should produce |
| --- | --- | --- | --- |
| Codex CLI | Local integrator and implementation owner | Files under an allowed project root, within the configured sandbox ceiling | Focused changes, tests, local build evidence, and integration decisions |
| Claude Code CLI | Independent local review, alternative implementation, and regression analysis | Files under an allowed project root, within the configured sandbox ceiling | Findings tied to paths/commands, adversarial review, and acceptance evidence |
| Manus API | Remote product, workflow, research, and threat review of a sanitized brief | Only text or remote-accessible artifacts explicitly sent to the API; never the local workspace by implication | Advisory recommendations, external-facing critique, and checklist coverage |

Claude Desktop/Cowork login does not authenticate the `claude` CLI. Sign the CLI in separately. Manus is a remote service: enabling it does not give it local filesystem access.

For Codex-only work, use Codex directly. When `gpt-5.3-codex-spark` is available to the account, select it in Codex's model selector (or `/model` in the CLI) or launch `codex --model gpt-5.3-codex-spark`; routing Codex through Agent Bridge adds no benefit. Use Agent Bridge when Claude or another MCP host needs to delegate to Codex/other agents, or when the workflow needs shared cross-agent audit, approval, session, recommendation, and handoff records.

## Classify data before delegation

Use the most restrictive class that fits the whole payload, including paths, excerpts, screenshots, logs, and generated context.

| Class | Examples | Remote operating rule |
| --- | --- | --- |
| `public` | Published documentation, public website copy, released source | May be sent only when remote egress policy and a fresh scoped approval allow it |
| `internal` | Unpublished plans, ordinary source excerpts, non-sensitive project notes | Sanitize first; require explicit remote-egress approval |
| `confidential` | Client material, private business data, unreleased commercial assets | Prefer local agents; send remotely only after a specific risk decision and narrow approval |
| `restricted` | API keys, passwords, session tokens, private keys, recovery codes, regulated identity data | Do not send to any agent prompt or shared evidence; use only an abstract credential name there, and keep any actual file path in protected config or private operations evidence |

Classification is not declassification. Removing a filename does not make confidential content public. If a brief combines classes, use the highest class.

## Use approvals as a transaction boundary

A general instruction such as "finish the app" is not a reusable approval for external transmission, unknown cost, authority escalation, applying changes, or publishing. Use a scoped approval for each material action.

1. Describe one action and its expected outcome.
2. Bind the request to an exact **subject**, **action**, **data class**, canonical **root**, and **agent**.
3. Bind it to the complete approval envelope. `prompt_sha256` identifies the finalized outbound prompt; `payload_sha256` identifies the complete JSON envelope containing that prompt plus model, sandbox, timeout, continuity/context replay, fresh/resume mode, bridge session/revision, config-extension policy, provider endpoint, request-capability policy version, and non-secret account-capability profile. Approvals must use the preview-returned envelope hash, not prompt text or a locally reconstructed envelope. `request_approval` can hash a supplied envelope without persisting it; `preview_recommendation_approval` also returns `recommendation_payload_sha256` for the recommendation prompt and `brief_sha256` for the isolated brief. For a Manus continuation or handoff, call `preview_turn_approval` with the intended agent/prompt/session first because the bridge may inject transcript context that the caller cannot safely reconstruct. A new-session preview returns `session_revision: null`: call `delegate_task` without `session_id` and without `expected_session_revision`. For an existing session, pass its exact returned integer revision as `expected_session_revision` on execution.
4. State whether cost is estimated or unknown and its currency. Direct remote API calls always require `paid_or_unknown_cost`; a caller-supplied zero is not proof of a free task.
5. Set a short expiry. `remote_egress` and `paid_or_unknown_cost` are categorically one-time with `max_uses=1`; the bridge rejects reusable records before provider launch.
6. If `policy.cumulativeRemoteCost` is enabled, approve a positive maximum that resolves to whole USD cents. The bridge reserves the approval's full maximum—not a lower caller estimate—under the shared ledger lock before launch. Use `get_budget_status` to review committed and remaining cents. Unknown/zero costs are deliberately rejected in this mode. A reservation is not rolled back if later approval consumption or provider transport fails.
7. A human reviews the displayed scope through host form elicitation or the real-TTY `--approve <id>` fallback and explicitly approves or denies it.
8. The bridge consumes the matching approval when the action starts. A changed agent, root, action, data class, or outbound byte changes the digest and requires a new approval.
9. Export the request, decision event, budget snapshot, and final consumption state with the run evidence. A reservation remains committed after any outcome; it is not a claim about the final provider invoice.

Approval categories are `remote_egress`, `paid_or_unknown_cost`, `secrets`, `browser_or_connectors`, `authority_escalation`, `apply_or_merge`, and `deploy_or_publish`. An approval record is workflow evidence, not cryptographic proof of the human's identity. Never put a credential value in an approval reason or scope.

See [approval-request.example.json](../examples/approval-request.example.json) and [paid-approval-request.example.json](../examples/paid-approval-request.example.json) for the two one-time requests required when remote task cost is unknown. Remote execution expects the exact subject `agent-bridge:delegate_task` and action `delegate:<agent-id>`; descriptive alternatives do not match.

## Run the first normal remote Manus turn

Follow this section only when the derived release profile is `windows-local-manus` and Manus is explicitly enabled. RC9 treats that profile as diagnostic and refuses accepted export until live artifacts are bound to its shared-config profile input. A `windows-local-core` acceptance says **“Manus disabled; not live-certified”** and is not authority to enable the integration. This is the normal task-execution path. `preview_manus_confirmation` is **not** part of it; that tool is only for a task already paused in the provider's `waiting` state.

1. Run `list_agents` and confirm Manus is usable, is marked as a direct remote API, and is not represented as having local filesystem access.
2. Call `preview_turn_approval` with the exact Manus prompt, canonical allowed working root, model, sandbox, timeout, `allow_remote_egress=true`, and reviewed `data_classification`. It does not accept cost fields. Review the finalized prompt hash, complete approval-envelope hash, exact approval scope, provider/capability profile, budget result, and returned session revision. Preview is local-only.
3. Create two fresh one-use records from that exact returned scope and envelope: one `remote_egress` approval and one `paid_or_unknown_cost` approval. Use the returned `payload_sha256`, not only `prompt_sha256`; use the supplied examples rather than reconstructing scope labels.
4. Have the host/user explicitly decide both approval records. Re-preview if any execution input or the session revision changes.
5. Call `delegate_task` with the same execution inputs, both approval IDs, `allow_remote_egress=true`, the same data classification, and the execution cost fields (`estimated_cost` and `estimated_currency`) covered by the paid approval. For a new-session preview, omit `session_id` and `expected_session_revision`; for an existing session, pass that same session ID and its exact preview-returned integer `expected_session_revision`. With the cumulative breaker enabled, the approved maximum is reserved before provider launch and is not replenished after any outcome.
6. Inspect the returned bridge session and use `get_turn_output` when the inline response is clipped. If the result is `waiting`, use the separate fixed-decision flow below. If it is `unknown`, `timed_out`, `aborted`, or `error`, reconcile instead of resending the prompt.

## Resolve a safe Manus waiting action

1. Call `get_manus_waiting_action` with the bridge session ID. It reads persisted sanitized state only; it does not contact Manus or reveal the native task ID.
2. Choose only the matching fixed decision: `browser_skip`, `email_save_draft`, `video_standard`, or `high_credit_reject`.
3. Call `preview_manus_confirmation` with the bridge session ID, event ID, decision, `allow_remote_egress=true`, and the reviewed data classification. This contacts no provider and changes no state. Review the returned execution envelope: it exposes and binds the provider endpoint, connector/default-skill capability-policy version, and non-secret account profile.
4. Request two fresh approvals using the exact returned scope: `remote_egress` plus the returned action category. For standard video, approve a positive whole-cent USD maximum compatible with the cumulative budget. High-credit rejection requires an exact zero-USD cost approval and reserves no budget.
5. Have the host/user explicitly approve both records. Pass both IDs and the returned session revision to `confirm_manus_action`.
6. The bridge revalidates local state, then re-reads the live provider action **before** consuming authority or reserving budget. If it still matches, the bridge commits authority, persists the attempted-confirmation record immediately before the non-idempotent POST, posts the fixed input, records provider acceptance, and resumes polling. A revision/event/input/provider-action change requires a new preview and new approvals; a stale live action consumes neither approval nor budget.

The bridge never reflects Manus's dynamic `confirm_input_schema` or `waiting_description`. It refuses user-question replies, secret requests, browser selection, actual email sends, premium video, accepting high-credit work, deploy/terminal/calendar/marketing actions, OAuth renewal, and persistent grants. The provider contract is documented in [task.listMessages](https://open.manus.ai/docs/v2/task.listMessages), [task.confirmAction](https://open.manus.ai/docs/v2/task.confirmAction), and the [task lifecycle](https://open.manus.ai/docs/v2/task-lifecycle).

A future release that accepts `windows-local-manus` requires a passing `manus-waiting-action-canary` remote-service record. RC9 refuses accepted export for that profile. If no safe naturally occurring waiting event exists, record the gate as blocked; never create paid or externally consequential work merely to make this gate pass.

## Reconcile an unresolved Manus task

Use reconciliation after a persisted Manus turn ends as `timed_out`, `aborted`, `error`, or `unknown`. Do not retry the prompt: that could create duplicate provider work.

1. Read the bridge session and record its current revision.
2. Call `reconcile_manus_task` with the session ID, that exact revision, `allow_remote_egress=true`, the reviewed data classification, and a one-to-300-second local timeout.
3. The bridge performs GET-only provider polling. It does not send another user message, consume task-execution approvals, or widen a waiting action.
4. If the local window expires, the bridge records the task as still `unknown` and sends no provider stop request. Read the new session revision before another reconciliation attempt.
5. If reconciliation reports `waiting`, use the fixed-decision confirmation flow above. If it reports `stopped`, ordinary continuation is available. A stale revision fails before provider polling.

Reconciliation is remote access, so the configured remote-egress policy, explicit consent, and data classification still apply. It is not a provider cancel operation and does not prove that the prior task was free or side-effect-free.

## Turn recommendations into accepted work

Use this loop instead of asking every agent to edit the same tree.

1. Write one objective plus measurable acceptance conditions.
2. Run `collect_recommendations` against two to four unique local agents for `workspace` scope. An isolated `brief` collection accepts one to four unique no-filesystem agents, allowing a single Manus review without pretending that a local backend was isolated from the real workspace.
3. Use `workspace` scope for local Codex/Claude inspection. The bridge rejects `brief` scope for any backend with local-filesystem capability. Use `brief` only for Manus after isolating and sanitizing the text; retain its `briefSha256` separately from the recommendation-prompt and full approval-envelope hashes. This proves only that Manus receives no Agent Bridge local-filesystem capability; it does not enforce provider-side read-only or no-side-effect behavior.
4. Preserve each run status. Schema 2 `partial-output` means at least one strict recommendation item was retained while one or more malformed siblings were omitted; inspect `invalidRecommendationCount`, the bounded path-only `invalidRecommendations`, and the run detail before using valid items. `invalid-output` means no usable recommendation survived. Neither status authorizes an automatic remote retry. Aggregation combines only matching normalized title/change pairs; a shared title with a different proposed change remains a separate variant and is not consensus.
5. Triage the combined results: **P0** blocks release, **P1** is high risk/value, **P2** is useful, and **P3** is polish. Source count helps corroboration but does not replace technical evidence.
6. Convert only accepted recommendations into dependency-aware workboard items. Give every item an owner-independent acceptance criterion, data class, filesystem/network requirement, budget, and evidence target.
7. Run each work item read-only. An `implementation` item may produce a patch plan or artifact, but cooperative workboards do not authorize parallel writes.
8. Have a different agent review the submission. Rejection consumes review budget and returns the item for a bounded retry when budget remains.
9. Apply an accepted change through the local integrator under the configured sandbox and any required `apply_or_merge` approval.
10. Re-run the acceptance check on the changed tree, then complete and archive the workboard.

Reusable inputs and outputs are in [creator-workboard.example.json](../examples/creator-workboard.example.json) and [recommendation-collection.example.json](../examples/recommendation-collection.example.json).

## Configure clients safely on Windows

All clients should point to the stable shim and shared config, never directly to `releases\<release-id>`.

First select the installed immutable candidate and preview the exact registration state. Dry-run is the default:

```powershell
$candidate = "$env:USERPROFILE\.codex\agent-bridge\releases\<release-id>"
& "$candidate\operations\configure-clients.ps1"
```

Review every reported path, state, planned action, error, and active process. The script covers Codex, Claude Code, and detected Claude Desktop locations while preserving unrelated configuration, including single-quoted TOML values. Distinguish the installed shared config from the source checkout's example or a config beside source `dist`. Any explicit or fallback config whose canonical path or SHA-256 differs from the installed shared config blocks cutover even if no current registration selects it. Preserve a divergent fallback's exact bytes and hash in a reviewed protected backup outside the fallback location before deliberately moving it aside; release automation must not delete or relocate it. Audit the state ACL before transaction: omit `-ApplyStateAcl` when compliant; if noncompliant, provide a nonexisting absolute `-StateAclBackupPath` outside state and install, obtain explicit operator authorization, then add `-ApplyStateAcl`. A successful hardening is forward-only security hardening: later registration/promotion failure retains the hardening and receipt-backed external snapshot; only `protect-state.ps1 -RestoreFrom <backup> -ExpectedBackupSha256 <lowercase-sha256>` may explicitly restore it. An ambiguous registration must be resolved deliberately; do not overwrite it by hand from a guessed example.

For a release cutover, do not run standalone `-Apply`. Fully quit every MCP host, verify repeated host-family quiescence, and use the one-lock transaction:

```powershell
& "$candidate\operations\check-cutover-readiness.ps1"
$stagedConfig = 'C:\absolute\private-evidence\staged-core-config.json'
$expectedConfigSha256 = '<lowercase-sha256>'
$stateAclBackup = 'C:\absolute\private-evidence\state-acl-before-rc9.json'
& "$candidate\operations\cutover-release.ps1" `
  -ReleaseId '<version+sha7>' `
  -StagedConfigPath $stagedConfig `
  -ExpectedConfigSha256 $expectedConfigSha256 `
  -ApplyStateAcl `
  -StateAclBackupPath $stateAclBackup
```

The complete command above is the current maintenance-window form because the known live ACL is noncompliant. If the immediately preceding audit is compliant, omit only `-ApplyStateAcl` and `-StateAclBackupPath`; never omit the staged core config or its exact SHA-256 for RC9 acceptance. The readiness command checks Agent Bridge nodes plus known Codex/Claude host processes and descendants across multiple samples. It never closes an app. A background watcher may notify you that the system appears ready, but it must never run a cutover automatically. The cutover command rechecks under its install lock, establishes a refusing startup barrier, and restores registrations and release pointers if promotion fails. Record both returned backup paths.

To preview a registration restore, omit `-Apply`; to perform it in a deliberate recovery window after all hosts are closed:

```powershell
& "$candidate\operations\configure-clients.ps1" -RestoreFrom '<backup-path>'
& "$candidate\operations\configure-clients.ps1" -RestoreFrom '<backup-path>' -Apply
```

Registration changes are loaded at host startup. Reopen one host after a successful cutover, run the installed-runtime canary, and reopen the others only after it passes.

For one compact local-only view after startup, run `get_creator_status`. It aggregates runtime/config state, configured capabilities, approved-cost reservations, and a mutation-free sample of at most 200 session, approval, and workboard records without launching a CLI or contacting a provider. Read `scanned`, `truncated`, and `unreadable` literally: they are bounded sampling evidence, not unbounded totals. A truncated or unreadable sample forces `needs-attention`. Backend health is deliberately separate; run `list_agents` only when a live authentication/reachability check is intended. Use the dedicated session, approval, and workboard tools for complete operational decisions. The status view omits IDs, titles, working directories, approval narratives, provider-native IDs, and transcript contents.

## Resolve the Manus credential and account capability boundary

Any Manus key pasted into chat, source, logs, a prompt, or an approval record is compromised.

1. In the Manus account API settings, revoke the exposed key before using the backend. If the operator explicitly refuses rotation, record the exposed credential as an accepted residual security risk; credential hygiene remains not-passed.
2. When rotating, create a replacement key and do not paste it into an agent conversation.
3. Run `.\scripts\setup-manus.ps1` and enter the active key through its intended secret-input flow.
4. Confirm the credential file is outside the repository and has a user-only ACL.
5. Review the account's default Manus skills, then set `agents.manus.acknowledgeAccountDefaultCapabilities` to `true` and give that review a stable non-secret `accountCapabilityProfile` label. The API does not let Agent Bridge enumerate or disable account defaults, so the backend remains unusable/unknown until both values are explicit. Changing the endpoint, connector/default-skill policy version, or profile label changes the approval envelope and requires new approvals.
6. Select a supported model (`manus-1.6`, `manus-1.6-lite`, or `manus-1.6-max`) and keep the finalized outbound prompt within the bridge's conservative 4,500 UTF-8 byte ceiling. The local-only preflight rejects credential, acknowledgement, model, and prompt-size problems before approval consumption or provider contact.
7. Keep `agents.manus.enabled` and remote egress disabled until the policy allowlists the intended agent, canonical root, and data class.
8. Configure a deliberate `cumulativeRemoteCost.maxReservedCents` ceiling and review `get_budget_status`; do not enable a remote provider with an accidental unlimited local policy.
9. Request fresh `remote_egress` and positive bounded `paid_or_unknown_cost` approvals before the first live task.
10. Start with a sanitized `public` or `internal` brief. New tasks request empty connectors, forced skills, and task references; continuations request connector clearing plus empty forced skills/references. These fields do not override account defaults.
11. Confirm that the private native ID is exactly 22 alphanumeric characters. Public output and evidence should use the bridge session/lifecycle plus sanitized request/response correlation SHA-256 values, not the task ID. Treat a message-list 404 during the 15-second creation grace as pending; afterward, successful task detail means `unknown`/resumable, while absence from both endpoints means `not_found`/non-resumable. API acceptance is not proof of useful completion.
12. Ordinary continuation sends a new message only when the persisted task state is `stopped`. A `waiting` task must use the specialized fixed-decision confirmation path. Use `reconcile_manus_task`, not another prompt, for a persisted `timed_out`, `aborted`, `error`, or `unknown` result.

Never test a disclosed key by creating a paid task. If the operator explicitly refuses rotation, record that as an accepted residual security risk, keep the key only in the ACL-protected credential file, and do not represent credential hygiene itself as a passing check.

## Restart, canary, and live acceptance

Installation, registration, authentication, capability selection, and functional delegation are separate gates. Follow [LIVE_ACCEPTANCE.md](LIVE_ACCEPTANCE.md). Create an operator-controlled evidence root outside the install root and protect its ACL separately, run the installed canary with `--evidence-dir`, retain each required live result as hash-pinned sanitized structured JSON inside that root, and let `npm run evidence:release` derive the profile from the exact shared-config bytes and generate the paired JSON and Markdown reports. Verify the packet with `npm run evidence:verify`; do not hand-edit an accepted packet. Changing enabled agents, remote-egress state/allowlist, the Manus endpoint, or the non-secret account-capability profile changes the config hash and requires a new packet.

The minimum local sequence is:

```powershell
& "$candidate\operations\inspect-install.ps1"
node "$env:USERPROFILE\.codex\agent-bridge\agent-bridge.mjs" --doctor --json
```

Then, from each restarted host, run `diagnose_install`, `list_agents`, and one disposable read-only task for each enabled local backend. Re-export and confirm that the post-cutover profile ID and `profileInputSha256` match the pre-promotion values. For the core profile, the exporter derives and records the capability state from the hash-verified shared config at export time, while the disposable provider-disabled canary independently verifies the exact runtime's adapter-registry rejection behavior; do not claim the canary ran under the shared config. For diagnostic Manus work, use the durable one-use harness after credential setup:

```powershell
$env:AGENT_BRIDGE_SERVER_PATH = "$candidate\server\agent-bridge.mjs"
$env:AGENT_BRIDGE_INSTALL_ROOT = "$env:USERPROFILE\.codex\agent-bridge"
$env:AGENT_BRIDGE_EXPECTED_VERSION = '0.3.0-rc.9'
$env:AGENT_BRIDGE_EXPECTED_RUNTIME_SHA256 = '<recorded-runtime-sha256>'
$env:AGENT_BRIDGE_LIVE_REQUIRED = '1'
npm run test:live:manus -- --evidence-dir 'C:\absolute\durable-evidence-root\manus-live'
# Review preview-result.json and the exact confirmation SHA-256. Preview contacts no provider.
npm run test:live:manus -- --execute --evidence-dir 'C:\absolute\durable-evidence-root\manus-live' --confirm-ticket-sha256 '<exact-preview-digest>'
```

The preview creates a 15-minute ticket bound to runtime, credential file, prompt, model, timeout, data class, capability policy, budget maximum, and evidence paths. Execution atomically consumes it before provider launch; replay must fail. Keep `preview-result.json`, `consumed-ticket.json`, `ticket-consumption.json`, and `result.json` in that durable directory. If the operator accepted a disclosed-key risk instead of rotating, record that as an explicit residual risk rather than a credential-hygiene pass. Automated tests do not prove CLI login, remote credits, Desktop registration, or visible creator workflow quality.

## Roll back without deleting evidence

Before production cutover, rehearse candidate → prior → candidate against a disposable install outside the repository and live install. Supply both exact bundle hashes and a brand-new private evidence directory:

```powershell
.\scripts\rehearse-rollback.ps1 -CandidateBundlePath '<candidate.mcpb>' -ExpectedCandidateBundleSha256 '<sha256>' -PriorBundlePath '<prior.mcpb>' -ExpectedPriorBundleSha256 '<sha256>' -EvidenceDir 'C:\absolute\private-evidence\rollback-rehearsal'
```

The source-only wrapper never edits client registrations or accepts a live install root. It verifies both bundles, uses a valid provider-disabled fixture config, exercises the fixture stable shim and MCP handshake at all three pointer states, and writes hashed command/pointer evidence. Its trusted switch primitive still enforces global MCP-host quiescence, so fully quit Codex and Claude before the rehearsal. A disposable rehearsal does not replace the post-cutover live rollback drill.

1. Fully quit all MCP hosts.
2. Confirm `activeProcessCount` is zero with `<trusted-release>\operations\inspect-install.ps1`.
3. Prefer switching to the prior immutable release with `<trusted-release>\operations\switch-release.ps1 -ReleaseId <prior-version+sha7>`. Use the newest verified operational script bytes even though the target runtime is older. For emergency backup restore, restore shim, config, and promotion marker together according to `rollback-state.json`; remove the marker when the backup records prior absence.
4. Before restarting a host, run the pointer-only gate through the restored stable shim. `rollback-minimum` accepts only the exact historical `0.2.1+4785d63` source identity, and every hash must come from the reviewed install/package record or the just-completed switch receipt:

   ```powershell
   node .\scripts\canary-live-pointer.mjs --release-path '<absolute-prior-release-path>' --install-root '<absolute-install-root>' --expected-version 0.2.1 --expected-source-git-sha 4785d630c416df692869540a52466c9895cfa6d6 --expected-runtime-sha256 '<reviewed-runtime-sha256>' --expected-metadata-sha256 '<reviewed-metadata-sha256>' --expected-manifest-sha256 '<reviewed-manifest-sha256>' --expected-stable-shim-sha256 '<switch-receipt-shim-sha256>' --expected-shared-config-sha256 '<switch-receipt-config-sha256>' --evidence-dir 'C:\absolute\private-evidence\rollback-pointer-canary' --profile rollback-minimum
   ```

5. Restart one host only after that gate passes, verify runtime identity and hash, then run one read-only live canary. Use `diagnose_install` when the restored release provides it; for v0.2.1, verify immutable metadata/runtime hashes plus the MCP initialization version, then invoke `list_agents` and a disposable read-only delegation.
6. Restart the remaining hosts only after the live canary passes.
7. Preserve both releases, the failed artifact, hashes, sanitized logs, workboard/recommendation exports, and rollback record. Do not copy credentials or raw confidential transcripts into a report.

## Evidence packet

Use [EVIDENCE_CONVENTIONS.md](EVIDENCE_CONVENTIONS.md), [the exporter descriptor example](../examples/evidence-export-descriptor.example.json), [evidence-report.example.json](../examples/evidence-report.example.json), and [evidence-report.example.md](../examples/evidence-report.example.md). The sequence is durable canary output, retained live results, provisional promotion, restarted-client checks, `npm run evidence:release -- --descriptor <absolute-descriptor.json> --output-dir <evidence-root>\<packet-id> --require-accepted`, then `npm run evidence:verify -- --packet-dir <absolute-packet-directory>`. A release is accepted only for the profile derived from its exact config and only when every selected item passes. `blocked`, `failed`, `not-run`, profile/config drift, or an asserted check without a pre-recorded hash and retained artifact prevents acceptance; residual risks do not waive selected gates.

Ignored RC5/RC6/RC7/RC8 bundles and their `.release-staging` directories are historical artifacts only; never use them as RC9 release inputs.
