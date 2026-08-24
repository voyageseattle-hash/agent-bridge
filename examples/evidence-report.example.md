# Agent Bridge release evidence

**Packet:** `agent-bridge-0.3.0-rc.7-example`
**Disposition:** candidate-ready-promotion-blocked
**Machine record:** `evidence-report.example.json`
**Machine-record SHA-256:** `<compute after final export>`

## Candidate

| Field | Value |
| --- | --- |
| Version | `0.3.0-rc.7` |
| Source commit | `0123456789abcdef0123456789abcdef01234567` |
| Immutable release | `0.3.0-rc.7+0123456` |
| Live at start | `0.2.1+4785d63` |
| Live at end | `0.2.1+4785d63` |
| Bundle SHA-256 | `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` |
| Runtime SHA-256 | `cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc` |
| Config SHA-256 | `dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd` |

This is a truthful blocked template, not an accepted packet. RC6 has not been promoted; ignored RC5 bundles and `.release-staging\agent-bridge-v0.3.0-rc.5` directories are historical artifacts, not RC6 inputs.

## Gate results

| Check | Gate | Status | Reason |
| --- | --- | --- | --- |
| `repository-verify` | automated | not-run | No hash-pinned RC6 verification log is attached |
| `production-dependency-audit` | automated | not-run | No production audit evidence is attached |
| `mcpb-manifest-validation` | automated | not-run | No official validator evidence is attached |
| `immutable-operations-integrity` | automated | not-run | Installed operation hashes and bytes are unverified |
| `installed-provider-disabled-canary` | automated | not-run | Immutable installed-runtime canary not run |
| `windows-npm-shim-installed-runtime` | automated | not-run | Installed Windows npm-shim canary not run |
| `codex-installed-runtime` | local-cli | not-run | No signed-in Codex result attached |
| `claude-installed-runtime` | local-cli | not-run | No signed-in Claude Code result attached |
| `registration-normalization` | client-restart | blocked | Stable-shim targeting and zero shared-versus-fallback config divergence are unproven |
| `release-promotion` | client-restart | blocked | Stable shim remains on `0.2.1+4785d63` |
| `manus-remote-canary` | remote-service | blocked | No provider call or one-use ticket consumption occurred |
| `manus-waiting-action-canary` | remote-service | blocked | No safe naturally occurring waiting event was available; none was manufactured |
| `codex-restarted-client` | client-restart | not-run | RC6 not promoted/restarted |
| `claude-code-restarted-client` | client-restart | not-run | RC6 not promoted/restarted |
| `claude-desktop-restarted-client` | client-restart | not-run | RC6 not promoted/restarted |
| `creator-visible-acceptance` | human-visible | not-run | Creator-visible workflow acceptance not run |
| `rollback-canary` | automated | not-run | RC6 rollback canary not run |

## Manus boundary

The live harness must create a new durable 15-minute one-use ticket. Preview is local-only and records `providerContacted: false`; execution must use the exact ticket SHA-256, consume the ticket before provider launch, and reject replay. Evidence distinguishes the finalized-prompt `prompt_sha256` from the complete approval-envelope `payload_sha256`. The latter is the digest approved.

Private provider handling validates exact 22-character alphanumeric task IDs. Public evidence omits the native ID and retains bridge session/lifecycle plus sanitized correlation SHA-256 values. During the 15-second creation grace, message-list 404 remains pending; afterward, successful task detail means `unknown`/resumable, while absence from both endpoints means `not_found`/non-resumable.

New Manus tasks request empty connectors, forced skills, and task references; continuations request connector clearing. The Manus API cannot disable account-default skills, so the operator must review them and explicitly set `acknowledgeAccountDefaultCapabilities: true` plus a stable non-secret `accountCapabilityProfile` before enablement. The provider endpoint, request-capability policy version, and profile label are bound into the approval envelope. These request fields and the operator-attested profile are not represented as provider-enforced disabling of account defaults.

## Cooperative recommendations

Codex and Claude use `workspace` scope. Manus receives only an isolated, sanitized `brief`; its `briefSha256` is recorded independently of the recommendation-prompt hash and full approval-envelope hash. No recommendation or workboard completion is claimed in this template.

## Residual risks

- The operator explicitly declined rotation of a Manus key previously exposed in chat. This is documented as accepted residual risk; credential hygiene is not passed.
- Manus account-default skills cannot be disabled by Agent Bridge and require explicit operator acknowledgement plus an operator-attested account-capability profile.

## Rollback

The retained prior release is `0.2.1+4785d63`. The rollback canary is `not-run`, so rollback readiness is not accepted.

## Redaction statement

This shareable report replaces personal path prefixes and omits prompts, transcripts, credentials, authorization headers, native provider task IDs, and raw provider details. A real generated packet must record artifact hashes and byte counts in `manifest.json`.
