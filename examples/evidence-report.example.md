# Agent Bridge release evidence

**Packet:** `agent-bridge-0.3.0-rc.9-example`
**Disposition:** candidate-ready-promotion-blocked
**Machine record:** `evidence-report.example.json`
**Machine-record SHA-256:** `<compute after final export>`

## Capability-scoped acceptance

| Field | Value |
| --- | --- |
| Derived profile | `windows-local-core` |
| Derivation | `hash-verified-shared-config` |
| Profile-input SHA-256 | `3658b3f6c191cdd919c1326943dc994cbf4b7a13eb927b4574a5b3a755046349` |
| Manus | Disabled; not live-certified |
| Gemini | Disabled; not certified by this profile |

The descriptor asserts the expected profile but cannot select or waive it. The exporter derives this profile from the exact hash-verified shared config.

## Candidate

| Field | Value |
| --- | --- |
| Version | `0.3.0-rc.9` |
| Source commit | `0123456789abcdef0123456789abcdef01234567` |
| Immutable release | `0.3.0-rc.9+0123456` |
| Live at start | `0.2.1+4785d63` |
| Live at end | `0.2.1+4785d63` |
| Bundle SHA-256 | `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` |
| Runtime SHA-256 | `cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc` |
| Config SHA-256 | `dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd` |

This is a truthful blocked template, not an accepted packet. RC9 has not been promoted; ignored RC5–RC8 bundles and `.release-staging` directories are historical artifacts, not RC9 inputs.

## Gate results

| Check | Gate | Status | Reason |
| --- | --- | --- | --- |
| `repository-verify` | automated | not-run | No hash-pinned RC9 verification log is attached |
| `production-dependency-audit` | automated | not-run | No production audit evidence is attached |
| `mcpb-manifest-validation` | automated | not-run | No official validator evidence is attached |
| `immutable-operations-integrity` | automated | not-run | Installed operation hashes and bytes are unverified |
| `installed-provider-disabled-canary` | automated | not-run | Immutable installed-runtime canary not run |
| `windows-npm-shim-installed-runtime` | automated | not-run | Installed Windows npm-shim canary not run |
| `codex-installed-runtime` | local-cli | not-run | No signed-in Codex result attached |
| `claude-installed-runtime` | local-cli | not-run | No signed-in Claude Code result attached |
| `registration-normalization` | client-restart | blocked | Stable-shim targeting and zero shared-versus-fallback config divergence are unproven |
| `release-promotion` | client-restart | blocked | Stable shim remains on `0.2.1+4785d63` |
| `codex-restarted-client` | client-restart | not-run | RC9 not promoted/restarted |
| `claude-code-restarted-client` | client-restart | not-run | RC9 not promoted/restarted |
| `claude-desktop-restarted-client` | client-restart | not-run | RC9 not promoted/restarted |
| `creator-visible-acceptance` | human-visible | not-run | Creator-visible workflow acceptance not run |
| `rollback-canary` | automated | not-run | RC9 rollback canary not run |

## Manus boundary

Manus is disabled in this core profile and is **not live-certified**. The exporter derives and records that state from the hash-verified shared config at export time; the separately structured provider-disabled canary shows that the exact runtime rejects Manus/Gemini at its adapter registry under a disposable disabled config with zero sessions or approvals. Enabling Manus or remote egress changes the shared-config hash and derives `windows-local-manus`, which RC9 refuses to accept until live artifacts are profile-input-bound.

## Cooperative recommendations

Codex and Claude use `workspace` scope. Manus receives only an isolated, sanitized `brief`; its `briefSha256` is recorded independently of the recommendation-prompt hash and full approval-envelope hash. No recommendation or workboard completion is claimed in this template.

## Residual risks

No residual risks are recorded in this core-profile template.

## Rollback

The retained prior release is `0.2.1+4785d63`. The rollback canary is `not-run`, so rollback readiness is not accepted.

## Redaction statement

After operator inspection, this report may be shared: its bounded redaction replaces personal path prefixes and omits prompts, transcripts, credentials, authorization headers, native provider task IDs, and raw provider details. The exporter is not a semantic DLP classifier, so the operator must still remove sensitive business content that does not resemble a credential or path. A real generated packet must record artifact hashes and byte counts in `manifest.json`.
