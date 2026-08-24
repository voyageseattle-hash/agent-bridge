# Public release privacy gate

Every public repository update, source archive, MCPB bundle, website archive, and release attachment must pass this checklist before upload or deployment.

1. Build from a clean, committed worktree. Never publish the private repository's Git history; use the dedicated history-clean public repository.
2. Run `npm run privacy:scan` before tests or packaging. Run `npm run privacy:scan:history` in the public repository before every push.
3. Scan every attachment with `node scripts/scan-public.mjs --no-tree --archive <path>` before upload.
4. Verify that no actual `.env`, `config.json`, credential file, state, session, transcript, evidence, backup, key, certificate, private user path, personal email, or bearer credential is included.
5. Publish only checksum values, release identifiers, public repository URLs, generic examples, and deliberately public documentation.
6. Keep hosted environment variables empty unless the feature requires them. Never place provider credentials in a client bundle, static page, public evidence, release notes, or browser prompt.
7. Stop the release if any scanner finding is unexplained. Findings are reported by category and location without echoing the matched value. Rotate any credential that has crossed a public or untrusted boundary; deletion alone is not sufficient.

The scanner is a release safeguard, not proof that arbitrary private material is safe to publish. Human review of the exact final files and public pages remains required.
