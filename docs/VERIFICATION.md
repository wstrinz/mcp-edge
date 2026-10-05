# Repository preparation evidence

Prepared 2026-10-05 on Windows. The original package preparation created no
remote repository, Coolify resource, domain, deployment, persistent access or
credentials. The owner subsequently approved private repository publication;
Coolify actions remain pending. The authenticated owner helper has never been
executed by an agent.

| Check | Result | Evidence / practical limit |
| --- | --- | --- |
| Root HTTP tests, `cargo test --locked --offline` | Six passed from this staged repository | `evidence/repo-test.log`; ephemeral loopback only, Windows runtime |
| Root formatting, `cargo fmt -- --check` | Exit 0 | `evidence/repo-format.log`; ordinary home-canonicalization warning |
| Root Clippy | Earlier exact runtime source passed | `evidence/clippy.log`; source copied unchanged except LF normalization |
| Source Compose policy | Exact reviewed inert definition passed | `evidence/repo-package.log`; no ports/mounts/domains, network `none`, deny-all, bounded unprivileged runtime |
| Fixture preservation | All 23 files match their original archives byte-for-byte | `evidence/fixture-files.json`, `fixture-provenance.json`; 12 transport-test and 14 policy-test records retained, not rerun for the copy |
| Owner API helper | Static PowerShell syntax parsing passed | `evidence/owner-helper-syntax.log`; parsed using `Parser.ParseFile`, with no invocation, dot-sourcing, secret reads or authenticated calls |
| Source ZIP | Explicit allowlist, CRC and per-file SHA256 checks | Root `MANIFEST-SHA256.json`; package includes sources/docs/evidence only, no build cache or credential files |

The root container cannot forward MCP traffic. Its health endpoint only proves
the process is alive; `/mcp` and readiness remain unavailable. The transport and
policy fixtures use synthetic data and do not supply production OAuth or Wiskit
integration. The complete remaining integration is in BUILDER-HANDOFF.md.

Linux Docker compilation and runtime health have not been verified. Actual
Coolify version, server/destination/source IDs, repository installation access,
webhook delivery, asynchronous Git clone, generated `.env` and rendered runtime
configuration remain unknown. The one-time activation step is deliberately
pending those concrete target checks. The old inline-service gate/test evidence
does not prove the new Git-backed application setup.

Once the owner approves/publishes the exact repository and finishes the target
setup, a real branch push must prove commit-to-deployment behavior. Public HTTPS,
TLS/domain routing, persistent gateway identity, origin enrollment and OAuth
still need their own implemented and approved activation phase.
