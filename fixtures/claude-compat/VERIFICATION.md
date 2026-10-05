# Verification record

Verified on 2026-10-05 in the delegated Windows task workspace. This is a
separate in-process policy fixture, not a deployed server or an integration with
Claude, Wiskit, Coolify, or an identity provider.

## Commands and evidence

| Command | Result | Saved output |
| --- | --- | --- |
| `cargo test --locked --offline` | Exit 0; 14 tests passed, 0 failed | `compatibility-test.log` |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | Exit 0 | `clippy.log` |
| `cargo fmt -- --check` | Exit 0 | `format.log` |

The wrapper emitted a path-canonicalization warning for the user profile. It
did not prevent any command from completing successfully. The crate is pinned
by Cargo.lock and all final checks ran offline.

The eleven compatibility tests cover discovery and 401 challenges, DCR and
synthetic CIMD selection, one-use authorization codes and S256 PKCE,
client/redirect/issuer/state/resource binding, explicit local-owner approval,
tracker isolation across grants sharing one public client ID, legacy MCP
initialize and read-only dispatch, rotating refresh families and replay,
expiry/revocation/restart, redacted audit and bounded registrations/approvals.

Three boundary tests additionally cover client-bound idempotent token
revocation; rejected token queries, untrusted Host/Origin, anonymous approval
and tokens from another fixture; and rejected plain PKCE, altered redirects,
wrong resources and write scope.

## What these results do not establish

The fixture represents HTTP requests/replies as Rust values and dispatches
synchronously. It opens no listener and runs no real MCP SDK. Local owner proof
and browser binding use synthetic labels; there are no real cookies, CSRF
defenses, browser redirects or CIMD network fetches. Audit is an in-memory
bounded record, not a durable database. There is no persistent token storage,
rate limiter, real provider account, Wiskit broker integration or iroh/OAuth
wire integration.

In-flight revocation and grant-scoped cancellation propagation remain real
adapter/bridge work. The 2025 MCP disconnect policy differs from the 2026
revision; phase-1 transport cancellation does not prove legacy MCP compliance.
Actual Claude protocol negotiation, DCR payloads, refresh and end-to-end consent
must be verified later with synthetic data and authorized public access.

## Prior PoC preservation

At 2026-10-05 14:34 UTC, every one of the 12 files in the delivered phase-1
archive matched its corresponding current workspace file byte-for-byte by
SHA-256. The original source, tests, documentation and logs were unchanged.

Original archive: `../wiskit-edge-poc.zip`

SHA-256: `EF1094591E4EAABD4E639C8CD20A05E5575EADDB4B9E3172F3E6724781F04E23`

All work for this phase is under `claude-compat/`. No project checkout or shared
service was changed. No account was connected, persistent credential minted,
deployment performed or family data used.
