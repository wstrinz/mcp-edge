# mcp-edge (repository `wiskit-mcp-edge`)

Dedicated repository: **`wstrinz/wiskit-mcp-edge`**, private, with **`main`** as
the intended Coolify deployment branch. **Current plan: [docs/DESIGN.md](docs/DESIGN.md)**:
a generic, OAuth-hardened front door for all the owner's MCP servers, with Wiskit
as the first iroh backend. The [builder handoff](docs/BUILDER-HANDOFF.md) still
holds its safety rules and Wiskit details.

Local Wiskit use, peer sync and data recovery must remain independent of the edge.

## Status: phase 2 (auth + echo), deployable but not deployed

| Piece | State |
|---|---|
| `crates/edge-assert` | Signed, request-bound Ed25519 assertions; mint + verify + replay cache. Format spec and test vector in [its README](crates/edge-assert/README.md). |
| `crates/edge-auth` | OAuth 2.1 authorization server: RFC 8414/9728 metadata, RFC 7591 public-client DCR, S256 PKCE, passkey (WebAuthn) owner proof, consent, one-use codes, rotating refresh with family revocation, RFC 7009 revocation, owner grant page, SQLite store. |
| `mcp-edge` (root binary) | `EDGE_MODE=edge`: the above plus a closed route table whose only backend kind is the built-in `echo`. `EDGE_MODE=deny-all` (the default when unset): the original inert process. |
| iroh tunnel / origin / HTTP backends | Not implemented (phases 3–4). `kind = "http"`, `kind = "iroh"` and `consent = "origin"` are refused at startup. |

No Coolify resource, domain or deployment was created. Linux container build and a
real claude.ai connector run are **unverified** (see [phase 2 notes](docs/DESIGN.md#phase-2-implementation-notes)).

## Endpoints (edge mode)

| Route | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 issuer metadata |
| `GET /.well-known/oauth-protected-resource/<backend>/mcp` | RFC 9728 resource metadata |
| `GET /.well-known/edge-assertion-key` | Public Ed25519 key backends verify assertions with |
| `POST /register` | RFC 7591 DCR, public clients, allowlisted redirect URIs only |
| `GET /authorize` → `GET/POST /consent` | Authorization request → passkey proof → consent |
| `POST /token`, `POST /revoke` | Code / refresh exchange; RFC 7009 revocation |
| `GET /owner`, `GET /owner/enroll` | Owner grant list (revoke / revoke all, add passkey); first-passkey enrollment |
| `POST /owner/{login,register}/{start,finish}` | WebAuthn ceremonies (JSON, same-origin) |
| `POST /<backend>/mcp` | Authenticated MCP (JSON-RPC, JSON responses); `GET` and other methods → 405 |
| `GET /healthz`, `GET /readyz` | Process liveness; store readiness |

Missing or invalid bearer tokens get `401` with
`WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource/<backend>/mcp"`.
The `echo` backend verifies the forwarded `Edge-Assertion` like any backend would
and exposes one tool, `whoami`, returning the verified claims.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `EDGE_MODE` | `deny-all` | `edge` runs the authorization server and built-in backends |
| `EDGE_PUBLIC_URL` | (required in edge mode) | Issuer and public origin, e.g. `https://mcp.app.stri.nz`; https only (http only for `localhost`), no path or trailing slash |
| `EDGE_BIND` | `0.0.0.0:8080` | Listener; `--healthcheck` probes `127.0.0.1:<port>` |
| `EDGE_DATA_DIR` | `/data` | Holds `edge.db` (SQLite) and `assertion-key.bin` (Ed25519 seed, created on first start, never silently replaced) |
| `EDGE_ROUTES` | `/etc/mcp-edge/routes.toml` | Route table ([config/routes.toml](config/routes.toml) is baked into the image) |
| `EDGE_ENROLL_CODE` | unset | One-time code (≥ 16 ASCII chars) authorizing the **first** owner passkey. Consumed on use; remove it afterwards |
| `EDGE_REDIRECT_ALLOWLIST` | `https://claude.ai/api/mcp/auth_callback` | Comma-separated exact https redirect URIs clients may register |
| `EDGE_TRUSTED_PROXIES` | RFC 1918 + loopback + `fc00::/7` | Comma-separated CIDRs. `X-Forwarded-For` is honoured only when the TCP peer is in this list; the right-most hop outside it is the client used for per-IP limits. Empty = never trust the header |
| `EDGE_RP_ID` | public host | WebAuthn RP id (the host or a parent domain) |
| `EDGE_RP_NAME` | `mcp-edge` | WebAuthn RP display name |

Route table entries: `id` (lowercase path segment, also the assertion audience),
`kind = "echo"`, `consent = "edge"`, `display_name`, `scopes` (default `["mcp"]`),
`grant_lifetime_secs` (300 s – 90 days, default 30 days), `max_request_bytes`
(1 KiB – 4 MiB, default 1 MiB). Unknown keys and reserved ids are startup errors.

Fixed policy: codes 60 s; access tokens 15 min; pending authorization 10 min;
passkey proof must be < 5 min old at approval; owner sessions 30 min. Logs are one
line per request (`method`, route template, `status`, `ms`, `backend`, `grant`) plus
named events; never bodies, headers, tokens, codes, cookies or the enrollment code.

## Deployment steps (owner; not performed)

1. Generate an enrollment code (e.g. 32 random characters) and keep it private.
2. Create the Coolify application as described in [docs/COOLIFY.md](docs/COOLIFY.md)
   (Docker Compose build pack, `/compose.yaml`). Note: the prepared owner helper still
   creates the application with **no domain**; phase 2 needs one (step 3).
3. In Coolify, set the domain of service `edge` to `https://mcp.app.stri.nz:8080`
   (Traefik terminates TLS with Let's Encrypt and routes to container port 8080).
4. Set `EDGE_ENROLL_CODE` as a secret environment variable. Leave
   `EDGE_PUBLIC_URL` at its default unless the host differs.
5. Deploy. Check `https://mcp.app.stri.nz/healthz` and `/readyz`, and note the
   `assertion_key=` value in the startup log (also at `/.well-known/edge-assertion-key`).
6. Open `https://mcp.app.stri.nz/owner/enroll`, enter the code, create the passkey.
   Then remove `EDGE_ENROLL_CODE` from Coolify and redeploy (the code is consumed
   either way; removing it keeps it out of the environment).
7. In claude.ai add a custom connector with URL `https://mcp.app.stri.nz/echo/mcp`.
   Claude registers, the browser lands on the consent page: confirm with the passkey,
   approve, then call the `whoami` tool. Revoke from `https://mcp.app.stri.nz/owner`.

The `edge-data` volume holds the grant store and the assertion signing key; back it
up if grants should survive a rebuilt volume. Losing it revokes everything and
requires a new `EDGE_ENROLL_CODE` enrollment and a new key for backends.

## Local checks

```powershell
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
python tools/verify_repo.py
```

`webauthn-rs` links OpenSSL. On Windows point `OPENSSL_DIR` at an OpenSSL 3
installation with MSVC import libraries (any directory with `include\openssl` and
`lib\libssl.lib`/`libcrypto.lib`) and make its DLLs reachable on `PATH`. The Docker
build links OpenSSL statically from Alpine packages.

The integration tests bind ephemeral loopback sockets, drive real WebAuthn
ceremonies with a software passkey, and use a manual clock for expiry rules. Do not
launch the binary on a host-wide interface for testing. A Windows run is not a Linux
image build or proof of claude.ai compatibility.

## Fixtures and older evidence

`fixtures/iroh-transport-poc/` (12 passing transport tests) and
`fixtures/claude-compat/` (14 synthetic OAuth/MCP policy tests) are unchanged
byte-for-byte; they are starting points for later phases, not packaged runtime.
`MANIFEST-SHA256.json` and `docs/VERIFICATION.md` describe the original preparatory
package (deny-all only); phase 2 results are in DESIGN.md's implementation notes.
