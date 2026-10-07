# mcp-edge (repository `wiskit-mcp-edge`)

Dedicated repository: **`wstrinz/wiskit-mcp-edge`**, private, with **`main`** as
the intended Coolify deployment branch. **Current plan: [docs/DESIGN.md](docs/DESIGN.md)**:
a generic, OAuth-hardened front door for all the owner's MCP servers, with Wiskit
as the first iroh backend. The [builder handoff](docs/BUILDER-HANDOFF.md) still
holds its safety rules and Wiskit details.

Local Wiskit use, peer sync and data recovery must remain independent of the edge.

## Status: phase 2 live (auth + echo); phase 3 (HTTP) and phase 4 edge side (iroh + origin consent) implemented, no such backend enabled

| Piece | State |
|---|---|
| `crates/edge-assert` | Signed, request-bound Ed25519 assertions; mint + verify + replay cache. Format spec and test vector in [its README](crates/edge-assert/README.md). |
| `crates/edge-auth` | OAuth 2.1 authorization server: RFC 8414/9728 metadata, RFC 7591 public-client DCR, S256 PKCE, passkey (WebAuthn) owner proof, consent, one-use codes, rotating refresh with family revocation, RFC 7009 revocation, owner grant page, SQLite store. |
| `mcp-edge` (root binary) | `EDGE_MODE=edge`: the above plus a closed route table with the built-in `echo` backend and `kind = "http"` upstreams (phase 3 forwarder, `src/forward.rs`). `EDGE_MODE=deny-all` (the default when unset): the original inert process. |
| HTTP backends | Implemented and tested against a verifying loopback upstream; the shipped route table enables none (see [Adding an HTTP backend](#adding-an-http-backend)). |
| `crates/edge-tunnel`, `crates/edge-origin` | `mcp-edge/1` wire protocol + edge client; embeddable origin side for a local app ([PHASE4.md](docs/PHASE4.md) §9). |
| iroh backends / origin consent | Edge side implemented (`src/tunnel.rs`, origin consent in `edge-auth`) and tested against an in-repo fake origin over loopback iroh. The shipped route table has the `wiskit` route **commented out**; the Wiskit app side does not exist yet (see [Wiskit over iroh](#wiskit-over-iroh-phase-4)). |

Phase 2 is deployed at `https://mcp.app.stri.nz` from `main`. The phase 3 forwarder
has only been run on Windows against loopback upstreams; a Linux image build and a
real upstream (hevy) are **unverified** (see [phase 3 notes](docs/DESIGN.md#phase-3-implementation-notes)).

## Endpoints (edge mode)

| Route | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 issuer metadata |
| `GET /.well-known/oauth-protected-resource/<backend>/mcp` | RFC 9728 resource metadata |
| `GET /.well-known/edge-assertion-key` | Public Ed25519 key backends verify assertions with |
| `POST /register` | RFC 7591 DCR, public clients, allowlisted redirect URIs only |
| `GET /authorize` → `GET/POST /consent` | Authorization request → passkey proof → consent |
| `POST /consent/start`, `GET /consent/status`, `POST /consent/finish`, `POST /consent/cancel` | Origin consent (`consent = "origin"`): send the request to the app with a pairing code, poll, return to the client, cancel |
| `POST /token`, `POST /revoke` | Code / refresh exchange; RFC 7009 revocation |
| `GET /owner`, `GET /owner/enroll` | Owner grant list (revoke / revoke all, add passkey); first-passkey enrollment |
| `POST /owner/{login,register}/{start,finish}` | WebAuthn ceremonies (JSON, same-origin) |
| `POST /<backend>/mcp` | Authenticated MCP. `echo`: POST only (JSON); other methods → 405 |
| `GET`/`POST`/`DELETE /<backend>/mcp` | `kind = "http"` backends: Streamable HTTP (JSON or SSE responses, `GET` server stream, `DELETE` session end); other methods → 405 |
| `POST /<backend>/mcp` | `kind = "iroh"` backends: one JSON-RPC message over the tunnel (JSON or SSE answer); other methods → 405 |
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
| `EDGE_DATA_DIR` | `/data` | Holds `edge.db` (SQLite), `assertion-key.bin` (Ed25519 seed, created on first start, never silently replaced) and, only when an iroh backend is configured, `iroh-edge.key` (the edge's iroh identity, same rules) |
| `EDGE_ORIGIN_<NAME>` | unset | Origin EndpointId of an iroh backend (64 lowercase hex), named by that route's `origin_endpoint_env`. Read only for enabled iroh routes; then it must be set and valid or startup fails. Compose passes `EDGE_ORIGIN_WISKIT` |
| `EDGE_ROUTES` | `/etc/mcp-edge/routes.toml` | Route table ([config/routes.toml](config/routes.toml) is baked into the image) |
| `EDGE_ENROLL_CODE` | unset | One-time code (≥ 16 ASCII chars) authorizing the **first** owner passkey. Consumed on use; remove it afterwards |
| `EDGE_REDIRECT_ALLOWLIST` | `https://claude.ai/api/mcp/auth_callback` | Comma-separated exact https redirect URIs clients may register |
| `EDGE_TRUSTED_PROXIES` | RFC 1918 + loopback + `fc00::/7` | Comma-separated CIDRs. `X-Forwarded-For` is honoured only when the TCP peer is in this list; the right-most hop outside it is the client used for per-IP limits. Empty = never trust the header |
| `EDGE_RP_ID` | public host | WebAuthn RP id (the host or a parent domain) |
| `EDGE_RP_NAME` | `mcp-edge` | WebAuthn RP display name |

Route table entries: `id` (lowercase path segment, also the assertion audience),
`kind = "echo"`, `"http"` or `"iroh"`, `consent = "edge"` (echo, http) or
`"origin"` (iroh, required), `display_name`, `scopes` (default `["mcp"]`),
`grant_lifetime_secs` (300 s – 90 days, default 30 days; iroh ≤ 30 days),
`max_request_bytes` (1 KiB – 4 MiB, default 1 MiB; iroh ≤ 64 KiB, default 64 KiB).
Unknown keys and reserved ids are startup errors.

`kind = "iroh"` only:

| Key | Default | Range | Meaning |
|---|---|---|---|
| `origin_endpoint_env` | required | `EDGE_ORIGIN_[A-Z0-9_]+` | Name of the environment variable holding the origin's EndpointId (D6: the id never goes into git). Two routes may not resolve to the same id |
| `max_response_bytes` | 1 MiB | 1 KiB – 1 MiB | Response cap (the tunnel's own cap is 1 MiB) |
| `scopes` | | 1 – 4 entries | Travel in the enrollment string and consent requests |

`kind = "http"` only (these keys on an `echo` entry are errors):

| Key | Default | Range | Meaning |
|---|---|---|---|
| `url` | required | | Exact upstream MCP endpoint. `https` to any host; `http` only to an RFC 1918/loopback IP or a single-label service name (e.g. `http://hevy-mcp:3000/mcp` on the Coolify network). No userinfo, query or fragment; never unspecified, link-local, multicast or broadcast IPs; must be written in canonical form (lowercase host, no default port, a path). Its path is what the upstream receives and what `req` signs. |
| `max_response_bytes` | 4 MiB | 1 KiB – 16 MiB | Response body cap (streams included) |
| `connect_timeout_secs` | 5 | 1 – 30 | TCP/TLS connect |
| `response_timeout_secs` | 20 | 1 – 25 | Time to the upstream's response headers (stays under the edge's 30 s request deadline) |
| `idle_timeout_secs` | 60 | 1 – 300 | Longest gap between response body chunks |
| `max_concurrent_per_grant` | 4 | 1 – 64 | In-flight requests plus open streams per grant on this backend |

### HTTP backend behaviour

- A method other than `GET`, `POST` or `DELETE` is a 405 before anything else.
  Then the bearer token is checked exactly as for `echo` (it must be bound to this
  backend), before any body is read. `POST` needs `Content-Type: application/json`;
  `GET`/`DELETE` must have no body (400).
- The upstream request is built from scratch: the configured URL (the client's path
  and query never reach it), the client's method, the exact body bytes (never
  re-serialised), and only these request headers, each at most once and at most
  1 KiB of visible ASCII (otherwise 400): `content-type`, `accept`,
  `mcp-session-id`, `mcp-protocol-version`, `last-event-id`. `Authorization`,
  `Cookie`, `Host`, `Forwarded`, `X-Forwarded-*`, `Accept-Encoding` and any client
  `Edge-Assertion` are dropped. The edge adds its own `Edge-Assertion` (aud =
  backend id, `req` over method, upstream path and body). The HTTP client also sends
  `Host` (the upstream's), `Content-Length`, and `Accept: */*` when the client sent
  no `Accept`. No compression, HTTP/1.1, no proxies, redirects never followed; TLS
  via rustls with the webpki root set.
- The response keeps its status and only `content-type`, `mcp-session-id` and
  `cache-control` (`no-store` if absent). The body is streamed as it arrives (SSE
  events are not buffered) and aborted when it passes `max_response_bytes`, stalls
  longer than `idle_timeout_secs`, or runs past 300 s; an aborted body ends without
  the chunked terminator, so the client sees a truncated response, never a
  complete-looking one.
- Fixed errors (JSON `{"error": ...}`): upstream 3xx → 502 `upstream_redirect`
  (no `Location`); upstream 401 → 502 `backend_rejected` (the upstream refused the
  edge's assertion; its `WWW-Authenticate` is never passed on); connection failure
  (refused, DNS, TLS, connect timeout) → 502 `upstream_unavailable`; no response
  headers within `response_timeout_secs` → 504 `upstream_timeout`; declared length
  over the cap → 502 `upstream_response_too_large`; per-grant in-flight cap → 429
  `too_many_in_flight`. Other statuses (including 404 for an expired MCP session)
  pass through.
- Logs: the usual request line plus `event=upstream_*` /
  `backend_rejected_assertion` with backend and grant id; never URLs, headers,
  bodies, session ids or tokens.

### Adding an HTTP backend

1. Make the upstream verify `Edge-Assertion` per
   [the edge-assert spec](crates/edge-assert/README.md): the edge public key from
   `/.well-known/edge-assertion-key`, issuer `https://mcp.app.stri.nz`, audience =
   the route `id`, and `req` over the method, the exact path of the configured URL
   and the raw body. It must drop its own OAuth and reject requests without a valid
   assertion (its 401 shows up as 502 `backend_rejected`).
2. Add an entry to `config/routes.toml` (the same example is there, commented out):

   ```toml
   [[backend]]
   id = "hevy"
   kind = "http"
   consent = "edge"
   display_name = "Hevy"
   url = "https://hevy-mcp.app.stri.nz/mcp"
   ```

   Prefer an internal URL (`http://<service>:<port>/mcp` on a network shared with
   the edge) once the upstream no longer needs to be public.
3. Merging to `main` deploys. In claude.ai add a connector for
   `https://mcp.app.stri.nz/hevy/mcp`; then remove the upstream's public route.

Fixed policy: codes 60 s; access tokens 15 min; pending authorization 10 min;
passkey proof must be < 5 min old at approval; owner sessions 30 min. Logs are one
line per request (`method`, route template, `status`, `ms`, `backend`, `grant`) plus
named events; never bodies, headers, tokens, codes, cookies or the enrollment code.

## Wiskit over iroh (phase 4)

Specification: [docs/PHASE4.md](docs/PHASE4.md); edge implementation notes in its
§10. The edge dials the configured origin only (n0 public relays + n0 DNS/pkarr
lookup, D5); its endpoint publishes nothing and accepts no inbound protocol. The
container needs outbound UDP and HTTPS to n0; no port is published. If the iroh
endpoint cannot be bound at startup the edge still starts (health green) and the
iroh route answers `503 origin_offline`.

**Consent.** After the passkey proof the consent page shows **Continue to
Wiskit** (no Approve button: only the app can approve). The edge sends a
`consent_request` and shows a 6-character pairing code; the owner types it in the
app, picks trackers and a lifetime there and approves. The page polls
`/consent/status` (2 s, `edge.js`; a Check button without JS) and returns to Claude
through `POST /consent/finish`. The edge verifies the app's signed approval
(`mcp-edge-approval.v1.`, the origin's transport key, bound to edge id, issuer,
route, tx, grant id, nonce and client) and only then issues a code; the grant
carries the approved `resource_scope` and lifetime (≤ the route's
`grant_lifetime_secs`). Denied in the app, no decision within 180 s, Cancel, or an
unreachable app (3 attempts, each with a new code) all end in `access_denied`. An
invalid approval of any kind is treated as "unreachable", never as approval.

**Requests.** `POST /wiskit/mcp` only; bearer check as for every backend, then
`Content-Type: application/json`, the allowlisted headers validated as for http
backends (none is forwarded), `MCP-Protocol-Version` ∈ {2025-03-26, 2025-06-18,
2025-11-25}, body ≤ 64 KiB. The tunnel request is built from scratch (body, a fresh
assertion, `accept` derived from `Accept`, the version). Failures:

| Situation | Answer |
|---|---|
| PC off/asleep, app closed, relay down, dial > 3 s | `503`, `Retry-After: 30`, JSON-RPC error `-32010` with `data.reason = "origin_offline"` and the request's `id`; repeated immediately for 15 s |
| Remote access off / enrollment stale / app locked / audit paused / edge not admitted | same 503 shape, reason `origin_remote_off` / `origin_unenrolled` / `origin_locked` / `origin_paused` / `origin_rejected_edge` |
| Grant unknown, revoked or expired at the app | `401 invalid_token` with `WWW-Authenticate`; the edge revokes its grant too (Claude must reconnect) |
| App rejects the assertion or the scope | `502 backend_rejected` (scope mismatch also revokes) |
| Busy (edge or app limits) | `429` + `Retry-After` |
| Deadline (25 s) | `504 upstream_timeout` |
| Malformed or truncated answer | `502 backend_protocol` |

Revoking at `/owner` (or RFC 7009, refresh replay, expiry) also tells the app
(`grant_revoke`, best effort); every new tunnel connection reconciles grants
(`grant_sync`) and revokes at the edge what the app no longer knows.

**Enrollment (owner, both sides).**

1. Uncomment the `wiskit` entry in `config/routes.toml` (on a branch; merging to
   `main` deploys) and set the Coolify secret `EDGE_ORIGIN_WISKIT` to the
   EndpointId Wiskit shows under Settings → Agent access → Remote access.
2. Deploy. The startup log shows `iroh edge_id=...`; a changed
   `EDGE_ORIGIN_WISKIT` revokes all wiskit grants (`event=origin_reenrolled`).
3. Sign in at `/owner`. Under **Local apps (enrollment)** copy the
   `mcp-edge-enroll:1:...` string into Wiskit ("Enroll an edge") and compare the
   fingerprint (`XXXX-XXXX-XXXX-XXXX`) on both screens. Check that the configured
   origin shown there is the id Wiskit shows for itself. The status line reports
   the last `ping` (reload after a few seconds).
4. In claude.ai add a connector for `https://mcp.app.stri.nz/wiskit/mcp`.

A wiped `edge-data` volume creates a new edge identity (and assertion key): paste
the new enrollment string into Wiskit. A changed Wiskit transport key needs a new
`EDGE_ORIGIN_WISKIT`, a redeploy and a new connection in Claude.

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

### Optional: Traefik request buffering

Traefik streams request bodies to the container. The edge already bounds slow
clients (8 in-flight requests per client network, 5 s body deadline on OAuth/owner
routes, 30 s overall), but Traefik can also buffer whole requests before they reach
the edge. In Coolify, add custom labels to the `edge` service (replace `<router>`
with the router name Coolify generated for the domain, visible in its labels view):

```text
traefik.http.middlewares.mcp-edge-buffer.buffering.maxRequestBodyBytes=4194304
traefik.http.middlewares.mcp-edge-buffer.buffering.memRequestBodyBytes=1048576
traefik.http.routers.<router>.middlewares=mcp-edge-buffer
```

This is not in `compose.yaml` because Coolify owns the router names. Check that
other middlewares Coolify attached (e.g. redirect to HTTPS) are kept in that list.

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
