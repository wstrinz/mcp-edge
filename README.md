# mcp-edge (repository `wiskit-mcp-edge`)

Dedicated repository: **`wstrinz/wiskit-mcp-edge`**, private, with **`main`** as
the intended Coolify deployment branch. **Current plan: [docs/DESIGN.md](docs/DESIGN.md)**:
a generic, OAuth-hardened front door for all the owner's MCP servers, with Wiskit
as the first iroh backend. The [builder handoff](docs/BUILDER-HANDOFF.md) still
holds its safety rules and Wiskit details.

Local Wiskit use, peer sync and data recovery must remain independent of the edge.

## Status: phase 2 live (auth + echo); phase 3 (HTTP backends) implemented, no backend enabled

| Piece | State |
|---|---|
| `crates/edge-assert` | Signed, request-bound Ed25519 assertions; mint + verify + replay cache. Format spec and test vector in [its README](crates/edge-assert/README.md). |
| `crates/edge-auth` | OAuth 2.1 authorization server: RFC 8414/9728 metadata, RFC 7591 public-client DCR, S256 PKCE, passkey (WebAuthn) owner proof, consent, one-use codes, rotating refresh with family revocation, RFC 7009 revocation, owner grant page, SQLite store. |
| `mcp-edge` (root binary) | `EDGE_MODE=edge`: the above plus a closed route table with the built-in `echo` backend and `kind = "http"` upstreams (phase 3 forwarder, `src/forward.rs`). `EDGE_MODE=deny-all` (the default when unset): the original inert process. |
| HTTP backends | Implemented and tested against a verifying loopback upstream; the shipped route table enables none (see [Adding an HTTP backend](#adding-an-http-backend)). |
| iroh tunnel / origin consent | Not implemented (phase 4). `kind = "iroh"` and `consent = "origin"` are refused at startup. |

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
| `POST /token`, `POST /revoke` | Code / refresh exchange; RFC 7009 revocation |
| `GET /owner`, `GET /owner/enroll` | Owner grant list (revoke / revoke all, add passkey); first-passkey enrollment |
| `POST /owner/{login,register}/{start,finish}` | WebAuthn ceremonies (JSON, same-origin) |
| `POST /<backend>/mcp` | Authenticated MCP. `echo`: POST only (JSON); other methods → 405 |
| `GET`/`POST`/`DELETE /<backend>/mcp` | `kind = "http"` backends: Streamable HTTP (JSON or SSE responses, `GET` server stream, `DELETE` session end); other methods → 405 |
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
`kind = "echo"` or `"http"`, `consent = "edge"`, `display_name`, `scopes` (default
`["mcp"]`), `grant_lifetime_secs` (300 s – 90 days, default 30 days),
`max_request_bytes` (1 KiB – 4 MiB, default 1 MiB). Unknown keys and reserved ids
are startup errors.

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
