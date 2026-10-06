# mcp-edge: one authenticated front door for personal MCP servers

Status: design, 2026-10-05. Supersedes the transport and OAuth placement in
[BUILDER-HANDOFF.md](BUILDER-HANDOFF.md). The handoff's safety rules, origin authority and Wiskit
integration details still apply unless this document says otherwise.

## Why

The owner runs several MCP servers for Claude on Coolify (`hevy-mcp`, `spotify-mcp`,
`football-mcp`) and wants local apps (Wiskit first) reachable the same way. Today each server
hand-rolls OAuth, and at least one (`hevy-mcp`) issues codes with no owner proof at all. The
reusable piece is a single, hardened OAuth front door that every backend sits behind, whether the
backend is a container next to it or an app on a home PC reached over iroh.

## Goals

- **One OAuth implementation**, done properly: owner proof (passkey) before any consent, PKCE S256,
  exact redirect binding, one-use codes, rotating refresh, revocation.
- **Backends never see Claude's tokens.** They receive a short-lived assertion signed by the edge and
  verify one signature.
- **Closed routing.** A fixed table of backends. No open proxy, no URL/port from requests, no wildcard
  enrollment.
- **Local apps stay authoritative** over their own data. The edge proves *who*. The app decides
  *what*, and enforces it.
- **Library-shaped.** The service is a thin composition of crates that other projects can reuse.

Non-goals: being a general reverse proxy, multi-user/tenant hosting, making local apps depend on the
edge (local use, sync and recovery stay independent of it).

## Architecture

```text
claude.ai ──HTTPS──▶ mcp-edge (Coolify; Traefik terminates TLS with Let's Encrypt)
                      │
                      ├─ OAuth authorization server (one issuer)
                      │    /.well-known/oauth-authorization-server, /register, /authorize, /token, /revoke
                      │    owner passkey login + consent page
                      │
                      ├─ per-backend protected resources:  https://mcp.app.stri.nz/<backend>/mcp
                      │    /.well-known/oauth-protected-resource/<backend>/mcp
                      │
                      └─ forwarder (closed route table)
                           ├─ kind=http : container on the Coolify network   (hevy, spotify, football …)
                           └─ kind=iroh : enrolled EndpointId + fixed ALPN   (Wiskit on the home PC)
                                each forwarded request carries  Edge-Assertion: <signed, ~60 s>
```

One public host, a path per backend: one certificate, one issuer, no DNS work (`*.app.stri.nz` already
resolves to the Coolify server). TLS terminates at the owner's own server, which therefore sees
plaintext: acceptable for a personal box, and stated in consent text.

## Crates (Cargo workspace)

| Crate | Role | Reusable by |
|---|---|---|
| `edge-assert` | The signed assertion: Ed25519 over canonical claims; mint (edge) and verify (backend) | Every backend, in any language (the format is documented below) |
| `edge-auth` | OAuth 2.1 authorization server, owner passkeys, consent, token store | The edge service |
| `edge-gateway` | Route table, request admission and limits, forwarding to http/iroh backends | The edge service |
| `edge-tunnel` | Bounded request/response framing over one iroh bidirectional stream (from `fixtures/iroh-transport-poc`) | Edge and origin |
| `edge-origin` | Embeddable origin side: accept the tunnel ALPN, check the edge's EndpointId, verify assertions, hand requests to an app's HTTP service | Local apps (Wiskit first) |
| `mcp-edge` (bin) | Wires the above together; the Coolify deployment | — |

### Edge assertion

Claims: `iss` (edge), `aud` (backend id), `sub` (owner id), `client_id`, `grant_id`, `scope` (list),
`resource_scope` (opaque JSON the backend approved, e.g. Wiskit tracker ids), `gen` (revocation
generation), `iat`, `exp` (≤ 60 s), `jti`, and `req` (SHA-256 of method + path + body). Encoded as a
compact `base64url(claims).base64url(ed25519 sig)`. Backends verify against the edge public key they
were configured with, check `aud`, `exp` and `req`, and remember `jti` for the assertion lifetime to
stop replay. No bearer token, cookie or `Authorization` header is forwarded.

## OAuth details

- **Discovery:** RFC 9728 protected-resource metadata per backend; RFC 8414 issuer metadata.
- **Registration:** RFC 7591 dynamic registration, public clients only (`token_endpoint_auth_method:
  none`). Redirect URIs must be in an allowlist (default: `https://claude.ai/api/mcp/auth_callback`).
  Registration is rate-limited and bounded in count. CIMD support later.
- **Authorize:** requires `response_type=code`, a registered `client_id`, an exact registered
  `redirect_uri`, `code_challenge_method=S256`, `state`, and `resource` naming a configured backend.
  The owner logs in with a passkey (WebAuthn), sees the client, backend, scopes and lifetime, and
  approves. Backends marked `consent = "origin"` (Wiskit) add the step below.
- **Codes:** random, one-use, 60 s, bound to client, redirect, PKCE challenge, resource and grant.
- **Tokens:** opaque random access tokens (15 min) and refresh tokens, stored only as SHA-256
  hashes. Refresh rotates; reuse of a rotated refresh token revokes the whole family. Absolute grant
  lifetime per backend (default 30 days; Wiskit 24 h for the trial). Refresh never widens scope.
- **Revocation:** RFC 7009 endpoint, plus an owner page listing grants with "revoke" and "revoke
  all". Each grant has a generation; assertions carry it, so origins can drop in-flight work.
- **Storage:** SQLite on a Coolify volume. No plaintext token, code, verifier or passkey secret is
  stored or logged.
- **Owner bootstrap:** the first passkey is registered with a one-time enrollment code supplied via
  a Coolify secret env var. After registration the code is consumed; adding a passkey later needs an
  existing passkey.

### Origin consent (local apps)

For `consent = "origin"` backends, the edge's consent page shows a short pairing code and waits. The
app (reached over the tunnel) shows the pending request with the same code, client name and edge
host. The owner chooses resources (Wiskit: specific trackers, read-only) **in the app**, and the app
returns a signed approval naming that `resource_scope`. The edge then issues the code. The app keeps
its own record and re-checks `resource_scope` and `gen` on every request. Revoking in the app, or
turning remote access off, refuses further requests regardless of edge state.

## Forwarding rules

- Route table loaded from config at start: `id`, path prefix, kind (`http` URL on the internal
  network / `iroh` EndpointId + ALPN), allowed methods and sub-paths, scopes, consent mode, lifetimes.
- Only `POST <prefix>/mcp` (and `GET` returning 405 for SSE until needed) reach a backend.
- Request body ≤ 1 MiB, response ≤ 4 MiB (per backend, configurable), deadlines on connect, first
  byte and total; redirects never followed; no `Host`/`Forwarded` value chooses anything.
- Pre-auth limits per client IP: connections, request rate, body size. Post-auth limits per grant.
- Logs: route, status, timing, grant id. Never bodies, tokens, codes, cookies or headers.

## Security checklist (acceptance, not aspiration)

1. No path issues a code without a fresh owner passkey assertion. Tested.
2. Unknown `client_id`, unregistered `redirect_uri`, missing/plain PKCE, missing `state`, or an
   unconfigured `resource` → error, never a code. Tested per case.
3. Code reuse, expired code, wrong verifier, wrong client, wrong resource → `invalid_grant`. Tested.
4. Refresh-token replay revokes the family. Tested.
5. A token for backend A is rejected at backend B. Tested.
6. Backends reject unsigned, expired, replayed, wrong-`aud` or wrong-`req` assertions. Tested in
   `edge-assert`, and in each backend integration.
7. The forwarder cannot be pointed at an arbitrary host. Route table only; tested with crafted paths,
   encoded slashes and Host headers.
8. Secrets never appear in logs. Tested by grepping captured logs in integration tests.

## Phases

1. **This document.** Agree the shape.
2. **Auth + deny-all deploy.** `edge-assert` and `edge-auth`, an `echo` backend inside the binary (it
   returns the verified assertion claims), owner passkey enrollment, Coolify app at `mcp.app.stri.nz`
   with a volume. Acceptance: the security checklist plus a real claude.ai custom connector reaching
   `echo` through the full OAuth flow.
3. **First real HTTP backend.** Move `hevy-mcp` behind the edge (it verifies assertions and drops its
   own OAuth). Acceptance: Claude uses Hevy through the edge; the direct hevy URL is no longer public.
4. **Wiskit over iroh.** `edge-tunnel` + `edge-origin`, origin consent in the app, a remote
   Streamable HTTP MCP endpoint with `RemoteGrantContext`, read-only tools first (BUILDER-HANDOFF
   phases 1, 2, 5 and 6 apply). Acceptance per the handoff's synthetic-account trial.
5. **Library polish.** Publish-ready crate docs and examples once two backends of each kind work.

## Decisions taken (2026-10-05)

- Edge on the owner's Coolify; Traefik terminates TLS. One host `mcp.app.stri.nz`, path per backend.
- Generic edge for all the owner's MCP servers, not Wiskit-only. Rust, building on this repo's crate.
- Owner login by passkey. Repo keeps its name for now.

## Open questions

- Persistent Wiskit grants (beyond the 24 h trial) and where their state lives.
- Whether the iroh relay used by the edge should be n0's public relays or self-hosted.
- CIMD (client ID metadata documents) once Claude's metadata URL can be pinned.
