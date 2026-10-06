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

## Phase 2 implementation notes

Status 2026-10-05, branch `phase2-auth`: `edge-assert`, `edge-auth` and the `mcp-edge`
binary with the built-in `echo` backend are implemented and tested on Windows
(loopback, software passkey). Not done: Linux image build, Coolify deployment, a real
claude.ai connector run (the phase 2 acceptance item), `edge-gateway`/`edge-tunnel`/
`edge-origin` (phases 3–4). Where this document was silent, the conservative choice
below was taken.

**Owner proof and consent**
- Proof is per authorization request. `/authorize` creates a pending request bound to
  the browser by a `__Host-` cookie; the passkey ceremony must be started *for that
  request* from that browser, and its result must be under 5 minutes old when the
  CSRF-protected consent form is submitted. An owner session (from `/owner`) never
  approves consent by itself. Pending requests live 10 minutes and are one-shot.
- Errors before the client and exact redirect URI are verified render a 400 page and
  never redirect. Later errors redirect with `error` and `iss` (and `state` if valid).
- Browser POSTs with an `Origin` other than the issuer are refused; JSON endpoints
  require `application/json`. Cookies: `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`.
  Pages send a strict CSP whose `form-action` also lists the redirect-allowlist
  origins (the consent POST answers with a redirect there).
- Enrollment: the code must be ≥ 16 ASCII characters (otherwise ignored, enrollment
  disabled); it is compared in constant time, and stored only as a hash when consumed,
  in the same transaction as the first passkey. Once any passkey exists codes are never
  accepted again. 10 wrong codes lock enrollment for the rest of a 15-minute window
  (global; bounds guessing, and a stranger can delay enrollment only briefly). Adding passkeys needs an owner session
  authenticated within 5 minutes. There is no passkey removal yet; recovery from lost
  passkeys is "wipe the volume, enroll again", which also revokes everything.
- The owner id (`sub`) is a random UUID created on first start.

**Codes and tokens**
- `resource` is required at `/authorize` and must equal `<issuer>/<backend>/mcp`
  exactly (no normalization). At `/token` it is optional; if present it must match, or
  the result is `invalid_grant` (the checklist's code, rather than RFC 8707's
  `invalid_target`). `redirect_uri` is required at `/token` and must match exactly.
- Any presentation of a code consumes it: a failed exchange (wrong verifier, client,
  redirect, resource, expiry) burns the code and its pending grant; presenting an
  already-used code also revokes the grant it produced.
- Public clients only: an `Authorization` header or `client_secret` at `/token` or
  `/revoke` is `invalid_client`, as is an unknown `client_id`.
- A rotated refresh token presented again, or a refresh token presented by a different
  client, revokes the whole grant ("family" = grant). Refresh never extends the grant's
  absolute lifetime; a `scope` parameter on refresh is ignored (tokens always carry
  exactly the granted scope).
- `/revoke` (RFC 7009) revokes the whole grant for either token type; tokens of other
  clients and unknown tokens get 200 with no effect. Revocation increments `gen`.
- Secrets (tokens, codes, cookies) are 256-bit random values stored as unsalted
  SHA-256; grants, codes and sessions are in SQLite (`EDGE_DATA_DIR/edge.db`); WebAuthn
  ceremony state is memory-only (5 minutes). Revoked/expired grants are deleted 7 days
  after creation; never-used client registrations are pruned after 1 hour when the
  100-client cap is reached.
- DCR accepts at most 4 redirect URIs, all exact allowlist members; unknown metadata
  is ignored; `client_name` is stripped of control characters, cut to 80 characters
  and always HTML-escaped.

**Assertions**
- The signature covers `"edge-assert.v1." + <payload segment>`; `req` is
  base64url(SHA-256) and `path` is the path the backend receives (`/mcp`). Claims are
  canonical JSON (integers only); the Rust verifier rejects non-canonical payloads and
  unknown claims and allows 5 s skew. `resource_scope` is `{}` for edge-consent
  backends; `gen` starts at 1.
- The signing seed is `EDGE_DATA_DIR/assertion-key.bin`, created on first start; a
  file of the wrong size stops startup instead of being replaced. Rotation is manual
  (delete the file, update backends). Backends get the key from
  `/.well-known/edge-assertion-key` or the startup log, configured out of band.

**Transport and limits**
- MCP is stateless JSON (no `Mcp-Session-Id`, no SSE). `initialize` negotiates
  2025-11-25, 2025-06-18 or 2025-03-26 (default 2025-06-18); an `MCP-Protocol-Version`
  header, if present, must be one of these; batches are rejected; notifications get 202.
  The bearer token is checked before the body is read.
- Limits: 128 connections; 10 s header deadline; 5 min connection lifetime; 30 s
  request deadline; 32 KiB of request headers (enforced explicitly: hyper's read-buffer
  limit is not a strict cap, which also let the old deny-all server serve a 32 KiB
  header intermittently — fixed there too); bodies 16 KiB (OAuth forms), 64 KiB
  (WebAuthn), per-backend MCP cap (default 1 MiB, echo 64 KiB). Per client IP per
  minute: 600 requests, 30 authorize, 60 token/revoke, 20 owner ceremonies; 10
  registrations per hour per IP and 60 globally; 300 MCP requests per grant per minute.
  Anonymous state never refuses the owner: WebAuthn ceremonies are capped at 4 per
  client network and 64 overall, and pending authorization requests at 4 per network
  and 64 overall, evicting the network's own oldest entry and then the oldest
  unverified one instead of answering 429 (found in review: a refusing cap let one
  anonymous IP lock the owner out of login and consent). A response cap is not needed for the in-binary echo and
  belongs to the HTTP forwarder in phase 3.
- Client IP is the TCP peer. Only when the peer is inside `EDGE_TRUSTED_PROXIES`
  (default RFC 1918, loopback and `fc00::/7`, since only Coolify's Traefik can reach
  the container) is `X-Forwarded-For` read, taking the right-most hop that is not a
  trusted proxy; an unparsable hop ends the walk. IPv6 is limited per /64. The
  limiter holds at most 10 000 keys; when all are live, new keys are refused for the
  rest of the window (fail closed, a bounded DoS trade-off).
- Logs: one line per request (method, route template, status, ms, backend, grant id)
  plus named events (`consent_approved`, `refresh_reuse`, `grant_revoked`, ...). A test
  greps captured logs for every secret the flow produced.

**Deployment shape**
- `EDGE_MODE` unset still runs the inert deny-all process; `compose.yaml` sets `edge`.
  The compose service exposes 8080 to the Coolify proxy network (no host port), mounts
  the named volume `edge-data` at `/data`, and keeps read-only rootfs, `cap_drop: ALL`,
  `no-new-privileges`, UID 65532 and pids/memory/CPU limits.
- `webauthn-rs` depends on OpenSSL (a C dependency the design did not anticipate). The
  image links it statically; Windows development needs `OPENSSL_DIR`.

**Checklist coverage** (tests run against the real server on an ephemeral loopback
port): 1 `security.rs::checklist_1_*` (+ enrollment tests); 2 `checklist_2_*`;
3 `checklist_3_*`; 4 `checklist_4_*`; 5 `checklist_5_*`; 6 `edge-assert` unit tests and
`tests/echo_assertions.rs`; 8 `oauth_flow.rs::logs_never_contain_*`. Item 7 does not
apply until a forwarder exists; absolute-form, `CONNECT`, unknown-backend and
odd-path requests are already covered.

**Open questions from phase 2**
- Does claude.ai send `resource` on `/authorize` and `/token`, and `redirect_uri` on
  `/token`? Both are required/enforced here; a real connector run must confirm.
- Should one owner session be allowed to approve several requests (fewer passkey
  prompts) instead of per-request proof?
- The prepared owner Coolify helper still creates the application with no domain and
  an "inert" description; phase 2 needs the domain set (see README).
- Backup policy for the `edge-data` volume (grants and the assertion key).
