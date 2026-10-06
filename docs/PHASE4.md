# Phase 4: Wiskit as an iroh backend of mcp-edge

Status: specification draft for owner review, 2026-10-06. Nothing here is implemented.
Branch `phase4-spec`. Baselines read: this repo at `f4033a0` (phase 2 merged; phase 3, the
HTTP forwarder, is being built in parallel), Wiskit `wiskit-iroh` `main` at `c53f804`
(release 1.6.2).

Precedence: [DESIGN.md](DESIGN.md) governs placement (OAuth issuer, tokens and passkey
owner proof live **at the edge**, not in Wiskit). [BUILDER-HANDOFF.md](BUILDER-HANDOFF.md)
still governs Wiskit origin integration items 1–7, the threat model and phased
acceptance, except where noted here. Where the handoff assumed an origin-owned issuer
(its `register_post`/`token_post`/`authorize_get` tunnel operations), that is superseded:
OAuth never crosses the tunnel. Only MCP requests and four small control operations do.

## 0. Shape in one picture

```text
claude.ai ──HTTPS──▶ mcp-edge (Coolify)                         home PC (Windows)
                      edge-auth: OAuth, passkey, consent      ┌───────────────────────────┐
                      edge-gateway: route "wiskit" kind=iroh   │ Wiskit app (Tauri)        │
                         │                                     │  existing iroh Endpoint   │
                         │ dial ONLY the enrolled EndpointId   │  Router: gossip, blobs,   │
                         │ ALPN mcp-edge/1, 1 bidi stream/req  │   direct, + mcp-edge/1    │
                         └────────── iroh (n0 relay/direct) ──▶│  edge-origin handler      │
                                                               │   peer check, assertion   │
                                                               │   verify, grant record    │
                                                               │  remote MCP adapter       │
                                                               │  broker (RemoteGrantCtx)  │
                                                               │  nonce bridge → WebView   │
                                                               └───────────────────────────┘
```

The edge always dials; the origin only accepts. The edge has **no inbound iroh
protocol**. Everything the origin needs to tell the edge goes back on a stream the
edge opened.

| Decision | Choice in this spec | Why |
|---|---|---|
| Who issues tokens | Edge (DESIGN.md) | One OAuth implementation; Wiskit never sees Claude's bearer |
| Who decides *what* | Wiskit app (origin consent + per-request enforcement) | Local app stays authoritative |
| Dial direction | Edge → origin only | Smallest surface; origin needs no outbound dial or edge address |
| Tunnel scope | `mcp_post` + 4 control ops | No OAuth, no URL, no headers beyond an allowlist |
| Grant state at origin (trial) | Memory only; restart drops all remote grants | Handoff default; persistence is an open decision (§8) |

## 1. Enrollment

Enrollment is closed and owner-driven on both sides. Nothing is learned automatically,
nothing is remapped silently, and changing either key needs a fresh owner action plus
fresh consent.

### 1.1 Identities involved

| Key | Holder | Stored at | Purpose | Lost or changed means |
|---|---|---|---|---|
| Edge assertion key (Ed25519) | Edge | `EDGE_DATA_DIR/assertion-key.bin` (exists, phase 2) | Signs `Edge-Assertion` | Origin rejects every request (`assertion_invalid`) until re-enrollment |
| Edge iroh key (Ed25519, new) | Edge | `EDGE_DATA_DIR/iroh-edge.key`, created with the same crash-safe hard-link procedure as `keyfile.rs`; 32 raw bytes; mode 0600; never regenerated if the file exists with the wrong size | Edge's EndpointId; the origin admits only this peer | Origin closes the connection with `peer_not_admitted`; edge shows `origin_rejected_edge` |
| Wiskit transport key | Origin | `app_data/iroh/secret.key` (existing) | Origin EndpointId; **also signs consent approvals** (domain-separated, §3.4) | Edge cannot reach the origin (indistinguishable from offline); app detects and forces re-enrollment (§1.4) |

The edge's two keys are separate files so either can be rotated alone. Both live on the
`edge-data` volume; backup policy for that volume is already an open phase 2 question
and now also covers the iroh key (§8, D9).

### 1.2 Edge side: the origin is configuration

Route entry (route table is baked into the image; the origin id comes from a Coolify
secret env var so the home PC's address never lands in git):

```toml
[[backend]]
id = "wiskit"
kind = "iroh"
consent = "origin"
display_name = "Wiskit (home PC)"
scopes = ["wiskit:read"]
grant_lifetime_secs = 86400          # trial ceiling; the owner picks ≤ this in the app
max_request_bytes = 65536
max_response_bytes = 1048576
origin_endpoint_env = "EDGE_ORIGIN_WISKIT"   # value: 64 lowercase hex chars
```

| Rule | Behaviour |
|---|---|
| Parse | `origin_endpoint_env` must name a set env var holding exactly 64 lowercase hex chars that decode to a valid Ed25519 point; otherwise startup fails (no "disabled" fallback) |
| Uniqueness | Two routes may not name the same EndpointId |
| Admission | The edge dials only EndpointIds that come from this table. No request field, Host, path segment or encoded id ever selects or adds a peer |
| Change | Editing the env var + redeploy is the only remap path. On start, if the configured id differs from the id stored in `meta(k='origin:wiskit')`, the edge revokes every grant of that backend (gen++), logs `event=origin_reenrolled backend=wiskit`, and stores the new id |
| Visibility | `/owner` shows: edge EndpointId, assertion key, and the configured origin id (first 8 / last 4 chars) with its enrollment status from the last `ping` |

### 1.3 Origin side: the edge is pasted by the owner

The edge's `/owner` page (passkey session) shows an **enrollment string** and its
fingerprint:

```text
mcp-edge-enroll:1:<base64url-nopad(canonical JSON)>
```

| Field | Type / bound | Meaning |
|---|---|---|
| `v` | int = 1 | Format version |
| `iss` | https URL ≤ 128 | Edge issuer, e.g. `https://mcp.app.stri.nz` |
| `aud` | backend id ≤ 32 | Assertion audience the origin will require (`wiskit`) |
| `edge_id` | 64 hex | Edge iroh EndpointId |
| `assert_key` | 43 b64url | Edge assertion public key |
| `sub` | ≤ 64 | Edge owner id; the origin requires `sub` to match on every assertion |
| `scopes` | list ≤ 4 | Scopes the edge will put in assertions (`["wiskit:read"]`) |

Fingerprint = first 10 bytes of SHA-256 over the decoded JSON, shown as 4 groups of 4
Crockford base32 characters on both the edge page and the app. The owner compares it.

App flow: Settings → Agent access → **Remote access (mcp-edge)** → "Enroll an edge" →
paste → the app shows issuer host, fingerprint and its **own** EndpointId (to copy into
Coolify as `EDGE_ORIGIN_WISKIT`) → owner confirms. Stored in the `settings` table under
`remote_edge_enrollment` (no secrets inside), together with
`enrolled_as = <this device's EndpointId at enrollment time>`. One enrollment at a time;
enrolling again replaces it and drops every remote grant.

The app never fetches anything from the edge to enroll (no network dependency, no
TOFU over the internet).

### 1.4 Key change and re-enrollment

| Event | Detected by | Result | Owner action |
|---|---|---|---|
| Wiskit transport key changes (corrupt file fallthrough, reinstall, restore to a new device: backups exclude network identity) | App at start: own EndpointId ≠ `enrolled_as` | Enrollment marked **stale**; remote mode forced off and cannot be turned on; edge sees `origin_offline` | Re-enroll in app; update `EDGE_ORIGIN_WISKIT`; redeploy; reconnect in Claude |
| Edge iroh key changes (volume wiped) | Origin: unknown peer at accept | Connection closed `peer_not_admitted`; edge returns `origin_rejected_edge` | Paste new enrollment string in app |
| Edge assertion key rotated | Origin: signature check | `assertion_invalid`; edge logs `backend_rejected` | Paste new enrollment string |
| Edge issuer / backend id changes | Origin: `iss`/`aud` check | `assertion_invalid` | Paste new enrollment string |
| Owner revokes enrollment in app | App | All remote grants dropped; listener refuses with `peer_not_admitted` | — |

Recommended Wiskit change in the same release: `load_or_create_secret_key` should stop
silently replacing a wrong-length `secret.key`; move the bad file aside
(`secret.key.invalid-<ts>`) and log it, so the change is at least visible. This affects
peer sync too, so it is listed as an owner decision (§8, D7), not assumed.

## 2. Transport

### 2.1 ALPN

`mcp-edge/1`.

| Option | Verdict |
|---|---|
| `wiskit-mcp-poc/1` | Test-only (PoC); must never be accepted by a real app |
| `wiskit-mcp-edge/1` (handoff draft) | Superseded: DESIGN.md made the tunnel a reusable `edge-tunnel`/`edge-origin` pair for any local app, and the protocol is not Wiskit-specific |
| **`mcp-edge/1`** | Names the protocol owner (this repo) and the major version. An incompatible change becomes `mcp-edge/2` and fails at the TLS handshake, before any byte is parsed. Minor, compatible additions use the in-band `v` field. Does not collide with Wiskit's existing gossip, blobs and direct-message ALPNs |

The origin registers the ALPN in its Router **in both construction branches** (normal and
`halo-acceptance-fixture`) and adds it to the endpoint's `alpns(...)` list and the
`iroh:router-ready` readiness event (handoff item 1). It is registered even while remote
mode is off; the handler then refuses (`remote_disabled`), so toggling remote mode never
rebuilds the Router or endpoint.

### 2.2 Connections

| Item | Value | Notes |
|---|---|---|
| Edge endpoint preset | n0 relays + DNS address lookup; no address publishing; no mDNS; no portmapper | Edge only dials; it has nothing to publish |
| Edge connection policy | One cached connection to the origin, opened lazily, kept with QUIC keep-alive 5 s, idle timeout 20 s | Gives fast liveness without a dial per request |
| Origin admission | `connection.remote_id() == enrolled edge_id`, checked in `accept` before any stream is read | Else close code 1 |
| Origin connection cap | 2 concurrent admitted connections | Third is closed with code 2 |
| Bidi streams per connection | 8 | Uni streams: 0 |
| Stream receive window / connection window / send window | 64 KiB / 256 KiB / 64 KiB | PoC used 16/64/16 KiB for a 16 KiB body cap; raised for the 1 MiB result budget, still bounded |
| MTU | Wiskit's existing Tailscale-safe MTU settings apply (shared endpoint) | — |

QUIC application close codes (connection level):

| Code | Name | Sent by | Edge maps to |
|---|---|---|---|
| 1 | `peer_not_admitted` | origin | 503 `origin_rejected_edge` |
| 2 | `connection_limit` | origin | 503 `origin_busy` (retry the dial once after 1 s) |
| 3 | `remote_disabled` | origin | 503 `origin_remote_off` |
| 4 | `shutting_down` | either | 503 `origin_offline` |
| 5 | `enrollment_stale` | origin | 503 `origin_unenrolled` |

### 2.3 Framing (one bidirectional stream per request)

Reuses the PoC's tested framing: every field is `u32` big-endian length + bytes; the
length is checked against the field's cap **before** allocation; the request side ends
with QUIC FIN and the origin rejects any trailing byte; the response side ends with an
explicit zero-length terminator frame followed by FIN. A response without the terminator
is a truncated transport error, never a fabricated success.

```text
edge → origin:  [len][request meta JSON] [len][body]  FIN
origin → edge:  [len][response meta JSON] [len][chunk] ... [len][chunk] [0x00000000]  FIN
```

| Field | Cap | Encoding |
|---|---|---|
| Request meta | 12 KiB | UTF-8 JSON object, `deny_unknown_fields`, tagged by `op` |
| Request body | per op (below) | raw bytes; must be empty for control ops |
| Response meta | 2 KiB | UTF-8 JSON object, `deny_unknown_fields` |
| Response chunk | 16 KiB | raw bytes; zero length only as terminator |
| Response total | per op (below) | counted across chunks; exceeding it is a transport error at the receiver |

Operations (`op`):

| `op` | Body cap | Response cap | Purpose |
|---|---|---|---|
| `mcp_post` | 64 KiB | 1 MiB | One JSON-RPC message (`POST /mcp`) |
| `consent_request` | 0 | 4 KiB | Ask the app owner to approve a grant (§3); stream stays open up to 180 s |
| `grant_sync` | 0 | 16 KiB | Reconcile live grants after (re)connect |
| `grant_revoke` | 0 | 1 KiB | Edge tells the origin a grant ended |
| `ping` | 0 | 1 KiB | Liveness and enrollment status for `/owner` and fast-fail |

### 2.4 `mcp_post` metadata

Request meta:

| Field | Type / bound | Rule |
|---|---|---|
| `v` | 1 | Unknown → response `version_unsupported` |
| `op` | `"mcp_post"` | — |
| `path` | `"/mcp"` exactly | Anything else is refused before body read |
| `content_type` | `"application/json"` | Fixed |
| `accept` | `"json"` \| `"json_or_sse"` | Derived by the edge from the client's `Accept`; never a free string |
| `mcp_protocol_version` | optional, one of `2025-03-26`, `2025-06-18`, `2025-11-25` | Edge already validates the header (phase 2); forwarded as an enum |
| `assertion` | string ≤ 8 KiB | `Edge-Assertion` value. Edge refuses to mint one larger than 8 KiB for iroh routes |
| `request_id` | 16 random bytes, b64url | Non-secret correlation for logs on both sides; not the JSON-RPC id |
| `deadline_ms` | 1000..=25000 | Remaining budget; the origin aborts work and answers `deadline` when it passes |

No header map, URL, host, port, method, cookie or `Authorization` field exists.

Response meta:

| Field | Type | Rule |
|---|---|---|
| `v` | 1 | — |
| `status` | one of 200, 202, 400, 401, 403, 404, 413, 429, 500, 503, 504 | Other values are a transport error at the edge |
| `content_type` | `"application/json"` \| `"text/event-stream"` \| absent | Absent only with status 202 |
| `error` | optional enum (§2.7) | Present iff the origin refused at transport/authorization level |
| `retry_after` | optional int 1..=300 | Becomes `Retry-After` at the edge |

Wiskit v1 answers only `application/json` (stateless, no sessions, no SSE, no
`Mcp-Session-Id`). The framing keeps SSE so other origins and later versions can stream;
the edge already forwards chunks as they arrive (`x-accel-buffering: no`, PoC-proven).

### 2.5 Control op metadata

| Op | Request fields (besides `v`, `op`) | Response fields |
|---|---|---|
| `consent_request` | see §3.3 | `{v, status: 200, approval: <compact string ≤ 3 KiB>}` or `{v, status, error}` |
| `grant_sync` | `grants: [{grant_id, gen}]` ≤ 64 | `{v, status: 200, grants: [{grant_id, state: "active"\|"revoked"\|"unknown"}]}` |
| `grant_revoke` | `grant_id`, `gen`, `reason: "owner"\|"client"\|"replay"\|"expired"` | `{v, status: 200}` |
| `ping` | — | `{v, status: 200, remote: "on"\|"off"\|"paused"\|"stale", enrolled_fingerprint, origin_version}` |

Control ops carry no assertion: they are authorized by the peer check alone (only the
enrolled edge can open a stream) and none of them can read family data. `grant_sync`
and `grant_revoke` can only *end* grants; nothing on the tunnel can create, widen or
extend one except a consent the owner approves in the app.

### 2.6 Concurrency, deadlines, cancellation

| Limit | Edge | Origin |
|---|---|---|
| In-flight `mcp_post` per route / globally at origin | 8 | 4 (excess → `busy`, 429, `retry_after: 2`) |
| In-flight per grant | 4 | 2 |
| Pending `consent_request` | 4 per route (one per pending tx) | **1**; a second gets `consent_busy` |
| Requests per grant per minute | 300 (phase 2 limit) | 120 |
| Dial deadline (connect + handshake) | 3 s, then fast-fail (§2.8) | — |
| Request write deadline | 2 s (PoC) | Intake read deadline 2 s |
| First response byte | 15 s | Bridge timeout stays 10 s |
| Idle between chunks | 5 s | 5 s write stall → abort |
| Total | 25 s (under the edge's 30 s request deadline) | `deadline_ms` from meta |

Cancellation:

| Trigger | Mechanism | Effect at origin |
|---|---|---|
| Claude's HTTP connection drops | Edge drops the response reader → `stop` on the receive stream (PoC: slots released in ~25 ms) | Handler sees `stopped()`, cancels the pending bridge request for this stream |
| `notifications/cancelled` | Forwarded as an ordinary `mcp_post`; origin keys in-flight work by `(grant_id, JSON-RPC id)` | Cancels only that grant's request; a different grant cannot cancel it (tested) |
| Deadline | `deadline_ms` / edge total | Bridge request cancelled; `deadline` returned if the stream is still open |
| Revocation (either side) or remote off | Origin cancels all bridge requests of the grant (or all) | Response `grant_revoked` / `remote_disabled` |

Physical cancellation on disconnect is acceptable in v1 only because every exposed tool
is read-only. The 2025 transport says a disconnect is not a cancellation; before any
write tool exists, writes must run to completion or not start (§8, D10). The edge never
retries a POST.

### 2.7 Origin error codes → edge responses

| `error` (origin) | Origin status | Edge → Claude | Edge side effect |
|---|---|---|---|
| `remote_disabled` | 503 | 503 `origin_remote_off` | — |
| `enrollment_stale` | 503 | 503 `origin_unenrolled` | — |
| `origin_locked` (identity not unlocked / WebView not ready) | 503 | 503 `origin_locked` | — |
| `audit_unavailable` | 503 | 503 `origin_paused` | — |
| `assertion_invalid` (signature, iss, aud, exp, req, replay, sub, scope) | 401 | 502 `backend_rejected` | log `event=backend_rejected_assertion` |
| `unknown_grant` / `grant_revoked` / `grant_expired` | 401 | 401 `invalid_token` + `WWW-Authenticate` challenge | Edge revokes its grant (gen++) |
| `scope_mismatch` (assertion trackers ⊄ record) | 403 | 502 `backend_rejected` | log; revoke grant |
| `busy` | 429 | 429 + `Retry-After` | — |
| `deadline` | 504 | 504 | — |
| `bad_request` (framing, meta, body) | 400 | 502 `backend_protocol` | log |
| `version_unsupported` | 400 | 502 `backend_protocol` | log |
| `consent_busy` | 429 | consent page message (§3) | — |

MCP-level errors (unknown tool, tracker not in grant, result too large) are **not**
transport errors: they are ordinary JSON-RPC responses with status 200.

### 2.8 Offline, asleep, closed

The goal is a fast, honest failure, never a 25 s hang.

| State | Detection at edge | Time to answer |
|---|---|---|
| Cached connection alive | Use it | — |
| No connection; dial succeeds | — | normal |
| No connection; dial fails or exceeds 3 s | Mark route `offline` for 15 s | ≤ 3 s for the first request, immediate during the 15 s window |
| Connection drops mid-request | Stream error | 503 `origin_offline` (no retry) |

Response for every `origin_*` 503:

```http
HTTP/1.1 503 Service Unavailable
Content-Type: application/json
Retry-After: 30
Cache-Control: no-store

{"jsonrpc":"2.0","id":<request id if the body parsed, else null>,
 "error":{"code":-32010,"message":"Wiskit is not reachable: the home PC is off or asleep, or Wiskit is closed. Try again when it is running.","data":{"reason":"origin_offline"}}}
```

`message` varies per reason (remote access off, locked, needs re-enrollment, paused).
How claude.ai displays a 503 to the user is unverified and is an acceptance item (§7).
The edge parses the body only to echo the JSON-RPC `id`; it never logs it.

### 2.9 Relay and discovery

| Option | For | Against |
|---|---|---|
| **n0 public relays + n0 DNS discovery (recommended for trial)** | Wiskit already uses them (`presets::N0`); zero new infrastructure; relays carry only end-to-end encrypted QUIC | Third party sees both IPs, both EndpointIds and timing; availability depends on n0 |
| Self-hosted iroh relay on Coolify | Metadata stays on the owner's server; edge↔relay is local | Wiskit must then also use it as its home relay, which changes peer-sync behaviour for the whole family; a new service to run |
| Direct only (no relay) | No third party | Home NAT usually blocks inbound; unreliable |

The Coolify container needs outbound UDP (QUIC to relay and for hole punching) and
HTTPS to n0 DNS. No inbound UDP port is published.

## 3. Origin consent (`consent = "origin"`)

### 3.1 End to end

```text
Claude            browser / edge                          edge → origin tunnel        Wiskit app (owner)
  │ /authorize ──▶ pending tx (browser-bound cookie)
  │                passkey proof (as phase 2)
  │                consent page: client, backend, warnings
  │                [Continue to Wiskit]  (CSRF, fresh proof)
  │                pairing code K7Q-M2X shown ───────────── consent_request ───────▶ "Claude wants access"
  │                page polls /consent/status (2 s)                                   type code K7Q-M2X
  │                                                                                   pick trackers (read)
  │                                                                                   pick lifetime ≤ 24 h
  │                                                  ◀──── signed approval ──────── [Approve] / [Deny]
  │                verify approval, create grant with
  │                resource_scope, issue one-use code
  │ ◀── 303 redirect_uri?code&state&iss
  │ /token (PKCE) ─▶ access + refresh (phase 2 rules)
```

### 3.2 Edge pending-request state machine

Extends the phase 2 `pending` row (10 min TTL, browser-bound, one-shot).

| State | Entered when | Page shows | Leaves to |
|---|---|---|---|
| `created` | `/authorize` accepted | passkey prompt | `proved`, `expired` |
| `proved` | passkey verified (≤ 5 min old) | client/backend details, data-export warning, **Continue to Wiskit** | `sent`, `denied` (owner clicks Deny here), `expired` |
| `sent` | Continue POST (CSRF + proof still fresh) and the tunnel accepted `consent_request` | pairing code, "Approve in Wiskit on your PC", Cancel | `approved`, `denied`, `origin_timeout`, `origin_unreachable`, `cancelled` |
| `origin_unreachable` | dial/stream failed or `consent_busy` | reason + **Try again** (≤ 3 attempts per tx, new pairing code each time) | `sent`, `denied`, `expired` |
| `approved` | valid approval verified (§3.5) | "Approved, returning to Claude" | `code_issued` |
| `code_issued` | grant + code created atomically | 303 to `redirect_uri` with `code`, `state`, `iss` | terminal |
| `denied` | owner denied in app or on edge page | 303 with `error=access_denied` | terminal |
| `origin_timeout` | no decision within 180 s | "No decision in Wiskit" + button that redirects `access_denied` | terminal |
| `cancelled` | owner clicked Cancel | edge stops the stream (origin drops the prompt); redirect `access_denied` | terminal |
| `expired` | pending TTL passed | phase 2 error page | terminal |

Status endpoint: `GET /consent/status?tx=…` (same `__Host-` browser binding as the
consent page; JSON `{"state": "...", "attempts_left": n}`; no codes, no tracker names).
The page's existing `edge.js` polls it every 2 s; without JS a **Check** button reloads.
The final redirect is issued by a CSRF-protected `POST /consent/finish` so the code never
appears in a JSON response.

### 3.3 `consent_request` fields (edge → origin)

Data minimization: the app gets what the owner needs to recognize the request, nothing
from the browser (no IP, user agent, cookie).

| Field | Type / bound | Shown in app |
|---|---|---|
| `tx` | random id ≤ 32 | no (bound into the approval) |
| `grant_id` | `g_` + random, ≤ 40 | no (becomes the shared grant id) |
| `nonce` | 32 random bytes b64url | no (must be echoed in the approval) |
| `pairing_code` | 6 Crockford base32 chars | **no**; the owner must type it (D3) |
| `client_id` | ≤ 64 | yes (small) |
| `client_name` | ≤ 80, control chars stripped, labelled "self-reported" | yes |
| `client_registered_at` | unix s | yes ("registered 3 min ago") |
| `redirect_host` | host only | yes (`claude.ai`) |
| `requested_at` | unix s | yes |
| `scopes` | ⊆ route scopes | yes (as "read-only") |
| `max_lifetime_secs` | route `grant_lifetime_secs` | caps the app's lifetime choices |
| `expires_at` | ≤ `requested_at` + 180 | countdown |

### 3.4 App side

| Step | Rule |
|---|---|
| Preconditions | Remote mode on, enrollment valid, identity unlocked, desktop build. Otherwise the origin answers `remote_disabled` / `enrollment_stale` / `origin_locked` immediately |
| Prompt | A modal in the main window plus an OS notification ("Claude is asking for read access to Wiskit"). One pending prompt at a time |
| Code | Owner types the 6-char code from the browser; compared in constant time; 3 wrong entries deny the request |
| Trackers | Checklist of grantable trackers, **none preselected**. Grantable = trackers whose owner is this identity (handoff item 4: a reader of a shared tracker is not automatically allowed to export it; D4). Archived trackers listed separately. 1..=32 selectable |
| Access | Read-only; no other choice exists in v1 |
| Lifetime | 1 h, 8 h, or `max_lifetime_secs` (24 h trial), whichever ≤ max; default 1 h |
| Export notice | Fixed text: the edge operator (the owner's own server) and Anthropic will see the returned tracker data in plaintext |
| Decision | Approve / Deny. Closing the modal = Deny. Timeout at `expires_at` = no response, stream closed |
| Record | On approve the app writes its grant record (§4.2) **before** sending the approval, and drops it if the send fails |

### 3.5 Signed approval

Signing key: the Wiskit transport secret key (`secret.key`, Ed25519), with domain
separation. Rationale: the edge already pins this key as the origin's EndpointId, so no
new key needs storage, backup or enrollment; a transport-key change already forces
re-enrollment and fresh consent; family keys (DEKs, HALO identity, Stronghold) stay
entirely out of remote access. Alternative keys are D2.

Wire form (mirrors `edge-assert`):

```text
<base64url-nopad(canonical JSON claims)>.<base64url-nopad(Ed25519 signature)>
signature over ASCII "mcp-edge-approval.v1." || payload segment as transmitted
```

| Claim | Type | Rule at the edge |
|---|---|---|
| `v` | 1 | — |
| `decision` | `"approve"` \| `"deny"` | — |
| `iss` | 64 hex | = configured origin EndpointId, and = the verifying key |
| `edge_id` | 64 hex | = this edge's iroh EndpointId |
| `aud` | URL | = edge issuer |
| `backend` | id | = route id |
| `tx`, `grant_id`, `nonce`, `client_id` | strings | = the values sent in `consent_request` |
| `resource_scope` | object (approve only) | `{"v":1,"access":"read","trackers":[...]}`; trackers sorted, unique, 1..=32, each matches `^[A-Za-z0-9_-]{1,64}$`; serialized ≤ 3 KiB |
| `lifetime_secs` | int (approve only) | 300 ≤ x ≤ route `grant_lifetime_secs` |
| `iat`, `exp` | unix s | `0 < exp - iat ≤ 120`; 5 s skew; `exp` not passed |

Canonical JSON and strict verification exactly as `edge-assert` (sorted keys, integers
only, unknown claims rejected). A valid `deny` moves the tx to `denied`; an invalid
approval of either kind is logged (`event=origin_approval_invalid`) and treated as
`origin_unreachable`, never as approval.

On approve the edge, in one transaction: consumes the pending row; creates the grant
with the given `grant_id`, `resource_scope`, `expires = now + lifetime_secs`, `gen = 1`;
stores the approval string on the grant row (evidence); creates the one-use code.
`create_grant_with_code` gains `resource_scope` and `expires` parameters (it currently
hard-codes `'{}'` and the route lifetime).

### 3.6 Revocation and `gen`

| Initiator | Edge | Origin |
|---|---|---|
| Owner in edge `/owner` (revoke / revoke all), RFC 7009 `/revoke`, refresh replay, expiry | Grant `revoked`, gen++ (phase 2 behaviour); best-effort `grant_revoke` to origin | Record → tombstone `revoked` until its expiry; in-flight work of the grant cancelled |
| Owner in app (per-grant Revoke, "Revoke all remote", remote mode off, re-enroll, app restart in trial) | Learns on the next request (`grant_revoked`/`unknown_grant` → revoke + 401) or at `grant_sync` on reconnect | Immediate: refuses the next request regardless of edge state |
| Edge offline from origin when it revokes | Grant already unusable (no assertion minted for revoked grants) | Cleaned at next `grant_sync`; record expires anyway |

`gen` rule: the origin stores the `gen` from the first assertion it sees for a grant
(always 1 today) and requires equality on every request. The edge changes `gen` only on
revocation, and a revoked grant never mints assertions, so a mismatch means a bug or
tamper: `assertion_invalid`, logged on both sides. Any future "narrow this grant"
feature must go through a new signed approval, not a `gen` bump.

`grant_sync` runs on every new edge→origin connection: the edge sends its active
grants for the route (≤ 64), revokes those the origin reports `revoked` or `unknown`.

## 4. Origin enforcement

### 4.1 Request pipeline (all inside `edge-origin` + Wiskit; fail closed at each step)

| # | Check | Failure |
|---|---|---|
| 1 | Peer = enrolled `edge_id` | close 1 |
| 2 | Enrollment not stale; remote mode on | close 5 / close 3 (or `remote_disabled` per stream if it changed mid-connection) |
| 3 | Framing, caps, meta schema, `path`, `v`, no trailing bytes | `bad_request` |
| 4 | Verify `Edge-Assertion` with the enrolled key: signature; `iss` = enrolled issuer; `aud` = enrolled backend; `0 < exp-iat ≤ 60`, 5 s skew; `req` = SHA-256 of `POST\n/mcp\n<body>`; `jti` unseen (replay cache 10 000 entries, full → reject); `sub` = enrolled `sub`; `scope` = enrolled scopes; `iat` ≥ origin process start − 5 s | `assertion_invalid` |
| 5 | Grant record for `grant_id`: exists, `active`, not expired, `client_id` equal, `gen` equal | `unknown_grant` / `grant_revoked` / `grant_expired` / `assertion_invalid` |
| 6 | `resource_scope.access == "read"` and assertion trackers ⊆ record trackers | `scope_mismatch` (also revokes the record) |
| 7 | Audit write for the request succeeds (§4.5) | `audit_unavailable`; remote mode → `paused` |
| 8 | Build `RemoteGrantContext` **from the record**, never from the assertion or request | — |
| 9 | Concurrency slot (global 4, per grant 2) | `busy` |
| 10 | Remote MCP adapter → broker → bridge (§4.3) | MCP-level errors |
| 11 | Before emitting the response: grant still active with the same `gen`, remote still on | `grant_revoked` / `remote_disabled`; the result is discarded |

### 4.2 `RemoteGrantContext` and the grant record

```rust
pub struct RemoteGrantContext {        // immutable; constructed only by the origin grant store
    pub grant_id: GrantId,             // shared with the edge, non-secret
    pub client_id: String,
    pub client_label: String,          // self-reported name at consent, for audit display only
    pub trackers: BTreeSet<TrackerId>, // explicit, owner-approved
    pub access: RemoteAccess,          // only RemoteAccess::Read exists in v1
    pub expires_at: u64,
    pub gen: u64,
    pub epoch: u64,                    // bumps on remote off / re-enroll / revoke-all
}
```

| Record field | Source |
|---|---|
| `grant_id`, `client_id`, `client_label`, `trackers`, `expires_at` | the owner's approval |
| `gen` | first verified assertion (then fixed) |
| `state` | `active` → `revoked` (tombstone) → deleted at `expires_at` |
| `epoch` | current remote epoch at approval; a record from an older epoch is `unknown` |
| `created_at`, `last_used_at` | local clock |

Storage in the trial: memory only (`RemoteGrantStore` in managed Tauri state). Restart
= all remote grants gone and remote mode off (handoff default). Persistent records are
D1. Limits: ≤ 16 active remote grants.

### 4.3 Broker and bridge changes

| Item | Change |
|---|---|
| Entry point | New `broker::handle_remote(state, &RemoteGrantContext, method, params, cancel)`; the loopback path (`handle_request`) is unchanged. Remote calls do **not** require the loopback listener (`is_live()`) and local capability tokens are never valid remotely |
| Method allowlist | Exactly `wiskit_list_trackers`, `wiskit_read_tracker_bundle`. Everything else (documents, decks, search, read_document, writes, session_status) → JSON-RPC `METHOD_NOT_FOUND` before the bridge |
| Pre-check | `wiskit_read_tracker_bundle`: `trackerId` ∈ `ctx.trackers` **before** emitting to the WebView; otherwise tool error `tracker_not_granted` (same message whether the tracker exists or not) |
| Bridge payload | `BridgeRequestPayload` gains `remote: Option<RemoteBridgeScope { grantId, trackerIds, epoch }>`; nonce rules unchanged; `mcp_bridge_authorize` additionally checks the remote scope it registered |
| WebView projection | `dispatchBridgeRequest` gets a remote mode: list filtered to `trackerIds`; bundle uses the remote projection (§4.4). Pure function, unit-tested |
| Rust post-check (authoritative) | The broker re-validates the JSON the WebView returned before emitting: list → every `id` ∈ ctx; bundle → `tracker.id` == requested and every event's `trackerId` == requested; only allowlisted keys present (§4.4); serialized size ≤ 1 MiB. Any violation → result dropped, `BRIDGE_ERROR`, audited as `leak_blocked` |
| Bridge availability | The agent-bridge listener (`installAgentBridge`) today exists only while local agent access is on; it must also be installed while remote mode is on |
| Cancellation | Bridge requests are registered with their `grant_id`; `cancel_grant(id)`, `cancel_remote_all()` added next to `cancel_all()` |

### 4.4 Remote tool surface (v1)

| Tool | Input | Output (allowlisted keys only) |
|---|---|---|
| `wiskit_list_trackers` | `{}` | `{trackers: [{id, name, description, icon, interval, unit, detailsSchema, archived, createdAt, updatedAt}]}`, granted trackers only |
| `wiskit_read_tracker_bundle` | `{trackerId: string, limit?: 1..=500 (default 200), before?: cursor}` | `{tracker: {…same keys…}, events: [{id, timestamp, details}], nextCursor: string \| null}` newest first |

Removed from the local projection for remote use: `owner` (identity ids), `deckId`
(reveals deck membership of other trackers), `accessState`, event `owner`, event
`attachmentIds`, and `details` fields whose schema type is an attachment/photo. Photos do
not leave the device in v1.

Pagination replaces truncation: the cursor is opaque (`b64url(timestamp:eventId)`),
bound to the tracker; a result that would still exceed 1 MiB returns tool error
`result_too_large` asking for a smaller `limit`. A ~10 000-event tracker is about 50
pages at the default.

MCP adapter (Rust, stateless JSON, mirrors the edge's echo backend): `initialize`
(negotiates `2025-11-25`/`2025-06-18`/`2025-03-26`, default `2025-06-18`, no session id),
`notifications/initialized` (202), `ping`, `tools/list` (two tools, `readOnlyHint: true`
as advisory annotation), `tools/call`, `notifications/cancelled` (202). Batches are
rejected. Tool results: `content: [{type: "text", text: <JSON>}]` plus `structuredContent`
for ≥ 2025-06-18.

### 4.5 Durable redacted audit

New append-only table in `wiskit.db`, separate from `mcp_audit` (whose summaries can
contain family text):

| Column | Content |
|---|---|
| `seq`, `ts` | — |
| `grant_id` | non-secret shared id |
| `client_label` | self-reported, ≤ 80 |
| `op` | `consent_prompt`, `consent_approve`, `consent_deny`, `initialize`, `tools_list`, `list_trackers`, `read_bundle`, `cancel`, `revoke`, `remote_on`, `remote_off`, `enroll`, `refused` |
| `decision` | `ok`, `denied`, `error`, `leak_blocked` |
| `reason` | error enum from §2.7 / tool error code |
| `tracker_id` | local id (names resolved only at display, locally) |
| `count` | events or trackers returned |
| `bytes` | response size |

Never stored: assertions, tokens, codes, pairing codes, nonces, JSON-RPC params beyond
`trackerId`, cursors, event content, names typed by Claude.

| Rule | Behaviour |
|---|---|
| Ordering | Request audited before the bridge call; outcome row before the response is emitted |
| Failure | Any insert failure → remote mode `paused`, in-flight remote work cancelled, every request `audit_unavailable` until the owner resumes in Settings (which retries an insert first) |
| No in-memory fallback | Unlike `mcp_audit`, remote audit never degrades to memory-only |
| Retention | 5 000 rows, as `mcp_audit` |
| UI | Agent Activity shows remote entries with a "Remote (mcp-edge)" badge |

### 4.6 Remote mode switch

| Property | Value |
|---|---|
| Location | Settings → Agent access → Remote access (mcp-edge), desktop only (hidden on iOS/Android) |
| Default | Off. In the trial it also returns to off on every app start (preference not persisted; D1) |
| Independence | Separate from the local agent-access switch (default on for desktop); neither implies or disables the other. A separate "Stop all agent access" button turns both off |
| On requires | Valid, non-stale enrollment; unlocked identity; audit table writable |
| Off does | Epoch++; all remote grant records dropped; pending consent prompt closed; remote bridge requests cancelled; origin answers `remote_disabled` (existing connections closed with code 3) |
| States | `off`, `on`, `paused` (audit failure), `stale` (enrollment) |

### 4.7 Restart behaviour

| Event | Origin | Edge |
|---|---|---|
| App restart (trial) | Grants gone, remote off, replay cache empty, assertions with `iat` before start refused | Next request: `remote_disabled` (503). After owner turns remote on: `unknown_grant` → grant revoked → Claude must reconnect (new consent) |
| PC sleep/wake | Grants kept (memory), endpoint reconnects | Requests during sleep fast-fail `origin_offline`; recover without consent |
| Edge restart | — | Grants in SQLite survive; first connection runs `grant_sync` |
| Wiskit identity locked | `origin_locked` for MCP and consent | 503 |
