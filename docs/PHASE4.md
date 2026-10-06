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
