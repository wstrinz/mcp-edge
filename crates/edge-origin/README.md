# edge-origin

Embeddable origin side of `mcp-edge/1` for a local app reached by `mcp-edge`
over iroh. The app keeps its own iroh endpoint and adds one ALPN; this crate
does admission, framing, assertion checks, limits and cancellation, and calls
the app through one trait. Nothing here is Wiskit-specific. Wire format:
[edge-tunnel](../edge-tunnel/README.md); behaviour:
[docs/PHASE4.md](../../docs/PHASE4.md) §2, §3.4, §4.1.

iroh is pinned to `=1.3.0` so an app that already uses iroh 1.3.0 links one
copy (depend on this crate by git, pinned to a commit).

## Wiring

```rust
use edge_origin::{Enrollment, OriginConfig, OriginHandler, ALPN};

let handler = OriginHandler::new(app.clone(), endpoint.secret_key().clone(), OriginConfig::default());
// Owner pasted the enrollment string from the edge's /owner page:
handler.set_enrollment(Some(Enrollment::parse(&pasted)?))?;
let router = Router::builder(endpoint.clone())
    .accept(ALPN, handler.clone())          // register even while remote access is off
    /* ... the app's other protocols ... */
    .spawn();
```

Add `edge_origin::ALPN` to the endpoint's `alpns(...)` list as well. Show the
owner `enrollment.fingerprint()` and the app's own EndpointId (`endpoint.id()`,
64 hex) to copy into the edge configuration.

| Handler method | Use |
|---|---|
| `set_enrollment(Some(e) / None)` | Enroll / unenroll; closes live connections (`peer_not_admitted`) and starts a fresh replay cache |
| `close_all(CloseCode::RemoteDisabled)` | Remote access turned off: existing connections closed with code 3 |
| `close_all(CloseCode::EnrollmentStale)` | Own EndpointId no longer matches `enrolled_as` |
| `live_connections()`, `in_flight()`, `pending_consents()` | Status |

## The trait

```rust
pub trait OriginApp: Send + Sync + 'static {
    fn remote_state(&self) -> RemoteState;                       // On | Off | Paused | Stale
    fn origin_version(&self) -> String;                          // reported by ping
    async fn mcp_post(&self, req: McpRequest) -> Result<McpResponse, Refusal>;
    async fn consent_request(&self, responder: ConsentResponder);
    async fn grant_sync(&self, grants: Vec<GrantRef>) -> Result<Vec<GrantSyncEntry>, Refusal>;
    async fn grant_revoke(&self, revoke: GrantRevokeMeta) -> Result<(), Refusal>;
}
```

(Declared as `fn ... -> impl Future<Output = ...> + Send`; implement with
`async fn`.) `ping` is answered by the handler from `remote_state()`, the
enrollment fingerprint and `origin_version()`.

| Type | Meaning |
|---|---|
| `McpRequest` | `grant: VerifiedGrant` (claims of the verified assertion: `grant_id`, `client_id`, `sub`, `scope`, `resource_scope`, `gen`, `iat`, `exp`), `accept`, `mcp_protocol_version`, `request_id`, `body` (exact bytes the assertion covers), `deadline`, `cancel: CancellationToken` |
| `McpResponse` | `status` (200, 202, 400, 401, 403, 404, 413, 429, 500, 503, 504), `content_type` (`None` only with 202), `body: Body::{Empty, Full(Bytes), Stream(BodyStream)}`; helpers `json`, `accepted`, `event_stream` |
| `Refusal` | `code: ErrorCode` + optional `retry_after`; sent as `{status: code.status(), error}` |
| `ConsentResponder` | `request()`, `cancelled()`, `expires()`, `pairing_code_matches(typed)`, `approve(trackers, lifetime_secs)`, `deny()`, `refuse(refusal)` |
| `VerifiedGrant` | Identity only; authority comes from the app's own grant record |

## What the handler does, in order

1. Admission at accept, before any stream is read: peer EndpointId = enrolled
   `edge_id` (else close 1); `remote_state()` `Off` → close 3, `Stale` → close
   5; at most 2 admitted connections (else close 2); at most 8 concurrent
   streams per connection (extra streams are reset).
2. Intake within 2 s: metadata ≤ 12 KiB, strict schema, `v`, `path`, then the
   body (≤ 64 KiB for `mcp_post`, empty for control ops), then FIN with no
   trailing byte. Failures → `bad_request` / `version_unsupported`.
3. `mcp_post`: `remote_state()` must be `On` (`Off` → `remote_disabled`,
   `Paused` → `audit_unavailable`, `Stale` → `enrollment_stale`); assertion
   verified with the enrolled key: signature, `iss`, `aud`, `0 < exp-iat ≤ 60`
   with 5 s skew, `req` = SHA-256 of `POST\n/mcp\n<body>`, `jti` unseen (10 000
   entries, full → reject), `sub` = enrolled `sub`, `scope` = enrolled scopes,
   `iat` ≥ handler start − 5 s. Any failure → `assertion_invalid` (401).
4. Limits: 120 requests per grant per minute, 4 in flight globally, 2 per grant
   → `busy` (429, `retry_after`).
5. Dispatch to `mcp_post` with a token that fires when the edge stops the
   stream (client disconnect), the deadline passes, the connection ends or the
   router shuts down. On cancellation the handler also drops the app's future
   or stream; on the deadline it answers `deadline` (504) if nothing was sent.
6. Response: metadata, chunks ≤ 16 KiB, total ≤ 1 MiB, 5 s write-stall bound,
   terminator, FIN. An over-cap body, a stalled write, an invalid status or an
   app stream error resets the stream: the edge reports a truncated response.

The app's part of §4.1 (steps 5–8, 10, 11): look up its grant record by
`grant_id` (exists, active, not expired, `client_id` equal, `gen` equal),
compare `resource_scope` against the record, audit, build its context from the
record (never from the assertion), run the call, and re-check the grant before
returning. Return `Refusal`s for `unknown_grant`, `grant_revoked`,
`grant_expired`, `scope_mismatch`, `origin_locked`, `audit_unavailable`.

## Consent

`consent_request` is refused before reaching the app unless remote access is
`On`, `expires_at` is in the future and ≤ 185 s away, and no other prompt is
pending (`consent_busy`). The app then:

1. shows the prompt (never the pairing code), asks the owner to type the code
   (`pairing_code_matches`, constant time; count wrong entries yourself);
2. on Approve, writes its grant record, calls `approve(trackers, lifetime_secs)`
   and drops the record if it returns `Err` (not delivered / cancelled);
3. on Deny calls `deny()`; when locked etc. calls `refuse(...)`;
4. watches `cancelled()`: it fires when the edge cancels or `expires_at` passes.

`approve` signs the approval with the key given to `OriginHandler::new` (the
endpoint's transport key) under `mcp-edge-approval.v1.`, bound to the edge id,
issuer, backend, `tx`, `grant_id`, `nonce` and `client_id`, valid 60 s, and
returns `Ok` only after the edge acknowledged every byte. Returning without
answering resets the stream (no decision).

## Tests

`tests/tunnel.rs` runs the edge client against this handler over real iroh
endpoints bound to 127.0.0.1 with ephemeral keys and relays/address lookup
disabled (the PoC setup): JSON and SSE round trips; caps at limit and +1 on
both sides; every assertion failure; replay; `iat` before start; remote
off/paused/stale; unenrolled peer, re-enrollment; connection limit with one
re-dial; offline fast-fail (≤ 3 s) and the immediate 15 s window; cancellation
on drop and on deadline; edge and origin concurrency and rate limits; ping,
`grant_sync`, `grant_revoke`; consent approve / deny / refuse / busy / cancel /
expiry with approvals verified by `edge_tunnel::approval::verify`; raw-wire
framing attacks; edge-side truncation and bad-response detection against a
fake origin.
