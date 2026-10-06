# edge-tunnel

The wire protocol between `mcp-edge` and a local origin app over iroh, ALPN
`mcp-edge/1`, plus the edge-side client. Normative source:
[docs/PHASE4.md](../../docs/PHASE4.md) §1.3, §2, §3.3, §3.5. This README is the
format reference for implementers of other origins; the origin library is
[`edge-origin`](../edge-origin/README.md).

The edge always dials; the origin only accepts. One QUIC connection, one
bidirectional stream per request. No HTTP crosses the tunnel: no URL, host,
port, method, header map, cookie or `Authorization` field exists anywhere in
the format.

iroh is pinned to `=1.3.0` (the version Wiskit resolves, D8) and re-exported as
`edge_tunnel::iroh`.

## Framing

```text
field     = u32 big-endian length || bytes
request   = field(request meta JSON) field(body) FIN
response  = field(response meta JSON) field(chunk)* 00 00 00 00 FIN
```

* Every length is checked against the field's cap **before** allocation.
* The request ends with FIN; any byte after the body is `bad_request`.
* The response ends with an explicit zero-length terminator, then FIN. A
  response without the terminator (FIN early, stream reset, connection lost) is
  a truncation error at the edge, never a success. Bytes after the terminator
  are a protocol error.
* Control operations and refusals have **no chunks**: metadata, then the
  terminator.

| Field | Cap |
|---|---|
| Request metadata | 12 KiB |
| `mcp_post` body | 64 KiB (must be non-empty) |
| Control op body | 0 (must be empty) |
| `mcp_post` response metadata | 2 KiB |
| Response chunk | 16 KiB |
| `mcp_post` response total | 1 MiB (counted across chunks) |
| `consent_request` / `grant_sync` / `grant_revoke` / `ping` response metadata | 4 KiB / 16 KiB / 1 KiB / 1 KiB |

## Request metadata

UTF-8 JSON object, unknown fields rejected, tagged by `op`. Every object has
`"v": 1`. A `v` that is an integer other than 1 is answered
`version_unsupported` (checked before the strict parse); anything else invalid
is `bad_request`.

`mcp_post`:

| Field | Rule |
|---|---|
| `path` | exactly `"/mcp"` (checked before the body is read) |
| `content_type` | exactly `"application/json"` |
| `accept` | `"json"` \| `"json_or_sse"` |
| `mcp_protocol_version` | optional: `2025-03-26` \| `2025-06-18` \| `2025-11-25` |
| `assertion` | `Edge-Assertion` ([edge-assert](../edge-assert/README.md)), ASCII, 1..=8 KiB, bound to `POST /mcp` + the exact body |
| `request_id` | 16 random bytes, base64url (non-secret log correlation) |
| `deadline_ms` | 1000..=25000; the origin answers `deadline` when it passes |

`consent_request`: `tx` (`[A-Za-z0-9_-]{1,32}`), `grant_id` (`g_` +
`[A-Za-z0-9_-]`, ≤ 40), `nonce` (32 bytes base64url), `pairing_code` (6
Crockford base32, upper case), `client_id` (≤ 64, no control chars),
`client_name` (≤ 80 chars, no control chars, self-reported), `client_registered_at`,
`redirect_host` (host only: `[A-Za-z0-9.-]`), `requested_at`, `scopes` (1..=4),
`max_lifetime_secs` (300..=2592000), `expires_at` (`requested_at` < x ≤
`requested_at` + 180).

`grant_sync`: `grants: [{grant_id, gen}]`, ≤ 64, unique ids.
`grant_revoke`: `grant_id`, `gen`, `reason: owner|client|replay|expired`.
`ping`: no fields.

Control ops carry no assertion: the origin authorizes them by the peer check
alone, and none of them can read data or create/extend a grant.

## Response metadata

`mcp_post`: `{v, status, content_type?, error?, retry_after?}`

* `status` ∈ 200, 202, 400, 401, 403, 404, 413, 429, 500, 503, 504.
* `content_type` ∈ `application/json`, `text/event-stream`; absent only with 202.
* `error` (refusal) implies `status == error.status()` (table below) and
  `content_type: application/json`, and no chunks follow.
* `retry_after` 1..=300.

Control ops: `{v, status: 200, <payload>}` or `{v, status, error, retry_after?}`:

| Op | Payload |
|---|---|
| `consent_request` | `approval` (compact string ≤ 3 KiB, below) |
| `grant_sync` | `grants: [{grant_id, state: active\|revoked\|unknown}]`, exactly the grants asked about |
| `grant_revoke` | none |
| `ping` | `remote: on\|off\|paused\|stale`, `enrolled_fingerprint`, `origin_version` |

## Error codes and close codes

| `error` | Origin status | Edge answers | Edge revokes its grant |
|---|---|---|---|
| `remote_disabled` | 503 | 503 `origin_remote_off` | |
| `enrollment_stale` | 503 | 503 `origin_unenrolled` | |
| `origin_locked` | 503 | 503 `origin_locked` | |
| `audit_unavailable` | 503 | 503 `origin_paused` | |
| `assertion_invalid` | 401 | 502 `backend_rejected` | |
| `unknown_grant` / `grant_revoked` / `grant_expired` | 401 | 401 `invalid_token` | yes |
| `scope_mismatch` | 403 | 502 `backend_rejected` | yes |
| `busy` | 429 | 429 + `Retry-After` | |
| `deadline` | 504 | 504 | |
| `bad_request` / `version_unsupported` | 400 | 502 `backend_protocol` | |
| `consent_busy` | 429 | consent page message | |

QUIC application close codes (connection level): 1 `peer_not_admitted` → 503
`origin_rejected_edge`; 2 `connection_limit` → re-dial once after 1 s, then
503 `origin_busy`; 3 `remote_disabled` → 503 `origin_remote_off`; 4
`shutting_down` → 503 `origin_offline`; 5 `enrollment_stale` → 503
`origin_unenrolled`. `ErrorCode::edge_failure`, `CloseCode::edge_failure` and
`TunnelError::edge_failure` encode these tables; unit tests pin them row by row.

## Signed consent approval (D2)

```text
approval  = <b64url-nopad(canonical JSON claims)>.<b64url-nopad(Ed25519 signature)>
signature = Ed25519(origin iroh transport secret key,
                    "mcp-edge-approval.v1." || payload segment as transmitted)
```

The verifying key is the configured origin EndpointId (no new key to enroll).
The prefix separates this use of the transport key from iroh's TLS handshake
and from `edge-assert`'s `edge-assert.v1.`. Canonical JSON as in `edge-assert`
(sorted keys, no whitespace, integers only); unknown claims and non-canonical
payloads are rejected.

| Claim | Rule at the edge |
|---|---|
| `v` | 1 |
| `decision` | `approve` \| `deny` |
| `iss` | origin EndpointId (64 hex) = the verifying key |
| `edge_id` | this edge's EndpointId |
| `aud` | edge issuer URL |
| `backend` | route id |
| `tx`, `grant_id`, `nonce`, `client_id` | exactly the values sent in `consent_request` |
| `resource_scope` | approve only: `{"v":1,"access":"read","trackers":[...]}`, sorted, unique, 1..=32, each `[A-Za-z0-9_-]{1,64}`, ≤ 3 KiB |
| `lifetime_secs` | approve only: 300..=route `grant_lifetime_secs` |
| `iat`, `exp` | `0 < exp - iat ≤ 120`; 5 s skew; not expired |

Origin: `approval::sign(&secret_key, &binding, decision, scope, lifetime, now, ttl)`.
Edge: `approval::verify(&approval, &binding, now)`. An invalid approval of
either kind must be treated as "origin unreachable", never as approval.

Test vector (`approval::tests::pinned_vector`; signature cross-checked with an
independent Ed25519 implementation):

```text
origin secret seed : 32 bytes of 0x02 → iss 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
edge secret seed   : 32 bytes of 0x04 → edge_id ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c
claims JSON        : {"aud":"https://edge.example","backend":"wiskit","client_id":"client","decision":"approve","edge_id":"ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c","exp":1700000060,"grant_id":"g_example","iat":1700000000,"iss":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394","lifetime_secs":3600,"nonce":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk","resource_scope":{"access":"read","trackers":["t1","t2"],"v":1},"tx":"tx_1","v":1}
signature          : UZrzyVaAYwMYY9NWTfw2rZmtgivFd-_je6miygMXqbNqwA9D30lKRG0cNtIx_BRl9t4gKSiywwXEwA7U0GS-Aw
```

## Enrollment string (§1.3)

```text
mcp-edge-enroll:1:<base64url-nopad(canonical JSON)>
fingerprint = Crockford base32(SHA-256(canonical JSON)[0..10]) as XXXX-XXXX-XXXX-XXXX
```

Fields: `v` (1), `iss` (https URL ≤ 128), `aud` (backend id
`[a-z][a-z0-9-]{0,31}`), `edge_id` (64 lowercase hex, valid Ed25519 point),
`assert_key` (43-char base64url Ed25519 key), `sub` (≤ 64), `scopes` (1..=4,
unique). Parsing requires the canonical encoding, so one enrollment has one
string and one fingerprint. No secrets inside.

Vector (`enrollment::tests::pinned_vector`): edge seed 0x04, assertion seed 0x01,
`iss https://edge.example`, `aud wiskit`, `sub owner`, `scopes ["wiskit:read"]` →
fingerprint `KR4R-3MMF-58NB-P74R`.

## Edge client

```rust
use edge_tunnel::client::{ClientConfig, McpPostRequest, OriginClient, Reply};

let client = OriginClient::new(edge_endpoint, EndpointAddr::new(origin_id), ClientConfig::default());
match client.mcp_post(McpPostRequest { grant_id, accept, mcp_protocol_version, assertion,
                                       request_id: new_request_id(), body, budget }).await {
    Ok(Reply::Ok(resp))       => /* resp.status, resp.content_type, resp.body.into_stream() */,
    Ok(Reply::Refused(r))     => /* r.edge_failure(), r.retry_after, r.error.revokes_edge_grant() */,
    Err(e)                    => /* e.edge_failure(): 503 origin_offline, 504, 502, 429, ... */,
}
```

* Dials only the `EndpointAddr` it was built with and checks the peer id.
* One cached connection, opened lazily; `subscribe_connections()` ticks on each
  new connection (run `grant_sync` then).
* Dial failure or > 3 s: `Offline`, and the origin is marked offline for 15 s
  (requests in the window fail immediately). A connection closed by the origin
  with a close code is reported as `Closed(code)` and redialled on the next
  request (no window).
* Limits: 8 in-flight `mcp_post` per client (route), 4 per grant, 4 pending
  consents; excess is `EdgeBusy` (429) without dialling.
* Deadlines: write 2 s, first byte 15 s, 5 s idle between chunks, total =
  `budget` (≤ 25 s, sent as `deadline_ms`).
* Dropping a `ResponseBody` (or the request future) stops the stream; the
  origin cancels the work. POSTs are never retried, except the single re-dial
  after `connection_limit` on a fresh connection (nothing was processed).
* `transport_config()` gives the §2.2 QUIC settings for the edge endpoint
  (8 bidi / 0 uni streams, 64/256/64 KiB windows, 5 s keep-alive, 20 s idle).

Tests: unit tests here (framing caps at limit and +1, metadata rules, codes,
approval and enrollment vectors); end-to-end tests over loopback iroh in
`crates/edge-origin/tests/tunnel.rs`.
