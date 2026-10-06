# edge-assert

The short-lived, signed assertion that `mcp-edge` attaches to every request it
forwards to a backend, in the `Edge-Assertion` HTTP header. Backends never see
the OAuth bearer token, cookies or the `Authorization` header; they verify one
Ed25519 signature instead.

This document is the format specification. The Rust crate implements it, but a
backend in any language can verify an assertion with a base64url decoder, a JSON
parser, SHA-256 and Ed25519.

## Wire format

```text
Edge-Assertion: <payload>.<signature>
```

* `payload` = base64url **without padding** of the UTF-8 claims JSON.
* `signature` = base64url without padding of the 64-byte Ed25519 signature over
  the ASCII bytes `edge-assert.v1.` followed by the `payload` segment *as
  transmitted* (the base64url text, not the decoded JSON).
* Exactly one `.`; total length at most 16 KiB.

The edge public key is the raw 32-byte Ed25519 key, base64url without padding.
`mcp-edge` serves it at `GET /.well-known/edge-assertion-key` and prints it at
startup. Configure it into the backend out of band; do not fetch it per request.

### Claims

| Claim | Type | Meaning |
|---|---|---|
| `iss` | string | Edge issuer URL (e.g. `https://mcp.app.stri.nz`) |
| `aud` | string | Backend id from the edge route table (e.g. `echo`) |
| `sub` | string | Owner id |
| `client_id` | string | OAuth client holding the grant |
| `grant_id` | string | Independent, non-secret grant id |
| `scope` | array of strings | Granted scopes |
| `resource_scope` | JSON | Opaque scope the backend approved (`{}` for edge-consent backends) |
| `gen` | integer | Grant revocation generation |
| `iat` | integer | Issued at, Unix seconds |
| `exp` | integer | Expiry, Unix seconds; `0 < exp - iat <= 60` |
| `jti` | string | Unique id, at most 64 bytes |
| `req` | string | `base64url_nopad(SHA-256(method + "\n" + path + "\n" + body))` |

`method` is the HTTP method (`POST`), `path` the request path the backend
received without query string (`/mcp`), and `body` the exact request body bytes.

The edge encodes claims as canonical JSON: keys sorted by UTF-8 bytes at every
level, no insignificant whitespace, integers only, strings escaped as JSON
requires. Verifiers only need this if they want to be as strict as the Rust
verifier (which re-encodes and rejects non-canonical payloads and unknown claims).

## Verifying (any language)

1. Reject if longer than 16 KiB, not ASCII, or not exactly two non-empty
   `.`-separated segments.
2. base64url-decode the signature (no padding) to exactly 64 bytes.
3. Verify Ed25519 (strict) over `"edge-assert.v1." + payload_segment` with the
   configured edge public key. Stop on failure.
4. base64url-decode the payload and parse the JSON claims.
5. `iss` must equal the configured edge issuer; `aud` must equal this backend's id.
6. `0 < exp - iat <= 60`; reject if `iat > now + skew` or `now >= exp + skew`
   (skew: 5 s by default).
7. Recompute `req` from the request you actually received and compare.
8. Remember `jti` until `exp + skew`; reject a `jti` seen before. If the memory is
   full of live entries, reject (fail closed).
9. Only then use `sub`, `grant_id`, `scope`, `resource_scope` and `gen`. Backends
   with their own authority (e.g. Wiskit) must still check `resource_scope` and
   `gen` against their own grant record.

## Test vector

Ed25519 seed (private key) = 32 bytes of `0x01`.

```text
public key  : iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w
issuer      : https://edge.example
audience    : echo
request     : POST /mcp  body {"jsonrpc":"2.0","id":1,"method":"ping"}
req         : mw6zvTQn96sHE6fLxKG0HprEzhyYC6js4quoFBDJhi8
claims JSON : {"aud":"echo","client_id":"client","exp":1700000060,"gen":1,"grant_id":"g_example","iat":1700000000,"iss":"https://edge.example","jti":"jti-example","req":"mw6zvTQn96sHE6fLxKG0HprEzhyYC6js4quoFBDJhi8","resource_scope":{},"scope":["mcp"],"sub":"owner"}
assertion   : eyJhdWQiOiJlY2hvIiwiY2xpZW50X2lkIjoiY2xpZW50IiwiZXhwIjoxNzAwMDAwMDYwLCJnZW4iOjEsImdyYW50X2lkIjoiZ19leGFtcGxlIiwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2VkZ2UuZXhhbXBsZSIsImp0aSI6Imp0aS1leGFtcGxlIiwicmVxIjoibXc2enZUUW45NnNIRTZmTHhLRzBIcHJFemh5WUM2anM0cXVvRkJESmhpOCIsInJlc291cmNlX3Njb3BlIjp7fSwic2NvcGUiOlsibWNwIl0sInN1YiI6Im93bmVyIn0._gS3X4w_uQgz_fjlBuamXMc1nNg5mdVwpP-zYgl-pQIJD73F6F3E9Ht69LEq-XuqavQbHCObRuklC1b9q3JwCg
```

It verifies at `now = 1700000030` and is expired from `1700000065`. The
`readme_test_vector` unit test pins these values.

## Rust usage

```rust
use edge_assert::{GrantContext, RequestBinding, Signer, Verifier};

// Edge
let signer = Signer::from_seed(&seed, "https://mcp.app.stri.nz");
let assertion = signer.mint(&grant_context, RequestBinding { method: "POST", path: "/mcp", body: &body }, now, 60)?;

// Backend
let verifier = Verifier::from_public_key_base64url(&edge_key, "https://mcp.app.stri.nz", "hevy")?
    .with_replay_cache(10_000);
let claims = verifier.verify(&assertion, RequestBinding { method: "POST", path: "/mcp", body: &body }, now)?;
```
