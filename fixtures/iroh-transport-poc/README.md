# Wiskit iroh edge transport PoC

An isolated, synthetic transport experiment. All TCP and UDP sockets bind to
`127.0.0.1` on OS-assigned ports. Every run creates fresh in-memory iroh keys.
The program performs one synthetic round trip, shuts down, and exits. It neither
loads Wiskit data nor writes credentials, endpoint identities, or deployment state.

```text
synthetic HTTP client
  POST /mcp, Host: poc.invalid
    -> loopback HTTP edge
      -> encrypted iroh stream, ALPN wiskit-mcp-poc/1
        -> admitted loopback origin peer
          -> one fixed loopback mock MCP HTTP endpoint
```

The HTTP portions are plain HTTP on loopback. This does not provide a public
HTTPS service, integrate the actual Tauri/newline MCP bridge, or demonstrate
full MCP lifecycle/client compatibility. OAuth and AI provider accounts are
deliberately deferred.

## Run

Rust 1.93.0 on Windows was used. Direct dependencies are exact-pinned, including
iroh 1.3.0; the included Cargo.lock pins transitive registry versions/checksums.
Fetch dependencies once if necessary, then run offline:

```powershell
cargo fetch --locked --target x86_64-pc-windows-msvc
cargo run --locked --offline
cargo test --locked --offline -- --test-threads=1 --nocapture
cargo fmt -- --check
```

Tests run serially because one test temporarily changes proxy environment
variables in its own test process and restores them with a drop guard. It uses
only loopback traps; no external proxy or production service is contacted.

## Admission and destination policy

- The edge accepts exactly one Host, `poc.invalid`, mapped to one pinned origin
  EndpointId and explicitly supplied loopback transport address.
- Unknown hosts, paths, queries, methods, absolute-form URLs, CONNECT requests,
  duplicate Host values, and unrecognized headers fail before any iroh dial.
- The origin accepts exactly the gateway's ephemeral EndpointId. Its global
  request limit covers every admitted connection.
- The wire request has version, fixed `/mcp` path, content type, and body only.
  Serde rejects unknown fields. No caller-supplied destination URL, host, port,
  alternate method, arbitrary headers, or upgraded connection exists.
- The origin's sole HTTP destination is the mock's checked loopback socket,
  fixed when the origin is created. The client uses `no_proxy()` and disables
  redirects. No response Location or credentials are forwarded.
- Endpoint setup uses iroh's Minimal preset, removes address lookup, disables
  relays, removes default IP transports, binds loopback explicitly, and disables
  the default portmapper feature. Address enumeration is checked and fails
  closed if any relay or non-loopback address appears.

## Resource and stream behavior

| Limit | Value |
| --- | --- |
| Request body | 16 KiB |
| Request/response metadata | 1 KiB |
| Response chunk | 8 KiB |
| Total response | 1 MiB |
| Active requests | 2 each at edge and origin |
| HTTP connections / admitted origin connections | 8 each |
| QUIC bidirectional / unidirectional streams per connection | 4 / 0 |
| QUIC stream receive / connection receive / send windows | 16 / 64 / 16 KiB |
| HTTP server socket send buffer requested | 8 KiB |
| Intake and connection/header exchange deadline | 2 seconds |
| Response idle / total deadline | 2 / 15 seconds |
| QUIC idle deadline | 5 seconds |

Length fields are validated before allocation. Response reads are demand-driven;
there is no unbounded application channel or whole-response collection. The edge
holds its concurrency permit until its HTTP response body ends or is dropped.
Dropping the response stops the QUIC receive stream, causing the origin to drop
the upstream request/response. A truncated or oversized response ends with a
transport error rather than a fabricated successful completion. POST requests
are never automatically retried.

These limits bound the application envelope and QUIC flow control. They are not
a measured whole-process RSS guarantee; HTTP, OS socket, TLS, and QUIC stacks
also have internal buffers. Production limits need workload measurements and
rate/connection controls before authentication, as well as per-principal limits.

## Synthetic tests

`tests/transport.rs` exercises JSON round trips, incremental SSE, rejection before
dialing, peer admission, destination override rejection, trailing-byte smuggling,
length/body caps, redirect and environment-proxy traps, edge/origin concurrency,
disconnect cancellation, stalled-reader backpressure, incomplete-body and idle
deadlines, response truncation at the cap, and an offline origin.

The mock accepts JSON-RPC-shaped requests with synthetic names: echo, stream,
flood, quiet, and redirect. It is not a production MCP implementation. Test logs
and the verification summary are retained in this task directory.

## Before a real Wiskit or Coolify phase

1. Add a separately enabled remote MCP adapter to Wiskit that dispatches into its
   existing capability/audit path; do not expose the current newline TCP listener
   as if it were HTTP. Remote access should default off and start read-only with
   explicit tracker scope.
2. Specify the supported MCP protocol/client versions and implement initialize,
   tool discovery, errors, cancellation, and required headers. Current request
   streams and legacy session/GET-SSE clients need explicit compatibility tests.
3. Add MCP authorization before public access. Validate issuer, audience, expiry,
   scope, and a principal-to-origin grant. An origin's gateway allowlist alone
   does not authorize callers at the edge.
4. Use an explicit edge enrollment/admission map before decoding or dialing any
   hostname. A valid encoded EndpointId is an address, not permission to connect.
   Keep the ALPN fixed-service and prohibit caller-selected destinations.
5. Bind the bridge to the existing persistent Wiskit endpoint only after defining
   enrollment, revocation, key loss, replacement, and backup/recovery behavior.
   Test offline LAN use separately from public discovery/relay use.
6. Obtain read-only access to the identified Coolify application/server and verify
   its actual network, TLS proxy, streaming, resource, log, and volume settings.
   A proposed deployment would have TLS at Coolify's existing proxy, an internal
   HTTP service, a narrowly configured iroh endpoint, and private admission/key
   state. It needs approved access and configuration changes before deployment.

The gateway operator and any authorized AI provider can see returned plaintext.
That privacy decision precedes real family data. The edge must remain optional:
local tracking, peer sync, portable backups, and restore cannot depend on it.

The cached lockfile initially retained yanked ChaCha20 0.10.0. The PoC lockfile
was updated to official 0.10.2 before executing tests; upstream documents the
SSE backend fix in its [changelog](https://github.com/RustCrypto/stream-ciphers/blob/master/chacha20/CHANGELOG.md).
