# Wiskit builder handoff: Claude through an optional iroh HTTPS edge

Prepared 2026-10-05. The owner will pass this to the Wiskit builder after its
current work finishes. No Wiskit checkout or builder thread was changed or
messaged. Re-read that checkout's current AGENTS.md and relevant .agents/skills
before implementation; reconcile this pinned baseline with the builder's final
changes. This document records a proposed integration, not authority to expose
data, create access or deploy a live forwarder.

## Outcome and current state

The goal is an optional route from Claude web custom connectors to an online,
locally owned Wiskit event tracker/baby book. Local tracking, peer sync and data
recovery must work without this gateway, its maintainer or a cloud account.

There are three independent artifacts:

| Artifact | Established evidence | Missing integration |
| --- | --- | --- |
| `../fixtures/iroh-transport-poc/` | 12 passing iroh 1.3 transport tests on loopback; bounded streaming, admission, backpressure and physical cancellation | Production HTTP/MCP, OAuth, real discovery, persistent gateway identity, Linux/Coolify |
| `../fixtures/claude-compat/` | 14 passing in-process OAuth/MCP policy tests | Actual provider/account, owner proof, cookies/CSRF, asynchronous bridge/cancellation, durable audit |
| Root deny-all runtime | Six actual HTTP tests; Clippy and formatting checks; reviewed normal repository Compose and static owner-helper syntax check | Linux container build, authenticated target inspection and verified Coolify deployment |

The current gateway container is **inert**. It has no iroh/OAuth dependencies or
dialer, cannot enable forwarding, and reports MCP unavailable. Its runtime uses
`network_mode: none` and a loopback health command. An owner-run helper is
prepared for the normal repository/GitHub App route; the agent has not used the
Coolify token or executed it. See [COOLIFY.md](COOLIFY.md) for the new one-time
setup flow. A later successful private deployment proves packaging/health only,
not Claude access.

Current official Coolify parsing injects `env_file: [.env]`. The earlier inline
service package had seven rendered-definition gate tests, but those do not
verify this repository application or the actual target. The new helper leaves
the application unstarted and auto-deploy off. Verify the actual cloned source,
rendered settings and generated nonsecret environment before the one-time
activation; the complete owner-run workflow remains unproved.

## Actual merged-PR1 baseline

Baseline commit: `c654db70439c1c406a30a6bb2dad9db6eefa216a` in
[wstrinz/wiskit-iroh](https://github.com/wstrinz/wiskit-iroh/tree/c654db70439c1c406a30a6bb2dad9db6eefa216a).

Cargo.toml declares iroh `1.0.0` as a semver range; its Cargo.lock resolves
**iroh 1.3.0**, matching the transport PoC. Gossip is 0.101.0, blobs 0.103.0 and
the patched local Loro engine is exactly 1.16.2. Preserve the native/JS Loro
compatibility boundary and HALO budgets/acceptance fixtures; remote MCP is not a
new HALO sync protocol. [Manifest](https://github.com/wstrinz/wiskit-iroh/blob/c654db70439c1c406a30a6bb2dad9db6eefa216a/src-tauri/Cargo.toml), [lock](https://github.com/wstrinz/wiskit-iroh/blob/c654db70439c1c406a30a6bb2dad9db6eefa216a/src-tauri/Cargo.lock)

`src-tauri/src/iroh/mod.rs` creates one persisted endpoint with the N0 preset,
which configures public address publishing/lookup and default relays. Custom
interface-controlled mDNS is the default LAN path; official iroh mDNS is an
optional, off-by-default feature. The Router accepts gossip, blobs and direct
messages, with separate normal and HALO-debug construction branches.

Transport identity is loaded from `app_data_dir/iroh/secret.key`, separate from
family data keys/account identity. The file contains the 32-byte transport
secret with file restrictions; the same key preserves EndpointId across restart.
Existing code falls through to a fresh key for an invalid-length file. That
changes the network address; remote enrollment must refuse silent remapping or
grant reuse. The edge adds no data-recovery dependency on this transport key.
[Endpoint/router/key implementation](https://github.com/wstrinz/wiskit-iroh/blob/c654db70439c1c406a30a6bb2dad9db6eefa216a/src-tauri/src/iroh/mod.rs)

Current local MCP is a newline TCP transport, not Streamable HTTP. Its Rust
broker authorizes capabilities, audits requests and dispatches through a nonce
bridge into the trusted WebView, where keys and real stores live. Capabilities
have read/read-write scope and expiry, but **no tracker ACL**. Existing audit
uses a token prefix as correlation and can degrade to memory; summaries may
contain family text. Do not expose a broad local token or bypass this broker.
[Broker](https://github.com/wstrinz/wiskit-iroh/blob/c654db70439c1c406a30a6bb2dad9db6eefa216a/src-tauri/src/mcp/broker.rs), [capabilities](https://github.com/wstrinz/wiskit-iroh/blob/c654db70439c1c406a30a6bb2dad9db6eefa216a/src-tauri/src/mcp/capability.rs), [bridge](https://github.com/wstrinz/wiskit-iroh/blob/c654db70439c1c406a30a6bb2dad9db6eefa216a/src-tauri/src/mcp/bridge.rs)

## Minimum architecture and trust boundaries

```text
Claude web --HTTPS--> admitted edge host --iroh / fixed service ALPN--> Wiskit
                                                                  issuer + remote MCP
                                                                          |
                                                                  broker grant/audit
                                                                          |
                                                                  nonce + trusted WebView

OAuth browser --HTTPS/edge fixed issuer routes--> origin transaction
local unlocked Wiskit owner --------------------> local consent approval
```

The edge maintains a closed hostname-to-enrolled-origin map. Encoding a valid
EndpointId in a Host is not authorization and must not cause a dial. For a first
trial, use one approved canonical host and one pinned origin, with no wildcard
enrollment. A 32-byte key encodes to 52 unpadded base32 characters; hexadecimal's
64 characters exceed a single DNS label. Any later z-base32 hostname scheme
needs canonical decoding and the same edge admission check.

The origin checks the gateway's transport EndpointId before accepting this ALPN,
then validates OAuth grants before data dispatch. These checks protect different
boundaries. A peer allowlist at the origin does not keep an unrestricted edge
from becoming an open proxy. Edge destination admission, fixed operation policy,
rate/connection limits and no alternate destination are mandatory before dialing.

Gateway TLS termination exposes token exchanges and tool results to its operator;
authorized results also go to Anthropic. Iroh encrypts the edge/origin segment
but does not make the gateway blind. Consent must explain this data export.

## Origin integration

1. Reuse Wiskit's existing persistent endpoint and Router. Add a separate protocol
   handler, its advertised ALPN and readiness reporting in both Router branches.
   Keep gossip/blob/direct/HALO policies intact. Do not run a second endpoint or
   turn the local TCP listener into an HTTP proxy.
2. Add an independently enabled remote Agent Access mode, default off. Both the
   master switch and remote switch gate calls. Disable/restart/revoke invalidates
   remote tokens and cancels pending remote work without disabling local books.
3. Add an immutable validated `RemoteGrantContext`: origin/issuer/resource,
   client ID, independent grant ID, explicit tracker IDs, read-only permission,
   expiry and revocation generation. Construct it only from issuer state.
4. Carry that context through the shared broker and pending bridge nonce. Check
   tracker authority before store access and grant generation before response
   emission. An existing shared tracker reader is not automatically an owner
   allowed to export it. Do not infer grant scope from headers/tool parameters.
5. Initially expose only `wiskit_list_trackers` and
   `wiskit_read_tracker_bundle`. Filter lists by granted tracker IDs; validate
   direct reads before touching stores. Audit bundle-associated document topology
   so no cross-tracker item leaks. Deny writes and generic document/deck/search
   tools until their complete resource topology has scoped rules. Tool read-only
   annotations are advisory, not enforcement.
6. Keep data keys in the WebView. Prefer in-process dispatch for this fixed
   transport; avoid an extra public/local HTTP destination. If a maintained MCP
   component requires an internal HTTP listener, bind an explicitly fixed
   loopback socket, disable redirects/environment proxies and forbid URL/port
   override. Offline/suspended bridge returns bounded unavailable errors.
7. Provide durable redacted remote audit before family reads. Audit only operation,
   decision, independent non-secret grant/correlation handle and bounded counts;
   resolve opaque tracker aliases only locally. No token prefixes, cookies,
   codes, OAuth state/verifiers, child names, queries, arguments or results.
   Persistence failure must pause remote access rather than silently bypass it.

## Draft wire contract to finalize together

The deployed inert binary implements **no ALPN**. The PoC's
`wiskit-mcp-poc/1` remains test-only. Reserve a different ALPN, proposed
`wiskit-mcp-edge/1`, for the real implementation. Confirm it with the gateway
maintainer before coding; this is a draft, not an existing interoperable protocol.

Use one bidirectional QUIC stream per request with bounded length-prefixed
metadata/body and explicit end-of-request/end-of-response framing. Reject
unknown fields/versions, trailing bytes, truncated fields and lengths before
allocation. Preserve demand-driven response chunks and a permit until completion.
Never retry a POST/tool call automatically.

| Fixed operation | Proposed public route | Purpose |
| --- | --- | --- |
| `mcp_post` | POST `/mcp` | Authenticated single JSON-RPC message |
| `resource_metadata_get` | Canonical PRM route for `/mcp` | Resource/issuer discovery |
| `issuer_metadata_get` | `/.well-known/oauth-authorization-server` | Issuer metadata |
| `authorize_get` / `authorize_status_get` | Fixed authorization UI/status routes | Browser-bound pending consent |
| `register_post` | POST `/register` | Bounded public-client DCR |
| `token_post` | POST `/token` | Form code/refresh exchange |
| `revoke_post` | POST `/revoke` | Client-bound token revocation |

DCR registration needs its own operation; the earlier PoC envelope cannot carry
it. No local approval, generic URL, destination host/port, arbitrary method/header,
CONNECT, SNI passthrough, private-network fetch or cookie-jar field is permitted.
Typed metadata may carry a bounded bearer, accepted response modes and approved
MCP version. Authorization UI routes alone may carry bounded browser cookies
and parameters. The origin owns the canonical issuer/resource configuration;
Host/Forwarded/X-Forwarded values never choose it.

Response metadata permits status, a content-type enum, canonical OAuth challenge,
and tightly validated authorization callback/cookie fields only where necessary.
No general Location/Set-Cookie forwarding. A redirect must match the configured
Claude callback; responses cannot send the edge to another address.

Start from the PoC's measured 16 KiB request, 1 MiB total response, 8 KiB chunks
and small concurrency/window limits. Separate small OAuth metadata/form limits
from data results. Do not silently truncate tracker bundles: enforce a result
budget or explicitly design pagination. The real limits and protocol metadata
budget need workload tests rather than copying numbers into production.

## Claude and OAuth decisions

Claude recommends Streamable HTTP; its guide lists authorization versions through
2025-11-25. First try DCR with a public client (`none`), authorization-code S256
PKCE and exact hosted callback `https://claude.ai/api/mcp/auth_callback`.
Prefer CIMD after verifying/pinning Claude's actual metadata URL. The fixture's
CIMD URL is synthetic and must never become production configuration.
[Claude authentication](https://claude.com/docs/connectors/building/authentication)

One origin-owned issuer is the smallest proposed authority. The owner approves
a browser-bound transaction in the unlocked Wiskit UI, with matching transaction
code, client/redirect details, explicit grantable tracker selection, read-only
permission and expiry. This is an OAuth authorization-code flow, not a required
device-code grant. It authorizes Claude to access Wiskit; it does not assume
Claude is an OIDC identity provider. Choose an existing owner OIDC provider only
if the owner wants one. Use a maintained authorization component for actual
owner proof, cookie/CSRF defenses, consent, PKCE and redirect handling; do not
deploy the synthetic policy fixture as an issuer.

Require canonical resource binding in code authorization/exchange and at dispatch.
Code/state/issuer/client/redirect must stay bound; a public shared client ID is
not a person and must not merge independent grants. Start with one-use codes
(60 s), pending consent (3 min), access (15 min), and rotating refresh families
with an absolute 24-hour trial grant. Refresh never widens trackers, scope,
audience or lifetime; replay revokes the family. Hash token indexes, use random
independent non-secret grant IDs and support immediate local revocation.

Start memory-only: restart revokes all remote grants and returns remote mode to
off. Persistent consent/refresh state is a separate storage/recovery decision.
Keep family backup/restore and local access independent of cloud issuer recovery.
An alias/transport-key remap needs authenticated re-enrollment and fresh consent.
[MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

For the first MCP adapter, support legacy initialize, initialized notification,
ping, tools/list and tools/call with stateless POST responses. Issue no MCP
session ID; optional standalone GET/SSE and DELETE may return 405. Validate the
negotiated legacy protocol header. Actual Claude wire negotiation must be
captured in an authorized synthetic test; authorization support is not proof
of every transport detail. [Claude build guide](https://claude.com/docs/connectors/building)

Legacy 2025 disconnects should not be treated as cancellation. Implement explicit
`notifications/cancelled` keyed by validated grant ID plus request ID; one grant
cannot cancel another's work. Keep worker lifecycle separate from HTTP lifecycle,
bound abandoned work by deadlines and cancel on owner revocation. The 2026
transport changes this lifecycle, so do not silently adopt it for the Claude
trial. The PoC's physical stream abort test and synchronous fixture acknowledgements
do not prove real MCP cancellation behavior. [Legacy transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

## Tests and phased acceptance

1. Agree the draft ALPN/envelope and maintained OAuth/MCP components. Add origin
   grant/bridge tests with two synthetic trackers, separate owners/grants sharing
   one client ID, revoked/expired grants, bundle cross-references and audit failure.
2. Integrate the real origin over ephemeral loopback iroh peers. Retain the original
   injection, pre-dial admission, malformed/trailing framing, redirect/proxy trap,
   backpressure, caps, concurrency and unavailable-origin tests. Add protocol
   cancellation, cross-grant cancellation denial and revocation mid-bridge/stream.
3. Run Linux container tests/build and verify the private inert Coolify deployment
   with the owner helper. Record exact server/resource UUID, image ID, source hash,
   effective network/UID/limits and health. Keep the mailbox and shared services intact.
4. Prepare an activation plan for one canonical HTTPS host, one origin enrollment,
   protected persistent gateway identity and a narrowly configured egress/relay
   policy. Inspect actual Coolify proxy buffering/compression/timeout behavior.
   OAuth discovery/exchange must fit Claude's shorter endpoint deadlines; streaming
   must flush incrementally and remain below its overall tool-call budget.
   No wildcard/open enrollment or public UDP publication is assumed necessary.
5. After scoped approval, use a synthetic-only Claude account trial: discover,
   register, local consent, code exchange, initialize, tools/list, allowed read,
   forbidden tracker/write, refresh/replay, revoke, restart, origin offline and
   disconnect/cancel. Capture protocol/status/timing without credentials/payloads.
6. Only after those results and explicit data-export consent, consider real
   tracker grants. Test recovery with gateway absent, key loss and maintainer absent.

## Threat model and remaining choices

| Risk | Required control | Remaining limit |
| --- | --- | --- |
| Open edge/SSRF | Closed host-to-peer map, fixed ALPN/operation, no URL/port override, bounded CIMD fetch/pinned provider | Address encoding and origin trust alone are insufficient |
| Anonymous resource exhaustion | Pre-auth connection/rate/body/deadline caps; bounded registration/pending state; per-grant limits after auth | Inert container caps are not production rate limits |
| Cross-tracker/owner leakage | Explicit export authority and grant context before store/bridge/results | Current broad broker capabilities need extension |
| Token/code theft or replay | HTTPS + iroh, PKCE and exact audience/client/callback, one-use codes, refresh rotation, no credential logs | TLS operator and authorized provider see plaintext |
| Revocation/restart races | Generation checks, pending/stream cancellation, fail-closed restart | Requires asynchronous integration tests |
| Loss of optional infrastructure | Local encrypted backup/key recovery, transport-key re-enrollment, export without maintainer | Persistent grants/alias migration are separate owner choices |

Unresolved activation choices: canonical public hostname; exact enrolled origin
and gateway transport identities; gateway key storage/backup/rotation authority;
closed enrollment administration; consent mechanism and trial grant lifetimes;
maintained OAuth/MCP implementation; data-output size/pagination; and actual
proxy/relay/network settings. Routine preparatory names are already chosen.
Public routes, DNS/firewall changes, persistent access creation and real family
data use still need the owner's scoped approval. No family data was used here.
