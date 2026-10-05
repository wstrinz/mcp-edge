# Claude-first compatibility preparation

This directory is separate from the successful phase-1 iroh transport PoC.
Its Rust fixture models HTTP replies and OAuth/MCP policy entirely in process.
It opens no listener, connects no account, loads no Wiskit data, and saves no
credential. Random codes/tokens exist only in memory. Tests do not contact
Claude or an identity provider. This is compatibility preparation, not proof
that the real Claude client connects, and not a production OAuth implementation.

## Verified Claude contract, 2026-10-05

Claude recommends Streamable HTTP; its build guide lists authorization support
through MCP 2025-11-25. Its hosted callback is
`https://claude.ai/api/mcp/auth_callback`. Custom connectors can use DCR, CIMD,
or a supplied OAuth client. CIMD requires both
`client_id_metadata_document_supported: true` and public-client `none` in token
authentication methods. Claude starts authorization from a 401 metadata
challenge, uses the first advertised issuer, requires an exact resource URL,
S256 PKCE, and form-urlencoded token requests. Public-client refresh tokens
rotate. Discovery/token endpoints have a 10-second budget; refresh has 30.
These provider-specific facts are from [Claude authentication docs](https://claude.com/docs/connectors/building/authentication).

Remote custom connectors originate in Anthropic's infrastructure, so the eventual
edge and authorization endpoints need approved public reachability. The existing
loopback PoC cannot be added directly to Claude web. [Claude help](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)

The newest MCP transport, 2026-07-28, changes lifecycle and metadata. We target
the older initialize handshake with stateless Streamable HTTP, supporting
2025-03-26, 2025-06-18, and 2025-11-25. Session IDs are optional in that era;
this server would issue none and return 405 for GET/DELETE on `/mcp`. The new
revision needs a separate implementation, not a date change in a header.
[2025 transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[2026 transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)

Actual Claude wire-version negotiation, registration payloads, and refresh behavior
remain to be captured in a later authorized account test. OAuth version support
in the provider's guide does not establish every detail of its MCP wire client.

Cancellation needs version-specific treatment. The 2025 transport says a
disconnection should not be interpreted as cancellation; the client should send
`notifications/cancelled`. Bind that notification to the validated grant and
request ID so one connection cannot cancel another owner's work. Keep worker
lifetime separate from HTTP connection lifetime, with explicit request deadlines
and owner revocation. Without resumability, a lost connection may lose a result;
do not automatically repeat a tool call. The 2026 transport instead requires
cancellation when its SSE stream closes. The phase-1 PoC verified physical
forwarding cancellation, not these legacy MCP semantics. This fixture acknowledges
notifications but has no asynchronous workers, so propagation remains an
integration test. [2025 cancellation semantics](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

## What authorizing a connector means

Wiskit is the resource server; Claude is the OAuth client. The resource owner
authorizes Claude to read selected Wiskit data. That does not authenticate a
Claude user to Wiskit using an OIDC identity token. No official source reviewed
here establishes a general "Sign in with Claude" identity provider for arbitrary
services. OAuth client metadata identifies a client configuration, not a person.
Do not treat an email, client name, client ID, MCP clientInfo, or an Anthropic IP
address as the resource owner's identity.

Every consent needs its own grant handle, local resource-owner identity,
client ID, exact MCP resource, origin binding, tracker IDs, permissions,
expiry, and revocation generation. Several Claude connections can share the
same public CIMD client ID; their grants must never merge on client ID alone.
[MCP authorization roles and resource binding](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

## Recommended first architecture

Use one origin-owned issuer and consent authority, alongside the remote MCP
adapter in the local Wiskit process. Keep the Coolify edge as an admitted route
to that origin. The edge stores its own transport identity and a closed
origin-enrollment map; local tracking and recovery remain independent of it.
The origin retains all grant decisions and secret token state.

```text
Claude web -> HTTPS edge -> admitted iroh origin -> remote MCP adapter
                                                   -> broker authorization/audit
                                                   -> existing nonce/WebView bridge

Claude OAuth browser -> HTTPS issuer routes -> origin authorization component
local unlocked Wiskit UI --------------------> trusted consent approval hook
```

For the first real trial, choose "Register automatically" in Claude and use
bounded DCR with `none` token authentication and the exact hosted callback.
This avoids handling a client secret or needing an unverified published metadata
URL. Prefer CIMD later once the exact hosted-Claude metadata URL/document is
verified and pinned. The failed public metadata fetch in this investigation did
not establish that URL. The fixture CIMD URL is explicitly synthetic.

Resource-owner authentication can be an explicit approval in the unlocked Wiskit
app, rather than a new cloud account/password database. On `/authorize`, a mature
OAuth component creates a short-lived browser-bound transaction. The browser
and local app show the same transaction code. The local app displays client and
redirect host, selected tracker names, read-only permission, and expiration.
The owner selects specific grantable trackers and approves. The browser receives
an authorization-code redirect to Claude. This uses the authorization-code grant;
it is not a device-code grant that would require Claude to support another flow.

The app approval must prove local grant authority. Being able to read a shared
tracker does not automatically grant permission to export it to an AI service.
Consent approval is a trusted local operation, never an anonymous `/approve`
endpoint. Browser session cookies, CSRF protection, transaction matching,
local-owner proof and replay prevention must be supplied by the real component.
The fixture's local approval method substitutes explicit synthetic booleans and
session labels for that machinery and must not be deployed.

If browser sign-in is wanted instead, use an explicitly chosen existing OIDC
provider to authenticate the owner to the issuer. Wiskit still owns tracker
consent. Do not assume an existing provider or enroll a new account implicitly.

## Adapter around the real broker

Inspection is pinned to merged PR1 commit
`c654db70439c1c406a30a6bb2dad9db6eefa216a`. Its
[capability store](https://github.com/wstrinz/wiskit-iroh/blob/c654db70439c1c406a30a6bb2dad9db6eefa216a/src-tauri/src/mcp/capability.rs)
has read/read+write scopes but no tracker ACL; capabilities disappear at app close.
Its [dispatch chokepoint](https://github.com/wstrinz/wiskit-iroh/blob/c654db70439c1c406a30a6bb2dad9db6eefa216a/src-tauri/src/mcp/broker.rs)
validates capabilities and delegates through the nonce/WebView bridge. Its
durable audit currently degrades to memory if persistence fails, and write
summaries can contain event details. An HTTP wrapper around the current broad
capability would not provide remote tracker isolation or redacted remote audit.

Implement these scoped changes only in a later approved Wiskit branch:

1. Add a separately enabled remote transport, default off, requiring the existing
   Agent Access authorization path. Turning remote access off cancels remote
   work and revokes remote grants; turning the master Agent Access switch off
   closes both paths. Enabling remote access must not mint or expose a broad
   local agent token.
2. Add an authenticated remote grant context to the shared broker chokepoint:
   transport kind, issuer/resource/client/grant identity, explicit tracker set,
   read-only permission and current revocation generation. Construct it only
   from validated issuer state. Never accept it from tool parameters or headers
   such as `x-user`/`x-tracker-scope`. Do not forward the external OAuth token to
   the existing local broker as if it were a local capability.
3. Initially expose only `wiskit_list_trackers` and
   `wiskit_read_tracker_bundle`. Lists contain only granted trackers. Direct reads
   check the exact tracker before store access. Bundles include only approved
   tracker-associated documents. Reject both write tools, generic document/deck
   enumeration and search until their complete data topology has scoped rules.
   Tool annotations are hints; server policy enforces read-only access.
4. Pass the immutable grant context through the broker's pending nonce record.
   Re-check grant generation, tracker authority and request parameters before
   WebView store execution and before emitting a result. Keep the existing
   trusted-main-window/nonce safeguards. Revocation must cancel pending bridge
   calls and response streams; filtering the final response alone is insufficient.
5. Implement initialize, initialized notification, ping, tools/list and
   tools/call using a maintained MCP implementation or bounded adapter. Preserve
   JSON-RPC IDs and translate broker denials to generic tool errors without
   disclosing whether an ungranted tracker exists. No sampling, subscriptions,
   resumability or legacy standalone GET/SSE stream is required for this trial.

The broker stays key-free. DEKs and store functions remain in the WebView. The
origin must be online and its bridge ready; an edge cannot answer local book
queries while the app is suspended or offline. Return a bounded unavailable
response without automatically retrying a tool call.

## OAuth and iroh boundary

The current PoC ALPN permits only fixed `/mcp` JSON POSTs and rejects Authorization
and protocol headers. Preserve it. A separate versioned envelope must enumerate
fixed operations: MCP POST, protected-resource metadata GET, issuer metadata GET,
authorization-page/status GET, token POST and revocation POST. There must still
be no caller-selected URL, host, port, CONNECT, arbitrary headers, or local
approval operation. OAuth form bodies and HTML consent replies need their own
small explicit limits and response-type allowlist.

Edge admission precedes every dial: a canonical configured hostname maps to one
explicitly enrolled origin and only that service ALPN. Never dial any EndpointId
just because it is well encoded in a wildcard hostname. With an origin-owned
opaque-token issuer, the edge cannot cheaply validate a bearer without contacting
the origin; enrollment plus strict path policy and pre-auth rate/concurrency
limits must bound those unauthenticated discovery/token/MCP requests. Origin
authorization precedes every family-data dispatch. Public metadata conveys no
grant. Host/Forwarded/X-Forwarded values cannot select issuer or resource URLs.

MCP responses need a tightly defined header surface: content type, status,
WWW-Authenticate, and approved protocol metadata. The OAuth wrapper needs only
exactly validated redirect Location and consent-cookie handling on its fixed
routes. No blanket arbitrary-header forwarding or inherited cookie jar.

Keep issuer/resource URLs canonical and HTTPS. PRM `resource` includes the exact
`/mcp` path. Require `resource` during authorization and code exchange. Validate
audience again at dispatch; an omitted resource during refresh may only retain
the original bound audience. S256 protects the one-use code; redirect, client,
issuer/state validation and consent protect the other flow boundaries.

Suggested trial lifetimes are 60 seconds for an issued code, 3 minutes for pending
approval, 15 minutes for access, and an absolute 24-hour maximum for the consent
and its rotating refresh family. Refresh never widens tracker IDs, permission,
resource or lifetime. Detect spent-refresh replay and revoke the whole family.
Use hashed token indexes and independently random public grant handles.
Bound registrations, pending approvals and histories; expire/reap them and
rate-limit discovery/registration before authentication. The fixture limits
registration to 32 and pending approval to 8 but does not model a network limiter.

For CIMD, allow only the verified hosted-Claude metadata URL, require HTTPS and
matching client_id/redirect metadata, and bound/cache the document. Disable
redirects and proxy inheritance, reject credentials/fragments/alternate ports
and private-address/DNS-rebinding targets. Do not fetch logo_uri, client_uri or
arbitrary URLs to decorate consent. DCR client names are untrusted text, not
proof that Anthropic sent a registration. [MCP client-metadata security](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#client-id-metadata-document-security)

## Restart, revocation, audit and privacy

Start with memory-only grants and tokens. Restart invalidates authorization and
returns remote access to off; Claude must reconnect and the owner approves again.
Persisting grant receipts/refresh families is a later explicit choice requiring
protected local storage, encrypted optional backup, key recovery and revocation
semantics. Data recovery must work with no gateway, issuer or maintainer.

Local revoke immediately invalidates all access/refresh tokens for that grant and
cancels in-flight work. Provide RFC-style token revocation as well. A Claude UI
disconnect must not be the only revocation mechanism: do not depend on the client
calling the issuer's revocation endpoint. Expired/revoked refresh returns
`invalid_grant`, allowing a fresh sign-in instead of an endless custom-error loop.

Remote audit records only time, a non-secret independent grant/correlation
handle, configured client label, allowlisted operation, decision/reason code,
opaque tracker alias when necessary, and byte/duration counts. Resolve names
only in the local UI. Do not persist raw tokens or their prefixes, codes, PKCE
verifiers, OAuth state, cookies, query text, child names, event text, tool arguments
or results. Redact reverse-proxy and application logs too. Denials need bounded
redacted audit. For remote data reads, require audit durability before dispatch;
if it is unavailable, pause remote access rather than silently bypassing the trail.
The fixture tests redaction and the unavailable-audit denial, but does not use a
durable database.

The Coolify operator sees plaintext at TLS termination, and authorized tool results
go to Anthropic. Iroh transport encryption does not make this an end-to-end blind
gateway. Consent must state that boundary. Use synthetic trackers for the first
account test and keep all family data out until those choices are explicit.

## Run the fixture

```powershell
cd claude-compat
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt -- --check
```

This fixture exercises discovery/401, DCR and synthetic CIMD selection, code+PKCE,
state/issuer/redirect/resource/client binding, local approval, tracker isolation
even under a shared client ID, legacy initialize and protocol headers, read-only
tools, refresh rotation/replay, revocation/restart/expiry, redacted audit and
resource limits. It does not test HTTP parsing or sockets, real cookies/CSRF,
actual local-owner cryptography, persistent storage, a real MCP SDK, provider
accounts, or authentication through the phase-1 iroh envelope. Those omissions
are explicit integration work, not production-ready security assurances.
In-flight cancellation and revocation propagation also need real adapter/bridge
tests; the synchronous fixture proves grant validation and token invalidation.

## Minimum choices and access before a real test

- Confirm local-app approval versus an existing owner identity provider. The
  recommended default is local-app approval, with no new web-account system.
- Confirm the two read-only tools, explicit synthetic tracker selection, 24-hour
  trial authorization, and reapproval after restart. No all-trackers wildcard.
- Choose the canonical HTTPS MCP/issuer hostname and an enrollment/recovery
  policy: encoded EndpointId changes when its transport key changes; a stable
  alias needs an explicit mapping and authenticated remap. Never silently move a
  valid grant to another origin.
- Authorize a scoped Wiskit branch for the adapter and grant/audit changes, then
  verify a maintained OAuth/MCP component before any exposure. This workspace
  contains policy fixtures, not changes to Wiskit.
- Supply an existing authenticated read-only Coolify session or identified SSH
  host/user to inspect the actual deployment. Later public HTTPS/domain/port
  changes and adding the connector to Claude need separate authorization. No
  credentials need to be pasted into this conversation.

The first live acceptance sequence is synthetic only: discover -> register ->
approve selected tracker in Wiskit -> exchange code -> initialize -> tools/list ->
allowed read -> forbidden tracker/write -> refresh -> revoke -> restart -> offline
origin. Capture provider protocol/headers without logging tokens or payloads,
then repeat through Coolify to verify TLS, streaming and timeout behavior.
