# Wiskit MCP edge

Dedicated repository: **`wstrinz/wiskit-mcp-edge`**, private, with **`main`** as
the intended Coolify deployment branch. The owner approved repository creation
and publication on 2026-10-05. Coolify setup and deployment remain pending.

The intended service gives ordinary HTTPS MCP clients an optional route to an
online local Wiskit instance through iroh. Local use, peer sync and data recovery
must remain independent of the edge. The production Wiskit adapter and OAuth
integration are still pending; see [the builder handoff](docs/BUILDER-HANDOFF.md).

## What is implemented

The root Rust crate is the current preparatory **deny-all** process. `/healthz`
reports process health; `/readyz` and `/mcp` return `503 forwarding_disabled`.
Other paths return fixed errors. It does not read or reflect request bodies,
dial peers, implement OAuth, load Wiskit data or create persistent identities.
There is no activation switch. Six actual loopback HTTP tests cover parser,
timeout, admission and fixed-response behavior.

`fixtures/iroh-transport-poc/` contains the actual bounded iroh/HTTP transport
experiment and its 12 passing-test record. `fixtures/claude-compat/` contains the
14-test synthetic OAuth/MCP policy fixture. Both are copied byte-for-byte from
their verified archives. They provide implementation starting points and test
evidence; the Docker build does not package them as a live forwarder.

## Ordinary Coolify auto-deploy

Use the existing Coolify GitHub App integration to create one application in a
separate `wiskit-mcp-edge` project, production environment. Select `main`, base
directory `/`, Docker Compose build pack and `/compose.yaml`. Coolify clones the
repository and builds the root Dockerfile itself. There is no separate image
registry, GitHub Actions deployment credential or custom management connector.

The initial Compose runtime is unprivileged and read-only, drops capabilities,
limits CPU/memory/PIDs, and uses `network_mode: none`. No ports, volumes or public
domains are configured. Its binary checks its own container loopback health.
The Docker build fetches locked public dependencies, then tests/builds offline.
Linux container compilation and real Coolify deployment remain unverified.

The prepared [owner-run API helper](tools/owner-coolify-repo.ps1) defaults to
read-only inspection. It can prepare a new unstarted GitHub-App-backed
application with auto-deploy initially disabled. Actual generated configuration
must be verified once before enabling auto-deploy and starting the first build.
After that, authorized pushes/merges to `main` trigger ordinary Coolify deploys;
the owner does not repeat API setup for each release.

Read [Coolify setup details](docs/COOLIFY.md) for the one-time flow, exact API
payload and unresolved target prerequisites. The older inline Compose service
package remains separate; this repository uses a normal **Git-backed application**.

## Local checks

```powershell
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt -- --check
python tools/verify_repo.py
```

The HTTP tests bind ephemeral loopback sockets. Do not launch the root binary's
container `main` on a host-wide interface for testing. Read each fixture README
before running it. No Wiskit checkout, real peers, family data, shared service or
mailbox was used or changed in this package.

The offline package check uses PyYAML and verifies the inert Compose policy and
all archived fixture hashes. See [verification limits](docs/VERIFICATION.md).
