# Wiskit MCP edge

This repository prepares an optional HTTPS/iroh edge for Wiskit. The root
`mcp-edge` binary runs the original deny-all process by default and, with
`EDGE_MODE=edge`, the phase 2 OAuth authorization server (`crates/edge-auth`),
signed assertions (`crates/edge-assert`) and only the built-in `echo` backend.
It does not forward to any other host. Read README.md, docs/DESIGN.md (current
plan and phase 2 notes), docs/COOLIFY.md and docs/BUILDER-HANDOFF.md first.

- Keep local Wiskit tracking, peer sync, export and recovery independent of this
  service. No family data, DEKs, real peer identities or credentials belong here.
- The phase 2 Compose shape exposes port 8080 to the Coolify proxy network and
  mounts one data volume; creating the Coolify application, its domain and
  secrets, and deploying remain owner actions. Public forwarding to other
  hosts, peer enrollment and origin consent require their own completed
  implementation and approved settings.
- Do not add a switch that enables unfinished forwarding. Health is distinct
  from MCP readiness. Preserve fixed errors and avoid logging request bodies,
  Authorization headers, tokens, OAuth codes or family text.
- Fixed transport operations must never accept arbitrary URLs, ports, methods,
  private-network destinations, CONNECT or unrestricted headers.
- Follow the real Wiskit checkout's current AGENTS.md before changing its
  integration. Preserve signed contact exchange, HALO authority and the pinned
  native/JS Loro contract. Never run fixture peers alongside the real app.
- `fixtures/` contains independent, synthetic experiments with their own locks
  and READMEs. Its PoC binds loopback only and uses ephemeral identities. Its
  OAuth policy fixture is not a production authorization server.
- Rust 1.93.0 was used; exact dependencies are locked. Run root `cargo test
  --locked --workspace`, `cargo clippy --locked --workspace --all-targets -- -D
  warnings` and `cargo fmt --all -- --check` for runtime changes (on Windows
  set `OPENSSL_DIR`, see README). Follow fixture
  READMEs if modifying those experiments. A Windows check is not a Linux image
  build or proof of web-client compatibility.
- The owner-run API helper must remain unexecuted by an agent. It uses existing
  owner credentials without printing them; do not broaden access, create keys,
  edit other projects or bypass a failed prerequisite.
- Once the owner completes normal Coolify GitHub App auto-deploy setup, commits
  to the configured deployment branch deploy automatically. Treat pushes and
  merges to that branch as deployment actions under the owner's current scope.

Use LF for new files. Keep scratch output in ignored folders. Do not add a
separate release platform or MCP management service for ordinary auto-deploy.
