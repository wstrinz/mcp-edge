# Phase-1 verification

Verified on 2026-10-05 at approximately 13:45 UTC in the isolated task-2
workspace. Runtime: Windows x86_64, Rust/Cargo 1.93.0. Dependencies: exact iroh
1.3.0 and the included checksummed Cargo.lock, with ChaCha20 0.10.2.

| Check | Result | Evidence |
| --- | --- | --- |
| Offline integration suite | Exit 0; 12 passed, 0 failed | transport-test.log |
| Clippy, all targets, warnings denied | Exit 0 | clippy.log |
| rustfmt check | Exit 0 | format.log |
| Offline one-shot demo | Exit 0; HTTP 200, synthetic JSON echo | demo.log |

Commands used for final verification:

```text
cargo test --locked --offline -- --test-threads=1 --nocapture
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt -- --check
cargo run --locked --offline
```

The harmless Cargo wrapper warning `could not canonicalize path` appears in
logs. The compiler and Clippy produced no code warnings in final verification.

Observed evidence from the final test run:

- Unknown hosts, prohibited headers, other methods, CONNECT and absolute URLs,
  duplicate Host values, and query overrides caused **zero iroh dials and zero
  mock requests**.
- An unadmitted iroh peer was rejected. Destination fields, non-MCP/absolute
  paths, unsupported versions, and trailing bytes caused **zero mock requests**.
- The explicit-proxy control visited the loopback trap, proving it was usable.
  Poisoned proxy environment variables and the mock redirect visited neither
  the environment trap nor redirect trap through the PoC.
- Response-drop cancellation released both origin slots in **25.2897 ms**.
  Both synthetic upstream bodies were dropped in **under one second**, before
  either idle deadline. The next request succeeded.
- During a stalled HTTP reader's observation window, origin wire chunk count
  remained **16 -> 16**; the response cap had not been reached. Disconnecting
  the reader then released the request.
- Two requests consumed all edge slots and a third received 429. Direct requests
  on separate admitted QUIC connections also exercised the origin's global
  two-request limit.
- Incremental SSE arrived over time. Incomplete requests and quiet responses
  met their deadlines. A response exceeding 1 MiB failed as a truncated stream.
  An offline origin returned 502/504 within the bounded exchange deadline.
- All advertised endpoint addresses and HTTP listener addresses were loopback.

Scope limits: this verifies the synthetic forwarding envelope and resource
behavior on this Windows host. It does not verify Linux, public HTTPS, Coolify,
NAT/relays/discovery, full MCP lifecycle or third-party client behavior, OAuth,
the actual Wiskit adapter, persistent identity/recovery, or whole-process memory
use. Public transport and real data need a separate authorized phase.

Only files in this task workspace and Cargo's ordinary dependency/build caches
were changed. Official crates.io metadata/dependencies were fetched with
approved network access; all prototype/test execution was offline. No Wiskit
checkout, Wulfram checkout, Coolify service, DNS, network/auth permissions,
provider account, persistent credential, or real family data was changed.
