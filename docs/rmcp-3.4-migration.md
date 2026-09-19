# rmcp 3.4 migration

The transport and server test client now use rmcp 3.4.0 and rmcp-macros
3.4.0. Rust 1.88 remains the workspace MSRV. Production keeps the default
features and `transport-io`; `client` remains a development feature. No
OAuth, Streamable HTTP, tasks, MRTR, cache, or subscription features were
enabled. The gateway's HTTP/SSE protocol is separate from rmcp transports.

## Compatibility decisions

- The supported MCP revisions remain `2024-11-05`, `2025-03-26`, and
  `2025-06-18`. Both the supported version list and the fallback are capped
  at `2025-06-18`. Newer initialize requests negotiate that fallback; this
  upgrade does not adopt the 2026 subscription lifecycle. Unknown revision
  strings are not a supported legacy contract.
- Explicit `schema_for_type` inputs preserve the old macro's full schemas,
  including root titles. The complete 36-tool catalog was captured with
  rmcp 1.3.0 in `transport/tests/fixtures/tools-1.3.json`. Only object key
  order and tool-list order are normalized; the fixture is unchanged by the
  upgrade.
- Custom `ServerHandler::call_tool` invokes an enabled route directly.
  The 3.4 router otherwise turns argument deserialization failures into
  successful JSON-RPC responses containing tool errors. Our callers retain
  protocol errors, including `-32602` for extraction/read-only/client HTTP
  errors and `-32603` for upstream failures. Genuine `isError` tool results
  remain results. Disabled and unknown tools remain inaccessible.
- Strings remain text content, including JSON encoded inside text; no
  structured return type was introduced. Raw tests check complete result
  envelopes without using rmcp model serialization, including the absence
  of `structuredContent` and `resultType` and calls without request metadata.
- Initialization still starts event forwarders once. Subscriber identity,
  reconnect cursors, channel metadata and polling drain behavior are
  preserved. Existing behavior sends channel notifications even when channel
  capability advertising is disabled. Shutdown now also cancels a forwarder
  blocked waiting for HTTP response headers, in addition to idle SSE bodies
  and retry backoff.
- One framing change is intentional: after initialization, the newline
  frame `not json\n` closed the rmcp 1.3 session; rmcp 3.4 skips it and accepts
  the next valid request. This was reproduced against both versions. Partial
  input followed by EOF terminates in bounded time. Malformed framing is
  tested separately from argument errors.

## Dependency review

Selective `cargo +1.88.0 update -p rmcp --precise 3.4.0` retained unrelated
surviving package versions. Published registry metadata reports both rmcp
crates as non-yanked with Rust 1.88. The macro upgrade requires darling
0.24.1 and syn 3.0.6 (syn 2 remains for other macros). rmcp's server feature
adds uuid 1.26.1 and uses existing indexmap/base64 dependencies. Removed
Chrono WASM edges reflect upstream feature changes. No MSRV override or
transitive downgrade was needed. `cargo tree --locked -e features -i rmcp`
shows one rmcp 3.4.0 graph and only default/server/macros, transport IO,
their implied dependencies, and development client features.

The baseline test commit adds Tokio's development-only `process` feature
and signal-hook-registry 1.4.8 for a spawned stdio smoke test. It uses only
synthetic credentials and loopback HTTP fixtures.

## Validation

Local validation uses `CARGO_TARGET_DIR=/tmp/target` and target
`x86_64-unknown-linux-gnu`. The MSRV compiler is actual rustc 1.88.0
(`6b00bc388`, LLVM 20.1.5); the default lint/format toolchain is Rust 1.93.0.

| Command | Result |
| --- | --- |
| `cargo +1.88.0 check --locked --workspace --all-features --all-targets` | Passed |
| `cargo +1.88.0 test --locked --workspace --all-features --all-targets` | 776 passed, 0 failed, 8 ignored |
| `cargo +1.88.0 test --locked --workspace --all-features --doc` | Passed; 0 doctests |
| `cargo +1.88.0 test --locked -p transport --all-features --all-targets` | 117 passed, 0 failed/ignored |
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --workspace --all-features --all-targets --no-deps -- -D warnings` | Passed |
| `git diff --check` | Passed |

Counts exclude subprocess re-executions of individual tests. Before upgrading,
the transport baseline passed 111 tests (100 library, 4 binary, 7 raw wire).
The upgraded suite includes raw legacy clients, a 3.4 `ClientConfig` client
at the legacy revision, the full catalog, HTTP/auth envelopes, SSE reconnect
and shutdown, cancellation, and a real stdio binary. Existing tests retain
multi-gateway routing and event metadata coverage.

The sandbox initially denied fixture port binding; the same tests ran with
loopback access. No local provider services were launched. Eight external
provider tests remain ignored locally. Existing Woodpecker checks and its
Forgejo integration lane, including the webhook-to-MCP polling test, are
the authority for provider-backed validation; their results belong to the
PR checks. CI configuration and `/tmp/target` are unchanged.
