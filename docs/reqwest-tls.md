# Outbound HTTP compatibility

Server and transport use reqwest 0.13 with defaults disabled. Server keeps
`stream`; transport keeps `json`. Neither needs reqwest's `query` or `form`
features (transport mutates URL query pairs directly). Forge retains its
existing `json`, `query`, `stream`, and `rustls-no-provider` configuration.

Both migrated clients explicitly configure rustls with ring, TLS 1.2/1.3,
and bundled WebPKI roots. This preserves their former `rustls-tls` trust
source instead of adopting platform trust or aws-lc through reqwest defaults.
They do not depend on a forge adapter installing a global crypto provider.
The small builders remain package-local so transport does not acquire a
forge dependency. Proxy defaults, timeouts, redirects, authentication,
request/response streaming, and error mapping retain the existing settings.

`rustls-no-provider` still compiles reqwest's platform-verifier dependency;
the server/transport preconfigured backend does not use it. Forge already
used that dependency. Ring's existing C/assembly toolchain requirements
remain; this migration introduces no aws-lc/CMake dependency or system
certificate-store requirement for server/transport deployment.

## Compiler and target validation

The workspace declares edition 2024 and no `rust-version` or MSRV policy.
The checked-in Woodpecker Rust gates use `rust:1.94-slim`, without a cross
compilation target matrix. Validate on Rust 1.94.0 for
`x86_64-unknown-linux-gnu`; this is not a claim that other targets are tested
or that 1.94 is the minimum supported version. Existing resolved dependencies
(including time 0.3.54, darling 0.23.0, and jsonwebtoken 10.4.0) already declare
Rust 1.88.0. Reqwest's 1.85 floor does not establish a workspace MSRV.
No retained dependency version changes in this migration.

## Regression checks

Run each package independently as well as the workspace gates:

```sh
cargo +1.94.0 test -p transport --all-targets --locked
cargo +1.94.0 test -p server --all-targets --locked
cargo +1.94.0 fmt --check
cargo +1.94.0 check --workspace --all-features --all-targets --locked
cargo +1.94.0 clippy --workspace --all-features --all-targets --locked --no-deps -- -D warnings
cargo +1.94.0 test --workspace --all-features --all-targets --locked
cargo +1.94.0 tree --locked -e features -i reqwest
cargo +1.94.0 tree --locked -e features -i rustls
```

The shared TLS test runs in a fresh process for each package, before any
global provider exists. It rejects an untrusted local certificate, accepts
that certificate only after explicitly trusting it, and rejects a hostname
mismatch even with that trust. No external service or disabled certificate
verification is involved. Provider-backed integration tests remain owned by
the dedicated CI lane.

Expected dependency evidence: only reqwest 0.13.2; `rustls-no-provider` in
all three consumers; rustls `ring`, `std`, and `tls12`; no aws-lc or reqwest
`default`, `rustls`, `http2`, `charset`, `system-proxy`, or `form` features.
