# Download acceptance boundaries

All added-output examples are synthetic. The pinned upstream provenance in this
directory describes the handler, not deployed retention or recovery. JSON v3.11
fixtures retain their original provenance. No private production output is used.

| Approved area | Owning deterministic evidence |
| --- | --- |
| 1. Paired output and identity | `server::handlers::tests::paired_sources_rest_mcp_preserve_identity_and_unknown_retention` traverses both sources through MCP and REST, compares every page, exact reconstructed text, commit/identity and distinct snapshot IDs. |
| 2. Missing endings and state independence | The same test covers both views ending early, empty, active and unknown state; download snapshot tests cover empty/lossy EOF. |
| 3. Exact canonical traversal | `woodpecker_download_snapshot` tests beginning/continuation/tail/rewind, multibyte/control text and atomic scalar/replacement boundaries; `woodpecker_download_decode` tests separators and redaction expansion. |
| 4. JSON compatibility | `woodpecker_log_snapshot::tests::frozen_json_v1_cursor_resumes_unchanged` freezes original tokens/hashes. Existing six-panics, record, excerpt and other-adapter suites remain required. |
| 5. Cursor isolation and mutations | `woodpecker_download_snapshot` tests real cross-source tokens over identical bodies, malformed versions/offsets and source/authority/policy changes; explicit restart creates a new snapshot. |
| 6. Authorization and membership | Public download traversal tests deny gateway/repository access before fetching; paired tests deny cursor reuse against another repository on each page. `woodpecker_step_log_download` tests selection failures, duplicate children, exact request count and CI-only authentication. |
| 7. Secret handling | Download decoder/reader/transport tests cover whole-stream redaction, atomic replacements, lossy decoding and safe provider errors; public tests inspect output and audit records. |
| 8. Resource and transport limits | `woodpecker` raw-TCP/wiremock tests cover media, encoding, declared/chunked framing, redirects, deadlines, status mapping and body budgets. Download decode/snapshot tests independently bound raw/decoded/canonical output and escaped envelopes. |
| 9. Public parity and discovery | Download DTO conversion/OpenAPI tests, typed MCP validation/query tests and actual MCP→REST→orchestrator→mocked-provider traversal cover discovery and per-page authorization. All returned evidence remains historical. |

Run the workspace/all-feature/all-target formatting, Clippy, tests and build
before publication. Real Forgejo lifecycle checks belong to the isolated CI lane;
local mock tests do not substitute for successful exact-head provider CI. No
independent approval, merge or deployment is performed by these tests.
