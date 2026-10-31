# Download transport fixture, profile 1

This synthetic byte fixture is separate from the v3.11.0 JSON fixtures.
It is not a production capture and establishes no deployed version or output
retention behavior. The transport test appends NUL and an invalid UTF-8 byte in Rust; this
transport boundary preserves them unchanged. The stored text has CRLF, ANSI
and no final newline.

Public upstream evidence inspected on 2026-10-31, pinned to commit
`af44fdc0ea03a27dd27df9927c110c9469544fc8`:

* [DownloadStepLogs](https://github.com/woodpecker-ci/woodpecker/blob/af44fdc0ea03a27dd27df9927c110c9469544fc8/server/api/pipeline.go)
  reads the selected step through LogFind, sets HTTP 200 and
  `text/plain; charset=utf-8`, sets an attachment filename, then writes raw
  entry data with an LF between entries. The client preserves the bytes the
  handler actually returned; it must not insert or remove separators itself.
* [Routes](https://github.com/woodpecker-ci/woodpecker/blob/af44fdc0ea03a27dd27df9927c110c9469544fc8/server/router/api.go)
  define the repository/run/step download path. A filename is never a client
  destination and is ignored by this reader.

The older v3.11.0 route table lacks this download route; a 404 can mean an
unavailable route or missing resource, and cannot establish capability alone.
The pinned download and JSON handlers use the same log store. They do not
promise recovery of missing terminal output. Any later paired fixture with
extra download text is a synthetic acceptance scenario, not evidence of
upstream reconstruction or production retention.

Transport acceptance lives in `forge/src/woodpecker.rs`: fixed numeric path,
configured prefix, CI-only optional auth, identity encoding, full bounded body,
media/encoding rejection, shared budgets, no cache/redirect/retry, safe errors,
and raw TCP truncation/deadline checks. Decoder, cursor and public traversal
acceptance remain the responsibility of the subsequent reader integration.
