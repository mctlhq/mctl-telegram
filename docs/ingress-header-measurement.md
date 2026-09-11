# Measuring what reaches the tg.mctl.ai ingress

This runbook covers Slice 1 of
[mctl-telegram#617](https://github.com/mctlhq/mctl-telegram/issues/617), the Phase 3 correlation
measurement under the enterprise MCP roadmap
[.github#35](https://github.com/mctlhq/.github/issues/35).

It answers one question and defers every design decision until it is answered: **which request
identifiers actually arrive at this ingress, and are they stable across calls?** Phase 2
([.github#43](https://github.com/mctlhq/.github/issues/43)) established that Cloudflare Gateway
supplies no MCP-tool-level evidence, so nothing here may assume a particular header exists --
`Cf-Ray` included.

## Why the probe sits on MCP_PATH

A Cloudflare MCP Server Portal proxies only to the upstream MCP URL it is configured with. A
dedicated `/debug/headers` route would therefore never be exercised by the path under measurement,
and any table built from it would describe a different request. `internal/web.HeaderProbe` is
mounted as the outermost layer of the `MCP_PATH` mount so it observes every request that reaches
it, including the ones the origin guard or auth will refuse: "the Portal call arrived and was
rejected" is itself a result.

## What it logs, and what it never logs

One `header_probe` line per request, at info level:

| Field | Meaning |
| --- | --- |
| `probe_seq` | Per-process counter, so repeats of the same call are distinguishable |
| `method`, `path`, `proto` | Route facts |
| `socket_peer` | Masked real TCP peer (`netctx.Peer`), not the `RealIP`-rewritten address |
| `header_names` | The complete sorted set of arriving header names (capped, see below) |
| `reconstructed` | Names rebuilt from the request struct rather than read from `r.Header` |
| `headers_omitted` | How many names the per-line cap dropped; `0` on any real request |
| `headers.h:*` | One sanitized value per header |

`r.Header` is not the arriving header set: `net/http` moves `Host` into `r.Host` and deletes it from
the map, moves `Transfer-Encoding` into `r.TransferEncoding`, and drops `Content-Length` on a chunked
request. The probe rebuilds those three and names them in `reconstructed`, so a missing `Host` on the
table means the Portal did not send one rather than that Go removed it. HTTP/2 pseudo-headers
(`:authority`, `:scheme`, `:path`) cannot be recovered at all -- `:authority` surfaces as `Host` and
the rest are gone; read `proto` before drawing conclusions about them.

Keys inside the group carry an `h:` prefix. `audit.RedactingHandler` recurses into groups and
rewrites any attribute whose key is exactly one of its sensitive names (`authorization`, `session`,
`signature`, `code`, `nonce`); without the prefix it would replace this middleware's output wholesale
and take the fingerprint with it -- losing the evidence the fingerprint exists to provide, on exactly
the headers that need it.

Sanitization, pinned by `internal/web/headerprobe_test.go`:

- secret-bearing names (anything containing `auth`, `token`, `secret`, `key`, `cookie`, `password`,
  `credential`, `signature`, `session`, `jwt`, `assertion`, `bearer` -- the last three because
  Cloudflare Access asserts identity in `Cf-Access-Jwt-Assertion`) become
  `[redacted len=N fp=xxxxxxxx]`;
- so do values that look credential-bearing under an innocent name: `?access_token=...` in a
  `Referer`, or a `eyJ`-prefixed JWT;
- address-bearing names (`cf-connecting-ip`, `x-forwarded-for`, ...) are masked to a `203.0.x.x`
  prefix, each hop separately, plus a fingerprint;
- everything else is verbatim, truncated at 256 bytes on a rune boundary;
- at most 64 headers are rendered per line, the rest counted in `headers_omitted`: the probe runs
  ahead of auth with no rate limiter, and one request must not become an unbounded line;
- repeated values are shown and counted (`[values=2]`).

The fingerprint is a truncated HMAC-SHA-256 under a random per-process key. It exists so that "the
same value arrived three times" is provable for a header whose value must not be logged; the key is
what stops a reader of the logs from confirming a guessed low-entropy secret offline against those
32 bits.

**Consequence for the procedure: fingerprints are comparable only within one process.** A restart or
a second replica re-keys them, so the repeated calls of a measurement window must land on the same
pod -- scale to one replica for the window, or pin the calls to a pod. **The request body is never read, buffered or
logged**; correlation evidence must not cost message content.

## Procedure

1. Enable the probe for a measurement window (it is off unless set):

   ```bash
   MCP_HEADER_PROBE=true
   ```

   The server logs a warning at startup while it is on.

2. Make at least three identical `tools/call` requests **through the Portal**
   (`mcp.mctl.ai` -> upstream). Three repeats are what separates a per-request id from a constant.

3. Make the same call **directly** against `https://tg.mctl.ai/mcp`. Without this second route an
   edge-injected header cannot be told apart from one the client sent itself.

4. Collect the lines:

   ```bash
   kubectl logs deploy/mctl-telegram | grep header_probe
   ```

5. Turn `MCP_HEADER_PROBE` back off.

## Reporting

Post on #617, for both routes:

- the complete observed header table (all names, sanitized values) -- not the first working
  combination;
- a per-candidate verdict: `arrives` / `does not arrive` / `arrives but is not stable`;
- the date and the exact routes measured.

State the result only in the scope of what was measured -- "on the route Portal -> tg.mctl.ai on
<date>, header X arrives" -- with no extrapolation to Gateway logs, other zones or other upstreams.
A finding of "no usable edge identifier" is a complete result: it selects Branch B of #617
(generate `mctl_request_id` at ingress) rather than leaving the issue open.

## Removal

`HeaderProbe`, the `MCP_HEADER_PROBE` flag and this runbook are temporary. Delete them once Slice 1
is reported; the correlation contract itself is built in Slice 2 and does not depend on them.
