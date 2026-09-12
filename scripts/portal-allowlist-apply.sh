#!/usr/bin/env bash
# Apply docs/portal-allowlist.json to the Cloudflare MCP portal mapping.
#
# The portal hides only what it has an explicit entry for, so this file is
# re-applied on every change to the server's tool set (the test in
# internal/mcp/portal_allowlist_test.go refuses to let the set change without
# a decision here). Operator-run: CI holds no Cloudflare credential (#1111).
#
#   CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=… scripts/portal-allowlist-apply.sh [--dry-run|--check|-h|--help]
#
# Run it from a checkout with Go installed: the file is only applied (or
# checked) when it matches HEAD and the guard test passes for it.
#
# What is sent: the portal body exactly as read, minus the four top-level
# timestamps (created_at, created_by, modified_at, modified_by), with only
# the target server's mapping rewritten. Nested read-only fields on the
# server elements go back out as they came; the API accepted a PUT of the
# full GET body when this was verified, and rejects loudly if that changes.
# Nothing else is projected away, so a field Cloudflare adds later survives
# an apply untouched.
#
# The token never appears on a command line: curl reads it from a config
# handed over a file descriptor, so it is in neither the process table nor
# the shell history. Same discipline as mcpprobe's --token-env.
#
# --check compares the committed file against the live portal mapping
# instead of writing to it: default_disabled, plus the enabled/disabled
# state of every tool the server has synced. It is held to exactly the same
# pre-flight guards as an apply or a --dry-run (credentials, jq, git
# checkout, tracked-and-matches-HEAD, portal=mcp/server=tg, go, the guard
# test) and never issues a PUT, on any path, including when it finds
# disagreement. Exit codes: 0 the portal and the file agree, 1 the
# comparison could not be made (a guard refused, or the API call failed),
# 2 a usage error, 3 the portal and the file disagree.
set -euo pipefail

usage() {
  cat <<EOF
usage: $0 [--dry-run|--check|-h|--help]

  (no argument)  apply docs/portal-allowlist.json to the Cloudflare portal
                 mapping. Exit 0 on success, 1 on any pre-flight or API
                 failure.
  --dry-run      print the body that would be PUT; never writes. Same exit
                 codes as the default apply.
  --check        compare the committed file against the live portal
                 mapping; never writes. Exit 0 when they agree, 1 when the
                 comparison could not be made (pre-flight or API failure),
                 3 when they disagree.
  -h, --help     print this usage and exit 0.

Exit codes: 0 in sync / applied, 1 could not check or apply, 2 usage error,
3 drift found (--check only). Every non-zero status is a failure a caller
must surface; the split exists to say which one happened, not to make any
of them ignorable.
EOF
}

mode=apply
case "${1:-}" in
  "")          mode=apply ;;
  --dry-run)   mode=dry-run ;;
  --check)     mode=check ;;
  -h|--help)   usage; exit 0 ;;
  *) usage >&2; echo "unknown argument: $1" >&2; exit 2 ;;
esac
[ $# -le 1 ] || { usage >&2; echo "usage error: $0 takes at most one argument" >&2; exit 2; }

here=$(cd "$(dirname "$0")/.." && pwd)
file="$here/docs/portal-allowlist.json"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
: "${CLOUDFLARE_ACCOUNT_ID:?set CLOUDFLARE_ACCOUNT_ID}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

# The invariant -- an enabled tool carries a reason and names the upstream
# gate that decides per identity what it may do -- lives in the Go test,
# because the list of real gates is Go source. This path publishes
# what is on disk, so it consults the same test first: an edit that has not
# passed the guard is not applied, whether it is uncommitted or merely not
# yet through CI. Both checks are cheap next to a PUT that changes what a
# shared surface exposes.
git -C "$here" rev-parse --git-dir >/dev/null 2>&1 \
  || { echo "$here is not a git checkout, so the file cannot be compared against the committed one; run this from a clone" >&2; exit 1; }
# Tracked first, then unchanged. `git diff HEAD -- <path>` compares a path HEAD
# has; it says nothing about one HEAD does not, so a file removed from the index
# and left on disk sails through the comparison below whatever it contains.
git -C "$here" ls-files --error-unmatch -- docs/portal-allowlist.json >/dev/null 2>&1 \
  || { echo "docs/portal-allowlist.json is not tracked in $here; what is applied must be the committed file" >&2; exit 1; }
# HEAD, not the index: a staged edit is as unreviewed as an unstaged one, and
# the bare `git diff` form compares against the index and would pass it.
if ! git -C "$here" diff --quiet HEAD -- docs/portal-allowlist.json; then
  echo "docs/portal-allowlist.json differs from HEAD; commit it (and let the guard test run) before applying" >&2; exit 1
fi
# What is applied is the committed blob, not the copy on disk. The comparison
# above says the two are identical; reading the blob is what makes that
# guarantee hold all the way to the PUT, which is built further down and would
# otherwise re-read a path that had since been edited.
vetted=$(git -C "$here" show HEAD:docs/portal-allowlist.json)
portal=$(jq -r .portal <<<"$vetted"); server=$(jq -r .server <<<"$vetted")

# The file names its own target, so a file that names a different one would
# rewrite a mapping this repository does not own. Pinned here as well as in
# the guard test, because this is the side that does the writing.
[ "$portal" = mcp ] && [ "$server" = tg ] || { echo "$file targets portal=$portal server=$server; expected mcp/tg" >&2; exit 1; }
command -v go >/dev/null \
  || { echo "go is not installed here, so the guard test cannot run; refusing to apply from a host that cannot verify the file" >&2; exit 1; }
# `go test -run` exits 0 when its pattern matches nothing -- a renamed, deleted
# or moved guard would read as a pass. The run must therefore name the test as
# passed, not merely exit well. The output is kept and printed on failure: the
# test says which tool is undecided or unreasoned, and an operator who is being
# refused should not have to re-run it by hand to find out.
# The credential is taken out of the test's environment: this is the one step
# that runs code from the checkout, and an operator previewing an unfamiliar
# branch should not hand it a portal token through os.Getenv. It narrows the
# obvious path, not the trust decision -- a test runs as the operator and a
# checkout you would not trust with a token is one you should not build.
if ! guard_out=$(cd "$here" && env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_ACCOUNT_ID go test -v ./internal/mcp/ -run '^TestPortalAllowlist_CoversEveryRegisteredTool$' -count=1 2>&1) \
   || ! grep -q '^--- PASS: TestPortalAllowlist_CoversEveryRegisteredTool' <<<"$guard_out"; then
  echo "the guard test did not pass for the current file; refusing to apply" >&2
  printf '%s\n' "$guard_out" >&2
  exit 1
fi

base="https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/access/ai-controls/mcp"

# curl config on a file descriptor: the Authorization header is not an argument.
cf() { curl -sS -K <(printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$CLOUDFLARE_API_TOKEN") "$@"; }
must_succeed() { # $1 = label, stdin = API envelope; prints the envelope on success
  local body; body=$(cat)
  if ! jq -e .success >/dev/null 2>&1 <<<"$body"; then
    echo "$1 failed: $(jq -c '.errors // .' 2>/dev/null <<<"$body" || echo "$body")" >&2; exit 1
  fi
  printf '%s' "$body"
}

current=$(cf "$base/portals/$portal" | must_succeed "read portal")
server_body=$(cf "$base/servers/$server" | must_succeed "read server")

# The mapping must exist: rewriting a server that is not on the portal would
# be a silent no-op, and a silent no-op here is exactly the drift this guard
# exists to prevent.
mapped=$(jq --arg s "$server" '[.result.servers // [] | .[] | select(.server_id == $s)] | length' <<<"$current")
[ "$mapped" = 1 ] || { echo "portal '$portal' has $mapped mapping(s) for server '$server'; expected exactly one" >&2; exit 1; }

# Every tool the upstream has synced must have a decision in the file; a
# synced tool with none is the drift itself. The file may list more than
# the portal sees -- a deployment running with MCP_TOOL_FILTER=read-only
# registers a subset, and the file must still cover the full set the test
# holds it to -- so this is subset, not equality.
# LC_ALL=C on both sorts so comm and sort cannot disagree on ordering.
synced=$(jq -r '.result.tools // [] | .[].name' <<<"$server_body" | LC_ALL=C sort)
[ -n "$synced" ] || { echo "server '$server': the API returned no synced tools (result.tools is missing or empty); has it connected?" >&2; exit 1; }
listed=$(jq -r '.tools[].name' <<<"$vetted" | LC_ALL=C sort)
uncovered=$(LC_ALL=C comm -23 <(echo "$synced") <(echo "$listed"))
uncovered_drift=""
if [ -n "$uncovered" ]; then
  if [ "$mode" = check ]; then
    # A check reports every category of disagreement in one run instead of
    # stopping at the first, so this is folded into the drift accumulator
    # rather than refusing immediately the way apply/dry-run must -- a
    # refusal here would protect a write that --check never makes.
    uncovered_drift=$(while IFS= read -r t; do
      printf 'drift: %s synced by the server with no decision in docs/portal-allowlist.json\n' "$t"
    done <<<"$uncovered")
  else
    echo "synced tools with no decision in $file:" >&2
    echo "$uncovered" >&2
    echo "if a recent release removed these tools, the portal has not re-synced yet: wait and re-run. Do not add them back to the file -- the guard test rejects entries for tools the server no longer registers." >&2
    exit 1
  fi
fi

# The write is the mirror of the read check: only tools the portal has
# synced go into updated_tools, because the API rejects a name it has not
# seen (error 7001), and a file entry for a not-yet-synced tool would
# otherwise turn a legitimate apply into a refusal. A missing "enabled"
# is written as false, never as null -- the guard test refuses the file
# in that state, and the PUT must not be the second place it could slip.
body=$(jq --arg s "$server" --argjson a "$vetted" --rawfile synced_raw <(echo "$synced") '
  ($synced_raw | split("\n") | map(select(. != ""))) as $synced
  | .result
  | del(.created_at, .created_by, .modified_at, .modified_by)
  | .servers |= map(
      if .server_id == $s then
        .default_disabled = $a.default_disabled
        | .updated_tools = [ $a.tools[] | select(.name as $n | $synced | index($n) != null)
                             | {name, enabled: (.enabled // false)} ]
      else . end)' <<<"$current")

if [ "$mode" = check ]; then
  # The expected side is read out of the apply's own body, not recomputed,
  # so the comparison covers exactly what a PUT would write and cannot fall
  # out of step with the apply. The actual side is the same mapping read
  # straight from the live portal, before any rewrite.
  expected=$(jq -c --arg s "$server" '[.servers[] | select(.server_id==$s)][0]' <<<"$body")
  actual=$(jq -c --arg s "$server" '[.result.servers // [] | .[] | select(.server_id==$s)][0]' <<<"$current")

  # jq's `//` substitutes on `false` as well as on `null`; used anywhere in
  # this comparison it would turn a genuine `false` into "absent" and report
  # a matching baseline as drifted -- the bug on record against
  # mctl-gitops/scripts/portal-controls-apply.sh. Every default below is
  # therefore built with has() and an explicit conditional, never with `//`.
  tool_drift=$(jq -r -n --argjson expected "$expected" --argjson actual "$actual" '
    def dtools(side): if (side|has("updated_tools")) and side.updated_tools != null then side.updated_tools else [] end;
    def sentinel(side; name):
      (dtools(side) | map(select(.name == name)) | first) as $e
      | if ($e != null and ($e|has("enabled"))) then $e.enabled else "absent" end;
    (if $expected.default_disabled == $actual.default_disabled then empty
     else "drift: default_disabled portal=\($actual.default_disabled) file=\($expected.default_disabled)" end),
    (((dtools($expected) | map(.name)) + (dtools($actual) | map(.name)) | unique) as $names
      | $names[] as $n
      | sentinel($actual; $n) as $p
      | sentinel($expected; $n) as $f
      | select($p != $f)
      | "drift: \($n) portal=\($p) file=\($f)")
  ')

  # printf always exits 0, even on an empty string, so this pipeline never
  # fails a component under pipefail; sed then drops the blank lines that
  # would otherwise leave from an empty side.
  total_drift=$(
    { printf '%s\n' "$uncovered_drift"
      printf '%s\n' "$tool_drift"; } | sed '/^$/d'
  )
  if [ -n "$total_drift" ]; then
    printf '%s\n' "$total_drift"
    n=$(wc -l <<<"$total_drift" | tr -d ' ')
    echo "$n difference(s) between the portal and docs/portal-allowlist.json" >&2
    exit 3
  fi

  # A tool the file decides and the server has not synced never reaches
  # updated_tools in $body in the first place -- the apply holds it back by
  # design -- so it is not drift; it is named here so it stays visible.
  held_back=$(LC_ALL=C comm -23 <(echo "$listed") <(echo "$synced"))

  # Same discipline as the applied: summary below: select(. != null) so an
  # unexpected missing mapping cannot print an empty "in sync" line.
  jq -er -n --argjson want "$expected" '
    $want | select(. != null)
    | "in sync: default_disabled=\(.default_disabled) tools=\(.updated_tools|length) enabled=\([.updated_tools[]|select(.enabled)|.name]|join(","))"' \
    || { echo "check produced no result for '$server'; verify the portal by hand" >&2; exit 1; }
  if [ -n "$held_back" ]; then
    echo "held back (not synced by the server): $(echo "$held_back" | paste -sd, -)"
  fi
  exit 0
fi

if [ "$mode" = dry-run ]; then jq . <<<"$body"; exit 0; fi
# The decisions going out, as a sorted {name, enabled} projection; the
# summary must see exactly the same set coming back, or a portal that
# silently drops, flips or pads decisions would read as a clean apply.
sent=$(jq -c --arg s "$server" '[.servers[] | select(.server_id==$s)][0].updated_tools | map({name, enabled}) | sort_by(.name)' <<<"$body")
res=$(cf -X PUT "$base/portals/$portal" --data "$body" | must_succeed "update portal")
# The summary is the record that the allowlist landed, so it must not be
# able to print nothing. select(. != null) drops an empty selection before
# the string is built; with no output at all, jq -e exits 4 and the ||
# branch runs. -e alone would not do this: a string interpolated from
# null is still a truthy string.
jq -er --arg s "$server" --argjson sent "$sent" '[.result.servers // [] | .[] | select(.server_id==$s)] | first | select(. != null)
  | select((.updated_tools | map({name, enabled}) | sort_by(.name)) == $sent)
  | "applied: default_disabled=\(.default_disabled) tools=\(.updated_tools|length) enabled=\([.updated_tools[]|select(.enabled)|.name]|join(","))"' <<<"$res" \
  || { echo "update returned success but the response's updated_tools for '$server' are not the decisions sent (missing mapping, dropped, flipped or extra entries); verify the portal by hand" >&2; exit 1; }
