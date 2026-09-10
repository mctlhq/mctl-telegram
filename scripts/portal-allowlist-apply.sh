#!/usr/bin/env bash
# Apply docs/portal-allowlist.json to the Cloudflare MCP portal mapping.
#
# The portal hides only what it has an explicit entry for, so this file is
# re-applied on every change to the server's tool set (the test in
# internal/mcp/portal_allowlist_test.go refuses to let the set change without
# a decision here). Operator-run: CI holds no Cloudflare credential (#1111).
#
#   CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=… scripts/portal-allowlist-apply.sh [--dry-run]
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
set -euo pipefail

case "${1:-}" in
  "")          dry_run=0 ;;
  --dry-run)   dry_run=1 ;;
  *) echo "usage: $0 [--dry-run]  (unknown argument: $1)" >&2; exit 2 ;;
esac
[ $# -le 1 ] || { echo "usage: $0 [--dry-run]" >&2; exit 2; }

here=$(cd "$(dirname "$0")/.." && pwd)
file="$here/docs/portal-allowlist.json"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
: "${CLOUDFLARE_ACCOUNT_ID:?set CLOUDFLARE_ACCOUNT_ID}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

portal=$(jq -r .portal "$file"); server=$(jq -r .server "$file")
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
synced=$(jq -r '.result.tools // [] | .[].name' <<<"$server_body" | sort)
[ -n "$synced" ] || { echo "server '$server': the API returned no synced tools (result.tools is missing or empty); has it connected?" >&2; exit 1; }
listed=$(jq -r '.tools[].name' "$file" | sort)
uncovered=$(comm -23 <(echo "$synced") <(echo "$listed"))
if [ -n "$uncovered" ]; then
  echo "synced tools with no decision in $file:" >&2
  echo "$uncovered" >&2
  exit 1
fi

# The write is the mirror of the read check: only tools the portal has
# synced go into updated_tools, because the API rejects a name it has not
# seen (error 7001), and a file entry for a not-yet-synced tool would
# otherwise turn a legitimate apply into a refusal. A missing "enabled"
# is written as false, never as null -- the guard test refuses the file
# in that state, and the PUT must not be the second place it could slip.
body=$(jq --arg s "$server" --slurpfile a "$file" --rawfile synced_raw <(echo "$synced") '
  ($synced_raw | split("\n") | map(select(. != ""))) as $synced
  | .result
  | del(.created_at, .created_by, .modified_at, .modified_by)
  | .servers |= map(
      if .server_id == $s then
        .default_disabled = $a[0].default_disabled
        | .updated_tools = [ $a[0].tools[] | select(.name as $n | $synced | index($n) != null)
                             | {name, enabled: (.enabled // false)} ]
      else . end)' <<<"$current")

if [ "$dry_run" = 1 ]; then jq . <<<"$body"; exit 0; fi
res=$(cf -X PUT "$base/portals/$portal" --data "$body" | must_succeed "update portal")
# The summary is the record that the allowlist landed, so it must not be
# able to print nothing. select(. != null) drops an empty selection before
# the string is built; with no output at all, jq -e exits 4 and the ||
# branch runs. -e alone would not do this: a string interpolated from
# null is still a truthy string.
jq -er --arg s "$server" '[.result.servers // [] | .[] | select(.server_id==$s)] | first | select(. != null)
  | "applied: default_disabled=\(.default_disabled) enabled=\([.updated_tools[]|select(.enabled)|.name]|join(","))"' <<<"$res" \
  || { echo "update returned success but no mapping for '$server' in the response; verify the portal by hand" >&2; exit 1; }
