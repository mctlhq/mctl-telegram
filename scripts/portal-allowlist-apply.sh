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
# The full portal body is read first and sent back whole, as the API
# overwrites unspecified fields; only the server mapping is rewritten.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
file="$here/docs/portal-allowlist.json"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
: "${CLOUDFLARE_ACCOUNT_ID:?set CLOUDFLARE_ACCOUNT_ID}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

portal=$(jq -r .portal "$file"); server=$(jq -r .server "$file")
base="https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/access/ai-controls/mcp"
auth=(-H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H "Content-Type: application/json")

current=$(curl -sS "${auth[@]}" "$base/portals/$portal")
jq -e .success >/dev/null <<<"$current" || { echo "read portal failed: $current" >&2; exit 1; }

# Every tool the upstream has synced must be covered; a synced tool with no
# decision is exactly the drift this guard exists for.
synced=$(curl -sS "${auth[@]}" "$base/servers/$server" | jq -r '.result.tools[].name' | sort)
listed=$(jq -r '.tools[].name' "$file" | sort)
if ! diff <(echo "$synced") <(echo "$listed") >/dev/null; then
  echo "tool set mismatch between the portal's synced list and $file:" >&2
  diff <(echo "$synced") <(echo "$listed") >&2 || true
  exit 1
fi

body=$(jq --arg server "$server" --slurpfile a "$file" '
  .result
  | {id, name, description, hostname, code_mode, secure_web_gateway,
     servers: [ .servers[] | if .server_id == $server then
        {server_id, on_behalf, default_disabled: $a[0].default_disabled,
         updated_tools: [ $a[0].tools[] | {name, enabled} ]}
       else {server_id, on_behalf, default_disabled, updated_tools} end ]}' <<<"$current")

if [ "${1:-}" = "--dry-run" ]; then jq . <<<"$body"; exit 0; fi
res=$(curl -sS -X PUT "${auth[@]}" "$base/portals/$portal" --data "$body")
jq -e .success >/dev/null <<<"$res" || { echo "update failed: $res" >&2; exit 1; }
jq -r --arg server "$server" '.result.servers[] | select(.server_id==$server) | "applied: default_disabled=\(.default_disabled) enabled=\([.updated_tools[]|select(.enabled)|.name]|join(","))"' <<<"$res"
