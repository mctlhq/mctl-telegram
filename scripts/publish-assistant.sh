#!/usr/bin/env bash
# Publish one catalog assistant version to the mctl-api registry.
#
#   bash mctl-telegram/scripts/publish-assistant.sh <name> <version> <git-sha> <digest>
#
# Publishing is a human-admin call by design (requireAgentRegistryHumanAdmin
# in mctl-api), so CI never runs this: on every push to main the
# assistant-publish-prep workflow prints this exact command for each version
# the registry does not have yet. The owner runs it, usually from the
# workspace root (it works from anywhere).
#
# It trusts nothing CI produced. It rebuilds the materialized document from
# <git-sha> (which must be on origin/main) in a temporary worktree, refuses
# unless the digest is <digest>, checks the agent row and the version in the
# registry with the admin token, publishes, and then checks the public
# catalog serves the version, lifecycle published, under the same digest.
# It exits non-zero on anything else. The admin token comes from
# tools/mctl-token/mctl_token.py in the workspace (a browser sign-in if the
# saved one has expired); override with MCTL_TOKEN_PY. MCTL_API_BASE_URL is
# read by both this script and mctl_token.py.
set -euo pipefail

die() { echo "publish-assistant: $*" >&2; exit 1; }

[ $# -eq 4 ] || die "usage: $0 <name> <version> <git-sha> <digest>"
name=$1 version=$2 sha=$3 want=$4
[[ $name =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "name $name is not a catalog name"
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version $version is not MAJOR.MINOR.PATCH"
[[ $sha =~ ^[0-9a-f]{40}$ ]] || die "git sha $sha is not a full commit id"
[[ $want =~ ^sha256:[0-9a-f]{64}$ ]] || die "digest $want is not sha256:<64 hex>"

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
token_py=${MCTL_TOKEN_PY:-$(dirname "$repo")/tools/mctl-token/mctl_token.py}
api=${MCTL_API_BASE_URL:-https://api.mctl.ai}
api=${api%/}
[ -f "$token_py" ] || die "no $token_py (set MCTL_TOKEN_PY)"
for tool in git go python3 curl; do
  command -v "$tool" >/dev/null || die "$tool is required"
done

tmp=$(mktemp -d)
cleanup() {
  git -C "$repo" worktree remove --force "$tmp/src" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

# 1. Rebuild at exactly that commit, which must already be on main.
git -C "$repo" fetch -q origin main
git -C "$repo" merge-base --is-ancestor "$sha" origin/main ||
  die "$sha is not on origin/main; only merged commits are published"
git -C "$repo" worktree add -q --detach "$tmp/src" "$sha"
(cd "$tmp/src" && go run ./cmd/assistant-materialize -out "$tmp/dist" -git-sha "$sha") >"$tmp/digests.txt" ||
  die "materialize failed at $sha"
line=$(awk -v k="$name@$version" '$1 == k' "$tmp/digests.txt")
[ -n "$line" ] || die "$name@$version is not in the catalog at $sha"
got=$(awk '{print $2}' <<<"$line")
[ "$got" = "$want" ] || die "$name@$version at $sha has digest $got, not $want; refusing"
body=$tmp/dist/$name-$version.request.json
[ -s "$body" ] || die "no request body at $body"
echo "Rebuilt $name@$version at $sha: $got ($(awk '{print $4}' <<<"$line"))"

# call METHOD PATH [BODY]: an admin call through mctl_token.py, which prints
# "HTTP <status>" and then the response. Sets status and resp.
call() {
  local out
  out=$(python3 "$token_py" call "$@") || die "mctl_token.py call $1 $2 failed"
  status=$(head -n1 <<<"$out" | awk '$1 == "HTTP" {print $2}')
  resp=$(tail -n +2 <<<"$out")
  [ -n "$status" ] || die "mctl_token.py printed no HTTP status for $1 $2"
}

# 2. The agent row must exist; it is created once per assistant, on purpose
#    not by this script.
call GET "/api/v1/agents/$name"
case $status in
  200) ;;
  404)
    cat >&2 <<EOF
publish-assistant: the registry has no agent row for $name yet.
Create it once (a deliberate step, not done here), then rerun this command:

  python3 $token_py call POST /api/v1/agents '{"name":"$name","description":"<one line>","owner":"mctl-telegram"}'
EOF
    exit 2
    ;;
  *) die "GET /api/v1/agents/$name answered HTTP $status: $resp" ;;
esac

# 3. The admin list is authoritative (every lifecycle, unlike the public
#    catalog). An existing version with the same digest is done; with
#    another digest it is a broken immutability invariant.
call GET "/api/v1/agents/$name/definition-versions"
[ "$status" = 200 ] || die "GET /api/v1/agents/$name/definition-versions answered HTTP $status: $resp"
existing=$(python3 -c '
import json, sys
version = sys.argv[1]
items = json.loads(sys.stdin.read())["items"]
if not isinstance(items, list):
    sys.exit("items is not a list")
for it in items:
    if it["version"] == version:
        print(it["sourceManifest"]["contentHash"], it["lifecycle"])
' "$version" <<<"$resp") || die "unreadable definition-versions response"
if [ -n "$existing" ]; then
  read -r have lifecycle <<<"$existing"
  [ "$have" = "$want" ] ||
    die "$name@$version is already in the registry with digest $have, not $want: immutability is broken, investigate"
  echo "$name@$version is already published with digest $have (lifecycle $lifecycle); nothing to do."
  exit 0
fi

# 4. Publish.
call POST "/api/v1/agents/$name/definition-versions" "$(cat "$body")"
[ "$status" = 201 ] || die "publish answered HTTP $status: $resp"
echo "Published $name@$version."

# 5. The public catalog must now serve it, published, under the same digest.
code=$(curl -sS -o "$tmp/catalog.json" -w '%{http_code}' "$api/api/v1/assistant-catalog/$name/versions/$version") ||
  die "could not read the public catalog after publishing; check it by hand"
[ "$code" = 200 ] || die "public catalog answered HTTP $code for $name@$version after publishing"
python3 -c '
import json, sys
path, digest = sys.argv[1:]
d = json.load(open(path))
if d.get("digest") != digest or d.get("lifecycle") != "published":
    sys.exit("catalog shows digest %s lifecycle %s" % (d.get("digest"), d.get("lifecycle")))
' "$tmp/catalog.json" "$want" || die "public catalog does not show $name@$version as published with $want"
echo "Verified: the public catalog serves $name@$version, lifecycle published, digest $want."
