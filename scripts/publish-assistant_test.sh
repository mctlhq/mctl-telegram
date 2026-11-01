#!/usr/bin/env bash
# Offline test of scripts/publish-assistant.sh. Nothing reaches mctl-api:
# the admin calls go to a fake mctl_token.py (MCTL_TOKEN_PY) and the public
# catalog check to a local fixture server (MCTL_API_BASE_URL). The script
# runs inside a throwaway copy of HEAD, with its own bare "origin", so the
# origin/main ancestry check and the rebuild at a commit are real. The
# script itself is the working-tree copy, so an edit to it is tested
# without committing.
#
#   bash scripts/publish-assistant_test.sh
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
t=$(mktemp -d)
server_pid=
# shellcheck disable=SC2329 # invoked by the trap
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$t"
}
trap cleanup EXIT

# A one-commit repository holding HEAD's tree and this script, pushed to a
# bare origin and cloned, as the owner's checkout would be.
mkdir -p "$t/seed"
git -C "$root" archive HEAD | tar -x -C "$t/seed"
cp "$root/scripts/publish-assistant.sh" "$t/seed/scripts/publish-assistant.sh"
git -C "$t/seed" init -q -b main
git -C "$t/seed" add -A
git -C "$t/seed" -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false commit -q -m seed
git init -q --bare -b main "$t/origin.git"
git -C "$t/seed" push -q "$t/origin.git" main
git clone -q "$t/origin.git" "$t/repo"
sha=$(git -C "$t/repo" rev-parse HEAD)
digest=$(cd "$t/repo" && go run ./cmd/assistant-materialize -out "$t/expect" | awk '$1 == "hr-recruiter@0.1.0" {print $2}')
[ -n "$digest" ] || { echo "no hr-recruiter@0.1.0 in the catalog"; exit 1; }
other=sha256:1111111111111111111111111111111111111111111111111111111111111111

# The fake admin tool: mctl_token.call(method, path, body) prints
# "HTTP <status>" and the response, like the real one. The definition-versions
# list uses mctl-api's real JSON shape (agentregistry.DefinitionVersion):
# camelCase sourceManifest.contentHash.
cat >"$t/fake_token.py" <<'PY'
import json, os

def call(method, path, body=None):
    mode, digest, other = os.environ["FAKE_MODE"], os.environ["FAKE_DIGEST"], os.environ["FAKE_OTHER"]
    with open(os.environ["FAKE_LOG"], "a") as log:
        log.write(f"{method} {path}\n")
        if method == "POST":
            log.write("manifest " + json.dumps(json.loads(body)["source_manifest"], sort_keys=True) + "\n")

    def row(content_hash, lifecycle):
        return {"id": 7, "agent": "hr-recruiter", "version": "0.1.0", "apiVersion": "agents.mctl.ai/v1alpha2",
                "spec": "{}", "owner": "mctl-telegram",
                "sourceManifest": {"repo": "mctlhq/mctl-telegram", "path": "assistants/hr-recruiter/assistant.yaml",
                                   "gitSha": "0" * 40, "contentHash": content_hash},
                "profileRange": "", "lifecycle": lifecycle, "createdAt": "2026-10-20T10:00:00Z"}

    if method == "GET" and path == "/api/v1/agents/hr-recruiter":
        status, resp = (404, {"error": "not found"}) if mode == "no-agent" else (200, {"name": "hr-recruiter"})
    elif method == "GET" and path == "/api/v1/agents/hr-recruiter/definition-versions":
        items = {"exists": [row(digest, "published")], "deprecated": [row(digest, "deprecated")],
                 "disabled": [row(digest, "disabled")], "conflict": [row(other, "published")]}.get(mode, [])
        status, resp = 200, {"items": items, "count": len(items)}
    elif method == "POST" and path == "/api/v1/agents/hr-recruiter/definition-versions":
        status, resp = (403, {"error": "forbidden"}) if mode == "post-refused" else (201, {"version": "0.1.0"})
    else:
        status, resp = 400, {"error": "unexpected call"}
    print(f"HTTP {status}")
    print(json.dumps(resp))
PY

# The public catalog fixture, served from $t/www on a free local port.
cat >"$t/serve.py" <<'PY'
import functools, http.server, sys
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass
srv = http.server.HTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=sys.argv[1]))
with open(sys.argv[2], "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PY
mkdir -p "$t/www/api/v1/assistant-catalog/hr-recruiter/versions"
catalog=$t/www/api/v1/assistant-catalog/hr-recruiter/versions/0.1.0
python3 "$t/serve.py" "$t/www" "$t/port" &
server_pid=$!
for _ in $(seq 50); do [ -s "$t/port" ] && break; sleep 0.1; done
[ -s "$t/port" ] || { echo "fixture server did not start"; exit 1; }
base=http://127.0.0.1:$(cat "$t/port")

fail=0
# expect NAME WANT_EXIT WANT_POSTS MODE CATALOG_DIGEST [ARGS...]
expect() {
  local name=$1 want=$2 posts=$3 mode=$4 served=$5
  shift 5
  local args=("$@")
  [ ${#args[@]} -gt 0 ] || args=(hr-recruiter 0.1.0 "$sha" "$digest")
  : >"$t/log"
  rm -f "$catalog"
  [ "$served" = none ] || printf '{"name":"hr-recruiter","version":"0.1.0","lifecycle":"published","digest":"%s"}' "$served" >"$catalog"
  local got=0
  FAKE_MODE=$mode FAKE_DIGEST=$digest FAKE_OTHER=$other FAKE_LOG=$t/log \
    MCTL_TOKEN_PY=$t/fake_token.py MCTL_API_BASE_URL=$base \
    bash "$t/repo/scripts/publish-assistant.sh" "${args[@]}" >"$t/out" 2>&1 || got=$?
  local n
  n=$(grep -c '^POST ' "$t/log" || true)
  if [ "$got" != "$want" ] || [ "$n" != "$posts" ]; then
    echo "FAIL $name: exit $got (want $want), $n POST (want $posts)"
    sed 's/^/    /' "$t/out"
    fail=1
  else
    echo "ok   $name"
  fi
}

expect "new version is published and verified" 0 1 new "$digest"
grep -qxF "manifest {\"content_hash\": \"$digest\", \"git_sha\": \"$sha\", \"path\": \"assistants/hr-recruiter/assistant.yaml\", \"repo\": \"mctlhq/mctl-telegram\"}" "$t/log" ||
  { echo "FAIL publish body manifest:"; cat "$t/log"; fail=1; }
expect "already published, same digest" 0 0 exists none
expect "already deprecated, same digest" 0 0 deprecated none
expect "disabled with the same digest is not success" 1 0 disabled none
expect "registry holds another digest" 1 0 conflict none
expect "no agent row: instruction, nothing created" 2 0 no-agent none
grep -q "call POST /api/v1/agents " "$t/out" || { echo "FAIL no-agent printed no instruction"; fail=1; }
expect "publish refused, even if the catalog would match" 1 1 post-refused "$digest"
expect "catalog serves another digest after publishing" 1 1 new "$other"
expect "catalog does not serve it after publishing" 1 1 new none
expect "rebuild has another digest" 1 0 new none hr-recruiter 0.1.0 "$sha" "$other"
expect "commit not on origin/main" 1 0 new none hr-recruiter 0.1.0 0123456789abcdef0123456789abcdef01234567 "$digest"
expect "version not in the catalog" 1 0 new none hr-recruiter 9.9.9 "$sha" "$digest"

[ "$(git -C "$t/repo" worktree list --porcelain | grep -c '^worktree ')" = 1 ] ||
  { echo "FAIL temporary worktrees left behind:"; git -C "$t/repo" worktree list; fail=1; }
exit "$fail"
