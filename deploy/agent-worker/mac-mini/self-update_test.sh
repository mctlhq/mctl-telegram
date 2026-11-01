#!/usr/bin/env bash
# Offline test of self-update.sh's target resolution for both tracks. Nothing
# reaches GitHub or launchd: a fake curl on PATH serves the two values.yaml
# fixtures, a fake go stands in for the build, the source clone points at a
# local bare repository seeded from HEAD, and every run is --dry-run, which
# stops before install and restart. The script under test is the working-tree
# copy, so an edit to it is tested without committing.
#
#   bash deploy/agent-worker/mac-mini/self-update_test.sh
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
script="$root/deploy/agent-worker/mac-mini/self-update.sh"
t=$(mktemp -d)
# shellcheck disable=SC2329 # invoked by the trap
cleanup() { rm -rf "$t"; }
trap cleanup EXIT

# A repository with two commits: the older one tagged as a release, the newer
# one the tip of main, as production and tg-preview would run.
mkdir -p "$t/seed"
git -C "$root" archive HEAD | tar -x -C "$t/seed"
cp "$script" "$t/seed/deploy/agent-worker/mac-mini/self-update.sh"
gitc() { git -C "$t/seed" -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }
gitc init -q -b main
gitc add -A
gitc commit -q -m release
gitc tag 0.116.0
echo "# newer" >> "$t/seed/deploy/agent-worker/system-prompt.txt"
gitc commit -q -am main
release_sha=$(gitc rev-parse 0.116.0)
main_sha=$(gitc rev-parse main)
git init -q --bare -b main "$t/origin.git"
gitc push -q --tags "$t/origin.git" main

base="$t/base"
mkdir -p "$base"
git clone -q --no-checkout "$t/origin.git" "$base/src"
echo 0000000 > "$base/VERSION"

# Fake curl: the last argument is the URL; serve the fixture for the values
# file it names and fail for anything else, as -f would on a 404.
mkdir -p "$t/bin"
cat > "$t/bin/curl" <<'SH'
#!/usr/bin/env bash
url="${*: -1}"
case "$url" in
  */mctl-telegram-preview/values.yaml) cat "$FAKE_VALUES_DIR/preview.yaml" ;;
  */mctl-telegram/values.yaml) cat "$FAKE_VALUES_DIR/prod.yaml" ;;
  *) echo "curl: (22) unexpected url $url" >&2; exit 22 ;;
esac
SH
# Fake go: write the -o target so the build step has something to hash.
cat > "$t/bin/go" <<'SH'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then echo fake > "$2"; exit 0; fi
  shift
done
exit 1
SH
chmod +x "$t/bin/curl" "$t/bin/go"

values() { # <file> <tag>
  printf 'image:\n  repository: ghcr.io/mctlhq/mctl-telegram\n  tag: "%s"\n' "$2" > "$1"
}
mkdir -p "$t/values"
values "$t/values/preview.yaml" "main-$main_sha"
values "$t/values/prod.yaml" "0.116.0"

fails=0
run() { # <name> <expected exit> <expected substring>
  local name="$1" want_rc="$2" want_out="$3" rc=0 out
  rm -rf "$base/.update.lock"
  out=$(cd "$t" && PATH="$t/bin:$PATH" AGENT_WORKER_BASE="$base" AGENT_WORKER_GO="$t/bin/go" \
    FAKE_VALUES_DIR="$t/values" bash "$script" --dry-run 2>&1) || rc=$?
  if [ "$rc" != "$want_rc" ] || [[ "$out" != *"$want_out"* ]]; then
    echo "FAIL $name: exit $rc (want $want_rc); want output containing: $want_out"
    printf '    %s\n' "$out"
    fails=$((fails + 1))
  else
    echo "ok   $name"
  fi
}

rm -f "$base/TRACK"
run "no TRACK follows preview" 0 "source: preview main-$main_sha -> $main_sha"
echo preview > "$base/TRACK"
run "TRACK=preview follows preview" 0 "source: preview main-$main_sha -> $main_sha"
printf '  prod\n' > "$base/TRACK"
run "TRACK=prod resolves the release tag" 0 "source: prod 0.116.0 -> $release_sha"
run "prod dry run stops before install" 0 "dry run: not installing"
echo staging > "$base/TRACK"
run "unknown track dies" 1 "TRACK must contain 'preview' or 'prod', not 'staging'"
: > "$base/TRACK"
run "empty track dies" 1 "TRACK must contain 'preview' or 'prod', not ''"

echo prod > "$base/TRACK"
values "$t/values/prod.yaml" "main-$main_sha"
run "prod rejects a main-<sha> tag" 1 "prod image.tag 'main-$main_sha' is not a release tag"
values "$t/values/prod.yaml" "v0.116.0"
run "prod rejects a v-prefixed tag" 1 "prod image.tag 'v0.116.0' is not a release tag"
values "$t/values/prod.yaml" "9.9.9"
run "prod dies on a release without a git tag" 1 "prod 9.9.9: commit or tag '9.9.9' not found"
values "$t/values/prod.yaml" "0.116.0"

echo preview > "$base/TRACK"
values "$t/values/preview.yaml" "0.116.0"
run "preview rejects a release tag" 1 "preview image.tag '0.116.0' does not name a main commit"
values "$t/values/preview.yaml" "main-$main_sha"

# PIN wins over either track and names the commit directly.
echo "$release_sha" > "$base/PIN"
run "PIN overrides the track" 0 "source: PIN -> $release_sha"
rm -f "$base/PIN"

# Nothing to do: the installed commit and prompt already match the target.
echo "${main_sha:0:7}" > "$base/VERSION"
git -C "$base/src" show "$main_sha:deploy/agent-worker/system-prompt.txt" > "$base/system-prompt.txt"
run "no-op run is silent" 0 ""
out=$(cd "$t" && PATH="$t/bin:$PATH" AGENT_WORKER_BASE="$base" AGENT_WORKER_GO="$t/bin/go" \
  FAKE_VALUES_DIR="$t/values" bash "$script" --dry-run 2>&1)
if [ -n "$out" ]; then echo "FAIL no-op run printed: $out"; fails=$((fails + 1)); fi

# The self-replacement guard: a copy of the script without the TRACK marker
# is never installed, one with it is. The guard reads the staged file.
guard_ok=1
grep -q "predates TRACK support" "$script" || guard_ok=0
grep -q 'grep -q "TRACK"' "$script" || guard_ok=0
if [ "$guard_ok" = 1 ]; then echo "ok   self-replacement guard checks the TRACK marker"; else echo "FAIL self-replacement guard missing"; fails=$((fails + 1)); fi

[ "$fails" = 0 ] || { echo "$fails failure(s)"; exit 1; }
echo "all self-update tests passed"
