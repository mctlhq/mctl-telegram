#!/bin/bash
# Keep the off-cluster agent worker on the same commit as tg-preview.
#
# Runs on the worker host itself (launchd, see install.sh). Each run reads the
# image tag tg-preview runs from mctl-gitops (public, no token), and when it
# names a commit other than the installed one, builds cmd/agent-worker at that
# commit, installs the binary and deploy/agent-worker/system-prompt.txt from
# the same commit, restarts the worker and checks /readyz. A failed check
# rolls both files back. A prompt edited by hand on the host is put back to
# the commit's version on the next run.
#
# Hold or roll back: write a commit into $BASE/PIN and the timer installs
# that commit instead of tg-preview's; delete the file to follow tg-preview
# again. A commit that fails its readiness check is recorded in $BASE/FAILED
# and skipped until the target changes.
#
# Usage: self-update.sh [--dry-run]
set -euo pipefail

BASE="${AGENT_WORKER_BASE:-$HOME/agent-worker}"
SRC="$BASE/src"
REPO_URL="https://github.com/mctlhq/mctl-telegram.git"
VALUES_URL="https://raw.githubusercontent.com/mctlhq/mctl-gitops/main/platform-gitops/services/labs/mctl-telegram-preview/values.yaml"
LABEL="com.mctl.agent-worker"
READY_URL="http://127.0.0.1:18090/readyz"
PROMPT_PATH="deploy/agent-worker/system-prompt.txt"
SELF_PATH="deploy/agent-worker/mac-mini/self-update.sh"
GO="${AGENT_WORKER_GO:-$HOME/.local/go/bin/go}"

dry_run=0
[ "${1:-}" = "--dry-run" ] && dry_run=1

log() { printf '%s [self-update] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

# The lock records its owner. A run killed before its EXIT trap (reboot,
# SIGKILL, power loss) leaves the lock behind; a lock whose owner is gone, or
# one older than an hour, is reclaimed instead of blocking updates for good.
lock="$BASE/.update.lock"
if ! mkdir "$lock" 2>/dev/null; then
  owner="$(cat "$lock/pid" 2>/dev/null || true)"
  # An empty owner is a run between its mkdir and its pid write: live
  # unless the lock is more than a minute old.
  if { [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null &&
    [ -z "$(find "$lock" -maxdepth 0 -mmin +60 2>/dev/null)" ]; } ||
    { [ -z "$owner" ] && [ -z "$(find "$lock" -maxdepth 0 -mmin +1 2>/dev/null)" ]; }; then
    log "run $owner holds $lock; skipping"
    exit 0
  fi
  log "reclaiming stale lock (owner ${owner:-unknown})"
  rm -rf "$lock"
  mkdir "$lock" || die "cannot take $lock"
fi
echo $$ > "$lock/pid"
work=""
cleanup() {
  rm -rf "$lock"
  if [ -n "$work" ]; then rm -rf "$work"; fi
}
trap cleanup EXIT

# Resolve the target. A failed or unparsable read is an error, never "no
# change": the worker is left exactly as it is.
if [ -s "$BASE/PIN" ]; then
  want="$(tr -d '[:space:]' < "$BASE/PIN")"
  source_desc="PIN"
else
  values="$(curl -fsS --max-time 30 "$VALUES_URL")" || die "cannot read tg-preview values from mctl-gitops"
  tag="$(awk '/^image:/{f=1;next} f&&/^[^ ]/{f=0} f&&/^  tag:/{gsub(/"/,"",$2);print $2;exit}' <<<"$values")"
  case "$tag" in
    main-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) want="${tag#main-}" ;;
    *) die "tg-preview image.tag '$tag' does not name a main commit" ;;
  esac
  source_desc="tg-preview $tag"
fi

if [ ! -d "$SRC/.git" ]; then
  git clone -q --no-checkout "$REPO_URL" "$SRC" || die "clone failed"
fi
git -C "$SRC" fetch -q origin || die "fetch failed"
full="$(git -C "$SRC" rev-parse --verify -q "$want^{commit}")" || die "commit $want ($source_desc) not found"
short="${full:0:7}"

new_prompt="$(git -C "$SRC" show "$full:$PROMPT_PATH")" || die "no $PROMPT_PATH at $short"
[ -n "$new_prompt" ] || die "empty $PROMPT_PATH at $short"
want_prompt_sha="$(printf '%s\n' "$new_prompt" | shasum -a 256 | cut -d' ' -f1)"
have_version="$(cat "$BASE/VERSION" 2>/dev/null || true)"
have_prompt_sha="$(shasum -a 256 "$BASE/system-prompt.txt" 2>/dev/null | cut -d' ' -f1 || true)"

if [ "$have_version" = "$short" ] && [ "$have_prompt_sha" = "$want_prompt_sha" ]; then
  exit 0
fi
# A commit that already failed its readiness check is not retried until the
# target changes; otherwise every run would bounce the worker through the same
# failed install and rollback.
if [ "$(cat "$BASE/FAILED" 2>/dev/null || true)" = "$short" ]; then
  log "target $short failed before; staying on ${have_version:-none} until the target changes (rm $BASE/FAILED to retry)"
  exit 1
fi
log "target $short ($source_desc); installed ${have_version:-none}, prompt ${have_prompt_sha:0:12} -> ${want_prompt_sha:0:12}"

work="$(mktemp -d "${TMPDIR:-/tmp}/agent-worker-build.XXXXXX")"
binary="$BASE/agent-worker"
if [ "$have_version" != "$short" ]; then
  mkdir "$work/src"
  git -C "$SRC" archive "$full" | tar -x -C "$work/src"
  (cd "$work/src" && CGO_ENABLED=0 GOTOOLCHAIN=auto \
    "$GO" build -trimpath -ldflags "-s -w -X main.version=$short" -o "$work/agent-worker" ./cmd/agent-worker) ||
    die "build of $short failed"
  binary="$work/agent-worker"
  log "built $short $(shasum -a 256 "$binary" | cut -c1-16)"
fi
printf '%s\n' "$new_prompt" > "$work/system-prompt.txt"

if [ "$dry_run" -eq 1 ]; then
  log "dry run: not installing"
  exit 0
fi

cd "$BASE"
cp -p agent-worker agent-worker.prev 2>/dev/null || true
cp -p system-prompt.txt system-prompt.txt.prev 2>/dev/null || true
prev_version="${have_version:-unknown}"
if [ "$binary" != "$BASE/agent-worker" ]; then
  install -m 755 "$binary" agent-worker.new || die "cannot stage the new binary"
  mv agent-worker.new agent-worker || die "cannot install the new binary"
fi
install -m 644 "$work/system-prompt.txt" system-prompt.txt.new || die "cannot stage the new prompt"
mv system-prompt.txt.new system-prompt.txt || die "cannot install the new prompt"

worker_pid() { launchctl list "$LABEL" 2>/dev/null | awk -F' = ' '/"PID"/{gsub(/;/,"",$2);print $2}'; }
ready() { [ "$(curl -s -o /dev/null -w '%{http_code}' "$READY_URL" || true)" = 200 ]; }
# restart replaces the worker process and succeeds only once a process other
# than the one it replaced is ready and still the same process 30s later. A
# 200 from the old process while it shuts down, or a new one that crashes
# during its first long-poll claim, is a failure.
restart() {
  local old new
  old="$(worker_pid)"
  launchctl kickstart -k "gui/$(id -u)/$LABEL" || return 1
  for _ in $(seq 1 24); do
    sleep 5
    new="$(worker_pid)"
    if [ -n "$new" ] && [ "$new" != "$old" ] && ready; then
      sleep 30
      [ "$(worker_pid)" = "$new" ] && ready && return 0
      return 1
    fi
  done
  return 1
}

if restart; then
  rm -f "$BASE/FAILED"
  echo "$short" > VERSION
  log "ready on $short (previous $prev_version), prompt sha256 $want_prompt_sha"
  # Take this script from the same commit for the next run, if it parses.
  # Not while pinned: an older commit's script may not know about PIN.
  if [ ! -s "$BASE/PIN" ] && new_self="$(git -C "$SRC" show "$full:$SELF_PATH" 2>/dev/null)" && [ -n "$new_self" ]; then
    printf '%s\n' "$new_self" > "$BASE/self-update.sh.new"
    if bash -n "$BASE/self-update.sh.new"; then
      chmod 755 "$BASE/self-update.sh.new"
      mv "$BASE/self-update.sh.new" "$BASE/self-update.sh"
    else
      rm -f "$BASE/self-update.sh.new"
      log "self-update.sh at $short does not parse; keeping the current one"
    fi
  fi
  exit 0
fi

log "not ready on $short; rolling back to $prev_version"
echo "$short" > "$BASE/FAILED"
tail -5 "$HOME/Library/Logs/$LABEL.log" 2>/dev/null || true
[ -f agent-worker.prev ] && mv agent-worker.prev agent-worker
[ -f system-prompt.txt.prev ] && mv system-prompt.txt.prev system-prompt.txt
if restart; then
  log "rolled back; ready on $prev_version"
else
  log "ERROR: rollback to $prev_version is not ready either"
fi
exit 1
