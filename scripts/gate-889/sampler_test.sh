#!/usr/bin/env bash
# Offline test of sampler.sh against a fake kubectl: proves it both ways, green on
# a converged cluster and red on each failure it exists to surface. Touches no
# cluster and no database.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/bin"
cat >"$ROOT/bin/kubectl" <<'FAKE'
#!/usr/bin/env bash
# Behaviour comes from files in $FAKE: fail.<word> makes any call containing that
# word fail; the rest are canned, synthetic responses.
args="$*"
for f in "$FAKE"/fail.*; do
  [ -e "$f" ] || continue
  w=${f##*/fail.}
  case "$args" in *"$w"*) echo "fake failure: $w" >&2; exit 1 ;; esac
done
stdin_seen=""
case "$args" in
*" exec "*)
  stdin_seen=$(cat)
  case "$stdin_seen" in
  *end_of_reasons*) cat "$FAKE/reasons"; echo end_of_reasons ;;
  *c3a_dead_letter*) cat "$FAKE/detectors" ;;
  *) cat "$FAKE/counts" ;;
  esac
  ;;
*"get pods"*) printf 'labs-mctl-telegram-preview-x %s <none> %s\nlabs-agent-worker-managed-preview-y 0 <none> digest-w\nunrelated-z 0 <none> digest-o\n' "$(cat "$FAKE/restarts")" "$(cat "$FAKE/image")" | sed "s/preview-x/preview-$(cat "$FAKE/podsuffix")/" ;;
*"top pod"*) printf 'labs-mctl-telegram-preview-x 1m 10Mi\nlabs-agent-worker-managed-preview-y 1m 10Mi\n' ;;
*"get deploy"*) cat "$FAKE/template" ;;
*" logs "*) echo "2030-06-15T00:00:00Z synthetic log line since=${args##*--since-time=}" ;;
esac
FAKE
chmod +x "$ROOT/bin/kubectl"

export FAKE="$ROOT/fake"
export PATH="$ROOT/bin:$PATH"
export GATE889_WS=2030-06-15T00:00:00Z GATE889_WE=2030-06-18T00:00:00Z

fails=0
check() { # check NAME got want
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2' want '$3'"; fails=$((fails + 1)); fi
}

fresh() {
  rm -rf "$FAKE" "$ROOT/evidence"
  mkdir -p "$FAKE"
  export GATE889_DIR="$ROOT/evidence"
  echo 0 >"$FAKE/restarts"
  echo digest-s >"$FAKE/image"
  echo x >"$FAKE/podsuffix"
  echo template-a >"$FAKE/template"
  : >"$FAKE/reasons"
  printf 'max_job_id 1\nlistening_with_send_enabled 0\n' >"$FAKE/counts"
  printf 'c3a_dead_letter 0 green\n' >"$FAKE/detectors"
  "$HERE/sampler.sh" pin >/dev/null
}

last_sample() { ls "$GATE889_DIR/samples" | tail -1 | sed "s#^#$GATE889_DIR/samples/#"; }
alerts() { cat "$GATE889_DIR/alerts.log" 2>/dev/null; }

fresh
"$HERE/sampler.sh" once; check "converged: exit 0" "$?" 0
check "converged: no alerts" "$(alerts)" ""
check "converged: no errors" "$(grep -c COLLECT_ERROR "$(last_sample)")" 0
check "converged: unrelated pod not sampled" "$(grep -c unrelated "$(last_sample)")" 0
check "logs saved" "$(grep -c synthetic "$GATE889_DIR/logs/labs-mctl-telegram-preview-x.log")" 1

for word in 'get pods' 'top pod' ' exec ' 'get deploy' ' logs '; do
  fresh
  "$HERE/sampler.sh" once >/dev/null; rc=$?
  : >"$FAKE/fail.$word"
  "$HERE/sampler.sh" once >/dev/null; rc=$?
  check "failed read [$word]: exit 1" "$rc" 1
  check "failed read [$word]: recorded" "$(grep -c COLLECT_ERROR "$(last_sample)" | awk '$1>0{print "yes"}')" yes
done

fresh; : >"$FAKE/counts"
"$HERE/sampler.sh" once >/dev/null; check "empty db answer is an error, not zero" "$?" 1

fresh; echo digest-new >"$FAKE/image"
"$HERE/sampler.sh" once >/dev/null; check "image change alerts" "$(alerts | grep -c IMAGE_CHANGED)" 1

fresh; echo template-b >"$FAKE/template"
"$HERE/sampler.sh" once >/dev/null; check "template change alerts" "$(alerts | grep -c CONFIG_CHANGED)" 1

fresh; "$HERE/sampler.sh" once >/dev/null; echo 1 >"$FAKE/restarts"
"$HERE/sampler.sh" once >/dev/null; check "restart alerts" "$(alerts | grep -c RESTART)" 1
check "restart saves previous logs" "$(ls "$GATE889_DIR/logs" | grep -c previous)" 1

fresh; echo renamed >"$FAKE/podsuffix"
"$HERE/sampler.sh" once >/dev/null; check "replaced pod alerts" "$(alerts | grep -c POD_REPLACED)" 1

# A failed log fetch must keep the cursor, so that the next tick recovers the interval.
fresh; "$HERE/sampler.sh" once >/dev/null; cursor=$(cat "$GATE889_DIR/state/last_ts")
sleep 1; : >"$FAKE/fail. logs "
"$HERE/sampler.sh" once >/dev/null
check "failed log fetch keeps the cursor" "$(cat "$GATE889_DIR/state/last_ts")" "$cursor"
rm "$FAKE/fail. logs "
sleep 1; "$HERE/sampler.sh" once >/dev/null
check "next tick refetches from the kept cursor" "$(tail -1 "$GATE889_DIR/logs/labs-mctl-telegram-preview-x.log" | sed 's/.*since=\([^ ]*\).*/\1/')" "$cursor"
check "successful fetch moves the cursor" "$([ "$(cat "$GATE889_DIR/state/last_ts")" != "$cursor" ] && echo moved)" moved

fresh; printf 'c5_coalesced_turns 1 red\n' >"$FAKE/detectors"
"$HERE/sampler.sh" once >/dev/null; check "c5 below minimum does not alert every tick" "$(alerts | grep -c c5_)" 0

fresh; printf 'max_job_id 1\nlistening_with_send_enabled 1\n' >"$FAKE/counts"
"$HERE/sampler.sh" once >/dev/null; check "send enabled alerts" "$(alerts | grep -c SEND_ENABLED)" 1

fresh; printf 'c3a_dead_letter 1 red\n' >"$FAKE/detectors"
"$HERE/sampler.sh" once >/dev/null; check "red detector alerts" "$(alerts | grep -c c3a_dead_letter)" 1

fresh; printf '7 managed worker_unclaimed\n8 own worker_unclaimed\n' >"$FAKE/reasons"
"$HERE/sampler.sh" once >/dev/null; check "managed worker_unclaimed alerts" "$(alerts | grep -c worker_unclaimed)" 1
check "reasons saved" "$(wc -l <"$GATE889_DIR/route-reasons.log" | tr -d ' ')" 2

fresh; printf '8 own worker_unclaimed\n' >"$FAKE/reasons"
"$HERE/sampler.sh" once >/dev/null; check "own worker_unclaimed is expected" "$(alerts | grep -c worker_unclaimed)" 0

fresh; "$HERE/sampler.sh" once >/dev/null; echo 1 >"$GATE889_DIR/state/last_epoch"
"$HERE/sampler.sh" once >/dev/null; check "gap alerts" "$(alerts | grep -c GAP)" 1

fresh; rm "$GATE889_DIR/state/images.pinned"
"$HERE/sampler.sh" once >/dev/null; check "no pin is an error" "$?" 1

if [ "$fails" -ne 0 ]; then echo "$fails failed"; exit 1; fi
echo "all passed"
