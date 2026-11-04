#!/usr/bin/env bash
# Read-only evidence sampler for the Part B soak of mctlhq/mctl-telegram#889.
# See scripts/gate-889/README.md.
#
#   sampler.sh pin    record the image digests and pod templates under test
#   sampler.sh once   take one sample; exit 0 only if every collector succeeded
#   sampler.sh loop   sample every GATE889_INTERVAL seconds until killed
#
# Environment: GATE889_DIR (evidence directory, outside any repository),
# GATE889_WS and GATE889_WE (window, RFC 3339), KUBECONFIG.
#
# A collector that fails or returns nothing is recorded as COLLECT_ERROR. It is
# never recorded as zero or clean: "could not observe" is not "observed absent".
set -u -o pipefail
umask 077

DIR=${GATE889_DIR:?GATE889_DIR must be set}
WS=${GATE889_WS:?GATE889_WS must be set}
WE=${GATE889_WE:?GATE889_WE must be set}
INTERVAL=${GATE889_INTERVAL:-300}
MAX_GAP=${GATE889_MAX_GAP:-900}
HERE=$(cd "$(dirname "$0")" && pwd)
NS=labs
PODS='agent-worker-managed-preview|mctl-telegram-preview'
DEPLOYS='labs-agent-worker-managed-preview-base-service labs-mctl-telegram-preview-base-service'
PG_NS=platform-db
PG_POD=shared-pg-1
PG_DB=labs-mctl-telegram-preview

mkdir -p "$DIR/samples" "$DIR/logs" "$DIR/state"
SAMPLE=/dev/null
ERRORS=0

alert() {
  printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$DIR/alerts.log"
  printf 'ALERT %s\n' "$*" >>"$SAMPLE"
}

collect_error() {
  ERRORS=$((ERRORS + 1))
  printf 'COLLECT_ERROR %s\n' "$*" >>"$SAMPLE"
  printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$DIR/errors.log"
}

# collect NAME CMD...: record CMD's stdout under NAME. A non-zero exit or empty
# output is a collection error, and the partial output is kept under a marker.
collect() {
  local name=$1 out rc
  shift
  out=$("$@" 2>"$DIR/state/stderr")
  rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$out" ]; then
    collect_error "$name rc=$rc empty=$([ -z "$out" ] && echo yes || echo no) stderr=$(head -c 300 "$DIR/state/stderr" | tr '\n' ' ')"
    [ -n "$out" ] && printf '%s\n' "$out" | sed "s/^/PARTIAL $name /" >>"$SAMPLE"
    return 1
  fi
  printf '%s\n' "$out" | sed "s/^/$name /" >>"$SAMPLE"
}

psql_ro() {
  { printf 'begin read only;\n'; cat; printf 'rollback;\n'; } |
    kubectl -n "$PG_NS" exec -i "$PG_POD" -c postgres -- \
      psql -U postgres -d "$PG_DB" -X -q -A -t -F ' ' -v ON_ERROR_STOP=1 -v "ws=$WS" -v "we=$WE"
}

pod_lines() {
  kubectl -n "$NS" get pods --no-headers \
    -o 'custom-columns=N:.metadata.name,R:.status.containerStatuses[0].restartCount,T:.status.containerStatuses[0].lastState.terminated.reason,I:.status.containerStatuses[0].imageID' |
    grep -E "$PODS"
}

top_lines() { kubectl -n "$NS" top pod --no-headers | grep -E "$PODS"; }

db_counts() {
  psql_ro <<'SQL'
select 'max_job_id', coalesce(max(id),0) from agent_jobs;
select 'window_jobs', status, count(*) from agent_jobs where created_at >= :'ws'::timestamptz and created_at < :'we'::timestamptz group by 2 order by 2;
select 'processing_past_5m', count(*) from agent_jobs where status='processing' and claimed_at < now()-interval '5 minutes';
select 'usage_not_settled', count(*) from agent_usage where status<>'settled';
select 'managed_month_durable_usd', coalesce(round(sum(coalesce(cost_usd,reserved_usd))::numeric,4),0) from agent_usage where runtime='managed' and created_at >= date_trunc('month', now() at time zone 'utc') at time zone 'utc';
select 'window_notifications', kind, status, count(*) from owner_notifications where created_at >= :'ws'::timestamptz and created_at < :'we'::timestamptz group by 2,3 order by 2,3;
select 'profile', runtime, mode, listener_enabled, autopilot_paused, budget_paused_until is not null, count(*) from agent_profiles where runtime='managed' or listener_enabled group by 2,3,4,5,6 order by 2,3;
select 'listening_with_send_enabled', count(*) from agent_profiles p join telegram_accounts a on a.user_id=p.user_id where p.listener_enabled and a.send_enabled and a.revoked_at is null;
SQL
}

# Reasons live in event_outbox and may not outlast the window, so they are saved
# per job as they appear. A routed job with no outbox row is written as unobserved.
db_route_reasons() {
  psql_ro <<'SQL'
select j.id, j.runtime, coalesce((select e.envelope::jsonb->'subject'->>'routing_reason' from event_outbox e
         where e.event_id=j.event_id and e.envelope::jsonb->'subject'->>'routing_reason' is not null order by e.id limit 1),'unobserved')
  from agent_jobs j where j.status='routed' and j.created_at >= :'ws'::timestamptz and j.created_at < :'we'::timestamptz order by 1;
select 'end_of_reasons';
SQL
}

db_detectors() { psql_ro <"$HERE/criteria.sql"; }

templates() {
  local d t
  for d in $DEPLOYS; do
    t=$(kubectl -n "$NS" get deploy "$d" -o 'jsonpath={.spec.template}') && [ -n "$t" ] || return 1
    printf '%s %s\n' "$d" "$(printf '%s' "$t" | shasum -a 256 | cut -d' ' -f1)"
  done
}

images() { pod_lines | awk '{print $NF}' | sort -u; }

save_logs() {
  local since=$1 pod
  for pod in $(pod_lines | awk '{print $1}'); do
    if ! kubectl -n "$NS" logs "$pod" --timestamps --since-time="$since" >>"$DIR/logs/$pod.log" 2>"$DIR/state/stderr"; then
      collect_error "logs $pod stderr=$(head -c 300 "$DIR/state/stderr" | tr '\n' ' ')"
    fi
  done
}

check_restarts() {
  local pod count prev
  pod_lines | while read -r pod count _; do
    prev=$(cat "$DIR/state/restarts.$pod" 2>/dev/null || echo "$count")
    if [ "$count" != "$prev" ]; then
      echo RESTART "$pod" "$prev" "$count"
      kubectl -n "$NS" logs "$pod" --previous --timestamps >"$DIR/logs/$pod.previous.$count.log" 2>&1 || echo COLLECT_ERROR previous "$pod"
    fi
    echo "$count" >"$DIR/state/restarts.$pod"
  done
}

epoch() { date -u +%s; }

pin() {
  ERRORS=0
  SAMPLE="$DIR/state/pin.out"
  : >"$SAMPLE"
  images >"$DIR/state/images.pinned" && [ -s "$DIR/state/images.pinned" ] || { echo 'cannot read images' >&2; return 1; }
  templates >"$DIR/state/templates.pinned" || { echo 'cannot read templates' >&2; return 1; }
  cat "$DIR/state/images.pinned" "$DIR/state/templates.pinned"
}

once() {
  local now stamp last gap since cur
  now=$(epoch)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  SAMPLE="$DIR/samples/$stamp.txt"
  ERRORS=0
  printf 'ts %s\n' "$(date -u +%FT%TZ)" >"$SAMPLE"

  last=$(cat "$DIR/state/last_epoch" 2>/dev/null || echo "")
  if [ -n "$last" ]; then
    gap=$((now - last))
    printf 'gap_s %s\n' "$gap" >>"$SAMPLE"
    [ "$gap" -gt "$MAX_GAP" ] && alert "GAP ${gap}s exceeds ${MAX_GAP}s"
  fi

  collect pod pod_lines
  collect top top_lines
  collect db db_counts
  collect detector db_detectors

  if cur=$(db_route_reasons 2>"$DIR/state/stderr") && printf '%s\n' "$cur" | grep -q '^end_of_reasons$'; then
    printf '%s\n' "$cur" | grep -v '^end_of_reasons$' >"$DIR/state/reasons.cur" || true
    cat "$DIR/state/reasons.cur" >>"$DIR/route-reasons.log"
    sort -u -o "$DIR/route-reasons.log" "$DIR/route-reasons.log"
    grep -q ' worker_unclaimed$' "$DIR/state/reasons.cur" && grep -v ' own ' "$DIR/state/reasons.cur" | grep -q ' worker_unclaimed$' && alert 'managed job routed as worker_unclaimed'
  else
    collect_error "route_reasons stderr=$(head -c 300 "$DIR/state/stderr" | tr '\n' ' ')"
  fi

  if [ -s "$DIR/state/images.pinned" ]; then
    if cur=$(images) && [ -n "$cur" ]; then
      [ "$cur" = "$(cat "$DIR/state/images.pinned")" ] || alert 'IMAGE_CHANGED: running digests differ from the pin'
    else
      collect_error 'images unreadable'
    fi
    if cur=$(templates) && [ -n "$cur" ]; then
      [ "$cur" = "$(cat "$DIR/state/templates.pinned")" ] || alert 'CONFIG_CHANGED: pod template differs from the pin'
    else
      collect_error 'templates unreadable'
    fi
  else
    collect_error 'no pin: run sampler.sh pin first'
  fi

  cur=$(check_restarts) || collect_error 'restarts unreadable'
  case "$cur" in *COLLECT_ERROR*) collect_error 'previous logs unreadable' ;; esac
  [ -n "$cur" ] && while read -r line; do alert "$line"; done <<<"$cur"

  since=$(cat "$DIR/state/last_ts" 2>/dev/null || echo "$WS")
  save_logs "$since"
  date -u +%FT%TZ >"$DIR/state/last_ts"

  grep -E '^detector c[0-9a-z_]+ .* red$' "$SAMPLE" | while read -r line; do printf '%s %s\n' "$(date -u +%FT%TZ)" "$line" >>"$DIR/alerts.log"; done
  grep -E '^db listening_with_send_enabled [1-9]' "$SAMPLE" >/dev/null && alert 'SEND_ENABLED on a listening account'

  printf '%s\n' "$now" >"$DIR/state/last_epoch"
  printf '%s errors=%s\n' "$stamp" "$ERRORS" >>"$DIR/ticks.log"
  [ "$ERRORS" -eq 0 ]
}

case "${1:-}" in
pin) pin ;;
once) once ;;
loop)
  while :; do
    once
    sleep "$INTERVAL"
  done
  ;;
*)
  echo "usage: $0 pin|once|loop" >&2
  exit 2
  ;;
esac
