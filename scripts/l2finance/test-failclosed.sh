#!/usr/bin/env bash
# Regression: a failed rerun in a reused directory must never expose old PASS
# summaries or old tuple files. No network or finance credentials are used.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$(mktemp -d)"
MARKER="$(mktemp "$ROOT/.l2finance-failclosed-XXXXXX")"
trap 'rm -f "$MARKER"; rm -rf "$OUT"' EXIT

# Simulate a previous successful run with stale evidence.
printf 'FINANCE_SECURITY_GATE=PASS\n- harness_status: `COMPLETE`\n' >"$OUT/summary.md"
printf 'old-reproducible-tuple\n' >"$OUT/tuples1.tsv"
printf 'old-reproducible-tuple\n' >"$OUT/tuples2.tsv"
printf 'PASS\n' >"$OUT/gate1.status"

# The temporary untracked marker makes the git worktree dirty. The next run
# must fail in preflight, before opening a network connection or running tests.
set +e
bash "$ROOT/scripts/l2finance/run.sh" "$OUT" >"$OUT/runner.stdout" 2>"$OUT/runner.stderr"
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  echo 'failclosed regression: runner accepted dirty worktree' >&2
  exit 1
fi

grep -q '^FINANCE_SECURITY_GATE=BLOCKED$' "$OUT/summary.md"
grep -q 'harness_status: `INVALID`' "$OUT/summary.md"
grep -q '^FINANCE_SECURITY_GATE=BLOCKED$' "$OUT/status.txt"
grep -q '^harness_status=INVALID$' "$OUT/status.txt"
test ! -e "$OUT/tuples1.tsv"
test ! -e "$OUT/tuples2.tsv"
test ! -e "$OUT/gate1.status"
! grep -q '^FINANCE_SECURITY_GATE=PASS$' "$OUT/summary.md"

echo 'failclosed reused-output regression: PASS (blocked sentinel preserved)'
