#!/usr/bin/env bash
# Finance Assistant L2 (#1244) slice D runner: one pinned, offline, full-suite
# run of the tagged matrix plus the machine-checked FINANCE_SECURITY_GATE.
#
# Fail-closed: the sentinel result (INVALID / BLOCKED / CANNOT_OBSERVE_BLOCKED)
# is written before any test and replaced only after every step succeeded.
# Exit 0 does NOT mean FINANCE_SECURITY_GATE=PASS; read the status lines.
#
# Usage: scripts/l2finance/run.sh [outdir]
# Run `go mod download` yourself first (explicit preflight, needs network).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 2
# Capture original dirtiness before creating the output directory, which may
# be a fresh untracked directory inside the worktree for a relative argument.
# Recheck tracked files just before tests, so generated output is the only
# newly accepted untracked path.
PREFLIGHT_TREE_STATUS="$(git status --porcelain 2>/dev/null || printf 'git-status-failed\\n')"
OUT="${1:-${L2FINANCE_OUT:-$(mktemp -d)}}"
mkdir -p "$OUT" || exit 2
# Gate test binaries run from package directories, not the repo root. Always
# supply them an absolute path for the results JSON and summary artifacts.
OUT="$(cd "$OUT" && pwd -P)" || exit 2
# No previous run may influence the next one. In particular a stale summary
# must never mask a failed preflight, and stale tuples must not satisfy cmp.
rm -f "$OUT"/summary*.md "$OUT"/tuples*.tsv "$OUT"/gate*.log \
      "$OUT"/gate*.status "$OUT"/results*.json "$OUT"/results*.err \
      "$OUT"/preflight.err "$OUT"/vet.log "$OUT"/untagged.log \
      "$OUT"/lint.log "$OUT"/status.md "$OUT"/status.txt || exit 2

PKGS=(./internal/agent/policy/ ./internal/agent/listener/ ./internal/agent/control/ ./internal/agentapi/ ./internal/telegram/)
HARNESS=INVALID
GATE=BLOCKED
ISSUE=CANNOT_OBSERVE_BLOCKED
FINAL_RC=2
REV=""
GATE_UNIT_RC="not-run" VET_RC="not-run" UNTAGGED_RC="not-run" LINT="not-run" REPRO="not-run" RUN1_RC="not-run" RUN2_RC="not-run"
FINALIZED=0

write_sentinel() {
	{
		echo "FINANCE_SECURITY_GATE=$GATE"
		echo
		echo "- harness_status: \`$HARNESS\`"
		echo "- issue_outcome: \`$ISSUE\`"
		echo "- source revision: \`${REV:-unknown}\`"
		echo "- go: \`$(go version 2>/dev/null || echo unknown)\`"
		echo "- tagged run 1 exit: \`$RUN1_RC\`; tagged run 2 exit: \`$RUN2_RC\`"
		echo "- go vet -tags l2finance exit: \`$VET_RC\`"
		echo "- gate aggregator unit tests exit: \`$GATE_UNIT_RC\`"
		echo "- untagged go test -race exit: \`$UNTAGGED_RC\`"
		echo "- golangci-lint: \`$LINT\`"
		echo "- reproducibility (two tagged runs): \`$REPRO\`"
		echo "- offline scope: default resolver and http.DefaultTransport guards only; OFFLINE.whole_process stays CANNOT-OBSERVE"
		echo "- RESEARCH_ONLY_DEFER (mctlhq/.github#325) unchanged"
	} >"$OUT/status.md"
	{
		echo "issue_outcome=$ISSUE"
		echo "harness_status=$HARNESS"
		echo "FINANCE_SECURITY_GATE=$GATE"
	} >"$OUT/status.txt"
	# The summary is the artifact CI publishes on failure, including when a
	# previous run in this directory completed successfully.
	cp "$OUT/status.md" "$OUT/summary.md"
}

finalize() {
	local rc=$?
	[ "$FINALIZED" = 1 ] && return
	FINALIZED=1
	# Persist fail-closed status on *every* abnormal exit, including a signal
	# after a success-path summary was assembled. Never publish a stale PASS.
	if [ "$rc" != 0 ] && { [ "$FINAL_RC" = 0 ] || [ "$FINAL_RC" = 2 ]; }; then
		FINAL_RC=$rc
	fi
	if [ "$FINAL_RC" != 0 ]; then
		HARNESS=INVALID GATE=BLOCKED
		case "$ISSUE" in
			COMPLETE_WITH_PASS|COMPLETE_WITH_GAPS_BLOCKED) ISSUE=CANNOT_OBSERVE_BLOCKED ;;
		esac
		write_sentinel || FINAL_RC=2
	elif [ ! -s "$OUT/summary.md" ]; then
		HARNESS=INVALID GATE=BLOCKED ISSUE=CANNOT_OBSERVE_BLOCKED FINAL_RC=2
		write_sentinel || FINAL_RC=2
	fi
	cat "$OUT/status.txt" 2>/dev/null
	exit "$FINAL_RC"
}
trap finalize EXIT
trap 'exit 130' INT TERM
write_sentinel

fail() { # fail <issue> <message>
	ISSUE=$1
	echo "l2finance: $2" >&2
	write_sentinel
	FINAL_RC=1
	exit 1
}

# Preflight: clean tree, pinned revision, no credentials, offline go env.
git rev-parse HEAD >/dev/null 2>&1 || fail CANNOT_OBSERVE_BLOCKED "not a git work tree"
REV="$(git rev-parse HEAD)"
[[ "$REV" =~ ^[0-9a-f]{40}$ ]] || fail CANNOT_OBSERVE_BLOCKED "revision is not 40-hex"
[ -z "$PREFLIGHT_TREE_STATUS" ] && [ -z "$(git status --porcelain --untracked-files=no)" ] || fail CANNOT_OBSERVE_BLOCKED "work tree is not clean; commit first so the pinned sha is the tested code"
command -v go >/dev/null || fail CANNOT_OBSERVE_BLOCKED "go not found"

unset TG_API_ID TG_API_HASH DATABASE_URL GITHUB_TOKEN GH_TOKEN
export L2FINANCE_SOURCE_REV="$REV"
# Resolve the pinned toolchain once, while the environment is still normal
# (toolchain switching verifies through the checksum database), then lock down.
GOROOT_RESOLVED="$(go env GOROOT 2>/dev/null)"
[ -x "$GOROOT_RESOLVED/bin/go" ] || fail CANNOT_OBSERVE_BLOCKED "cannot resolve the Go toolchain"
export PATH="$GOROOT_RESOLVED/bin:$PATH" GOTOOLCHAIN=local
export GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly

# Verify dependencies resolve from the cache with downloads disabled.
go list -deps -tags l2finance "${PKGS[@]}" ./internal/l2finance/gate/ >/dev/null 2>"$OUT/preflight.err" ||
	fail CANNOT_OBSERVE_BLOCKED "dependencies are not cached (run go mod download first): $(head -c 300 "$OUT/preflight.err")"

tagged_run() { # tagged_run <n>
	go test -json -tags l2finance -race -count=1 -run L2Finance "${PKGS[@]}" >"$OUT/results$1.json" 2>"$OUT/results$1.err"
}

tagged_run 1
RUN1_RC=$?
[ -s "$OUT/results1.json" ] || fail CANNOT_OBSERVE_BLOCKED "tagged run 1 produced no JSON stream"
[ "$RUN1_RC" = 0 ] || { ISSUE=INCOMPLETE_BLOCKED; echo "l2finance: tagged run 1 exited $RUN1_RC" >&2; }

go vet -tags l2finance "${PKGS[@]}" ./internal/l2finance/gate/ >"$OUT/vet.log" 2>&1
VET_RC=$?

# Run the aggregator's own negative and positive controls, not just the
# integration test TestL2FinanceGate (which is run separately below).
go test -tags l2finance -count=1 -run '^TestGate' ./internal/l2finance/gate/ >"$OUT/gate-unit.log" 2>&1
GATE_UNIT_RC=$?

go test -race -count=1 ./... >"$OUT/untagged.log" 2>&1
UNTAGGED_RC=$?

if command -v golangci-lint >/dev/null 2>&1 && ls .golangci* >/dev/null 2>&1; then
	golangci-lint run ./... >"$OUT/lint.log" 2>&1
	LINT="exit $?"
else
	LINT="not configured"
fi

tagged_run 2
RUN2_RC=$?
[ -s "$OUT/results2.json" ] || fail CANNOT_OBSERVE_BLOCKED "tagged run 2 produced no JSON stream"

gate() { # gate <n>
	L2FINANCE_RESULTS_JSON="$OUT/results$1.json" L2FINANCE_SUMMARY_MD="$OUT/summary$1.md" \
		L2FINANCE_TUPLES="$OUT/tuples$1.tsv" \
		go test -tags l2finance -count=1 -v -run TestL2FinanceGate ./internal/l2finance/gate/ >"$OUT/gate$1.log" 2>&1
}
gate 1
GATE1_RC=$?
gate 2
GATE2_RC=$?

if [ -s "$OUT/tuples1.tsv" ] && cmp -s "$OUT/tuples1.tsv" "$OUT/tuples2.tsv"; then REPRO="identical"; else REPRO="DIFFERENT"; fi

grep -E '^(issue_outcome|harness_status|FINANCE_SECURITY_GATE)=' "$OUT/gate1.log" >"$OUT/gate1.status" || true
ISSUE_G="$(sed -n 's/^issue_outcome=//p' "$OUT/gate1.status")"
HARNESS_G="$(sed -n 's/^harness_status=//p' "$OUT/gate1.status")"
GATE_G="$(sed -n 's/^FINANCE_SECURITY_GATE=//p' "$OUT/gate1.status")"

# Only now may the sentinel be replaced, and only when every step succeeded.
if [ "$RUN1_RC" = 0 ] && [ "$RUN2_RC" = 0 ] && [ "$VET_RC" = 0 ] && [ "$GATE_UNIT_RC" = 0 ] && [ "$UNTAGGED_RC" = 0 ] &&
	[ "$GATE1_RC" = 0 ] && [ "$GATE2_RC" = 0 ] && [ "$REPRO" = identical ] &&
	[ "$HARNESS_G" = COMPLETE ] && [ -n "$ISSUE_G" ] && [ -n "$GATE_G" ]; then
	HARNESS=$HARNESS_G GATE=$GATE_G ISSUE=$ISSUE_G
	write_sentinel
	{ cat "$OUT/summary1.md"; echo; echo "## Run status"; echo; tail -n +3 "$OUT/status.md"; } >"$OUT/summary.md"
	FINAL_RC=0
else
	[ "$ISSUE" = CANNOT_OBSERVE_BLOCKED ] && ISSUE=INCOMPLETE_BLOCKED
	write_sentinel
	FINAL_RC=1
fi
exit "$FINAL_RC"
