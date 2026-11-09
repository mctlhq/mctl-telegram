//go:build l2finance

package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

const unitRev = "0123456789abcdef0123456789abcdef01234567"

type synthRow struct{ pkg, id, outcome, rev, fixture string }

func okRow(pkg, id, outcome string) synthRow {
	return synthRow{pkg, id, outcome, unitRev, "L2SYNTH-" + id}
}

func stream(extra []string, rows ...synthRow) string {
	var b strings.Builder
	emit := func(pkg, out string) {
		j, _ := json.Marshal(map[string]string{"Action": "output", "Package": "m/internal/" + pkg, "Output": out})
		b.Write(j)
		b.WriteString("\n")
	}
	for _, r := range rows {
		emit(r.pkg, fmt.Sprintf("    x_test.go:1: L2RESULT id=%s outcome=%s rev=%s evidence=fixture_id=%s e\n", r.id, r.outcome, r.rev, r.fixture))
	}
	for _, e := range extra {
		emit("policy", e)
	}
	return b.String()
}

func unitManifest(t *testing.T) []manifestRow {
	m, err := parseManifest(strings.NewReader(
		"policy:T1 case synthetic\nlistener:M1 control synthetic\nlistener:OFFLINE.default_paths offline synthetic\n"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func allPass() []synthRow {
	return []synthRow{okRow("policy", "T1", outPass), okRow("listener", "M1", outPass), okRow("listener", "OFFLINE.default_paths", outPass)}
}

func eval(t *testing.T, s string) result {
	return evaluate(unitManifest(t), strings.NewReader(s), unitRev)
}

func wantInvalid(t *testing.T, r result, issue string) {
	t.Helper()
	if r.Harness != harnessInvalid || r.Gate != gateBlocked || r.Issue != issue {
		t.Fatalf("got %s/%s/%s (%v), want INVALID/BLOCKED/%s", r.Harness, r.Gate, r.Issue, r.Problems, issue)
	}
}

func TestGateMissingRow(t *testing.T) {
	wantInvalid(t, eval(t, stream(nil, allPass()[:2]...)), issueIncomp)
}

func TestGateMissingEmitterMarker(t *testing.T) {
	m, _ := parseManifest(strings.NewReader("policy:T1 case synthetic\npolicy:T2 case synthetic MISSING\n"))
	r := evaluate(m, strings.NewReader(stream(nil, okRow("policy", "T1", outPass))), unitRev)
	wantInvalid(t, r, issueIncomp)
}

func TestGateDuplicate(t *testing.T) {
	rows := append(allPass(), okRow("policy", "T1", outPass))
	wantInvalid(t, eval(t, stream(nil, rows...)), issueIncomp)
}

func TestGateUnknownRow(t *testing.T) {
	rows := append(allPass(), okRow("policy", "T99", outPass))
	wantInvalid(t, eval(t, stream(nil, rows...)), issueIncomp)
}

func TestGateUnclassifiedToken(t *testing.T) {
	bad := fmt.Sprintf("    x_test.go:1: L2RESULT id=T1 outcome=PASS (detected) rev=%s evidence=x\n", unitRev)
	wantInvalid(t, eval(t, stream([]string{bad}, allPass()[1:]...)), issueIncomp)
	unk := fmt.Sprintf("    x_test.go:1: L2RESULT id=T1 outcome=MAYBE rev=%s evidence=x\n", unitRev)
	wantInvalid(t, eval(t, stream([]string{unk}, allPass()[1:]...)), issueIncomp)
}

func TestGateWrongRev(t *testing.T) {
	rows := allPass()
	rows[0].rev = "248db4f"
	r := eval(t, stream([]string{"    x_test.go:1: L2RESULT id=T1 outcome=PASS rev=248db4f evidence=x\n"}, rows[1:]...))
	wantInvalid(t, r, issueIncomp)
	rows = allPass()
	rows[0].rev = strings.Repeat("a", 40)
	wantInvalid(t, eval(t, stream(nil, rows...)), issueIncomp)
}

func TestGateBadPinnedRev(t *testing.T) {
	r := evaluate(unitManifest(t), strings.NewReader(stream(nil, allPass()...)), "abc")
	wantInvalid(t, r, issueCannotOb)
}

func TestGateControlOrOfflineNotPass(t *testing.T) {
	for i := 1; i <= 2; i++ {
		rows := allPass()
		rows[i].outcome = outFailGap
		wantInvalid(t, eval(t, stream(nil, rows...)), issueIncomp)
	}
}

func TestGateFixtureMismatch(t *testing.T) {
	rows := allPass()
	rows[0].fixture = "other"
	wantInvalid(t, eval(t, stream(nil, rows...)), issueIncomp)
}

func TestGateGapIsCompleteButBlocked(t *testing.T) {
	rows := allPass()
	rows[0].outcome = outFailGap
	r := eval(t, stream(nil, rows...))
	if r.Harness != harnessComplete || r.Gate != gateBlocked || r.Issue != issueGaps {
		t.Fatalf("got %s/%s/%s (%v)", r.Harness, r.Gate, r.Issue, r.Problems)
	}
	if !strings.HasPrefix(r.markdown(), "FINANCE_SECURITY_GATE=BLOCKED") || !strings.HasSuffix(r.statusLines(), "FINANCE_SECURITY_GATE=BLOCKED\n") {
		t.Fatal("blocked gate not visible")
	}
}

func TestGateAllPass(t *testing.T) {
	r := eval(t, stream(nil, allPass()...))
	if r.Harness != harnessComplete || r.Gate != gatePass || r.Issue != issuePass {
		t.Fatalf("got %s/%s/%s (%v)", r.Harness, r.Gate, r.Issue, r.Problems)
	}
}

func TestGateCannotObserve(t *testing.T) {
	wantInvalid(t, eval(t, ""), issueCannotOb)
	wantInvalid(t, eval(t, "not json\n"), issueCannotOb)
	build := stream([]string{"FAIL\tm/internal/policy [build failed]\n"})
	wantInvalid(t, eval(t, build), issueCannotOb)
}

func TestGatePackageFail(t *testing.T) {
	s := stream(nil, allPass()...) + `{"Action":"fail","Package":"m/internal/policy"}` + "\n"
	wantInvalid(t, eval(t, s), issueIncomp)
}

func TestGateManifestParse(t *testing.T) {
	for _, bad := range []string{"policy:T1 bogus synthetic\n", "policy:T1 case\n", "nocolon case synthetic\n", "a:b case synthetic\na:b case synthetic\n"} {
		if _, err := parseManifest(strings.NewReader(bad)); err == nil {
			t.Fatalf("manifest %q accepted", bad)
		}
	}
}

// TestGateCanonicalCrosswalk pins the source-derived #1244 coverage so an
// emitter and its manifest row cannot both disappear unnoticed on a rerun.
// The manifest itself contains the complete source-to-layer mapping.
func TestGateCanonicalCrosswalk(t *testing.T) {
	f, err := os.Open("testdata/manifest.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := parseManifest(f)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]manifestRow{}
	for _, r := range m {
		got[r.Key] = r
	}
	mandatory := []string{
		"listener:T1.listener_status",
		"listener:T1.finance_command",
		"control:T1.notifier_self_only",
		"listener:T2.bob_dm",
		"agentapi:T2.bob_job_owner_summary",
		"agentapi:T2.ordinary_owner_routing",
		"agentapi:T2.finance_origin_authorization",
		"agentapi:T3.finance_source_consent",
		"listener:T4.forwarded",
		"listener:T5.1.push_then_history",
		"listener:T6.reconnect_replay",
		"policy:T7.2",
		"agentapi:T7.3.omit_job_id",
		"control:T8.revoked_after_queue",
		"agentapi:T9.finance_tier",
		"agentapi:T10.redaction_slog",
		"agentapi:T10.intent_channel",
		"listener:M1",
		"control:M2",
		"control:M3",
		"agentapi:M4",
	}
	for _, key := range mandatory {
		if row, ok := got[key]; !ok || row.Missing {
			t.Errorf("mandatory #1244 crosswalk row missing or has no emitter: %s", key)
		}
	}
	if len(got) != 64 {
		t.Errorf("canonical #1244 manifest rows = %d, want reviewed 64", len(got))
	}
}
