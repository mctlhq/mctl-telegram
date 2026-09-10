package mcpprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// TestReportCarriesNoOpenEndedFields is the structural half of the redaction
// guarantee. Redaction here is meant to be a property of the type rather
// than a discipline applied at each call site, and that only holds while no
// field of Report can hold an arbitrary server-chosen value. This walk fails
// the moment someone adds one, which is the point: the guarantee should be
// broken by a compiler-visible change, not by a code review that missed it.
func TestReportCarriesNoOpenEndedFields(t *testing.T) {
	forbidden := map[string]string{
		"interface {}":            "an interface can hold anything the server sent",
		"map[string]interface {}": "a free-form map can hold anything the server sent",
		"[]uint8":                 "a byte slice can hold a raw response body",
		"json.RawMessage":         "raw JSON can hold a whole tool result",
	}
	seen := map[reflect.Type]bool{}
	var walk func(t *testing.T, typ reflect.Type, path string)
	walk = func(t *testing.T, typ reflect.Type, path string) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		if why, bad := forbidden[typ.String()]; bad {
			t.Errorf("%s is %s: %s", path, typ, why)
			return
		}
		switch typ.Kind() {
		case reflect.Ptr, reflect.Slice, reflect.Array:
			walk(t, typ.Elem(), path+"[]")
		case reflect.Map:
			walk(t, typ.Key(), path+".key")
			walk(t, typ.Elem(), path+".value")
		case reflect.Interface:
			t.Errorf("%s is an interface and can hold anything the server sent", path)
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				walk(t, f.Type, path+"."+f.Name)
			}
		}
	}
	walk(t, reflect.TypeOf(Report{}), "Report")
}

// TestReport_OmitsSensitiveValuesEndToEnd is T6. It drives a full run against
// a server whose responses are stuffed with exactly the values that must
// never be republished, then asserts that neither the serialized report nor
// its logged form contains any of them.
func TestReport_OmitsSensitiveValuesEndToEnd(t *testing.T) {
	const (
		bearer      = "probe-bearer-token-do-not-log"
		messageBody = "the quick brown fox said something private"
		chatTitle   = "Alice and Bob planning"
		peerID      = "778899001122"
		authCode    = "authcode-abcdefghijklmnop"
	)

	_, url := newFake(t, func(f *fakeServer) {
		f.modern = true
		f.mintSession = true
		f.callPayload = map[string]any{
			"isError": false,
			"content": []map[string]any{
				{"type": "text", "text": messageBody},
				{"type": "text", "text": chatTitle},
			},
			"structuredContent": map[string]any{
				"peer_id":            peerID,
				"authorization_code": authCode,
			},
		}
	})

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Token: bearer,
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("probe finished", "report", report)

	secrets := []string{bearer, messageBody, chatTitle, peerID, authCode, fakeSessionID}
	if found := containsAll(string(encoded), secrets); found != nil {
		t.Errorf("serialized report leaked %v", found)
	}
	if found := containsAll(logged.String(), secrets); found != nil {
		t.Errorf("logged report leaked %v", found)
	}

	// The report should still be useful: withholding the value of a session
	// identifier is not the same as pretending nothing was observed.
	if !strings.Contains(string(encoded), `"schema":"`+ReportSchema+`"`) {
		t.Error("report lost its schema marker")
	}
	if !strings.Contains(string(encoded), DefaultTool) {
		t.Error("report lost the tool name it probed")
	}
}

// TestReport_RecordsSessionShapeWithoutTheValue pins the compromise the
// session fields exist to make.
func TestReport_RecordsSessionShapeWithoutTheValue(t *testing.T) {
	_, url := newFake(t, func(f *fakeServer) { f.mintSession = true })

	report, err := Run(context.Background(), Options{
		URL: url, Mode: ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618,
		Source: SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), fakeSessionID) {
		t.Fatal("report serialized the session identifier itself")
	}
	if report.Session.IDLength != len(fakeSessionID) {
		t.Errorf("id length = %d, want %d", report.Session.IDLength, len(fakeSessionID))
	}
}

// TestFinalize_FailClosed covers the aggregation rule directly: a mandatory
// cell that never executed must not be able to produce a PASS.
func TestFinalize_FailClosed(t *testing.T) {
	pass := func(label string) Step { return Step{Label: label, Outcome: OutcomePass} }

	t.Run("modern run missing a negative is not PASS", func(t *testing.T) {
		r := &Report{Mode: ModeModern, Steps: []Step{
			pass("discover"), pass("tools_list"), pass("tools_call_readonly"),
		}}
		for _, l := range mandatoryNegatives(ModeModern)[:4] {
			r.Negatives = append(r.Negatives, pass(l))
		}
		r.finalize()
		if r.Summary != OutcomePending {
			t.Errorf("summary = %s, want PENDING-OPERATOR", r.Summary)
		}
	})

	t.Run("modern run with every mandatory cell is PASS", func(t *testing.T) {
		r := &Report{Mode: ModeModern, Steps: []Step{
			pass("discover"), pass("tools_list"), pass("tools_call_readonly"),
		}}
		for _, l := range mandatoryNegatives(ModeModern) {
			r.Negatives = append(r.Negatives, pass(l))
		}
		r.finalize()
		if r.Summary != OutcomePass {
			t.Errorf("summary = %s, want PASS", r.Summary)
		}
	})

	t.Run("legacy run missing the call is not PASS", func(t *testing.T) {
		r := &Report{Mode: ModeLegacy, Steps: []Step{pass("initialize"), pass("tools_list")}}
		r.finalize()
		if r.Summary != OutcomePending {
			t.Errorf("summary = %s, want PENDING-OPERATOR", r.Summary)
		}
	})

	t.Run("a measured failure outranks a missing cell", func(t *testing.T) {
		r := &Report{Mode: ModeLegacy, Steps: []Step{
			pass("initialize"),
			{Label: "tools_list", Outcome: OutcomeFail},
		}}
		r.finalize()
		if r.Summary != OutcomeFail {
			t.Errorf("summary = %s, want FAIL", r.Summary)
		}
	})

	t.Run("a failing OAuth cell fails the run", func(t *testing.T) {
		r := &Report{Mode: ModeLegacy, Steps: []Step{
			pass("initialize"), pass("tools_list"), pass("tools_call_readonly"),
		}, OAuth: &OAuthReport{
			ProtectedResource:     MetadataProbe{Outcome: OutcomePass},
			ProtectedResourcePath: MetadataProbe{Outcome: OutcomePass},
			AuthorizationServer:   AuthServerProbe{Outcome: OutcomeFail},
			Unauthenticated:       ChallengeProbe{Outcome: OutcomePass},
		}}
		r.finalize()
		if r.Summary != OutcomeFail {
			t.Errorf("summary = %s, want FAIL", r.Summary)
		}
	})
}

// TestFinalize_UnsetOutcomeIsNotAPass covers the one value the enum does not
// name. A map miss on outcomeRank yields zero — PASS's rank — so an outcome
// nobody set would aggregate exactly like a pass, in the function whose whole
// job is to fail closed.
func TestFinalize_UnsetOutcomeIsNotAPass(t *testing.T) {
	r := &Report{Mode: ModeLegacy, Steps: []Step{
		{Label: "initialize", Outcome: OutcomePass},
		{Label: "tools_list", Outcome: OutcomePass},
		{Label: "tools_call_readonly"}, // deliberately unset
	}}
	r.finalize()
	if r.Summary == OutcomePass {
		t.Fatal("summary = PASS although one mandatory step carries no outcome at all")
	}
}
