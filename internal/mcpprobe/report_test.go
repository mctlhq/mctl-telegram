package mcpprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

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

// fieldOrigin classifies where a Report string field's value comes from.
type fieldOrigin int

const (
	// originPackage is a closed enum or constant this package chose, e.g. an
	// Outcome, a Reason or the step Label a probe function assigned.
	originPackage fieldOrigin = iota
	// originCaller is a value supplied by the caller via Options (or, for
	// GitRef, by the build), never by the probed server.
	originCaller
	// originServer is text the probed server chose and published about
	// itself. This is exactly the set the Report doc comment promises is
	// exhaustive.
	originServer
)

// TestReportStringFieldsHaveADeclaredOrigin is the enumeration half of the
// redaction guarantee TestReportCarriesNoOpenEndedFields checks structurally.
// It walks every string-kind field reachable from Report and requires each
// one to be classified below. An unclassified field fails with a message
// telling the author to classify it and, if server-origin, to extend the
// Report doc comment -- so the comment's "only strings that did not
// originate in this package" claim stays true by construction rather than by
// a reviewer noticing drift (#605).
func TestReportStringFieldsHaveADeclaredOrigin(t *testing.T) {
	origin := map[string]fieldOrigin{
		"Schema":          originPackage,
		"GitRef":          originCaller,
		"Source":          originCaller,
		"Mode":            originCaller,
		"ProtocolVersion": originCaller,
		"TargetHost":      originCaller,
		"Summary":         originPackage,

		"Server.Name":              originServer,
		"Server.Version":           originServer,
		"Server.SupportedVersions": originServer,

		"Tools[].Name": originServer,

		"Steps[].Label":   originPackage,
		"Steps[].Method":  originPackage,
		"Steps[].Tool":    originCaller,
		"Steps[].Outcome": originPackage,
		"Steps[].Reason":  originPackage,

		"Negatives[].Label":   originPackage,
		"Negatives[].Method":  originPackage,
		"Negatives[].Tool":    originCaller,
		"Negatives[].Outcome": originPackage,
		"Negatives[].Reason":  originPackage,

		"OAuth.ProtectedResource.Outcome":     originPackage,
		"OAuth.ProtectedResource.Reason":      originPackage,
		"OAuth.ProtectedResourcePath.Outcome": originPackage,
		"OAuth.ProtectedResourcePath.Reason":  originPackage,

		"OAuth.AuthorizationServer.Issuer":                   originServer,
		"OAuth.AuthorizationServer.TokenEndpointAuthMethods": originServer,
		"OAuth.AuthorizationServer.Outcome":                  originPackage,
		"OAuth.AuthorizationServer.Reason":                   originPackage,

		"OAuth.Unauthenticated.Realm":     originServer,
		"OAuth.Unauthenticated.ErrorCode": originServer,
		"OAuth.Unauthenticated.Outcome":   originPackage,
		"OAuth.Unauthenticated.Reason":    originPackage,
	}

	timeType := reflect.TypeOf(time.Time{})

	var walk func(typ reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		if typ == timeType {
			return
		}
		switch typ.Kind() {
		case reflect.Ptr:
			walk(typ.Elem(), path)
		case reflect.Slice, reflect.Array:
			elem := typ.Elem()
			if elem.Kind() == reflect.String {
				// A []string (or named-string slice) field is itself the
				// unit worth classifying; its element type carries nothing
				// further to walk.
				checkClassified(t, origin, path, typ)
				return
			}
			walk(elem, path+"[]")
		case reflect.String:
			checkClassified(t, origin, path, typ)
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				if !f.IsExported() {
					continue
				}
				child := f.Name
				if path != "" {
					child = path + "." + f.Name
				}
				walk(f.Type, child)
			}
		}
	}
	walk(reflect.TypeOf(Report{}), "")

	// Every classified path must also exist in the type -- otherwise a
	// removed field would leave a stale entry silently over-claiming the
	// comment's enumeration.
	found := map[string]bool{}
	var collect func(typ reflect.Type, path string)
	collect = func(typ reflect.Type, path string) {
		if typ == timeType {
			return
		}
		switch typ.Kind() {
		case reflect.Ptr:
			collect(typ.Elem(), path)
		case reflect.Slice, reflect.Array:
			elem := typ.Elem()
			if elem.Kind() == reflect.String {
				found[path] = true
				return
			}
			collect(elem, path+"[]")
		case reflect.String:
			found[path] = true
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				if !f.IsExported() {
					continue
				}
				child := f.Name
				if path != "" {
					child = path + "." + f.Name
				}
				collect(f.Type, child)
			}
		}
	}
	collect(reflect.TypeOf(Report{}), "")
	for path := range origin {
		if !found[path] {
			t.Errorf("origin table names %q but Report no longer has that field; remove it from the table "+
				"(and from the doc comment, if it was server-origin)", path)
		}
	}

	var serverFields []string
	for path, o := range origin {
		if o == originServer {
			serverFields = append(serverFields, path)
		}
	}
	if len(serverFields) != 8 {
		t.Errorf("origin table classifies %d fields as server-origin, want exactly the 8 the Report "+
			"doc comment enumerates: %v", len(serverFields), serverFields)
	}
}

// checkClassified fails the test when path has no entry in origin -- the
// only way a new string field can pass silently.
func checkClassified(t *testing.T, origin map[string]fieldOrigin, path string, typ reflect.Type) {
	t.Helper()
	if _, ok := origin[path]; !ok {
		t.Errorf("Report.%s (%s) has no declared origin in TestReportStringFieldsHaveADeclaredOrigin's "+
			"table; classify it as originPackage, originCaller or originServer, and if server-origin, "+
			"add it to the Report doc comment's enumeration", path, typ)
	}
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
	if r.Summary != OutcomeFail {
		t.Fatalf("summary = %q, want FAIL: an outcome nobody set is a failure, and the "+
			"verdict must stay inside the enum the type documents", r.Summary)
	}

	// And it must not outrank a real measured failure: a report carrying both
	// has to say FAIL, not "nothing was measured".
	both := &Report{Mode: ModeLegacy, Steps: []Step{
		{Label: "initialize", Outcome: OutcomePass},
		{Label: "tools_list", Outcome: OutcomeFail},
		{Label: "tools_call_readonly"}, // unset
	}}
	both.finalize()
	if both.Summary != OutcomeFail {
		t.Errorf("summary = %q, want FAIL; a measured conformance failure reported as "+
			"unmeasured is the inversion the exit codes exist to prevent", both.Summary)
	}
}
