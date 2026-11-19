package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// RecordRefusal normalises every worker-supplied field, so a hostile value
// neither enters the record nor makes the sink drop the row (#1331
// follow-up: refusal-path Server/ApprovalID/Approver).
func TestRecordRefusalNormalises(t *testing.T) {
	sink := &fakeSink{ev: &events{}}
	x := newExecutor(sink)
	pinned := func(s string) bool { return s == "tg" }
	x.RecordRefusal(context.Background(), Refusal{
		Principal: 555, Server: "tg evil", Tool: "list dialogs\n", ConnectionID: "c 1",
		AuthorityRevision: -3, Reason: "Drop Table",
	}, pinned)
	x.RecordRefusal(context.Background(), Refusal{Principal: 0, Server: "tg", Reason: ReasonFlagOff}, pinned)
	if len(sink.entries) != 1 {
		t.Fatalf("entries %d, want 1 (principal 0 has no chain)", len(sink.entries))
	}
	e := sink.entries[0]
	if e.Server != invalidServer || e.Tool != "invalid-tool-name" || e.ConnectionID != unboundConnection ||
		e.AuthorityRevision != 0 || e.Reason != ReasonInternal || e.Status != StatusRefused {
		t.Fatalf("entry %+v", e)
	}
	if _, err := FormatRecord(e); err != nil {
		t.Fatalf("normalised entry not recordable: %v", err)
	}
}

// Execute normalises approval fields taken from worker input instead of
// letting FormatRecord drop the refusal row.
func TestExecuteNormalisesApprovalFields(t *testing.T) {
	sink := &fakeSink{ev: &events{}}
	x := newExecutor(sink)
	call := Call{Policy: alicePolicy(t), ConnectionID: "nope", Tool: "list_dialogs", Args: []byte(`{}`),
		Taint: TaintExternal, ApprovalID: "id with spaces", Approver: "<script>"}
	if _, err := x.Execute(context.Background(), observeTG(t, nil), call, func(context.Context) (Result, error) {
		t.Fatal("dispatched")
		return Result{}, nil
	}); err == nil {
		t.Fatal("unbound connection accepted")
	}
	if len(sink.entries) != 1 {
		t.Fatalf("entries %d", len(sink.entries))
	}
	e := sink.entries[0]
	if e.ApprovalID != invalidMarker || e.Approver != invalidMarker || e.Reason != ReasonConnectionUnbound {
		t.Fatalf("entry %+v", e)
	}
	rec, err := FormatRecord(e)
	if err != nil || !strings.HasSuffix(rec, " reason=connection_unbound") {
		t.Fatalf("record %q err %v", rec, err)
	}
}

func TestPinRefusalReasonIsClosed(t *testing.T) {
	for err, want := range map[error]string{
		catalog.ErrServerUnavailable: ReasonServerUnavailable,
		catalog.ErrUnknownServer:     ReasonUnknownServer,
		catalog.ErrListingStale:      ReasonListingStale,
		catalog.ErrNotPinned:         ReasonNotPinned,
		catalog.ErrToolChanged:       ReasonToolChanged,
		catalog.ErrNoWritePath:       ReasonNoWritePath,
		ErrInvalidCall:               ReasonInternal,
	} {
		if got := PinRefusalReason(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
}

// PinDrift: the committed listing is no drift; a changed pinned tool is;
// an extra unpinned tool is not; an unreadable listing is unknown, not
// "no drift".
func TestPinDrift(t *testing.T) {
	if drift, denied, ok := PinDrift(observeTG(t, nil)); !ok || drift || denied[string(catalog.DenyNotPinned)] == 0 {
		t.Fatalf("committed: drift=%v ok=%v denied=%v", drift, ok, denied)
	}
	changed := observeTG(t, func(tools []map[string]any) []map[string]any {
		for _, tool := range tools {
			if tool["name"] == "get_messages" {
				tool["description"] = "changed"
			}
		}
		return tools
	})
	if drift, denied, ok := PinDrift(changed); !ok || !drift || denied[string(catalog.DenyChangedDescription)] != 1 {
		t.Fatalf("changed: drift=%v ok=%v denied=%v", drift, ok, denied)
	}
	removed := observeTG(t, func(tools []map[string]any) []map[string]any {
		out := tools[:0]
		for _, tool := range tools {
			if tool["name"] != "list_topics" {
				out = append(out, tool)
			}
		}
		return out
	})
	if drift, _, ok := PinDrift(removed); !ok || !drift {
		t.Fatal("a missing pinned tool is not drift")
	}
	pin := loadPin(t)
	if _, _, ok := PinDrift(pin.Observe("tg", nil, context.DeadlineExceeded, t0)); ok {
		t.Fatal("a failed listing reported as observed")
	}
	if _, _, ok := PinDrift(pin.Observe("tg", [][]byte{[]byte(`{"tools":null}`)}, nil, t0)); ok {
		t.Fatal("a malformed listing reported as observed")
	}
}

func TestEnvFlags(t *testing.T) {
	env := map[string]string{}
	flags := EnvFlags(func(k string) string { return env[k] })
	f, err := flags()
	if err != nil || f.ExternalTools || f.Servers["tg"] || f.Servers["alice"] {
		t.Fatalf("defaults %+v %v", f, err)
	}
	env[ExternalToolsFlagEnv], env["PA_SERVER_TG_ENABLED"] = "true", "true"
	if f, err = flags(); err != nil || !f.ExternalTools || !f.Servers["tg"] || f.Servers["alice"] {
		t.Fatalf("on %+v %v", f, err)
	}
	for _, bad := range []string{"1", "TRUE", "yes"} {
		env[ExternalToolsFlagEnv] = bad
		if _, err := flags(); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestFenceAuditRecords(t *testing.T) {
	sink := &fakeSink{ev: &events{}}
	fa := FenceAudit{Sink: sink}
	if err := fa.RecordFenced(context.Background(), connection.FenceEvent{
		Principal: 555, ConnectionID: "c1", Server: connection.ServerTG, BoundRevision: 4, Reason: "not_active",
	}); err != nil {
		t.Fatal(err)
	}
	e := sink.entries[0]
	if e.Status != StatusFenced || e.Tool != fenceTool || e.Reason != "fence_not_active" || e.AuthorityRevision != 4 {
		t.Fatalf("entry %+v", e)
	}
	if _, err := FormatRecord(e); err != nil {
		t.Fatal(err)
	}
}

func loadPin(t *testing.T) *catalog.Pin {
	t.Helper()
	pin, err := catalog.LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

// observeTG observes the committed pin against tg's descriptors, changed
// by mutate when it is not nil.
func observeTG(t *testing.T, mutate func([]map[string]any) []map[string]any) *catalog.Surface {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "tool-descriptors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snap struct {
		Tools map[string]map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	var tools []map[string]any
	for _, d := range snap.Tools {
		tools = append(tools, d)
	}
	if mutate != nil {
		tools = mutate(tools)
	}
	page, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		t.Fatal(err)
	}
	return loadPin(t).Observe("tg", [][]byte{page}, nil, t0)
}

// GatewayPrefixed names only a listing whose pinned names all moved under
// the "<server>_" prefix: a direct listing, an empty one and a failed one
// are not the gateway.
func TestGatewayPrefixed(t *testing.T) {
	pin := loadPin(t)
	prefixed := observeTG(t, func(tools []map[string]any) []map[string]any {
		for _, tool := range tools {
			tool["name"] = "tg_" + tool["name"].(string)
		}
		return tools
	})
	if !GatewayPrefixed(prefixed, pin) {
		t.Fatal("prefixed listing not recognised")
	}
	empty := observeTG(t, func([]map[string]any) []map[string]any { return []map[string]any{} })
	for name, s := range map[string]*catalog.Surface{
		"direct": observeTG(t, nil), "empty": empty, "failed": pin.Observe("tg", nil, context.Canceled, t0), "nil": nil,
	} {
		if GatewayPrefixed(s, pin) {
			t.Errorf("%s listing taken for the gateway", name)
		}
	}
}
