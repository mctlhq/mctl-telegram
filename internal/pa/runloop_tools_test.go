package pa

// The claim's tools (#1318 slice C3): exactly the job's signed tool set,
// described from the pin, and nothing when the set is empty.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// TestRunLoop_ClaimCarriesPinnedTools: the claim describes each tool of the
// signed set, in its order, with the pin's catalog description and
// canonical schema (what Surface.ModelTools shows the model).
func TestRunLoop_ClaimCarriesPinnedTools(t *testing.T) {
	h := newRunLoopHarness(t)
	h.tools = []string{"tg/list_dialogs", "alice/alice_get_device_state"}
	h.consent(aliceID)
	h.text(aliceID, "what is new?")
	c := h.mustClaim()
	pin, err := catalog.LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tools) != len(c.ToolSet) || len(c.ToolSet) != 2 {
		t.Fatalf("tool set %v, tools %+v", c.ToolSet, c.Tools)
	}
	for i, name := range c.ToolSet {
		server, tool, _ := strings.Cut(name, "/")
		want, err := pin.ModelTool(server, tool)
		if err != nil {
			t.Fatal(err)
		}
		got := c.Tools[i]
		if got.Name != name || got.Description != want.Description || got.Description == "" ||
			!bytes.Equal(got.InputSchema, want.InputSchema) {
			t.Fatalf("tool %d = %+v, want %s %+v", i, got, name, want)
		}
		if got.Description != pin.Servers[server].Tools[tool].CatalogDescription {
			t.Fatalf("tool %s is not described by the catalog", name)
		}
	}
}

// TestRunLoop_ClaimOmitsToolsWhenNone: a job without tools carries no
// tools key at all.
func TestRunLoop_ClaimOmitsToolsWhenNone(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	w := h.post(RouteClaim, h.pool, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("claim: %d", w.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["tools"]; ok {
		t.Fatalf("tools present: %s", raw["tools"])
	}
	if string(raw["tool_set"]) != "[]" {
		t.Fatalf("tool_set = %s", raw["tool_set"])
	}
}

// TestRunLoop_ClaimToolsRefuseUnpinned: a set entry with no pinned read
// entry fails the claim's tools rather than being dropped.
func TestRunLoop_ClaimToolsRefuseUnpinned(t *testing.T) {
	h := newRunLoopHarness(t)
	for _, set := range [][]string{{"tg/send_message"}, {"tg/list_dialogs", "alice/alice_control_room"}} {
		if tools, err := h.loop.claimTools(set); !errors.Is(err, jobs.ErrInvalid) || tools != nil {
			t.Fatalf("%v: tools %+v, err %v", set, tools, err)
		}
	}
	if tools, err := h.loop.claimTools([]string{"tg/list_dialogs"}); err != nil || len(tools) != 1 {
		t.Fatalf("pinned read: %+v, %v", tools, err)
	}
}
