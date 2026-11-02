package agentworker

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/tools"
)

func TestToolDefs_MatchMCPServer(t *testing.T) {
	api := &fakeAPI{}
	job := JobContext{JobID: 1, Attempt: 1, EventID: "e", ConversationID: 2}
	_, defs, err := buildToolSet(api, job)
	if err != nil {
		t.Fatal(err)
	}
	bindings := tools.Default()
	if len(defs) != len(bindings) {
		t.Fatalf("defs=%d bindings=%d", len(defs), len(bindings))
	}
	for i, d := range defs {
		if d.Tool.Name != bindings[i].Name {
			t.Fatalf("tool[%d]=%q want %q", i, d.Tool.Name, bindings[i].Name)
		}
		if d.Handler == nil {
			t.Fatalf("tool[%d] handler is nil", i)
		}
	}
	if _, err := NewMCPServer(api, job); err != nil {
		t.Fatalf("NewMCPServer: %v", err)
	}
}

func TestToolDefs_AliasKeepsSchemaByteEquivalent(t *testing.T) {
	api := &fakeAPI{}
	_, canonical, err := buildToolSet(api, JobContext{Tools: []string{"get_event", "get_recruiter_profile", "complete_agent_job"}})
	if err != nil {
		t.Fatal(err)
	}
	_, aliased, err := buildToolSet(api, JobContext{Tools: []string{"get_event", "get_owner_profile", "complete_agent_job"}})
	if err != nil {
		t.Fatal(err)
	}
	var c, a any
	for _, d := range canonical {
		if d.Tool.Name == "get_recruiter_profile" {
			b, _ := json.Marshal(d.Tool.InputSchema)
			_ = json.Unmarshal(b, &c)
		}
	}
	for _, d := range aliased {
		if d.Tool.Name == "get_owner_profile" {
			b, _ := json.Marshal(d.Tool.InputSchema)
			_ = json.Unmarshal(b, &a)
		}
	}
	if !reflect.DeepEqual(c, a) {
		t.Fatalf("alias schema drifted\ncanonical=%#v\nalias=%#v", c, a)
	}
}
