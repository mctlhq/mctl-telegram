package tools

import (
	"slices"
	"testing"
)

func TestResolve(t *testing.T) {
	got, err := Resolve([]string{"get_event", "save_record", "get_owner_profile"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Binding{{"get_event", "get_event"}, {"save_record", "save_job_lead"}, {"get_owner_profile", "get_recruiter_profile"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("binding %d = %v, want %v", i, got[i], want[i])
		}
	}
	for name, names := range map[string][]string{
		"unknown":          {"send_email"},
		"alias and itself": {"save_job_lead", "save_record"},
		"twice":            {"get_event", "get_event"},
	} {
		if _, err := Resolve(names); err == nil {
			t.Errorf("%s: accepted %v", name, names)
		}
	}
	if b, err := ForJob(nil); err != nil || len(b) != len(Canonical) {
		t.Fatalf("ForJob(nil) = %v, %v", b, err)
	}
}

// A subset is valid when it keeps the mandatory tools, and invalid without
// either of them.
func TestValidateSubset(t *testing.T) {
	sub := []string{"get_event", "propose_reply", "complete_agent_job"}
	for name, f := range map[string]func([]string) ([]Binding, error){"Validate": Validate, "ForJob": ForJob} {
		b, err := f(sub)
		if err != nil || len(b) != 3 {
			t.Fatalf("%s(subset) = %v, %v", name, b, err)
		}
		if _, err := f(Canonical); err != nil {
			t.Fatalf("%s(every tool): %v", name, err)
		}
		for _, missing := range Mandatory {
			var without []string
			for _, n := range Canonical {
				if n != missing {
					without = append(without, n)
				}
			}
			if _, err := f(without); err == nil {
				t.Errorf("%s accepted a set without %s", name, missing)
			}
		}
	}
}

// Every route maps to known tools, and every tool is served by a route, so a
// tool cannot be added without deciding how the agent API gates it.
func TestEndpointsCoverEveryTool(t *testing.T) {
	served := map[string]bool{}
	for route, ts := range Endpoints {
		if len(ts) == 0 {
			t.Errorf("%s serves no tool", route)
		}
		for _, c := range ts {
			if !slices.Contains(Canonical, c) {
				t.Errorf("%s names unknown tool %q", route, c)
			}
			served[c] = true
		}
	}
	for _, c := range Canonical {
		if !served[c] {
			t.Errorf("tool %q has no route", c)
		}
	}
}
