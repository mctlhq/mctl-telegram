package tools

import "testing"

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
	if Complete(got) {
		t.Fatal("three tools reported complete")
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
	if !Complete(Default()) {
		t.Fatal("Default is not complete")
	}
	if b, err := ForJob(nil); err != nil || len(b) != len(Canonical) {
		t.Fatalf("ForJob(nil) = %v, %v", b, err)
	}
	if _, err := ForJob([]string{"get_event"}); err == nil {
		t.Fatal("ForJob accepted a partial list")
	}
}
