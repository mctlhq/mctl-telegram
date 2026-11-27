// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package auditevent

import (
	"errors"
	"strings"
	"testing"
)

func cancelled() Event {
	return Event{
		Principal: 4242001, Kind: ApprovalCancelled, Subject: "apr_1", Server: "alice", Tool: "alice_set_volume",
		ConnectionID: "pac_1", AuthorityRevision: 5, ArgsSHA256: strings.Repeat("a", 64), Reason: ReasonConnectionChanged, AtMS: 1000,
	}
}

// TestS2A8_EventRecordHoldsIdsAndClosedLabelsOnly: the record is a fixed
// sequence of key=value pairs; a value outside the identifier alphabet,
// an unknown kind and a reason that is not one of the closed set for the
// kind are refused, never escaped or written as they are.
func TestS2A8_EventRecordHoldsIdsAndClosedLabelsOnly(t *testing.T) {
	got, err := cancelled().Record()
	if err != nil {
		t.Fatal(err)
	}
	want := "pa-event/v1 event=approval_cancelled principal=4242001 server=alice tool=alice_set_volume conn=pac_1 rev=5 permission=- approval=apr_1 args=" +
		strings.Repeat("a", 64) + " reason=connection_changed at=1000"
	if got != want {
		t.Fatalf("record:\n %s\nwant:\n %s", got, want)
	}
	grant := Event{Principal: 4242001, Kind: PermissionGranted, Subject: "prm_1", Server: "alice", Tool: "alice_set_volume",
		ConnectionID: "pac_1", AuthorityRevision: 5, AtMS: 1000}
	got, err = grant.Record()
	if err != nil {
		t.Fatal(err)
	}
	if want := "pa-event/v1 event=permission_granted principal=4242001 server=alice tool=alice_set_volume conn=pac_1 rev=5 permission=prm_1 approval=- args=- reason=- at=1000"; got != want {
		t.Fatalf("record:\n %s\nwant:\n %s", got, want)
	}

	bad := map[string]func(e *Event){
		"free text as a reason":        func(e *Event) { e.Reason = "the user asked" },
		"a label that is not a reason": func(e *Event) { e.Reason = "manual_cleanup" },
		"an error text as a reason":    func(e *Event) { e.Reason = "dial tcp: refused" },
		"no reason on a cancellation":  func(e *Event) { e.Reason = "" },
		"an unknown kind":              func(e *Event) { e.Kind = "permission_edited" },
		"a tool with a space":          func(e *Event) { e.Tool = "alice_set_volume level=9" },
		"a tool with a newline":        func(e *Event) { e.Tool = "alice\nreason=by_principal" },
		"a subject with an equals":     func(e *Event) { e.Subject = "apr=1" },
		"an overlong connection id":    func(e *Event) { e.ConnectionID = strings.Repeat("c", 129) },
		"no subject":                   func(e *Event) { e.Subject = "" },
		"no args digest":               func(e *Event) { e.ArgsSHA256 = "" },
		"no principal":                 func(e *Event) { e.Principal = 0 },
		"no time":                      func(e *Event) { e.AtMS = 0 },
	}
	for name, mutate := range bad {
		e := cancelled()
		mutate(&e)
		if rec, err := e.Record(); !errors.Is(err, ErrUnrecordable) {
			t.Errorf("%s: recorded as %q, err %v", name, rec, err)
		}
	}
	// A reason of another kind is not this kind's.
	if ValidReason(PermissionRevoked, ReasonConversationClosed) || ValidReason(PermissionGranted, ReasonByPrincipal) {
		t.Error("a permission event accepts a reason it cannot have")
	}
	for _, r := range Reasons {
		if !ValidReason(ApprovalCancelled, r) {
			t.Errorf("reason %s is listed and not valid for a cancellation", r)
		}
	}
}
