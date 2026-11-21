package pa_test

// dispatch_taint_test.go pins the dispatcher's half of the durable taint
// (threat model T5, #1321): the audit record carries the conversation's
// flag read at dispatch, a read error records external (S2-I10), and a
// tool result reaches the worker only after it was stored as external
// conversation state, which taints the conversation.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// preDispatchTaints returns the taint of each pre-dispatch record of
// principal's chain, oldest first.
func (e *dispatchEnv) preDispatchTaints(principal int64) []string {
	e.t.Helper()
	var out []string
	for _, r := range e.audit(principal) {
		if r.status != "dispatching" {
			continue
		}
		for _, f := range strings.Fields(r.peer) {
			if v, ok := strings.CutPrefix(f, "taint="); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func (e *dispatchEnv) toolFragments(principal int64) int {
	return e.h.Count(`SELECT count(*) FROM pa_fragments WHERE principal = $1 AND kind = 'tool' AND provenance = 'external'`, principal)
}

// TestS2I10_DispatchTaintFromConversation: the first call of a run whose
// conversation holds only user text is recorded clean; its result taints
// the conversation, so the second is recorded external; and in a clean
// conversation a failed taint read is recorded external (S2-I10).
func TestS2I10_DispatchTaintFromConversation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		token, _ := e.run(alice)
		if a := e.call(token, req("tg", "list_dialogs", "")); a.code != http.StatusOK || a.Status != "ok" {
			t.Fatalf("first call %+v", a)
		}
		if a := e.call(token, req("tg", "list_dialogs", "")); a.code != http.StatusOK {
			t.Fatalf("second call %+v", a)
		}
		if got := e.preDispatchTaints(alice); len(got) != 2 || got[0] != "clean" || got[1] != "external" {
			t.Fatalf("taints %v, want [clean external]", got)
		}

		// Bob's conversation is clean; his taint read fails.
		tokB, _ := e.run(bob)
		e.jobs.taintFail.Store(true)
		a := e.call(tokB, req("tg", "list_dialogs", ""))
		e.jobs.taintFail.Store(false)
		if a.code != http.StatusOK {
			t.Fatalf("call with an unreadable taint %+v", a)
		}
		if got := e.preDispatchTaints(bob); len(got) != 1 || got[0] != "external" {
			t.Fatalf("taints %v, want [external] on a read error", got)
		}
	})
}

// TestS2I6_DispatchStoresResultBeforeAnswer: an answered result is a tool
// fragment of the conversation; one whose record fails is withheld
// (fenced) and leaves no fragment.
func TestS2I6_DispatchStoresResultBeforeAnswer(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		token, _ := e.run(alice)
		if a := e.call(token, req("tg", "list_dialogs", "")); a.code != http.StatusOK {
			t.Fatalf("call %+v", a)
		}
		if n := e.toolFragments(alice); n != 1 {
			t.Fatalf("tool fragments = %d, want 1", n)
		}

		tokB, _ := e.run(bob)
		e.jobs.recordFail.Store(true)
		a := e.call(tokB, req("tg", "list_dialogs", ""))
		e.jobs.recordFail.Store(false)
		if a.code != http.StatusConflict || a.Stop != "fenced" || a.Output != "" || strings.Contains(a.raw, "result of") {
			t.Fatalf("unrecorded result answered: %+v", a)
		}
		if n := e.toolFragments(bob); n != 0 {
			t.Fatalf("tool fragments = %d after a failed record", n)
		}
		rows := e.audit(bob)
		if len(rows) == 0 || rows[len(rows)-1].status != "fenced" {
			t.Fatalf("audit %+v, want the result recorded fenced", rows)
		}
	})
}
