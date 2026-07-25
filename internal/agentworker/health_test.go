package agentworker

import "testing"

func TestHealth_NilIsPermissive(t *testing.T) {
	var h *Health
	if !h.Alive() {
		t.Fatal("nil Health.Alive() = false, want true (no-op default)")
	}
	if !h.Ready() {
		t.Fatal("nil Health.Ready() = false, want true (no-op default)")
	}
	// None of these should panic on a nil receiver.
	h.SetPollResult(true)
	h.SetPollResult(false)
	h.SetFatal()
	h.SetStopped()
}

func TestHealth_ReadyRequiresAtLeastOneSuccessfulPoll(t *testing.T) {
	h := &Health{}
	if h.Ready() {
		t.Fatal("Ready() before any poll attempt = true, want false")
	}
	h.SetPollResult(false)
	if h.Ready() {
		t.Fatal("Ready() after a failed poll = true, want false")
	}
	h.SetPollResult(true)
	if !h.Ready() {
		t.Fatal("Ready() after a successful poll = false, want true")
	}
}

func TestHealth_FatalIsPermanent(t *testing.T) {
	h := &Health{}
	h.SetPollResult(true)
	if !h.Ready() {
		t.Fatal("Ready() after a successful poll = false, want true")
	}
	h.SetFatal()
	if h.Ready() {
		t.Fatal("Ready() after SetFatal = true, want false")
	}
	// A later successful poll must not clear a fatal auth error — restart
	// with a fresh token is the only real fix (see Worker.Loop's fatal-auth
	// branch), never a same-process self-heal.
	h.SetPollResult(true)
	if h.Ready() {
		t.Fatal("Ready() stayed true after a poll success following SetFatal, want it to remain false")
	}
}

func TestHealth_AliveUntilStopped(t *testing.T) {
	h := &Health{}
	if !h.Alive() {
		t.Fatal("Alive() before SetStopped = false, want true")
	}
	h.SetStopped()
	if h.Alive() {
		t.Fatal("Alive() after SetStopped = true, want false")
	}
}
