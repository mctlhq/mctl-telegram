package main

import "testing"

// The probe is wired only while the scope is requested and a token exists.
func TestBotChatProbeWiring(t *testing.T) {
	if botChatProbe(false, "123:abc") != nil {
		t.Error("probe wired with the scope not requested")
	}
	if botChatProbe(true, "") != nil {
		t.Error("probe wired without a token")
	}
	if botChatProbe(true, "123:abc") == nil {
		t.Error("probe not wired with the scope requested")
	}
}
