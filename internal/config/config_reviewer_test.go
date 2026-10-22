package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseReviewerWritePeers(t *testing.T) {
	ok := map[string][]string{
		"":                                     nil,
		"   ":                                  nil,
		"user:7001":                            {"user:7001"},
		" user:7001 , chat:7002,channel:7003 ": {"user:7001", "chat:7002", "channel:7003"},
	}
	for raw, want := range ok {
		got, err := parseReviewerWritePeers(raw)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("parseReviewerWritePeers(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"7001",              // a bare id does not say user, chat or channel
		"@alice",            // a username is not an id
		"user:",             // no id
		"user:abc",          // not a number
		"user:0",            // not positive
		"chat:-7002",        // not positive
		"user:+7001",        // not canonical
		"user:07001",        // not canonical
		"user: 7001",        // space inside the entry
		"group:7001",        // unknown kind
		"user:7001,",        // trailing comma
		"user:7001,,chat:2", // empty entry
		"user:7001;chat:2",  // wrong separator
	} {
		if got, err := parseReviewerWritePeers(raw); err == nil {
			t.Errorf("parseReviewerWritePeers(%q) = %v, want an error", raw, got)
		}
	}
}

// DEMO_REVIEWER_WRITE_PEERS fails closed: malformed is fatal only while
// reviewer mode is on, and with reviewer mode off nothing is kept.
func TestLoadDemoReviewerWritePeers(t *testing.T) {
	enable := func(t *testing.T) {
		t.Setenv("DEMO_REVIEWER_ENABLED", "true")
		t.Setenv("DEMO_REVIEWER_USERNAME", "reviewer")
		t.Setenv("DEMO_REVIEWER_PASSWORD", "synthetic-test-password")
		t.Setenv("DEMO_REVIEWER_TG_ID", "990001")
	}

	t.Run("enabled, valid", func(t *testing.T) {
		enable(t)
		t.Setenv("DEMO_REVIEWER_WRITE_PEERS", "user:7001,chat:7002")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if want := []string{"user:7001", "chat:7002"}; !reflect.DeepEqual(cfg.DemoReviewerWritePeers, want) {
			t.Fatalf("DemoReviewerWritePeers = %v, want %v", cfg.DemoReviewerWritePeers, want)
		}
	})
	t.Run("enabled, unset", func(t *testing.T) {
		enable(t)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if len(cfg.DemoReviewerWritePeers) != 0 {
			t.Fatalf("DemoReviewerWritePeers = %v, want empty", cfg.DemoReviewerWritePeers)
		}
	})
	t.Run("enabled, malformed", func(t *testing.T) {
		enable(t)
		t.Setenv("DEMO_REVIEWER_WRITE_PEERS", "user:7001,@alice")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DEMO_REVIEWER_WRITE_PEERS") {
			t.Fatalf("Load() error = %v, want a DEMO_REVIEWER_WRITE_PEERS error", err)
		}
	})
	t.Run("disabled, malformed", func(t *testing.T) {
		t.Setenv("DEMO_REVIEWER_WRITE_PEERS", "user:7001,@alice")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if len(cfg.DemoReviewerWritePeers) != 0 {
			t.Fatalf("DemoReviewerWritePeers = %v, want empty", cfg.DemoReviewerWritePeers)
		}
	})
	t.Run("disabled, valid", func(t *testing.T) {
		t.Setenv("DEMO_REVIEWER_WRITE_PEERS", "user:7001")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if len(cfg.DemoReviewerWritePeers) != 0 {
			t.Fatalf("DemoReviewerWritePeers = %v, want empty while reviewer mode is off", cfg.DemoReviewerWritePeers)
		}
	})
}
