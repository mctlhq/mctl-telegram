package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseDigestWeekday(t *testing.T) {
	for _, c := range []struct {
		in   string
		day  time.Weekday
		ok   bool
		fail bool
	}{
		{"", 0, false, false},
		{"mon", time.Monday, true, false},
		{" Monday ", time.Monday, true, false},
		{"SUN", time.Sunday, true, false},
		{"sat", time.Saturday, true, false},
		{"funday", 0, false, true},
		{"1", 0, false, true},
	} {
		d, ok, err := ParseDigestWeekday(c.in)
		if (err != nil) != c.fail || d != c.day || ok != c.ok {
			t.Errorf("ParseDigestWeekday(%q) = %v, %v, %v", c.in, d, ok, err)
		}
	}
}

func TestLoadDigestScheduleAndRecipients(t *testing.T) {
	t.Run("unset keeps daily and no recipients", func(t *testing.T) {
		t.Setenv("DIGEST_WEEKDAY", "")
		t.Setenv("DIGEST_RECIPIENTS", "")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DigestWeekday != "" || len(cfg.DigestRecipients) != 0 {
			t.Fatalf("got %q %v", cfg.DigestWeekday, cfg.DigestRecipients)
		}
	})
	t.Run("weekday and recipients", func(t *testing.T) {
		t.Setenv("DIGEST_WEEKDAY", "Mon")
		t.Setenv("DIGEST_RECIPIENTS", "7001, 7002,7003")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DigestWeekday != "mon" || len(cfg.DigestRecipients) != 3 || cfg.DigestRecipients[2] != 7003 {
			t.Fatalf("got %q %v", cfg.DigestWeekday, cfg.DigestRecipients)
		}
	})
	t.Run("bad weekday aborts", func(t *testing.T) {
		t.Setenv("DIGEST_WEEKDAY", "someday")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DIGEST_WEEKDAY") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad recipient aborts instead of dropping", func(t *testing.T) {
		t.Setenv("DIGEST_RECIPIENTS", "7001,@alice")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DIGEST_RECIPIENTS") {
			t.Fatalf("err = %v", err)
		}
	})
	for _, bad := range []string{"0", "-5", "7001,0", ",", " , ,"} {
		t.Run("non-positive id "+bad, func(t *testing.T) {
			t.Setenv("DIGEST_RECIPIENTS", bad)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DIGEST_RECIPIENTS") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
