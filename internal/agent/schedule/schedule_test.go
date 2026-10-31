package schedule

import (
	"testing"
	"time"
)

func mustParse(t *testing.T, tz string, hours ...string) *Hours {
	t.Helper()
	h, err := Parse(tz, hours)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func at(t *testing.T, tz, value string) time.Time {
	t.Helper()
	loc, err := time.LoadLocation(tz)
	if err != nil {
		t.Fatal(err)
	}
	v, err := time.ParseInLocation("2006-01-02 15:04", value, loc)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestContains(t *testing.T) {
	const zurich = "Europe/Zurich"
	office := mustParse(t, zurich, "mon-fri 09:00-18:00")
	night := mustParse(t, zurich, "fri 22:00-02:00")
	wrap := mustParse(t, zurich, "fri-mon 10:00-11:00")
	cases := []struct {
		name string
		h    *Hours
		at   string // local time in Zurich; 2026-11-02 is a Monday
		want bool
	}{
		{"office start is inside", office, "2026-11-02 09:00", true},
		{"office end is outside", office, "2026-11-02 18:00", false},
		{"before office", office, "2026-11-02 08:59", false},
		{"saturday", office, "2026-11-07 12:00", false},
		{"friday", office, "2026-11-06 17:59", true},
		{"past midnight, friday evening", night, "2026-11-06 23:30", true},
		{"past midnight, saturday early", night, "2026-11-07 01:59", true},
		{"past midnight, saturday 02:00", night, "2026-11-07 02:00", false},
		{"past midnight, thursday early", night, "2026-11-05 01:00", false},
		{"wrapped day range, sunday", wrap, "2026-11-08 10:30", true},
		{"wrapped day range, tuesday", wrap, "2026-11-03 10:30", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.h.Contains(at(t, zurich, tc.at)); got != tc.want {
				t.Fatalf("Contains(%s) = %v, want %v", tc.at, got, tc.want)
			}
		})
	}
}

// The windows follow local wall time across a DST change: the same UTC
// instant, 07:30, is 09:30 in Zurich before the change and 08:30 after.
func TestContains_FollowsDST(t *testing.T) {
	h := mustParse(t, "Europe/Zurich", "mon-fri 09:00-18:00")
	summer := time.Date(2026, 10, 23, 7, 30, 0, 0, time.UTC) // Fri 09:30 CEST
	winter := time.Date(2026, 10, 30, 7, 30, 0, 0, time.UTC) // Fri 08:30 CET
	if !h.Contains(summer) {
		t.Fatal("09:30 local in summer time is outside")
	}
	if h.Contains(winter) {
		t.Fatal("08:30 local in winter time is inside")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]struct {
		tz    string
		hours []string
	}{
		"no timezone":  {"", []string{"mon 09:00-10:00"}},
		"bad timezone": {"Mars/Olympus", []string{"mon 09:00-10:00"}},
		"no windows":   {"UTC", nil},
		"bad day":      {"UTC", []string{"funday 09:00-10:00"}},
		"bad time":     {"UTC", []string{"mon 9:00-10:00"}},
		"hour 25":      {"UTC", []string{"mon 25:00-10:00"}},
		"24:00 start":  {"UTC", []string{"mon 24:00-10:00"}},
		"empty window": {"UTC", []string{"mon 10:00-10:00"}},
		"no times":     {"UTC", []string{"mon"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(tc.tz, tc.hours); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestStoredRoundTrip(t *testing.T) {
	h := mustParse(t, "America/New_York", "Mon-Fri 09:00-17:30", "sat 22:00-24:00")
	s := h.String()
	if s != "America/New_York;mon-fri 09:00-17:30;sat 22:00-24:00" {
		t.Fatalf("String() = %q", s)
	}
	back, err := ParseStored(s)
	if err != nil {
		t.Fatal(err)
	}
	if back.String() != s {
		t.Fatalf("round trip = %q", back.String())
	}
	if _, err := ParseStored("garbage"); err == nil {
		t.Fatal("ParseStored accepted a value without windows")
	}
}
