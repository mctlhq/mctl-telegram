// Package schedule parses and evaluates an assistant install's working
// hours: the windows in which the owner answers messages personally, so the
// assistant may not reply on its own. It is pure apart from the embedded
// time zone database.
package schedule

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	// The runtime image has no zoneinfo; embedding it keeps every IANA zone
	// resolvable, including after a DST rule change ships with Go.
	_ "time/tzdata"
)

var days = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// window is one "mon-fri 09:00-18:00" entry. start and end are minutes
// after local midnight; end <= start means the window runs past midnight
// into the next day, and still belongs to the day it starts on.
type window struct {
	days       [7]bool
	start, end int
	spec       string
}

// Hours is a parsed set of working-hour windows in one time zone.
type Hours struct {
	loc     *time.Location
	windows []window
}

// Parse reads an IANA time zone and windows of the form
// "<day>[-<day>] HH:MM-HH:MM", for example "mon-fri 09:00-18:00" or
// "sat 22:00-02:00". A day range may wrap ("fri-mon"). 24:00 is accepted as
// an end time. At least one window is required.
func Parse(timezone string, hours []string) (*Hours, error) {
	if strings.TrimSpace(timezone) == "" {
		return nil, errors.New("schedule: timezone is required")
	}
	// "Local" would make the windows follow the server's zone, not one the
	// owner chose.
	if timezone == "Local" {
		return nil, errors.New("schedule: timezone must be an IANA zone name, not Local")
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("schedule: unknown timezone %q", timezone)
	}
	if len(hours) == 0 {
		return nil, errors.New("schedule: at least one working-hours window is required")
	}
	h := &Hours{loc: loc}
	for _, raw := range hours {
		w, err := parseWindow(raw)
		if err != nil {
			return nil, err
		}
		h.windows = append(h.windows, w)
	}
	return h, nil
}

func parseWindow(raw string) (window, error) {
	spec := strings.ToLower(strings.TrimSpace(raw))
	dayPart, timePart, ok := strings.Cut(spec, " ")
	if !ok {
		return window{}, fmt.Errorf("schedule: window %q: want \"<day>[-<day>] HH:MM-HH:MM\"", raw)
	}
	var w window
	first, last, isRange := strings.Cut(dayPart, "-")
	if !isRange {
		last = first
	}
	d0, ok0 := days[first]
	d1, ok1 := days[last]
	if !ok0 || !ok1 {
		return window{}, fmt.Errorf("schedule: window %q: unknown day", raw)
	}
	for d := d0; ; d = (d + 1) % 7 {
		w.days[d] = true
		if d == d1 {
			break
		}
	}
	from, to, ok := strings.Cut(strings.TrimSpace(timePart), "-")
	if !ok {
		return window{}, fmt.Errorf("schedule: window %q: want HH:MM-HH:MM", raw)
	}
	var err error
	if w.start, err = clock(from, false); err != nil {
		return window{}, fmt.Errorf("schedule: window %q: %w", raw, err)
	}
	if w.end, err = clock(to, true); err != nil {
		return window{}, fmt.Errorf("schedule: window %q: %w", raw, err)
	}
	if w.start == w.end {
		return window{}, fmt.Errorf("schedule: window %q is empty", raw)
	}
	w.spec = dayPart + " " + from + "-" + to
	return w, nil
}

// clock parses HH:MM into minutes after midnight; 24:00 only as an end.
func clock(s string, end bool) (int, error) {
	hh, mm, ok := strings.Cut(s, ":")
	// Two ASCII digits each: strconv.Atoi alone would also take "-1" or "+9".
	if !ok || !twoDigits(hh) || !twoDigits(mm) {
		return 0, fmt.Errorf("bad time %q", s)
	}
	h, err1 := strconv.Atoi(hh)
	m, err2 := strconv.Atoi(mm)
	if err1 != nil || err2 != nil || m > 59 {
		return 0, fmt.Errorf("bad time %q", s)
	}
	if h == 24 && m == 0 && end {
		return 24 * 60, nil
	}
	if h > 23 {
		return 0, fmt.Errorf("bad time %q", s)
	}
	return h*60 + m, nil
}

func twoDigits(s string) bool {
	return len(s) == 2 && s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9'
}

// Contains reports whether t falls in a working-hours window, judged by
// the wall clock in the schedule's zone at that instant, so DST shifts the
// windows with local time. A window past midnight covers the start day's
// evening and the next day's early hours.
func (h *Hours) Contains(t time.Time) bool {
	local := t.In(h.loc)
	day := local.Weekday()
	prev := (day + 6) % 7
	m := local.Hour()*60 + local.Minute()
	for _, w := range h.windows {
		if w.start < w.end {
			if w.days[day] && m >= w.start && m < w.end {
				return true
			}
			continue
		}
		if (w.days[day] && m >= w.start) || (w.days[prev] && m < w.end) {
			return true
		}
	}
	return false
}

// String is the canonical stored form: "<zone>;<window>;<window>...".
// ParseStored reads it back.
func (h *Hours) String() string {
	parts := []string{h.loc.String()}
	for _, w := range h.windows {
		parts = append(parts, w.spec)
	}
	return strings.Join(parts, ";")
}

// ParseStored reads the form String writes.
func ParseStored(s string) (*Hours, error) {
	parts := strings.Split(s, ";")
	return Parse(parts[0], parts[1:])
}
