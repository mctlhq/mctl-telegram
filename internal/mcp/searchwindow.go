package mcp

import (
	"fmt"
	"math"
	"time"
)

// parseSearchWindow resolves the optional min_date/max_date arguments of
// search_messages into UTC instants. A zero time.Time means "unbounded".
//
// Each bound is tried, in order, as an RFC 3339 timestamp (used verbatim,
// converted to UTC) and then as a plain YYYY-MM-DD date. A plain min_date
// resolves to 00:00:00 UTC of that day; a plain max_date resolves to
// 23:59:59 UTC of that same day, so that a plain-date range (e.g.
// min_date=2026-08-01, max_date=2026-08-31) includes both boundary days
// rather than excluding the last one.
func parseSearchWindow(minRaw, maxRaw string) (minDate, maxDate time.Time, err error) {
	minDate, err = parseSearchBound("min_date", minRaw, false)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	maxDate, err = parseSearchBound("max_date", maxRaw, true)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !minDate.IsZero() && !maxDate.IsZero() && minDate.After(maxDate) {
		return time.Time{}, time.Time{}, fmt.Errorf("min_date must not be after max_date")
	}
	return minDate, maxDate, nil
}

// parseSearchBound parses one min_date/max_date argument. endOfDay controls
// how a plain date resolves: false for the start of the day (min_date),
// true for the end of the day (max_date).
func parseSearchBound(argName, raw string, endOfDay bool) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	var t time.Time
	if parsed, perr := time.Parse(time.RFC3339, raw); perr == nil {
		t = parsed.UTC()
	} else if parsed, perr := time.Parse(time.DateOnly, raw); perr == nil {
		if endOfDay {
			t = time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 23, 59, 59, 0, time.UTC)
		} else {
			t = time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 0, 0, 0, 0, time.UTC)
		}
	} else {
		return time.Time{}, fmt.Errorf("%s must be RFC3339 (e.g. 2026-08-27T00:00:00Z) or a plain date (e.g. 2026-08-27)", argName)
	}
	// The wire fields are 32-bit and telegram.SearchMessages shifts each
	// bound by one second to turn Telegram's exclusive bounds into inclusive
	// ones (min_date - 1, max_date + 1). Keep one second of headroom at both
	// ends so the shifted value still fits and a min_date at the epoch never
	// becomes negative.
	unix := t.Unix()
	if unix < 1 || unix > math.MaxInt32-1 {
		return time.Time{}, fmt.Errorf("%s is out of range (supported: 1970-01-01 to 2038-01-19)", argName)
	}
	return t, nil
}
