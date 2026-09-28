package mcp

import (
	"strings"
	"testing"
	"time"
)

func TestParseSearchWindow(t *testing.T) {
	tests := []struct {
		name       string
		minRaw     string
		maxRaw     string
		wantMin    time.Time
		wantMax    time.Time
		wantErrSub string
	}{
		{
			name:    "RFC3339 pair used verbatim",
			minRaw:  "2026-08-27T00:00:00Z",
			maxRaw:  "2026-09-27T12:34:56Z",
			wantMin: time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC),
			wantMax: time.Date(2026, 9, 27, 12, 34, 56, 0, time.UTC),
		},
		{
			name:    "plain min_date resolves to UTC midnight",
			minRaw:  "2026-08-27",
			wantMin: time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC),
		},
		{
			name:    "plain max_date resolves to end of day UTC",
			maxRaw:  "2026-08-27",
			wantMax: time.Date(2026, 8, 27, 23, 59, 59, 0, time.UTC),
		},
		{
			name:    "mixed formats",
			minRaw:  "2026-08-01",
			maxRaw:  "2026-08-31T23:59:59Z",
			wantMin: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
			wantMax: time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			name: "both empty gives two zero times",
		},
		{
			name:    "min_date equal max_date is accepted",
			minRaw:  "2026-08-27T00:00:00Z",
			maxRaw:  "2026-08-27T00:00:00Z",
			wantMin: time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC),
			wantMax: time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC),
		},
		{
			name:       "unparseable min_date names argument and both formats",
			minRaw:     "yesterday",
			wantErrSub: "min_date must be RFC3339",
		},
		{
			name:       "unparseable max_date names argument and both formats",
			maxRaw:     "yesterday",
			wantErrSub: "max_date must be RFC3339",
		},
		{
			name:       "inverted range",
			minRaw:     "2026-09-27T00:00:00Z",
			maxRaw:     "2026-08-27T00:00:00Z",
			wantErrSub: "min_date must not be after max_date",
		},
		{
			name:       "year-3000 min_date is out of range",
			minRaw:     "3000-01-01T00:00:00Z",
			wantErrSub: "min_date is out of range",
		},
		{
			// max_date is shifted +1 on the wire; the int32 edge itself
			// would overflow to a negative MaxDate.
			name:       "max_date at the int32 edge is out of range",
			maxRaw:     "2038-01-19T03:14:07Z",
			wantErrSub: "max_date is out of range",
		},
		{
			// min_date is shifted -1 on the wire; the epoch would go negative.
			name:       "min_date at the epoch is out of range",
			minRaw:     "1970-01-01T00:00:00Z",
			wantErrSub: "min_date is out of range",
		},
		{
			// A plain max_date resolves to 23:59:59Z, past the int32 edge.
			name:       "plain max_date on the last supported day is out of range",
			maxRaw:     "2038-01-19",
			wantErrSub: "max_date must be 2038-01-18 or earlier",
		},
		{
			name:    "plain max_date one day earlier is accepted",
			maxRaw:  "2038-01-18",
			wantMax: time.Date(2038, 1, 18, 23, 59, 59, 0, time.UTC),
		},
		{
			name:    "max_date one second below the int32 edge is accepted",
			maxRaw:  "2038-01-19T03:14:06Z",
			wantMax: time.Date(2038, 1, 19, 3, 14, 6, 0, time.UTC),
		},
		{
			name:       "year-3000 max_date is out of range",
			maxRaw:     "3000-01-01T00:00:00Z",
			wantErrSub: "max_date is out of range",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotMin, gotMax, err := parseSearchWindow(tc.minRaw, tc.maxRaw)
			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrSub)
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !gotMin.Equal(tc.wantMin) {
				t.Errorf("minDate = %v, want %v", gotMin, tc.wantMin)
			}
			if !gotMax.Equal(tc.wantMax) {
				t.Errorf("maxDate = %v, want %v", gotMax, tc.wantMax)
			}
		})
	}
}

func TestParseSearchWindow_UnparseableNamesBothFormats(t *testing.T) {
	_, _, err := parseSearchWindow("yesterday", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "RFC3339") || !strings.Contains(err.Error(), "2026-08-27") {
		t.Fatalf("error %q does not mention both accepted formats", err.Error())
	}
}
