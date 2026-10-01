package profile

import "testing"

// TestRejectDuplicateJSONKeys_WordingIsStable pins the error text this
// package's callers see, so moving the walk to internal/jsonstrict cannot
// change what ParseJSON or the admin handler report.
func TestRejectDuplicateJSONKeys_WordingIsStable(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"valid", `{"a":[1,{"b":2}],"c":{"d":null}}`, ""},
		{"duplicate", `{"a":1,"a":2}`, `duplicate JSON key "a"`},
		{"nested duplicate", `{"x":[{"b":1,"b":2}]}`, `duplicate JSON key "b"`},
		{"trailing value", `{"a":1} {}`, "profile document must contain exactly one JSON object"},
		{"truncated", `{"a":`, "EOF"},
		{"stray closer", `}`, "invalid character '}' looking for beginning of value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RejectDuplicateJSONKeys([]byte(tc.in))
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != tc.want {
				t.Errorf("RejectDuplicateJSONKeys(%s) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
