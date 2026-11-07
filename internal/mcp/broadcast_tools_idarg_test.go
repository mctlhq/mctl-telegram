package mcp

import "testing"

func TestTelegramIDListArg(t *testing.T) {
	ok := map[string]struct {
		in   map[string]any
		want []int64
	}{
		"absent": {map[string]any{}, nil},
		"nil":    {map[string]any{"ids": nil}, nil},
		"one":    {map[string]any{"ids": []any{float64(1001)}}, []int64{1001}},
		"two":    {map[string]any{"ids": []any{float64(1), float64(2)}}, []int64{1, 2}},
	}
	for name, c := range ok {
		got, err := telegramIDListArg(c.in, "ids")
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v want %v", name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v want %v", name, got, c.want)
			}
		}
	}
	// A bad element must fail the whole call: dropping it would silently
	// widen the audience relative to what the operator typed.
	for name, in := range map[string]map[string]any{
		"not an array": {"ids": "123"},
		"string elem":  {"ids": []any{float64(1), "2"}},
		"fraction":     {"ids": []any{1.5}},
		"zero":         {"ids": []any{float64(0)}},
		"negative":     {"ids": []any{float64(-3)}},
		"too large":    {"ids": []any{float64(1 << 60)}},
		"empty array":  {"ids": []any{}},
	} {
		if _, err := telegramIDListArg(in, "ids"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
