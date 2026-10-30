package canaryguard

import "testing"

func TestParse(t *testing.T) {
	s, err := Parse(" 1001, ,1002 ")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !s.Contains(1001) || !s.Contains(1002) {
		t.Fatalf("listed ids not contained: %v", s)
	}
	if s.Contains(1003) {
		t.Fatal("unlisted id contained")
	}
	if len(s) != 2 {
		t.Fatalf("len = %d, want 2", len(s))
	}
}

func TestParseEmpty(t *testing.T) {
	for _, raw := range []string{"", " ", ",", " , "} {
		s, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if len(s) != 0 {
			t.Fatalf("Parse(%q) = %v, want empty", raw, s)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, raw := range []string{"abc", "1001,x", "0", "-5", "1.5"} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("Parse(%q) accepted a malformed id", raw)
		}
	}
}

func TestContainsIgnoresNonPositive(t *testing.T) {
	var zero Set
	if zero.Contains(1001) {
		t.Fatal("zero Set contained an id")
	}
	s, _ := Parse("1001")
	if s.Contains(0) || s.Contains(-1001) {
		t.Fatal("non-positive id matched")
	}
}
