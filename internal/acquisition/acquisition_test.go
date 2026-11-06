package acquisition

import (
	"strings"
	"testing"
	"time"
)

func TestUnmarshalEmptyOrMalformedHasNoClient(t *testing.T) {
	now := time.Now()
	for _, raw := range []string{"", "{not json", strings.Repeat("x", maxSnapshotBytes+1)} {
		if s := Unmarshal(raw, now); s.MCPClient != "" || s.CapturedAt.IsZero() {
			t.Fatalf("Unmarshal(%.20q) = %+v", raw, s)
		}
	}
}

func TestUnmarshalIgnoresCookieFieldsFromOlderImage(t *testing.T) {
	old := `{"s":"attributed","us":"x","uc":"y","rh":"news.example","lp":"/docs","mc":"claude","t":"2026-11-06T10:00:00Z"}`
	s := Unmarshal(old, time.Now())
	if s.MCPClient != "claude" || s.CapturedAt.Year() != 2026 {
		t.Fatalf("snapshot = %+v", s)
	}
	if strings.Contains(Marshal(s), "news.example") {
		t.Fatalf("old cookie values survived: %s", Marshal(s))
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	if s := Unmarshal(Marshal(New("chatgpt\n", now)), now); s.MCPClient != "chatgpt" || !s.CapturedAt.Equal(now) {
		t.Fatalf("round trip = %+v", s)
	}
}

func TestValidHeardFromOnlyAcceptsListedValues(t *testing.T) {
	for _, o := range HeardFromOptions {
		if !ValidHeardFrom(o.Value) {
			t.Errorf("%q must be valid", o.Value)
		}
	}
	for _, v := range []string{"", "SEARCH", "my friend Dana", "search "} {
		if ValidHeardFrom(v) {
			t.Errorf("%q must be refused", v)
		}
	}
}
