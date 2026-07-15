package sanitize

import (
	"strings"
	"testing"
)

// invisible returns a string containing the given Unicode code point.
// Used to construct test inputs without embedding literal invisible chars
// in the source file (Go's lexer rejects some code points in string literals).
func invisible(cp rune) string { return string([]rune{cp}) }

func TestUserContent(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		maxLength int
		want      string
	}{
		{"empty string", "", 4096, "[empty]"},
		{"whitespace only", "   \n  ", 4096, "[empty]"},
		// Invisible / zero-width characters stripped
		{"zero-width space stripped", "hello" + invisible(0x200B) + "world", 4096, "helloworld"},
		{"zero-width non-joiner stripped", "hello" + invisible(0x200C) + "world", 4096, "helloworld"},
		{"zero-width joiner stripped", "hello" + invisible(0x200D) + "world", 4096, "helloworld"},
		{"word joiner stripped", "hello" + invisible(0x2060) + "world", 4096, "helloworld"},
		{"ZWNBSP/BOM stripped", "hello" + invisible(0xFEFF) + "world", 4096, "helloworld"},
		{"soft hyphen stripped", "hello" + invisible(0x00AD) + "world", 4096, "helloworld"},
		// Control chars stripped, except \t and \n
		{"control char U+0001 stripped", "hello\x01world", 4096, "helloworld"},
		{"BEL stripped", "hello\x07world", 4096, "helloworld"},
		{"tab preserved", "hello\tworld", 4096, "hello\tworld"},
		{"newline preserved", "hello\nworld", 4096, "hello\nworld"},
		// Newline collapsing
		{"two newlines preserved", "a\n\nb", 4096, "a\n\nb"},
		{"three newlines collapsed", "a\n\n\nb", 4096, "a\n\nb"},
		{"four newlines collapsed", "a\n\n\n\nb", 4096, "a\n\nb"},
		// Normal text
		{"normal text unchanged", "Hello, World!", 4096, "Hello, World!"},
		{"unicode text unchanged", "\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 \xd0\xbc\xd0\xb8\xd1\x80", 4096, "\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 \xd0\xbc\xd0\xb8\xd1\x80"},
		// Truncation
		{"exact maxLength not truncated", "ab", 2, "ab"},
		{"over maxLength truncated", "abc", 2, "ab [truncated]"},
		// Trimming
		{"leading/trailing space trimmed", "  hello  ", 4096, "hello"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := UserContent(c.input, c.maxLength)
			if got != c.want {
				t.Errorf("UserContent(%q, %d) = %q, want %q", c.input, c.maxLength, got, c.want)
			}
		})
	}
}

func TestName(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		maxLength int
		want      string
	}{
		{"empty", "", 256, "[empty]"},
		{"newline replaced by space", "first\nlast", 256, "first last"},
		{"multiple newlines become spaces then collapsed", "a\n\nb", 256, "a b"},
		{"multiple spaces collapsed", "hello  world", 256, "hello world"},
		{"trimmed", "  hi  ", 256, "hi"},
		{"zero-width stripped", "name" + invisible(0x200B) + "!", 256, "name!"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Name(c.input, c.maxLength)
			if got != c.want {
				t.Errorf("Name(%q, %d) = %q, want %q", c.input, c.maxLength, got, c.want)
			}
		})
	}
}

func TestSensitiveTelegramContent(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "typical login code",
			input: "Login code: 31535. Do not share it.",
			want:  "Login code: [redacted]. Do not share it.",
		},
		{
			name:  "verification code with spaces",
			input: "verification code: 31 535",
			want:  "verification code: [redacted]",
		},
		{
			name:  "security code with hyphen",
			input: "security code: 315-35",
			want:  "security code: [redacted]",
		},
		{
			name:  "bare telegram code",
			input: "Telegram code: 31535",
			want:  "Telegram code: [redacted]",
		},
		{
			name:  "multiple codes",
			input: "Login code: 31535; confirmation code: 42424",
			want:  "Login code: [redacted]; confirmation code: [redacted]",
		},
		{
			name:  "ipv4 only",
			input: "IP: 79.143.107.63",
			want:  "IP: [redacted]",
		},
		{
			name:  "ipv6 only",
			input: "IP: 2001:db8::1",
			want:  "IP: [redacted]",
		},
		{
			name:  "combined code and ip",
			input: "Login code: 31535\nIP: 2001:db8::1",
			want:  "Login code: [redacted]\nIP: [redacted]",
		},
		{
			name:  "plain message unchanged",
			input: "Meet at 31535 near gate 2.",
			want:  "Meet at 31535 near gate 2.",
		},
		{
			name:  "bare number without keyword unchanged",
			input: "send 31535 now",
			want:  "send 31535 now",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SensitiveTelegramContent(c.input)
			if got != c.want {
				t.Errorf("SensitiveTelegramContent(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

func TestUserContent_LargeInput(t *testing.T) {
	large := strings.Repeat("a", 5000)
	got := UserContent(large, 4096)
	if !strings.HasSuffix(got, " [truncated]") {
		t.Error("expected truncation suffix")
	}
	suffix := " [truncated]"
	contentRunes := []rune(got[:len(got)-len(suffix)])
	if len(contentRunes) != 4096 {
		t.Errorf("expected 4096 runes before suffix, got %d", len(contentRunes))
	}
}
