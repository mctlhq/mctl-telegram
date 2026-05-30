package sanitize

import (
	"regexp"
	"strings"
	"unicode"
)

// invisibleChars is the set of zero-width and invisible Unicode code points
// that are stripped from user-controlled text.
var invisibleChars = map[rune]bool{
	0x00AD: true, // Soft hyphen
	0x034F: true, // Combining grapheme joiner
	0x061C: true, // Arabic letter mark
	0x17B4: true, // Khmer vowel inherent Aq
	0x17B5: true, // Khmer vowel inherent Aa
	0x180E: true, // Mongolian vowel separator
	0x200B: true, // Zero-width space
	0x200C: true, // Zero-width non-joiner
	0x200D: true, // Zero-width joiner
	0x2060: true, // Word joiner
	0xFEFF: true, // Zero-width no-break space / BOM
}

// excessiveNewlines matches three or more consecutive newlines.
var excessiveNewlines = regexp.MustCompile(`\n{3,}`)

// UserContent strips control characters, invisible chars, and excessive
// newlines from Telegram user-generated text before it is returned to an
// LLM client. Returns "[empty]" for blank input.
//
// maxLength is a rune count cap; text exceeding it is truncated with a
// " [truncated]" suffix. Pass 4096 for Telegram message bodies.
func UserContent(text string, maxLength int) string {
	if text == "" {
		return "[empty]"
	}

	cleaned := strings.Map(func(r rune) rune {
		if invisibleChars[r] {
			return -1
		}
		if (unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r)) && r != '\t' && r != '\n' {
			return -1
		}
		return r
	}, text)

	cleaned = excessiveNewlines.ReplaceAllString(cleaned, "\n\n")
	cleaned = strings.TrimSpace(cleaned)

	if cleaned == "" {
		return "[empty]"
	}

	runes := []rune(cleaned)
	if len(runes) > maxLength {
		return string(runes[:maxLength]) + " [truncated]"
	}
	return cleaned
}

// Name sanitizes a display name (username, chat title, sender name).
// Names are single-line: newlines are replaced with spaces.
func Name(text string, maxLength int) string {
	result := UserContent(text, maxLength)
	if result == "[empty]" {
		return result
	}
	result = strings.ReplaceAll(result, "\n", " ")
	result = regexp.MustCompile(` {2,}`).ReplaceAllString(result, " ")
	return strings.TrimSpace(result)
}
